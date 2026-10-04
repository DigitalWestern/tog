//! Importers for pnpm lockfiles and Yarn classic lockfiles.
//!
//! This is deliberately a small parser for the machine-written subsets used
//! here. It is not a general YAML implementation: anchors, aliases, folded
//! scalars, and arbitrary YAML tags are unsupported. The graph is normalized
//! to the npm tailor's literal node_modules paths before realization.

use crate::kernel::fetch::Digest;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::Platform;
use crate::tailors::node::inputs::input_exists;
use crate::tailors::node::{NpmLink, NpmPackage, NpmPatch, NpmPlan};
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(test)]
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

mod pnpm;
mod yaml;
mod yarn1;

pub use pnpm::*;
use yaml::*;
pub use yarn1::*;

fn err(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn identity_key(name: &str, version: &str) -> String {
    format!("{name}@{}", trim_peer_suffix(version))
}

#[derive(Debug, Clone)]
enum Target {
    Node(String),
    Link(String),
    External(String),
}

#[derive(Debug, Clone)]
struct Dependency {
    name: String,
    target: Target,
    optional: bool,
}

#[derive(Debug, Clone)]
struct Node {
    key: String,
    name: String,
    version: String,
    url: String,
    integrity: String,
    optional: bool,
    os: Vec<String>,
    cpu: Vec<String>,
    libc: Vec<String>,
    external: Option<String>,
    patch: Option<NpmPatch>,
    deps: Vec<Dependency>,
}

#[derive(Debug, Clone)]
struct RootDependency {
    dependency: Dependency,
    workspace: Option<String>,
}

#[derive(Debug, Clone)]
struct Graph {
    nodes: BTreeMap<String, Node>,
    roots: Vec<RootDependency>,
    workspace_roots: Vec<RootDependency>,
    workspace_paths: BTreeSet<String>,
    local_link_deps: BTreeMap<String, Vec<Dependency>>,
}

fn integrity_policy(path: &str, integrity: &str) -> io::Result<()> {
    integrity_policy_with(path, integrity, &mut crate::kernel::policy::record)
}

/// `integrity_policy` recording through `record`, so a test can pass a
/// policy of its own instead of the process one.
fn integrity_policy_with(
    path: &str,
    integrity: &str,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
) -> io::Result<()> {
    let digest = Digest::from_sri(integrity)?;
    if digest.algo() == "sha1" {
        record(
            crate::kernel::policy::WEAK_INTEGRITY,
            path,
            "sha1 integrity accepted and verified, but is cryptographically weak",
        )?;
    }
    Ok(())
}

/// Refuse a link target (project-relative, plain names only) that a
/// symlink carries outside `root`. A target that does not exist yet is
/// judged by its deepest existing ancestor: the rest is plain names, so
/// whatever is created there stays beneath it. A symlink that resolves
/// nowhere could lead anywhere once its target appears, so it is refused.
/// Resolved on the pathname: ProjectRoot has no canonicalize.
fn contain_link_target(root: &Path, target: &str, raw: &str) -> io::Result<()> {
    let mut existing = root.join(target);
    let canonical = loop {
        match existing.canonicalize() {
            Ok(canonical) => break canonical,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if existing.is_symlink() {
                    return Err(err(format!(
                        "workspace link target {raw:?} passes through a dangling symlink; tog cannot tell whether it stays in the project"
                    )));
                }
                existing.pop();
            }
            Err(error) => return Err(err(format!("workspace link target {raw:?}: {error}"))),
        }
    };
    if !canonical.starts_with(root) {
        return Err(err(format!(
            "workspace link target {raw:?} is outside the project"
        )));
    }
    Ok(())
}

fn package_url(
    name: &str,
    version: &str,
    resolution: Option<&BTreeMap<String, YamlValue>>,
) -> Option<String> {
    resolution
        .and_then(|resolution| yaml_str(resolution.get("tarball")))
        .map(str::to_string)
        .or_else(|| {
            let basename = name.rsplit('/').next().unwrap_or(name);
            Some(format!(
                "https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz"
            ))
        })
}

/// The git source a pnpm resolution names, when it is pinned to a full commit.
fn pinned_git_source(
    resolution: Option<&BTreeMap<String, YamlValue>>,
) -> Option<crate::kernel::gitsrc::GitSource> {
    let resolution = resolution?;
    if let (Some(repo), Some(commit)) = (
        yaml_str(resolution.get("repo")),
        yaml_str(resolution.get("commit")),
    ) {
        if crate::kernel::gitsrc::is_full_commit(commit) {
            return Some(crate::kernel::gitsrc::GitSource {
                url: crate::kernel::gitsrc::normalize_url(repo),
                commit: commit.to_ascii_lowercase(),
                subdirectory: None,
            });
        }
    }
    // A codeload/archive URL with an SRI is an attested tarball.  Only fall
    // back to commit-based git realization when the lock gives us no bytes
    // integrity to verify; explicit git protocols remain git sources.
    let tarball = yaml_str(resolution.get("tarball")).unwrap_or_default();
    let integrity = yaml_str(resolution.get("integrity"));
    crate::tailors::node::explicit_git_source(tarball).or_else(|| {
        integrity
            .is_none()
            .then(|| crate::tailors::node::git_source_from_url(tarball))
            .flatten()
    })
}

fn lock_git_source(url: &str, has_integrity: bool) -> Option<crate::kernel::gitsrc::GitSource> {
    crate::tailors::node::explicit_git_source(url).or_else(|| {
        (!has_integrity)
            .then(|| crate::tailors::node::git_source_from_url(url))
            .flatten()
    })
}

/// The restriction list that excludes this host, if one does. Only a pnpm
/// lock records restrictions; yarn.lock carries none, so its nodes are
/// compatible everywhere.
fn node_unsupported(platform: Platform, node: &Node) -> Option<&'static str> {
    fn values(list: &[String]) -> Vec<&str> {
        list.iter().map(String::as_str).collect()
    }
    crate::tailors::node::plan::unsupported_restriction(
        platform,
        &values(&node.os),
        &values(&node.cpu),
        &values(&node.libc),
    )
}

#[derive(Debug, Clone)]
enum Occupied {
    Package {
        node_key: String,
        name: String,
        version: String,
    },
    Link {
        target: String,
        name: String,
    },
}

fn occupied_description(occupied: &Occupied) -> String {
    match occupied {
        Occupied::Package { name, version, .. } => format!("{name}@{version}"),
        Occupied::Link { name, target } => format!("{name} (workspace link {target})"),
    }
}

fn target_identity(target: &Target, nodes: &BTreeMap<String, Node>) -> Option<String> {
    match target {
        // The full snapshot key, including peers, is the graph identity.
        // Tarball identity is intentionally not used for placement.
        Target::Node(key) => nodes.get(key).map(|node| node.key.clone()),
        Target::Link(target) => Some(format!("link:{target}")),
        Target::External(_) => None,
    }
}

fn same_target(existing: &Occupied, target: &Target, nodes: &BTreeMap<String, Node>) -> bool {
    match (existing, target_identity(target, nodes)) {
        (Occupied::Package { node_key, .. }, Some(identity)) => nodes
            .get(node_key)
            .map(|node| node.key == identity)
            .unwrap_or_else(|| node_key == &identity),
        (Occupied::Link { target: old, .. }, Some(identity)) => identity == format!("link:{old}"),
        _ => false,
    }
}

fn dependency_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        format!("node_modules/{name}")
    } else {
        format!("{parent}/node_modules/{name}")
    }
}

fn parent_context(path: &str) -> String {
    path.rsplit_once("/node_modules/")
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_default()
}

fn workspace_parent_context(path: &str, workspaces: &BTreeSet<String>) -> String {
    workspaces
        .iter()
        .filter(|workspace| {
            workspace.len() < path.len()
                && path.starts_with(workspace.as_str())
                && path.as_bytes().get(workspace.len()) == Some(&b'/')
        })
        .max_by_key(|workspace| workspace.len())
        .cloned()
        .unwrap_or_default()
}

/// Whoever needs a dependency resolved from a real path in the project: an
/// importer, or a local `file:` package. `context` is where Node's walk up
/// the projected node_modules starts.
#[derive(Debug, Clone)]
struct Requirer {
    who: String,
    context: String,
    local: bool,
}

/// The first `node_modules/<name>` Node's resolver meets walking up from
/// `context`, if any.
fn first_on_chain<'a>(
    context: &str,
    name: &str,
    occupied: &'a BTreeMap<String, Occupied>,
    workspaces: &BTreeSet<String>,
) -> Option<(String, &'a Occupied)> {
    let mut context = context.to_string();
    loop {
        let path = dependency_path(&context, name);
        if let Some(existing) = occupied.get(&path) {
            return Some((path, existing));
        }
        if context.is_empty() {
            return None;
        }
        context = if context.contains("/node_modules/") {
            parent_context(&context)
        } else {
            workspace_parent_context(&context, workspaces)
        };
    }
}

fn target_description(dependency: &Dependency, nodes: &BTreeMap<String, Node>) -> String {
    match &dependency.target {
        Target::Node(key) => nodes
            .get(key)
            .map(|node| format!("{}@{}", node.name, node.version))
            .unwrap_or_else(|| key.clone()),
        Target::Link(target) => format!("{} (workspace link {target})", dependency.name),
        Target::External(detail) => format!("{} ({detail})", dependency.name),
    }
}

/// Two requirements Node would resolve to the same `node_modules/<name>`,
/// named both ways round.
fn conflict(
    requirer: &Requirer,
    dependency: &Dependency,
    (path, found): (&str, &Occupied),
    requirements: &[(Requirer, Dependency)],
    occupied: &BTreeMap<String, Occupied>,
    workspaces: &BTreeSet<String>,
    nodes: &BTreeMap<String, Node>,
) -> io::Error {
    // Prefer the requirer that resolves to that very path.
    let holders = requirements.iter().filter(|(_, other)| {
        other.name == dependency.name && same_target(found, &other.target, nodes)
    });
    let holder = holders
        .clone()
        .find(|(holder, _)| {
            first_on_chain(&holder.context, &dependency.name, occupied, workspaces)
                .is_some_and(|(held, _)| held == path)
        })
        .or_else(|| holders.clone().next());
    let holder_who = holder.map_or("another package", |(holder, _)| holder.who.as_str());
    let mut message = format!(
        "{} needs {} but {holder_who} needs {}, and Node resolving from {}'s real path reaches {path} first; tog cannot project both",
        requirer.who,
        target_description(dependency, nodes),
        occupied_description(found),
        requirer.who,
    );
    if requirer.local || holder.is_some_and(|(holder, _)| holder.local) {
        message.push_str(
            ". file: packages whose dependencies conflict with their workspace member's are not supported yet",
        );
    }
    err(message)
}

fn existing_ancestor(
    parent: &str,
    name: &str,
    target: &Target,
    occupied: &BTreeMap<String, Occupied>,
    nodes: &BTreeMap<String, Node>,
    workspaces: &BTreeSet<String>,
) -> Result<Option<String>, ()> {
    let mut context = parent.to_string();
    loop {
        let path = dependency_path(&context, name);
        if let Some(existing) = occupied.get(&path) {
            if same_target(existing, target, nodes) {
                return Ok(Some(path));
            }
            // Node's resolver stops at the first node_modules/name it finds,
            // even when that package is the wrong version. Do not skip this
            // nearer conflict and incorrectly reuse a higher ancestor.
            return Err(());
        }
        if context.is_empty() {
            return Ok(None);
        }
        context = if context.contains("/node_modules/") {
            parent_context(&context)
        } else {
            workspace_parent_context(&context, workspaces)
        };
    }
}

/// A dependency the lockfile could not resolve to a package. Returning `Ok`
/// means the traversal skips it (an optional git dependency is recorded as a
/// policy exception first); a required one is fatal.
fn skip_external_dependency(
    dependency: &Dependency,
    detail: &str,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
) -> io::Result<()> {
    if !dependency.optional {
        return Err(err(format!("{}: {detail}", dependency.name)));
    }
    if detail.starts_with("npm_git_dep:") {
        record(
            crate::kernel::policy::GIT_DEPENDENCY,
            &dependency.name,
            detail,
        )?;
    }
    Ok(())
}

/// What a `foreign-platform-package` exception says about a package.
fn foreign_platform_detail(platform: Platform, node: &Node) -> String {
    let mut restrictions = Vec::new();
    for (field, values) in [("os", &node.os), ("cpu", &node.cpu), ("libc", &node.libc)] {
        if !values.is_empty() {
            restrictions.push(format!("{field}={values:?}"));
        }
    }
    format!(
        "{} excludes host {}; placed as files, the way pnpm places a required package, and its install scripts are not run",
        restrictions.join(", "),
        platform.triple()
    )
}

/// The graph node this dependency names, once it is known to be realizable on
/// this host. `Ok(None)` means the traversal skips it: an optional package
/// that is platform-incompatible, unresolvable, or carries no integrity.
///
/// A required package whose restrictions exclude this host is realizable:
/// pnpm warns and installs it (a project that cross-compiles lists every
/// platform's binary as a plain dependency), so it is placed and recorded as
/// a `foreign-platform-package` exception, which a policy can deny.
fn realizable_node<'a>(
    platform: Platform,
    nodes: &'a BTreeMap<String, Node>,
    node_key: &str,
    dependency: &Dependency,
    lock_source: &str,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
) -> io::Result<Option<&'a Node>> {
    let node = nodes.get(node_key).ok_or_else(|| {
        err(format!(
            "{}: missing graph node {node_key}",
            dependency.name
        ))
    })?;
    // A pnpm identity may carry its tarball URL as the version; never
    // print that URL's credentials.
    let version = crate::tailors::node::redact_url_userinfo(&node.version);
    if node_unsupported(platform, node).is_some() {
        if dependency.optional || node.optional {
            // pnpm records every platform variant in one lockfile;
            // incompatible optional packages are omitted.
            return Ok(None);
        }
        record(
            crate::kernel::policy::FOREIGN_PLATFORM_PACKAGE,
            &format!("{}@{version}", node.name),
            &foreign_platform_detail(platform, node),
        )?;
    }
    if let Some(detail) = &node.external {
        if dependency.optional || node.optional {
            if detail.starts_with("npm_git_dep:") {
                record(crate::kernel::policy::GIT_DEPENDENCY, &node.name, detail)?;
            }
            return Ok(None);
        }
        return Err(err(format!("{}@{version}: {detail}", node.name)));
    }
    // A git source is verified by its commit, so it legitimately
    // has no tarball integrity.
    let node_git = lock_git_source(&node.url, !node.integrity.is_empty());
    if node.integrity.is_empty() && node_git.is_none() {
        if dependency.optional || node.optional {
            return Ok(None);
        }
        // Both importers share this path, so name the lockfile that was
        // actually read: the field is `resolution.integrity` in
        // pnpm-lock.yaml and `integrity` in yarn.lock.
        return Err(err(format!(
            "{}@{}: {lock_source} entry has no integrity",
            node.name, version
        )));
    }
    // Git sources carry `git:<commit>` instead of an SRI.
    if node_git.is_none() {
        integrity_policy(&format!("{lock_source}/{node_key}"), &node.integrity)?;
    }
    Ok(Some(node))
}

/// npm's hoisting decision for one package: reuse the nearest ancestor that
/// already holds this exact target, else the root when it is free or holds the
/// same target, else a nested placement under the parent.
#[allow(clippy::too_many_arguments)]
fn place_node_package(
    node_key: &str,
    node: &Node,
    dependency: &Dependency,
    parent: &str,
    in_workspace: bool,
    occupied: &mut BTreeMap<String, Occupied>,
    nodes: &BTreeMap<String, Node>,
    workspace_paths: &BTreeSet<String>,
) -> io::Result<String> {
    let ancestor = existing_ancestor(
        parent,
        &dependency.name,
        &dependency.target,
        occupied,
        nodes,
        workspace_paths,
    );
    if let Ok(Some(path)) = &ancestor {
        return Ok(path.clone());
    }
    let blocked_by_nearer_conflict = ancestor.is_err();
    let root = dependency_path("", &dependency.name);
    let path = if let Some(existing) = occupied.get(&root) {
        if !blocked_by_nearer_conflict && same_target(existing, &dependency.target, nodes) {
            root
        } else if in_workspace {
            dependency_path(parent, &dependency.name)
        } else if parent.is_empty() {
            return Err(err(format!(
                "{}: root dependencies conflict between {} and {}@{}",
                dependency.name,
                occupied_description(existing),
                node.name,
                node.version
            )));
        } else {
            dependency_path(parent, &dependency.name)
        }
    } else {
        root
    };
    if let Some(existing) = occupied.get(&path) {
        if !same_target(existing, &dependency.target, nodes) {
            return Err(err(format!(
                "{}: two versions conflict at {} ({} and {}@{})",
                dependency.name,
                path,
                occupied_description(existing),
                node.name,
                node.version
            )));
        }
    } else {
        occupied.insert(
            path.clone(),
            Occupied::Package {
                node_key: node_key.to_string(),
                name: node.name.clone(),
                version: node.version.clone(),
            },
        );
    }
    Ok(path)
}

/// Placement for a workspace link. Same hoisting shape as a package, except
/// the claim also registers the `NpmLink` the projection plants.
fn place_workspace_link(
    target: &str,
    dependency: &Dependency,
    parent: &str,
    in_workspace: bool,
    occupied: &mut BTreeMap<String, Occupied>,
    links: &mut BTreeMap<String, NpmLink>,
    nodes: &BTreeMap<String, Node>,
) -> io::Result<String> {
    let claim = |occupied: &mut BTreeMap<String, Occupied>,
                 links: &mut BTreeMap<String, NpmLink>,
                 path: &str| {
        occupied.insert(
            path.to_string(),
            Occupied::Link {
                target: target.to_string(),
                name: dependency.name.clone(),
            },
        );
        links.insert(
            path.to_string(),
            NpmLink {
                path: path.to_string(),
                target: target.to_string(),
            },
        );
    };
    let root = dependency_path("", &dependency.name);
    let Some(existing) = occupied.get(&root) else {
        let path = if in_workspace {
            dependency_path(parent, &dependency.name)
        } else {
            root.clone()
        };
        claim(occupied, links, &path);
        return Ok(path);
    };
    if same_target(existing, &dependency.target, nodes) {
        return Ok(root);
    }
    if in_workspace {
        let path = dependency_path(parent, &dependency.name);
        if let Some(existing) = occupied.get(&path) {
            if !same_target(existing, &dependency.target, nodes) {
                return Err(err(format!(
                    "{}: two workspace versions conflict at {} ({} and link:{})",
                    dependency.name,
                    path,
                    occupied_description(existing),
                    target
                )));
            }
        } else {
            claim(occupied, links, &path);
        }
        return Ok(path);
    }
    if parent.is_empty() {
        return Err(err(format!(
            "{}: workspace hoisting conflict between {} and link:{}",
            dependency.name,
            occupied_description(existing),
            target
        )));
    }
    let path = dependency_path(parent, &dependency.name);
    claim(occupied, links, &path);
    Ok(path)
}

/// Turn the settled placement map into the plan's package list.
fn resolved_packages(
    platform: Platform,
    occupied: BTreeMap<String, Occupied>,
    nodes: &BTreeMap<String, Node>,
    needs_workspace: &BTreeSet<String>,
) -> io::Result<Vec<NpmPackage>> {
    let mut packages = Vec::new();
    for (path, occupied) in occupied {
        crate::tailors::node::validate_lock_path(&path)?;
        let Occupied::Package { node_key, .. } = occupied else {
            continue;
        };
        let node = nodes
            .get(&node_key)
            .ok_or_else(|| err(format!("internal: no package for {path}")))?;
        let git = lock_git_source(&node.url, !node.integrity.is_empty());
        packages.push(NpmPackage {
            path: path.clone(),
            name: node.name.clone(),
            version: node.version.clone(),
            url: node.url.clone(),
            integrity: match &git {
                Some(source) => format!("git:{}", source.commit),
                None => node.integrity.clone(),
            },
            bin: Vec::new(),
            patch: node.patch.clone(),
            git,
            // Placed although this host is excluded: only a required
            // package gets this far, and it was recorded when it was placed.
            foreign_platform: node_unsupported(platform, node).is_some(),
            needs_workspace: needs_workspace.contains(&path),
        });
    }
    packages.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(packages)
}

/// A link below a package sits inside that package's directory. When the
/// package itself asked for the link, the projection is a copy and the link
/// is planted in the copy. Any other link there (an importer keyed beneath a
/// package) would be written through a symlink into a read-only store
/// object.
fn check_links_inside_packages(
    links: &BTreeMap<String, NpmLink>,
    occupied: &BTreeMap<String, Occupied>,
    needs_workspace: &BTreeSet<String>,
) -> io::Result<()> {
    for (path, link) in links {
        // The nearest enclosing package owns the directory the link is in.
        let host = occupied
            .iter()
            .filter(|(package, entry)| {
                matches!(entry, Occupied::Package { .. })
                    && path.starts_with(&format!("{package}/"))
            })
            .map(|(package, _)| package)
            .max_by_key(|package| package.len());
        if let Some(package) = host.filter(|package| !needs_workspace.contains(*package)) {
            return Err(err(format!(
                "link {path} -> {} would be planted inside the package {package}, which is store content; tog cannot project a local package nested under a registry package that does not depend on it",
                link.target
            )));
        }
    }
    Ok(())
}

/// `build_plan_recording` through the process policy.
fn build_plan(
    platform: Platform,
    graph: Graph,
    lock_source: &str,
    node_version: &str,
) -> io::Result<NpmPlan> {
    let record = &mut crate::kernel::policy::record;
    build_plan_recording(platform, graph, lock_source, node_version, record)
}

/// Place every package and link the graph reaches. `needs_workspace`
/// collects, by placed path, the registry packages with a dependency on a
/// workspace package (a plugin whose peer is the package this repository
/// develops): wherever the link lands, beside the package or hoisted, the
/// package only finds it from a real path inside the project.
fn build_plan_recording(
    platform: Platform,
    graph: Graph,
    lock_source: &str,
    node_version: &str,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
) -> io::Result<NpmPlan> {
    // One placed package, one exception: the traversal below reaches a
    // required foreign-platform package once per dependency edge that names
    // it, but the package is placed a single time, so its
    // `foreign-platform-package` exception is recorded once per placed
    // package instead of once per edge. (Greptile review on #398.)
    let mut seen_foreign = BTreeSet::<String>::new();
    let inner_record = &mut *record;
    let mut dedup_record = |kind: &str, subject: &str, detail: &str| -> io::Result<()> {
        if kind == crate::kernel::policy::FOREIGN_PLATFORM_PACKAGE
            && !seen_foreign.insert(subject.to_string())
        {
            return Ok(());
        }
        inner_record(kind, subject, detail)
    };
    let record = &mut dedup_record;
    let workspace_paths = graph.workspace_paths.clone();
    let mut occupied = BTreeMap::<String, Occupied>::new();
    // (parent, dependency, workspace, who needs it when it is a requirement
    // Node must resolve from a real path in the project)
    let mut queue = VecDeque::<(String, Dependency, Option<String>, Option<Requirer>)>::new();
    let enqueue_roots = |roots: Vec<RootDependency>, queue: &mut VecDeque<_>| {
        for root in roots {
            let parent = root.workspace.clone().unwrap_or_default();
            let requirer = Requirer {
                who: match &root.workspace {
                    Some(workspace) => format!("importer {workspace}"),
                    None => "the root importer".to_string(),
                },
                context: parent.clone(),
                local: false,
            };
            queue.push_back((parent, root.dependency, root.workspace, Some(requirer)));
        }
    };
    enqueue_roots(graph.roots, &mut queue);
    let mut workspace_queue = VecDeque::new();
    enqueue_roots(graph.workspace_roots, &mut workspace_queue);
    let mut expanded = BTreeSet::<(String, String)>::new();
    let mut links = BTreeMap::<String, NpmLink>::new();
    // Every importer's own dependencies and every local package's, once
    // placed: checked against the final layout, so a later placement cannot
    // shadow one of them unnoticed.
    let mut requirements = Vec::<(Requirer, Dependency)>::new();
    let mut needs_workspace = BTreeSet::<String>::new();

    while !queue.is_empty() || !workspace_queue.is_empty() {
        if queue.is_empty() {
            std::mem::swap(&mut queue, &mut workspace_queue);
        }
        let (parent, dependency, workspace, requirer) = queue.pop_front().unwrap();
        // A local package's dependency that cannot be placed conflicts with
        // whatever already holds its name on the real-path lookup chain.
        let for_local = |error: io::Error,
                         occupied: &BTreeMap<String, Occupied>,
                         requirements: &[(Requirer, Dependency)]| {
            let Some(requirer) = requirer.as_ref().filter(|requirer| requirer.local) else {
                return error;
            };
            match first_on_chain(
                &requirer.context,
                &dependency.name,
                occupied,
                &workspace_paths,
            ) {
                Some((path, found)) => conflict(
                    requirer,
                    &dependency,
                    (&path, found),
                    requirements,
                    occupied,
                    &workspace_paths,
                    &graph.nodes,
                ),
                None => error,
            }
        };
        let in_workspace =
            workspace.is_some() || (!parent.is_empty() && !parent.starts_with("node_modules/"));
        let (path, should_expand) = match &dependency.target {
            Target::External(detail) => {
                skip_external_dependency(&dependency, detail, record)?;
                continue;
            }
            Target::Node(node_key) => {
                // A platform-skipped optional dependency is not placed, so it
                // is no requirement either.
                let Some(node) = realizable_node(
                    platform,
                    &graph.nodes,
                    node_key,
                    &dependency,
                    lock_source,
                    record,
                )?
                else {
                    continue;
                };
                let path = place_node_package(
                    node_key,
                    node,
                    &dependency,
                    &parent,
                    in_workspace,
                    &mut occupied,
                    &graph.nodes,
                    &workspace_paths,
                )
                .map_err(|error| for_local(error, &occupied, &requirements))?;
                (path, true)
            }
            Target::Link(target) => {
                // Only a registry package's own dependency has no requirer.
                if requirer.is_none() && occupied.contains_key(&parent) {
                    needs_workspace.insert(parent.clone());
                }
                let path = place_workspace_link(
                    target,
                    &dependency,
                    &parent,
                    in_workspace,
                    &mut occupied,
                    &mut links,
                    &graph.nodes,
                )
                .map_err(|error| for_local(error, &occupied, &requirements))?;
                (path, false)
            }
        };
        if let Some(requirer) = requirer {
            requirements.push((requirer, dependency.clone()));
        }
        if should_expand {
            let Target::Node(node_key) = dependency.target else {
                continue;
            };
            if expanded.insert((path.clone(), node_key.clone())) {
                if let Some(node) = graph.nodes.get(&node_key) {
                    for child in &node.deps {
                        queue.push_back((path.clone(), child.clone(), None, None));
                    }
                }
            }
        } else if let Target::Link(target) = &dependency.target {
            // A link is the user's own source directory, so nothing may be
            // planted beneath it: `<link>/node_modules/...` would be written
            // through the symlink into that source tree. Node resolves a
            // linked package from its real path, so:
            // - a target that is itself an importer already gets its own
            //   dependencies from its own projected node_modules, exactly as
            //   pnpm installs every importer; expanding again adds nothing;
            // - any other local package gets its dependencies placed where
            //   Node looks from the target's real path, wherever the link
            //   itself sits: the nearest enclosing importer's node_modules,
            //   then the importers above it. The only node_modules tog
            //   projects into source are importers', so that chain is the
            //   whole lookup; reachability is checked after placement.
            let importer = target == "." || workspace_paths.contains(target);
            if !importer && expanded.insert((String::new(), format!("link:{target}"))) {
                let context = workspace_parent_context(target, &workspace_paths);
                if let Some(children) = graph.local_link_deps.get(target) {
                    for child in children {
                        let requirer = Requirer {
                            who: format!("the file: package {target}"),
                            context: context.clone(),
                            local: true,
                        };
                        queue.push_back((context.clone(), child.clone(), None, Some(requirer)));
                    }
                }
            }
        }
    }

    // Node walks up from each requirer's real path and stops at the first
    // node_modules/<name>; that first hit must be what the lock gave it.
    for (requirer, dependency) in &requirements {
        if let Some((path, found)) = first_on_chain(
            &requirer.context,
            &dependency.name,
            &occupied,
            &workspace_paths,
        ) {
            if !same_target(found, &dependency.target, &graph.nodes) {
                return Err(conflict(
                    requirer,
                    dependency,
                    (&path, found),
                    &requirements,
                    &occupied,
                    &workspace_paths,
                    &graph.nodes,
                ));
            }
        }
    }
    check_links_inside_packages(&links, &occupied, &needs_workspace)?;
    let packages = resolved_packages(platform, occupied, &graph.nodes, &needs_workspace)?;
    check_destinations(&packages, &links)?;
    Ok(NpmPlan {
        node_version: node_version.to_string(),
        packages,
        links: links.into_values().collect(),
        workspaces: workspace_paths.into_iter().collect(),
        lock_source: lock_source.to_string(),
    })
}

/// Check the settled package and link paths together before they become a
/// plan: each is a well-formed lock path, none lies beneath a link, and no
/// two share a directory on a case-insensitive filesystem.
fn check_destinations(
    packages: &[NpmPackage],
    links: &BTreeMap<String, NpmLink>,
) -> io::Result<()> {
    for link in links.values() {
        crate::tailors::node::validate_lock_path(&link.path)?;
    }
    // Projection plants packages and links by creating directories along
    // their paths; one beneath a link would land in the user's source tree.
    let link_dirs = links
        .keys()
        .map(|link| format!("{link}/"))
        .collect::<Vec<_>>();
    let beneath_link = |path: &str| {
        link_dirs
            .iter()
            .find(|link| path.starts_with(link.as_str()))
            .map(|link| link.trim_end_matches('/').to_string())
    };
    for path in packages
        .iter()
        .map(|package| &package.path)
        .chain(links.keys())
    {
        if let Some(link) = beneath_link(path) {
            return Err(err(format!(
                "{path} would be placed inside the linked source directory {link}; refusing to write into it"
            )));
        }
    }
    crate::tailors::node::refuse_case_colliding_paths(
        packages
            .iter()
            .map(|package| package.path.as_str())
            .chain(links.keys().map(String::as_str)),
    )
}

#[cfg(test)]
mod tests {
    /// The importer tests care about the package graph, not about
    /// selection: any version the shipped catalog offers reads the same.
    pub(super) fn node_version() -> &'static str {
        crate::tailors::node::node_pin(crate::kernel::platform::Platform::X86_64UnknownLinuxGnu)
            .unwrap()
            .version
    }

    /// A fixture project held the way sync holds it.
    pub(super) fn held(dir: &std::path::Path) -> crate::kernel::fsroot::ProjectRoot {
        crate::kernel::fsroot::ProjectRoot::open(dir).unwrap()
    }

    #[test]
    fn a_quote_inside_a_plain_key_does_not_open_a_quoted_scalar() {
        let lock = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/it's: {}\n  packages/plain: {}\n";
        assert_eq!(
            pnpm_lock_importers(lock).unwrap(),
            vec![
                ".".to_string(),
                "packages/it's".to_string(),
                "packages/plain".to_string()
            ],
            "pnpm writes packages/it's unquoted, so treating the apostrophe as \
             the start of a quoted scalar rejects the whole lockfile and wedges \
             every project in the workspace"
        );
    }

    #[test]
    fn a_quote_opens_a_scalar_only_where_a_scalar_can_begin() {
        assert_eq!(
            split_key_value("packages/it's: {}"),
            Some(("packages/it's".to_string(), "{}".to_string())),
            "an apostrophe mid-token is an ordinary character"
        );
        assert_eq!(
            split_key_value("'packages/a #c': {}"),
            Some(("packages/a #c".to_string(), "{}".to_string())),
            "a quote at the very start does open a quoted scalar"
        );
        assert_eq!(
            split_key_value("key: {'a: b': 1, 'c': 2}"),
            Some(("key".to_string(), "{'a: b': 1, 'c': 2}".to_string())),
            "a quote after an opening brace or a comma opens a scalar, so the \
             colon inside it must not split the line"
        );
        assert_eq!(
            split_key_value("key: [{'x: y': 1}, 'z']"),
            Some(("key".to_string(), "[{'x: y': 1}, 'z']".to_string())),
            "nested flow collections keep the same rule"
        );
        assert_eq!(
            split_key_value("a:b: value"),
            Some(("a:b".to_string(), "value".to_string())),
            "a colon not followed by whitespace is part of the key and starts \
             a new scalar position"
        );
        assert_eq!(
            split_key_value("a:'b': value"),
            Some(("a:'b'".to_string(), "value".to_string())),
            "a quote right after a non-splitting colon opens a scalar, so the \
             quoted run is skipped rather than scanned for a separator"
        );
        assert_eq!(
            split_key_value("{a: 1}'b': c"),
            Some(("{a: 1}'b'".to_string(), "c".to_string())),
            "a closing bracket ends the scalar position, so a quote directly \
             after it is an ordinary character"
        );
        assert_eq!(split_key_value("no separator here"), None);
    }
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    pub(super) const SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

    pub(super) fn project() -> TempDir {
        let dir = TempDir::named("lock-import");
        fs::create_dir_all(dir.0.join("packages/lib")).unwrap();
        dir
    }

    /// Tests that inspect pending policy exceptions must not overlap with one
    /// another or inherit an exception from a previous test. The lock is the
    /// crate-wide one: a module-private lock that still clears the shared
    /// queue could wipe another module's test mid-assertion.
    fn exception_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::kernel::policy::exception_guard()
    }

    #[test]
    fn pnpm_v9_catalog_peer_link_optional_platform_and_undefined_catalog() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
settings: {{}}
catalogs:
  default:
    is-odd: ^3.0.0
importers:
  .:
    dependencies:
      is-odd:
        specifier: catalog:
        version: 3.0.1
      lib:
        specifier: workspace:*
        version: link:packages/lib
    optionalDependencies:
      mac-only:
        specifier: 1.0.0
        version: 1.0.0
packages:
  is-odd@3.0.1:
    resolution: {{integrity: {SRI}}}
  is-number@6.0.0:
    resolution: {{integrity: {SRI}}}
  mac-only@1.0.0:
    resolution: {{integrity: {SRI}}}
    os: [darwin]
snapshots:
  is-odd@3.0.1:
    dependencies:
      is-number: 6.0.0(peer@1.0.0)
  is-number@6.0.0(peer@1.0.0): {{}}
  mac-only@1.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert_eq!(plan.lock_source, "pnpm-lock.yaml");
        assert!(plan.links.iter().any(|link| link.target == "packages/lib"));
        assert!(plan.packages.iter().any(|package| package.name == "is-odd"));
        assert!(plan
            .packages
            .iter()
            .any(|package| package.name == "is-number"));
        assert!(!plan
            .packages
            .iter()
            .any(|package| package.name == "mac-only"));

        // A `catalog:` specifier the lock's catalogs do not define is refused:
        // a named catalog that is absent, and a default catalog without an
        // entry for the dependency.
        for (lock, catalog) in [
            (
                lock.replace("specifier: catalog:", "specifier: catalog:absent"),
                "absent",
            ),
            (
                lock.replace("    is-odd: ^3.0.0\n", "    other: ^1.0.0\n"),
                "",
            ),
        ] {
            let error = plan_pnpm(
                Platform::X86_64UnknownLinuxGnu,
                &lock,
                &held(&dir.0),
                node_version(),
            )
            .unwrap_err()
            .to_string();
            assert_eq!(
                error,
                format!("importer . dependency is-odd: catalog:{catalog} is not defined")
            );
        }
    }

    /// Characterization: the whole placement result for one graph that
    /// exercises hoisting, a nearer-conflict nesting, a workspace link and an
    /// optional platform skip — every package field pinned, so a refactor of
    /// the traversal cannot quietly move a value.
    #[test]
    fn build_plan_characterization_pins_the_whole_placement() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
settings: {{}}
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: 1.0.0
      b:
        specifier: 1.0.0
        version: 1.0.0
      lib:
        specifier: workspace:*
        version: link:packages/lib
    optionalDependencies:
      mac-only:
        specifier: 1.0.0
        version: 1.0.0
packages:
  a@1.0.0:
    resolution: {{integrity: {SRI}, tarball: https://r/a.tgz}}
  b@1.0.0:
    resolution: {{integrity: {SRI}, tarball: https://r/b.tgz}}
  c@1.0.0:
    resolution: {{integrity: {SRI}, tarball: https://r/c1.tgz}}
  c@2.0.0:
    resolution: {{integrity: {SRI}, tarball: https://r/c2.tgz}}
  mac-only@1.0.0:
    resolution: {{integrity: {SRI}}}
    os: [darwin]
snapshots:
  a@1.0.0:
    dependencies:
      c: 1.0.0
  b@1.0.0:
    dependencies:
      c: 2.0.0
  c@1.0.0: {{}}
  c@2.0.0: {{}}
  mac-only@1.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        let placed: Vec<(&str, &str, &str)> = plan
            .packages
            .iter()
            .map(|p| (p.path.as_str(), p.version.as_str(), p.url.as_str()))
            .collect();
        assert_eq!(
            placed,
            vec![
                ("node_modules/a", "1.0.0", "https://r/a.tgz"),
                ("node_modules/b", "1.0.0", "https://r/b.tgz"),
                ("node_modules/b/node_modules/c", "2.0.0", "https://r/c2.tgz"),
                ("node_modules/c", "1.0.0", "https://r/c1.tgz"),
            ],
            "the optional darwin package is dropped, c@1 hoists and the \
             nearer conflict nests c@2 under its dependent"
        );
        for package in &plan.packages {
            assert_eq!(package.integrity, SRI);
            assert!(package.bin.is_empty());
            assert!(package.patch.is_none());
            assert!(package.git.is_none());
        }
        let links: Vec<(&str, &str)> = plan
            .links
            .iter()
            .map(|l| (l.path.as_str(), l.target.as_str()))
            .collect();
        assert_eq!(links, vec![("node_modules/lib", "packages/lib")]);
        assert_eq!(plan.lock_source, "pnpm-lock.yaml");
        assert!(plan.workspaces.is_empty());
    }

    #[test]
    fn pnpm_v6_normalizes_package_keys_before_traversal() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '6.0'
dependencies:
  a:
    version: 1.0.0
packages:
  /a@1.0.0:
    resolution: {{integrity: {SRI}}}
    dependencies:
      b: 1.0.0
  /b@1.0.0:
    resolution: {{integrity: {SRI}}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan
            .packages
            .iter()
            .any(|package| package.path == "node_modules/a"));
        assert!(plan.packages.iter().any(|package| package.name == "b"));
    }

    #[test]
    fn pnpm_lock_without_packages_map_is_an_empty_plan() {
        // `pnpm self-update` in a bare directory writes a two-document lock:
        // a prelude holding pnpm's own binary, then the real project lock,
        // which has no dependencies and therefore no `packages` key.
        let dir = project();
        let lock = format!(
            r#"---
lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {{}}
    packageManagerDependencies:
      pnpm:
        specifier: 12.3.4
        version: 12.3.4

packages:

  pnpm@12.3.4:
    resolution: {{integrity: {SRI}}}

---
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.packages.is_empty(), "{:?}", plan.packages);
        assert!(plan.links.is_empty(), "{:?}", plan.links);
    }

    #[test]
    fn patched_dependencies_are_verified_and_change_the_package_identity() {
        let dir = project();
        let patch_path = dir.0.join("patches/foo@1.0.0.patch");
        fs::create_dir_all(patch_path.parent().unwrap()).unwrap();
        let patch_bytes = b"diff --git a/index.js b/index.js\n";
        fs::write(&patch_path, patch_bytes).unwrap();
        let hash = hex::encode(Sha256::digest(patch_bytes));
        let lock = format!(
            r#"lockfileVersion: '9.0'
patchedDependencies:
  foo@1.0.0: {hash}
importers:
  .:
    dependencies:
      foo:
        specifier: 1.0.0
        version: 1.0.0
packages:
  foo@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  foo@1.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert_eq!(
            plan.packages[0]
                .patch
                .as_ref()
                .map(|patch| patch.hash.as_str()),
            Some(hash.as_str())
        );
        fs::write(&patch_path, b"changed patch").unwrap();
        let error = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("patch foo@1.0.0 hash mismatch"));
    }

    /// pnpm 9 declares patch hashes as base32-encoded md5, not sha256 hex
    /// (see `check_patch_hash`). The lockfile string is stored verbatim
    /// because it is an environment-identity input.
    #[test]
    fn pnpm_9_base32_patch_hashes_are_accepted_and_stored_verbatim() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let dir = project();
        let patch_path = dir.0.join("patches/foo@1.0.0.patch");
        fs::create_dir_all(patch_path.parent().unwrap()).unwrap();
        let patch_bytes = b"diff --git a/index.js b/index.js\n";
        fs::write(&patch_path, patch_bytes).unwrap();
        let hash = "kpncbvlbnwqxywzzahw2g7pnwq";
        let lock = format!(
            r#"lockfileVersion: '9.0'
patchedDependencies:
  foo@1.0.0:
    path: patches/foo@1.0.0.patch
    hash: {hash}
importers:
  .:
    dependencies:
      foo:
        specifier: 1.0.0
        version: 1.0.0
packages:
  foo@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  foo@1.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert_eq!(
            plan.packages[0]
                .patch
                .as_ref()
                .map(|patch| patch.hash.as_str()),
            Some(hash)
        );
        let expected_content_sha256 = hex::encode(Sha256::digest(patch_bytes));
        assert_eq!(
            plan.packages[0]
                .patch
                .as_ref()
                .and_then(|patch| patch.content_sha256.as_deref()),
            Some(expected_content_sha256.as_str())
        );
        let exceptions = crate::kernel::policy::pending();
        assert_eq!(exceptions.len(), 1, "{exceptions:?}");
        assert_eq!(exceptions[0].kind, crate::kernel::policy::WEAK_INTEGRITY);
        assert_eq!(exceptions[0].subject, "foo@1.0.0");
        assert_eq!(
            exceptions[0].detail,
            "pnpm 9 md5 patch hash accepted and verified, but is cryptographically weak; the environment id binds the patch by sha256"
        );
        fs::write(&patch_path, b"changed patch").unwrap();
        let error = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap_err();
        // The computed value is reported in the declared encoding.
        assert!(
            error
                .to_string()
                .contains("expected kpncbvlbnwqxywzzahw2g7pnwq, got uncj4ibb6pblo7yg3phh2pzyhy"),
            "{error}"
        );
    }

    #[test]
    fn pnpm_9_md5_patch_hash_respects_a_denying_policy() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let dir = project();
        let patch_path = dir.0.join("patches/foo@1.0.0.patch");
        fs::create_dir_all(patch_path.parent().unwrap()).unwrap();
        let patch_bytes = b"diff --git a/index.js b/index.js\n";
        fs::write(&patch_path, patch_bytes).unwrap();
        let lock = |hash: &str| {
            format!(
                r#"lockfileVersion: '9.0'
patchedDependencies:
  foo@1.0.0:
    path: patches/foo@1.0.0.patch
    hash: {hash}
importers:
  .:
    dependencies:
      foo:
        specifier: 1.0.0
        version: 1.0.0
packages:
  foo@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  foo@1.0.0: {{}}
"#
            )
        };
        let deny_weak_integrity = crate::kernel::policy::Policy {
            deny: std::collections::BTreeSet::from([
                crate::kernel::policy::WEAK_INTEGRITY.to_string()
            ]),
            ..Default::default()
        };
        let md5_error = super::pnpm::plan_pnpm_with_policy(
            Platform::X86_64UnknownLinuxGnu,
            &lock("kpncbvlbnwqxywzzahw2g7pnwq"),
            &held(&dir.0),
            node_version(),
            &deny_weak_integrity,
        )
        .unwrap_err();
        assert!(md5_error
            .to_string()
            .contains("policy denies weak-integrity"));

        let sha256_plan = super::pnpm::plan_pnpm_with_policy(
            Platform::X86_64UnknownLinuxGnu,
            &lock("2692094a267de7e28825147fd6cb2ebde098a4e68c25dfa3976ac806f4a1a784"),
            &held(&dir.0),
            node_version(),
            &deny_weak_integrity,
        )
        .unwrap();
        assert!(sha256_plan.packages[0]
            .patch
            .as_ref()
            .unwrap()
            .content_sha256
            .is_none());
    }

    #[test]
    fn local_snapshot_dependencies_are_traversed_from_the_source_link() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      parent:
        specifier: 1.0.0
        version: 1.0.0
packages:
  parent@1.0.0:
    resolution: {{integrity: {SRI}}}
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  parent@1.0.0:
    dependencies:
      a: file:vendor/a
  a@file:vendor/a:
    dependencies:
      b: 1.0.0
  b@1.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.links.iter().any(|link| link.target == "vendor/a"));
        assert!(plan
            .packages
            .iter()
            .any(|package| package.path == "node_modules/b" && package.name == "b"));
    }

    #[test]
    fn peer_snapshots_are_separate_nodes_with_separate_children() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: 1.0.0
      b:
        specifier: 1.0.0
        version: 1.0.0
packages:
  a@1.0.0:
    resolution: {{integrity: {SRI}}}
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
  plugin@1.0.0:
    resolution: {{integrity: {SRI}}}
  child-a@1.0.0:
    resolution: {{integrity: {SRI}}}
  child-b@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  a@1.0.0:
    dependencies:
      plugin: 1.0.0(peer@1.0.0)
  b@1.0.0:
    dependencies:
      plugin: 1.0.0(peer@2.0.0)
  plugin@1.0.0(peer@1.0.0):
    dependencies:
      child-a: 1.0.0
  plugin@1.0.0(peer@2.0.0):
    dependencies:
      child-b: 1.0.0
  child-a@1.0.0: {{}}
  child-b@1.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.packages.iter().any(|package| {
            package.path == "node_modules/plugin" && package.version == "1.0.0"
        }));
        assert!(plan.packages.iter().any(|package| {
            package.path == "node_modules/b/node_modules/plugin" && package.version == "1.0.0"
        }));
        assert!(plan
            .packages
            .iter()
            .any(|package| package.name == "child-a"));
        assert!(plan
            .packages
            .iter()
            .any(|package| { package.name == "child-b" }));
    }

    #[test]
    fn nearer_conflict_nests_required_version_instead_of_skipping_to_root() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      b:
        specifier: 1.0.0
        version: 1.0.0
      c:
        specifier: 1.0.0
        version: 1.0.0
      d:
        specifier: 1.0.0
        version: 1.0.0
packages:
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
  c@1.0.0:
    resolution: {{integrity: {SRI}}}
  c@2.0.0:
    resolution: {{integrity: {SRI}}}
  d@1.0.0:
    resolution: {{integrity: {SRI}}}
  d@2.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  b@1.0.0:
    dependencies:
      c: 2.0.0
      d: 2.0.0
  c@1.0.0: {{}}
  c@2.0.0: {{}}
  d@1.0.0: {{}}
  d@2.0.0:
    dependencies:
      c: 1.0.0
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.packages.iter().any(|package| {
            package.path == "node_modules/b/node_modules/d/node_modules/c"
                && package.version == "1.0.0"
        }));
        assert!(!plan
            .packages
            .iter()
            .any(|package| { package.path == "node_modules/c" && package.version == "2.0.0" }));
        // The root keeps its own version, and the plan lists paths in order.
        assert!(plan
            .packages
            .iter()
            .any(|package| { package.path == "node_modules/c" && package.version == "1.0.0" }));
        let paths: Vec<_> = plan
            .packages
            .iter()
            .map(|package| package.path.as_str())
            .collect();
        assert_eq!(paths, {
            let mut sorted = paths.clone();
            sorted.sort();
            sorted
        });
    }

    #[test]
    fn pnpm_required_git_errors_and_optional_git_is_skipped_with_an_exception() {
        let _policy_guard = exception_guard();
        let dir = project();
        let required = "\
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      git-required:
        specifier: git
        version: 1.0.0
packages:
  git-required@1.0.0:
    resolution: {type: git, repo: https://example.invalid/a, commit: abc}
snapshots: {}
";
        let error = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            required,
            &held(&dir.0),
            node_version(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("npm_git_dep"));

        // Renamed in the importer and the package key alike, so the
        // optional importer entry still resolves to the git package.
        let optional = required
            .replace("dependencies:", "optionalDependencies:")
            .replace("git-required", "git-optional");
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &optional,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.packages.is_empty());
        let exceptions = crate::kernel::policy::drain();
        assert_eq!(exceptions.len(), 1, "{exceptions:?}");
        assert_eq!(exceptions[0].kind, crate::kernel::policy::GIT_DEPENDENCY);
        assert_eq!(exceptions[0].subject, "git-optional");
        assert!(
            exceptions[0]
                .detail
                .starts_with("npm_git_dep: git-optional: repo https://example.invalid/a"),
            "{exceptions:?}"
        );
    }

    /// tailwindcss's shape: a project that cross-compiles lists every
    /// platform's binary package as a plain dependency, and one more as an
    /// optional one.
    fn every_platform_lock() -> String {
        format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      watcher-darwin-arm64:
        specifier: 2.6.0
        version: 2.6.0
      watcher-linux-x64-glibc:
        specifier: 2.6.0
        version: 2.6.0
    optionalDependencies:
      watcher-win32-x64:
        specifier: 2.6.0
        version: 2.6.0
packages:
  watcher-darwin-arm64@2.6.0:
    resolution: {{integrity: {SRI}}}
    cpu: [arm64]
    os: [darwin]
  watcher-linux-x64-glibc@2.6.0:
    resolution: {{integrity: {SRI}}}
    cpu: [x64]
    os: [linux]
    libc: [glibc]
  watcher-win32-x64@2.6.0:
    resolution: {{integrity: {SRI}}}
    cpu: [x64]
    os: [win32]
snapshots:
  watcher-darwin-arm64@2.6.0: {{}}
  watcher-linux-x64-glibc@2.6.0: {{}}
  watcher-win32-x64@2.6.0:
    optional: true
"#
        )
    }

    /// (name, foreign_platform) of every planned package, in plan order.
    fn foreign_flags(plan: &NpmPlan) -> Vec<(&str, bool)> {
        plan.packages
            .iter()
            .map(|package| (package.name.as_str(), package.foreign_platform))
            .collect()
    }

    /// pnpm installs a required package whose os/cpu excludes the host, so
    /// the plan places it, marks it, and records one exception for it. An
    /// optional one is still left out, and a native one is not marked.
    #[test]
    fn a_required_foreign_platform_package_is_placed_and_recorded() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let dir = project();
        let permissive = crate::kernel::policy::Policy::default();
        let plan = super::pnpm::plan_pnpm_with_policy(
            Platform::X86_64UnknownLinuxGnu,
            &every_platform_lock(),
            &held(&dir.0),
            node_version(),
            &permissive,
        )
        .unwrap();
        assert_eq!(
            foreign_flags(&plan),
            [
                ("watcher-darwin-arm64", true),
                ("watcher-linux-x64-glibc", false)
            ]
        );
        let exceptions = crate::kernel::policy::drain();
        assert_eq!(exceptions.len(), 1, "{exceptions:?}");
        assert_eq!(
            exceptions[0].kind,
            crate::kernel::policy::FOREIGN_PLATFORM_PACKAGE
        );
        assert_eq!(exceptions[0].subject, "watcher-darwin-arm64@2.6.0");
        assert_eq!(
            exceptions[0].detail,
            "os=[\"darwin\"], cpu=[\"arm64\"] excludes host x86_64-unknown-linux-gnu; placed as files, the way pnpm places a required package, and its install scripts are not run"
        );
    }

    /// The same lock on the other host: which package is foreign follows the
    /// host, and `libc` is a restriction on Linux only.
    #[test]
    fn which_package_is_foreign_follows_the_host() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let dir = project();
        let permissive = crate::kernel::policy::Policy::default();
        let plan = super::pnpm::plan_pnpm_with_policy(
            Platform::Aarch64AppleDarwin,
            &every_platform_lock(),
            &held(&dir.0),
            node_version(),
            &permissive,
        )
        .unwrap();
        assert_eq!(
            foreign_flags(&plan),
            [
                ("watcher-darwin-arm64", false),
                ("watcher-linux-x64-glibc", true)
            ]
        );
        let exceptions = crate::kernel::policy::drain();
        assert_eq!(exceptions.len(), 1, "{exceptions:?}");
        assert_eq!(exceptions[0].subject, "watcher-linux-x64-glibc@2.6.0");
        assert!(
            exceptions[0].detail.starts_with(
                "os=[\"linux\"], cpu=[\"x64\"], libc=[\"glibc\"] excludes host aarch64-apple-darwin;"
            ),
            "{exceptions:?}"
        );
    }

    /// A policy that denies the kind turns the placement back into a
    /// refusal that names the kind and the package.
    #[test]
    fn a_denied_foreign_platform_package_refuses_the_lock() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let dir = project();
        let deny = crate::kernel::policy::Policy {
            deny: std::collections::BTreeSet::from([
                crate::kernel::policy::FOREIGN_PLATFORM_PACKAGE.to_string(),
            ]),
            ..Default::default()
        };
        let error = super::pnpm::plan_pnpm_with_policy(
            Platform::X86_64UnknownLinuxGnu,
            &every_platform_lock(),
            &held(&dir.0),
            node_version(),
            &deny,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("policy denies foreign-platform-package: watcher-darwin-arm64@2.6.0"),
            "{error}"
        );
        assert!(crate::kernel::policy::drain().is_empty());
    }

    /// A pnpm lock's restriction lists read the way a package-lock's do:
    /// the same list gives the same verdict through either planner, on
    /// either host.
    #[test]
    fn pnpm_and_npm_locks_judge_a_restriction_list_alike() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let dir = project();
        let permissive = crate::kernel::policy::Policy::default();
        // (the list as YAML, the list as JSON, supported on Linux, on macOS)
        let cases = [
            ("[any]", r#"["any"]"#, true, true),
            ("[linux, '!win32']", r#"["linux","!win32"]"#, true, false),
            ("['!darwin']", r#"["!darwin"]"#, true, false),
            ("[darwin, linux]", r#"["darwin","linux"]"#, true, true),
            ("linux", r#""linux""#, true, false),
            ("[any, '!darwin']", r#"["any","!darwin"]"#, false, false),
        ];
        for (yaml, json, on_linux, on_macos) in cases {
            let pnpm_lock = format!(
                r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      restricted:
        specifier: 1.0.0
        version: 1.0.0
packages:
  restricted@1.0.0:
    resolution: {{integrity: {SRI}}}
    os: {yaml}
snapshots:
  restricted@1.0.0: {{}}
"#
            );
            let npm_lock = format!(
                r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/restricted":{{"version":"1.0.0","os":{json},"resolved":"https://r/restricted.tgz","integrity":"{SRI}"}}}}}}"#
            );
            for (platform, supported) in [
                (Platform::X86_64UnknownLinuxGnu, on_linux),
                (Platform::Aarch64AppleDarwin, on_macos),
            ] {
                let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
                let plan = super::pnpm::plan_pnpm_with_policy(
                    platform,
                    &pnpm_lock,
                    &held(&dir.0),
                    node_version(),
                    &permissive,
                )
                .unwrap();
                assert_eq!(
                    foreign_flags(&plan),
                    [("restricted", !supported)],
                    "pnpm os: {yaml} on {platform:?}"
                );
                crate::kernel::policy::drain();
                assert_eq!(
                    crate::tailors::node::plan_npm(platform, &npm_lock).is_ok(),
                    supported,
                    "npm os: {json} on {platform:?}"
                );
            }
        }
    }

    /// tailwindcss's other shape: a registry plugin whose peer is the
    /// package the repository develops. `root_core` is what the root
    /// importer depends on under the name `core`.
    fn workspace_peer_lock(root_core: &str) -> String {
        format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      core:
{root_core}
      plugin:
        specifier: 1.0.0
        version: 1.0.0(core@packages+core)
  packages/core: {{}}
packages:
  core@3.0.0:
    resolution: {{integrity: {SRI}}}
  plugin@1.0.0:
    resolution: {{integrity: {SRI}}}
    peerDependencies:
      core: '*'
snapshots:
  core@3.0.0: {{}}
  plugin@1.0.0(core@packages+core):
    dependencies:
      core: link:packages/core
"#
        )
    }

    fn workspace_peer_plan(root_core: &str) -> NpmPlan {
        let dir = project();
        fs::create_dir_all(dir.0.join("packages/core")).unwrap();
        plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &workspace_peer_lock(root_core),
            &held(&dir.0),
            node_version(),
        )
        .unwrap()
    }

    /// (path, needs_workspace) of every planned package, in plan order.
    fn workspace_flags(plan: &NpmPlan) -> Vec<(&str, bool)> {
        plan.packages
            .iter()
            .map(|package| (package.path.as_str(), package.needs_workspace))
            .collect()
    }

    fn link_pairs(plan: &NpmPlan) -> Vec<(&str, &str)> {
        plan.links
            .iter()
            .map(|link| (link.path.as_str(), link.target.as_str()))
            .collect()
    }

    /// The root already holds a registry `core`, so the plugin's link to the
    /// workspace `core` has to sit inside the plugin. That is planned, not
    /// refused, and the plugin is marked so the projection becomes a copy.
    #[test]
    fn a_plugin_whose_peer_is_a_workspace_package_gets_its_link_beside_it() {
        let plan = workspace_peer_plan("        specifier: 3.0.0\n        version: 3.0.0");
        assert_eq!(
            workspace_flags(&plan),
            [("node_modules/core", false), ("node_modules/plugin", true)]
        );
        assert_eq!(
            link_pairs(&plan),
            [("node_modules/plugin/node_modules/core", "packages/core")]
        );
    }

    /// The dependent is itself nested: the root holds another version of it
    /// and of `core`. The link belongs to the nearest enclosing package, the
    /// nested dependent, which is the one marked, not the package above it.
    #[test]
    fn a_nested_dependent_owns_the_link_planted_inside_it() {
        let dir = project();
        fs::create_dir_all(dir.0.join("packages/core")).unwrap();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: 1.0.0(core@packages+core)
      core:
        specifier: 3.0.0
        version: 3.0.0
      plugin:
        specifier: 1.0.0
        version: 1.0.0
  packages/core: {{}}
packages:
  a@1.0.0:
    resolution: {{integrity: {SRI}}}
  core@3.0.0:
    resolution: {{integrity: {SRI}}}
  plugin@1.0.0:
    resolution: {{integrity: {SRI}}}
  plugin@2.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  a@1.0.0(core@packages+core):
    dependencies:
      plugin: 2.0.0(core@packages+core)
  core@3.0.0: {{}}
  plugin@1.0.0: {{}}
  plugin@2.0.0(core@packages+core):
    dependencies:
      core: link:packages/core
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert_eq!(
            workspace_flags(&plan),
            [
                ("node_modules/a", false),
                ("node_modules/a/node_modules/plugin", true),
                ("node_modules/core", false),
                ("node_modules/plugin", false),
            ]
        );
        assert_eq!(
            link_pairs(&plan),
            [(
                "node_modules/a/node_modules/plugin/node_modules/core",
                "packages/core"
            )]
        );
    }

    /// With the workspace `core` hoisted to the root, no link sits inside
    /// the plugin, and the plugin is marked all the same: from a store
    /// object it could not reach the root link either.
    #[test]
    fn a_plugin_whose_workspace_peer_is_hoisted_is_still_marked() {
        let plan = workspace_peer_plan(
            "        specifier: workspace:*\n        version: link:packages/core",
        );
        assert_eq!(workspace_flags(&plan), [("node_modules/plugin", true)]);
        assert_eq!(link_pairs(&plan), [("node_modules/core", "packages/core")]);
    }

    #[test]
    fn workspace_importer_gets_its_own_conflicting_version() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      shared:
        specifier: 1.0.0
        version: 1.0.0
  packages/lib:
    dependencies:
      shared:
        specifier: 2.0.0
        version: 2.0.0
packages:
  shared@1.0.0:
    resolution: {{integrity: {SRI}}}
  shared@2.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  shared@1.0.0: {{}}
  shared@2.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan
            .packages
            .iter()
            .any(|package| package.path == "node_modules/shared" && package.version == "1.0.0"));
        assert!(plan.packages.iter().any(|package| {
            package.path == "packages/lib/node_modules/shared" && package.version == "2.0.0"
        }));
    }

    #[test]
    fn nested_workspace_uses_an_explicit_placement_past_an_intervening_workspace() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      c:
        specifier: 1.0.0
        version: 1.0.0
  p:
    dependencies:
      c:
        specifier: 2.0.0
        version: 2.0.0
  p/child:
    dependencies:
      c:
        specifier: 1.0.0
        version: 1.0.0
packages:
  c@1.0.0:
    resolution: {{integrity: {SRI}}}
  c@2.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  c@1.0.0: {{}}
  c@2.0.0: {{}}
"#
        );
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan
            .packages
            .iter()
            .any(|package| { package.path == "p/node_modules/c" && package.version == "2.0.0" }));
        assert!(plan.packages.iter().any(|package| {
            package.path == "p/child/node_modules/c" && package.version == "1.0.0"
        }));
    }

    /// A yarn v1 entry keyed by several selectors serves the manifest's
    /// later one too; its `#sha1` fragments are accepted as sha1 integrity
    /// and each recorded as weak; a Berry lock is refused.
    #[test]
    fn yarn_v1_later_selector_resolves_sha1_is_recorded_weak_and_berry_is_refused() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let dir = project();
        let lock = "\
# yarn lockfile v1
\"is-odd@3.0.1\", is-odd@^3.0.0:
  version \"3.0.1\"
  resolved \"https://registry.yarnpkg.com/is-odd/-/is-odd-3.0.1.tgz#0000000000000000000000000000000000000000\"
  dependencies:
    is-number \"^6.0.0\"
is-number@^6.0.0:
  version \"6.0.0\"
  resolved \"https://registry.yarnpkg.com/is-number/-/is-number-6.0.0.tgz#0000000000000000000000000000000000000000\"
";
        // The entry's second key: the first one alone would not serve it.
        let package_json = r#"{"dependencies":{"is-odd":"^3.0.0"}}"#;
        let plan = plan_yarn(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            package_json,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert_eq!(plan.packages.len(), 2);
        assert!(plan
            .packages
            .iter()
            .all(|package| package.integrity.starts_with("sha1-")));
        // Both entries are recorded as weak. Subjects are the importer's
        // entry keys (`yarn:<index>`), each recorded at parse and again
        // when the entry is realized, so match per entry, not the count.
        let exceptions = crate::kernel::policy::drain();
        assert!(!exceptions.is_empty());
        for exception in &exceptions {
            assert_eq!(
                exception.kind,
                crate::kernel::policy::WEAK_INTEGRITY,
                "{exceptions:?}"
            );
            assert_eq!(
                exception.detail,
                "sha1 integrity accepted and verified, but is cryptographically weak"
            );
        }
        for entry in ["yarn:0", "yarn:1"] {
            assert!(
                exceptions
                    .iter()
                    .any(|exception| exception.subject.ends_with(entry)),
                "{entry}: {exceptions:?}"
            );
        }
        let berry = "__metadata:\n  version: 6\n";
        let error = plan_yarn(
            Platform::X86_64UnknownLinuxGnu,
            berry,
            package_json,
            &held(&dir.0),
            node_version(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cache-zip checksums"));
    }

    /// `realizable_node` is shared by the pnpm and Yarn-classic importers, so
    /// its missing-integrity refusal must name the lockfile that was read
    /// rather than pnpm's spelling of the field for every caller.
    #[test]
    fn missing_integrity_names_the_lockfile_that_was_read() {
        let node = Node {
            key: "is-odd@3.0.1".into(),
            name: "is-odd".into(),
            version: "3.0.1".into(),
            url: "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz".into(),
            integrity: String::new(),
            optional: false,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            external: None,
            patch: None,
            deps: Vec::new(),
        };
        let nodes = BTreeMap::from([(node.key.clone(), node)]);
        let dependency = Dependency {
            name: "is-odd".into(),
            target: Target::Node("is-odd@3.0.1".into()),
            optional: false,
        };
        for lock_source in ["pnpm-lock.yaml", "yarn.lock"] {
            let error = realizable_node(
                Platform::X86_64UnknownLinuxGnu,
                &nodes,
                "is-odd@3.0.1",
                &dependency,
                lock_source,
                &mut crate::kernel::policy::record,
            )
            .unwrap_err()
            .to_string();
            assert_eq!(
                error,
                format!("is-odd@3.0.1: {lock_source} entry has no integrity")
            );
        }

        // And the whole way through a real importer: a pnpm entry whose
        // resolution carries a tarball but no integrity.
        let dir = project();
        let lock = "\
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      is-odd:
        specifier: 3.0.1
        version: 3.0.1
packages:
  is-odd@3.0.1:
    resolution: {tarball: https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz}
snapshots:
  is-odd@3.0.1: {}
";
        let error = super::pnpm::plan_pnpm_with_policy(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            &held(&dir.0),
            node_version(),
            &crate::kernel::policy::Policy::default(),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(error, "is-odd@3.0.1: pnpm-lock.yaml entry has no integrity");
    }

    #[test]
    fn yarn_v1_workspace_manifests_supply_roots_and_links() {
        let dir = project();
        fs::write(
            dir.0.join("package.json"),
            r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"@fixture/lib":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.0.join("packages/lib/package.json"),
            r#"{"name":"@fixture/lib","version":"1.0.0","dependencies":{"dep":"1.0.0"}}"#,
        )
        .unwrap();
        let lock = format!(
            r#"# yarn lockfile v1
dep@1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/dep/-/dep-1.0.0.tgz#0000000000000000000000000000000000000000"
  integrity {SRI}
"#
        );
        let package = fs::read_to_string(dir.0.join("package.json")).unwrap();
        let plan = plan_yarn(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &package,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.packages.iter().any(|package| package.name == "dep"));
        assert!(plan
            .links
            .iter()
            .any(|link| link.path == "node_modules/@fixture/lib" && link.target == "packages/lib"));
    }

    /// A yarn.lock written before a manifest changed: every direct
    /// dependency must name a selector the lock holds, and every lock entry
    /// must be reachable from some manifest.
    #[test]
    fn yarn_refuses_a_lock_that_disagrees_with_a_manifest() {
        let lock = format!(
            r#"# yarn lockfile v1
a@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/a/-/a-1.0.0.tgz"
  integrity {SRI}
b@2.0.0:
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/b/-/b-2.0.0.tgz"
  integrity {SRI}
"#
        );
        let plan = |package: &str, lib: Option<&str>| {
            let dir = project();
            if let Some(lib) = lib {
                fs::write(dir.0.join("packages/lib/package.json"), lib).unwrap();
            }
            plan_yarn(
                Platform::X86_64UnknownLinuxGnu,
                &lock,
                package,
                &held(&dir.0),
                node_version(),
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        };
        let stale = |manifest: &str, field: &str| {
            Err(format!(
                "{manifest} {field} disagree with yarn.lock; regenerate the lock (yarn install)"
            ))
        };
        let fresh = r#"{"dependencies":{"a":"^1.0.0"},"devDependencies":{"b":"2.0.0"}}"#;
        assert_eq!(plan(fresh, None), Ok(()));
        assert_eq!(
            plan(
                r#"{"dependencies":{"a":"^1.0.0","left-pad":"^1.3.0"},"devDependencies":{"b":"2.0.0"}}"#,
                None
            ),
            stale("package.json", "dependencies")
        );
        assert_eq!(
            plan(
                r#"{"dependencies":{"a":"^1.0.0"},"devDependencies":{"b":"^2.0.0"}}"#,
                None
            ),
            stale("package.json", "devDependencies")
        );
        // An optional dependency is locked on every platform, so a missing
        // one is a stale lock too, not a skipped package.
        assert_eq!(
            plan(
                r#"{"dependencies":{"a":"^1.0.0"},"devDependencies":{"b":"2.0.0"},"optionalDependencies":{"c":"1"}}"#,
                None
            ),
            stale("package.json", "optionalDependencies")
        );
        assert_eq!(
            plan(r#"{"dependencies":{"a":"^1.0.0"}}"#, None),
            Err(
                "yarn.lock locks b@2.0.0, which no package.json depends on; \
                 regenerate the lock (yarn install)"
                    .to_string()
            )
        );

        // A workspace member's own dependencies are checked under its path,
        // and a member another manifest names is a link, not a lock entry.
        let root = r#"{"name":"root","workspaces":["packages/*"],
            "dependencies":{"a":"^1.0.0","lib":"^1.0.0"}}"#;
        let lib = r#"{"name":"lib","version":"1.2.0","dependencies":{"b":"2.0.0"}}"#;
        assert_eq!(plan(root, Some(lib)), Ok(()));
        let edited =
            r#"{"name":"lib","version":"1.2.0","dependencies":{"b":"2.0.0","left-pad":"^1.3.0"}}"#;
        assert_eq!(
            plan(root, Some(edited)),
            stale("packages/lib/package.json", "dependencies")
        );
        let malformed = plan(root, Some("{")).unwrap_err();
        assert!(
            malformed.starts_with("Yarn workspace packages/lib: package.json: "),
            "{malformed}"
        );
        assert!(plan("{", None).unwrap_err().starts_with("package.json: "));
    }

    /// Yarn classic never locks a `link:` dependency, so its absence from
    /// the lock is not a stale lock. It is planned as the link Yarn makes:
    /// a symlink in the naming manifest's `node_modules` to a directory read
    /// relative to the directory holding yarn.lock, required or optional
    /// alike.
    #[test]
    fn an_unlocked_yarn_link_is_planned_as_a_link_to_its_directory() {
        fn links(dir: &TempDir, package_json: &str) -> io::Result<Vec<(String, String)>> {
            plan_yarn(
                Platform::X86_64UnknownLinuxGnu,
                "# yarn lockfile v1\n",
                package_json,
                &held(&dir.0),
                node_version(),
            )
            .map(|plan| {
                assert!(plan.packages.is_empty(), "{:?}", plan.packages);
                plan.links
                    .into_iter()
                    .map(|link| (link.path, link.target))
                    .collect()
            })
        }
        let dir = project();
        fs::create_dir_all(dir.0.join("vendor/local")).unwrap();
        let local = vec![("node_modules/local".to_string(), "vendor/local".to_string())];
        for field in ["dependencies", "devDependencies", "optionalDependencies"] {
            for spec in ["link:./vendor/local", "link:vendor/local"] {
                let package = format!(r#"{{"{field}":{{"local":"{spec}"}}}}"#);
                assert_eq!(links(&dir, &package).unwrap(), local, "{field} {spec}");
            }
        }

        // A workspace member's link lands in the member's node_modules, and
        // is still read from the project root, as Yarn reads it: not from
        // the member's own directory, where the same words would name
        // packages/lib/vendor/local.
        fs::create_dir_all(dir.0.join("packages/lib/vendor/local")).unwrap();
        fs::write(
            dir.0.join("packages/lib/package.json"),
            r#"{"name":"lib","version":"1.0.0","dependencies":{"local":"link:vendor/local"}}"#,
        )
        .unwrap();
        assert_eq!(
            links(&dir, r#"{"private":true,"workspaces":["packages/*"]}"#).unwrap(),
            vec![
                ("node_modules/lib".to_string(), "packages/lib".to_string()),
                (
                    "packages/lib/node_modules/local".to_string(),
                    "vendor/local".to_string()
                ),
            ]
        );
        fs::remove_file(dir.0.join("packages/lib/package.json")).unwrap();

        // The directory must be inside the project, and must be named.
        for (spec, words) in [
            (
                "link:../outside",
                r#"workspace link target "../outside" is outside the project"#,
            ),
            (
                "link:/etc",
                r#"workspace link target "/etc" is outside the project"#,
            ),
            (
                "link:",
                "package.json dependencies local: link: names no directory",
            ),
        ] {
            let package = format!(r#"{{"dependencies":{{"local":"{spec}"}}}}"#);
            let error = links(&dir, &package).unwrap_err().to_string();
            assert!(error.contains(words), "{spec}: {error}");
        }

        // Any other spec the lock does not hold is still a stale lock.
        let error = links(&dir, r#"{"dependencies":{"local":"file:./vendor/local"}}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("yarn.lock"), "{error}");
    }

    /// Yarn reads a linked directory's package.json and locks its
    /// `dependencies` and `optionalDependencies` (never its
    /// `devDependencies`), so the plan installs them, their lock entries
    /// are not leftovers, and the linked manifest is held to the lock like
    /// the project's own. A link inside a linked package is followed too.
    #[test]
    fn a_yarn_linked_package_brings_its_locked_dependencies() {
        let dir = project();
        fs::create_dir_all(dir.0.join("vendor/local")).unwrap();
        fs::create_dir_all(dir.0.join("vendor/inner")).unwrap();
        let write = |local: &str| {
            fs::write(dir.0.join("vendor/local/package.json"), local).unwrap();
        };
        fs::write(
            dir.0.join("vendor/inner/package.json"),
            r#"{"name":"inner","version":"1.0.0","optionalDependencies":{"deep":"^2.0.0"}}"#,
        )
        .unwrap();
        let lock = format!(
            r#"# yarn lockfile v1
dep@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/dep/-/dep-1.0.0.tgz"
  integrity {SRI}
deep@^2.0.0:
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/deep/-/deep-2.0.0.tgz"
  integrity {SRI}
"#
        );
        let plan = |lock: &str| {
            plan_yarn(
                Platform::X86_64UnknownLinuxGnu,
                lock,
                r#"{"dependencies":{"local":"link:vendor/local"}}"#,
                &held(&dir.0),
                node_version(),
            )
        };
        write(
            r#"{"name":"local","version":"1.0.0","dependencies":{"dep":"^1.0.0","inner":"link:vendor/inner"},"devDependencies":{"unlocked":"9.9.9"}}"#,
        );
        let planned = plan(&lock).unwrap();
        let mut packages: Vec<(&str, &str)> = planned
            .packages
            .iter()
            .map(|package| (package.path.as_str(), package.version.as_str()))
            .collect();
        packages.sort();
        assert_eq!(
            packages,
            [
                ("node_modules/deep", "2.0.0"),
                ("node_modules/dep", "1.0.0")
            ]
        );
        let mut links: Vec<(&str, &str)> = planned
            .links
            .iter()
            .map(|link| (link.path.as_str(), link.target.as_str()))
            .collect();
        links.sort();
        assert_eq!(
            links,
            [
                ("node_modules/inner", "vendor/inner"),
                ("node_modules/local", "vendor/local")
            ]
        );

        // The linked manifest asks for something the lock does not hold.
        write(r#"{"name":"local","version":"1.0.0","dependencies":{"dep":"^3.0.0"}}"#);
        let error = plan(&lock).unwrap_err().to_string();
        assert!(
            error.starts_with("vendor/local/package.json dependencies disagree with yarn.lock"),
            "{error}"
        );
        // The linked manifest stopped asking for what the lock holds.
        write(r#"{"name":"local","version":"1.0.0"}"#);
        let error = plan(&lock).unwrap_err().to_string();
        assert!(
            error.starts_with("yarn.lock locks de") && error.contains("no package.json depends on"),
            "{error}"
        );
        // A linked manifest that does not parse is named.
        write("{");
        let error = plan(&lock).unwrap_err().to_string();
        assert!(error.starts_with("vendor/local/package.json: "), "{error}");
    }

    #[test]
    fn yarn_links_every_discovered_member_at_the_root() {
        let dir = project();
        fs::create_dir_all(dir.0.join("packages/a")).unwrap();
        fs::create_dir_all(dir.0.join("packages/b")).unwrap();
        fs::write(
            dir.0.join("package.json"),
            r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        fs::write(
            dir.0.join("packages/a/package.json"),
            r#"{"name":"workspace-a","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            dir.0.join("packages/b/package.json"),
            r#"{"name":"workspace-b","version":"1.0.0"}"#,
        )
        .unwrap();
        let package = fs::read_to_string(dir.0.join("package.json")).unwrap();
        let plan = plan_yarn(
            Platform::X86_64UnknownLinuxGnu,
            "# yarn lockfile v1\n",
            &package,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.links.iter().any(|link| {
            link.path == "node_modules/workspace-a" && link.target == "packages/a"
        }));
        assert!(plan.links.iter().any(|link| {
            link.path == "node_modules/workspace-b" && link.target == "packages/b"
        }));
    }

    /// A prerelease only matches itself: the kernel's ordering keeps
    /// 1.0.0-beta.1 below 1.0.0, so a workspace at 1.0.0 is not the member a
    /// `1.0.0-beta.1` dependency asks for.
    #[test]
    fn yarn_workspace_match_compares_prereleases_exactly() {
        assert!(!yarn_workspace_spec_matches("1.0.0-beta.1", "1.0.0"));
        assert!(yarn_workspace_spec_matches("1.0.0-beta.1", "1.0.0-beta.1"));
    }
}

#[cfg(test)]
mod git_import_tests {
    use super::tests::{held, node_version};
    use crate::kernel::testutil::TempDir;

    const SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

    fn project() -> TempDir {
        TempDir::named("lock-git-import")
    }

    #[test]
    fn pnpm_sri_codeload_resolution_stays_a_tarball() {
        // A codeload URL with an SRI is an attested tarball. It must not be
        // converted to a git checkout, whose bytes can differ from the URL.
        let commit = "8bf567b9e2230cdd02f9b8c9774fb8eb0d71af1e";
        let lock = format!(
            "lockfileVersion: '9.0'\n\
             \n\
             packages:\n\
             \x20\x20api@https://codeload.github.com/o/r/tar.gz/{commit}:\n\
             \x20\x20\x20\x20resolution: {{gitHosted: true, integrity: sha512-ZUNzoqUI/328gbYuFUw9oKe0BVi/reurZZ2ut1+B8ZgEtZ6dtNgKMea7Kp8UvKTnF543WvI/8RwetH1Fzkflzw==, tarball: https://codeload.github.com/o/r/tar.gz/{commit}}}\n"
        );
        let parsed = super::parse_yaml(&lock).expect("parse");
        let super::YamlValue::Map(top) = &parsed else {
            panic!("top level is a map")
        };
        let super::YamlValue::Map(packages) = &top["packages"] else {
            panic!("packages map")
        };
        let (_key, entry) = packages.iter().next().expect("one package");
        let super::YamlValue::Map(entry) = entry else {
            panic!("entry map")
        };
        let resolution = match entry.get("resolution") {
            Some(super::YamlValue::Map(map)) => Some(map),
            other => panic!("resolution is not a map: {other:?}"),
        };
        assert!(super::pinned_git_source(resolution).is_none());
    }

    #[test]
    fn pnpm_sri_codeload_plan_preserves_integrity() {
        let commit = "8bf567b9e2230cdd02f9b8c9774fb8eb0d71af1e";
        let lock = format!(
            "lockfileVersion: '9.0'\n\
             importers:\n\
             \x20\x20.:\n\
             \x20\x20\x20\x20dependencies:\n\
             \x20\x20\x20\x20\x20\x20plugin:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20specifier: 1.0.0\n\
             \x20\x20\x20\x20\x20\x20\x20\x20version: 1.0.0\n\
             packages:\n\
             \x20\x20plugin@1.0.0:\n\
             \x20\x20\x20\x20resolution: {{integrity: {SRI}, tarball: https://codeload.github.com/o/r/tar.gz/{commit}}}\n\
             snapshots:\n\
             \x20\x20plugin@1.0.0: {{}}\n"
        );
        let project = project();
        let plan = super::plan_pnpm(
            crate::kernel::platform::Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&project.0),
            node_version(),
        )
        .unwrap();
        let package = plan.packages.iter().find(|p| p.name == "plugin").unwrap();
        assert!(package.git.is_none());
        assert_eq!(package.integrity, SRI);
    }

    #[test]
    fn yarn_sri_codeload_plan_preserves_integrity() {
        let commit = "8bf567b9e2230cdd02f9b8c9774fb8eb0d71af1e";
        let lock = format!(
            r#"# yarn lockfile v1
plugin@1.0.0:
  version "1.0.0"
  resolved "https://codeload.github.com/o/r/tar.gz/{commit}"
  integrity {SRI}
"#
        );
        let project = project();
        let plan = super::plan_yarn(
            crate::kernel::platform::Platform::X86_64UnknownLinuxGnu,
            &lock,
            r#"{"dependencies":{"plugin":"1.0.0"}}"#,
            &held(&project.0),
            node_version(),
        )
        .unwrap();
        let package = plan.packages.iter().find(|p| p.name == "plugin").unwrap();
        assert!(package.git.is_none());
        assert_eq!(package.integrity, SRI);
    }

    /// ChatGPTNextWeb/NextChat's `rt-client`: a GitHub release asset whose
    /// `#fragment` is Yarn's sha1 of the tarball. It was misread as a git
    /// source pinned to that sha1, which names no commit, so the checkout
    /// failed with "unable to read tree".
    #[test]
    fn yarn_github_release_asset_is_a_tarball_verified_by_its_sha1_fragment() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let url = "https://github.com/Azure-Samples/aoai-realtime-audio-sdk/releases/download/js/v0.5.0/rt-client-0.5.0.tgz";
        let lock = format!(
            r#"# yarn lockfile v1
"rt-client@{url}":
  version "0.5.0"
  resolved "{url}#abf2e9a850201e3571b8d36830f77bc52af3de9b"
"#
        );
        let project = project();
        let plan = super::plan_yarn(
            crate::kernel::platform::Platform::X86_64UnknownLinuxGnu,
            &lock,
            &format!(r#"{{"dependencies":{{"rt-client":"{url}"}}}}"#),
            &held(&project.0),
            node_version(),
        )
        .unwrap();
        let package = plan
            .packages
            .iter()
            .find(|p| p.name == "rt-client")
            .unwrap();
        assert!(package.git.is_none(), "{:?}", package.git);
        assert_eq!(package.url, url);
        assert_eq!(package.integrity, "sha1-q/LpqFAgHjVxuNNoMPd7xSrz3ps=");
    }

    /// A Yarn 1 archive URL names a commit in its path and the tarball's
    /// sha1 in its fragment. The lock attests the bytes, so the entry is the
    /// tarball checked against that sha1, not a git checkout of the commit.
    #[test]
    fn yarn_github_archive_with_sha1_fragment_is_an_attested_tarball() {
        let _attribution_lock = crate::kernel::policy::exception_guard();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let commit = "8bf567b9e2230cdd02f9b8c9774fb8eb0d71af1e";
        let sha1 = "abf2e9a850201e3571b8d36830f77bc52af3de9b";
        for url in [
            format!("https://codeload.github.com/o/r/tar.gz/{commit}"),
            format!("https://github.com/o/r/archive/{commit}.tar.gz"),
        ] {
            let lock = format!(
                "# yarn lockfile v1\nplugin@1.0.0:\n  version \"1.0.0\"\n  resolved \"{url}#{sha1}\"\n"
            );
            let dir = project();
            let plan = super::plan_yarn(
                crate::kernel::platform::Platform::X86_64UnknownLinuxGnu,
                &lock,
                r#"{"dependencies":{"plugin":"1.0.0"}}"#,
                &held(&dir.0),
                node_version(),
            );
            let plan = plan.unwrap();
            let package = plan.packages.iter().find(|p| p.name == "plugin").unwrap();
            assert!(package.git.is_none(), "{url}: {:?}", package.git);
            assert_eq!(package.url, url);
            assert_eq!(package.integrity, "sha1-q/LpqFAgHjVxuNNoMPd7xSrz3ps=");

            // A fragment that is not a sha1 is refused, not reinterpreted.
            let lock = format!(
                "# yarn lockfile v1\nplugin@1.0.0:\n  version \"1.0.0\"\n  resolved \"{url}#not-a-hash\"\n"
            );
            let dir = project();
            let result = super::plan_yarn(
                crate::kernel::platform::Platform::X86_64UnknownLinuxGnu,
                &lock,
                r#"{"dependencies":{"plugin":"1.0.0"}}"#,
                &held(&dir.0),
                node_version(),
            );
            let error = result.expect_err("malformed fragment refused").to_string();
            assert!(error.contains("malformed yarn sha1 fragment"), "{error}");
        }
    }

    #[test]
    fn a_codeload_dependency_is_realized_not_rejected() {
        let commit = "8bf567b9e2230cdd02f9b8c9774fb8eb0d71af1e";
        let lock = format!(
            "lockfileVersion: '9.0'\n\
             \n\
             importers:\n\
             \x20\x20.:\n\
             \x20\x20\x20\x20dependencies:\n\
             \x20\x20\x20\x20\x20\x20plugin:\n\
             \x20\x20\x20\x20\x20\x20\x20\x20specifier: https://codeload.github.com/o/r/tar.gz/{commit}\n\
             \x20\x20\x20\x20\x20\x20\x20\x20version: https://codeload.github.com/o/r/tar.gz/{commit}\n\
             \n\
             packages:\n\
             \x20\x20plugin@https://codeload.github.com/o/r/tar.gz/{commit}:\n\
             \x20\x20\x20\x20resolution: {{tarball: https://codeload.github.com/o/r/tar.gz/{commit}}}\n\
             \n\
             snapshots:\n\
             \x20\x20plugin@https://codeload.github.com/o/r/tar.gz/{commit}: {{}}\n"
        );
        let scratch = TempDir::named("gitimport");
        let project = scratch.0.clone();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"root","version":"1.0.0"}"#,
        )
        .unwrap();
        let result = super::plan_pnpm(
            crate::kernel::platform::Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&project),
            node_version(),
        );
        let plan = match result {
            Ok(plan) => plan,
            Err(error) => panic!("codeload dependency was rejected: {error}"),
        };
        let package = plan
            .packages
            .iter()
            .find(|p| p.name == "plugin")
            .expect("the git package is in the plan");
        let source = package.git.as_ref().expect("a git source");
        assert_eq!(source.commit, commit);
        assert_eq!(source.url, "https://github.com/o/r");
    }
}

#[cfg(test)]
mod placement_tests {
    use super::tests::{held, node_version, project, SRI};
    use super::*;

    fn node(name: &str, version: &str) -> Node {
        Node {
            key: format!("{name}@{version}"),
            name: name.into(),
            version: version.into(),
            url: format!("https://r/{name}-{version}.tgz"),
            integrity: SRI.into(),
            optional: false,
            os: Vec::new(),
            cpu: Vec::new(),
            libc: Vec::new(),
            external: None,
            patch: None,
            deps: Vec::new(),
        }
    }

    fn requires(name: &str, target: Target, workspace: Option<&str>) -> RootDependency {
        RootDependency {
            dependency: Dependency {
                name: name.into(),
                target,
                optional: false,
            },
            workspace: workspace.map(str::to_string),
        }
    }

    /// c@1.0.0, c@2.0.0 and c@3.0.0 as graph nodes, with a packages/lib
    /// workspace.
    fn graph(roots: Vec<RootDependency>, workspace_roots: Vec<RootDependency>) -> Graph {
        Graph {
            nodes: ["1.0.0", "2.0.0", "3.0.0"]
                .into_iter()
                .map(|version| (format!("c@{version}"), node("c", version)))
                .collect(),
            roots,
            workspace_roots,
            workspace_paths: BTreeSet::from(["packages/lib".to_string()]),
            local_link_deps: BTreeMap::new(),
        }
    }

    fn c(version: &str) -> Target {
        Target::Node(format!("c@{version}"))
    }

    fn placed(graph: Graph) -> io::Result<Vec<(String, String)>> {
        build_plan(
            Platform::X86_64UnknownLinuxGnu,
            graph,
            "pnpm-lock.yaml",
            node_version(),
        )
        .map(|plan| {
            plan.packages
                .into_iter()
                .map(|package| (package.path, package.version))
                .chain(
                    plan.links
                        .into_iter()
                        .map(|link| (link.path, format!("link:{}", link.target))),
                )
                .collect()
        })
    }

    fn refused(graph: Graph, expected: &str) {
        let error = placed(graph).unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn two_root_requirements_of_one_name_conflict() {
        refused(
            graph(
                vec![
                    requires("c", c("1.0.0"), None),
                    requires("c", c("2.0.0"), None),
                ],
                Vec::new(),
            ),
            "c: root dependencies conflict between c@1.0.0 and c@2.0.0",
        );
    }

    #[test]
    fn two_versions_at_one_workspace_path_conflict() {
        refused(
            graph(
                vec![requires("c", c("1.0.0"), None)],
                vec![
                    requires("c", c("2.0.0"), Some("packages/lib")),
                    requires("c", c("3.0.0"), Some("packages/lib")),
                ],
            ),
            "c: two versions conflict at packages/lib/node_modules/c (c@2.0.0 and c@3.0.0)",
        );
    }

    #[test]
    fn a_version_and_a_link_at_one_workspace_path_conflict() {
        refused(
            graph(
                vec![requires("c", c("1.0.0"), None)],
                vec![
                    requires("c", c("2.0.0"), Some("packages/lib")),
                    requires("c", Target::Link("vendor/c".into()), Some("packages/lib")),
                ],
            ),
            "c: two workspace versions conflict at packages/lib/node_modules/c (c@2.0.0 and link:vendor/c)",
        );
    }

    #[test]
    fn a_root_version_and_a_root_link_of_one_name_conflict() {
        refused(
            graph(
                vec![
                    requires("c", c("1.0.0"), None),
                    requires("c", Target::Link("vendor/c".into()), None),
                ],
                Vec::new(),
            ),
            "c: workspace hoisting conflict between c@1.0.0 and link:vendor/c",
        );
    }

    /// The passing shape of the same graphs: a repeated identical
    /// requirement shares one placement, and a workspace's differing
    /// version and link nest under their own importers.
    #[test]
    fn identical_requirements_share_and_differing_ones_nest() {
        let mut graph = graph(
            vec![
                requires("c", c("1.0.0"), None),
                requires("c", c("1.0.0"), None),
            ],
            vec![
                requires("c", c("2.0.0"), Some("packages/lib")),
                requires("c", c("2.0.0"), Some("packages/lib")),
                requires("c", Target::Link("vendor/c".into()), Some("packages/app")),
            ],
        );
        graph.workspace_paths.insert("packages/app".into());
        assert_eq!(
            placed(graph).unwrap(),
            vec![
                ("node_modules/c".to_string(), "1.0.0".to_string()),
                (
                    "packages/lib/node_modules/c".to_string(),
                    "2.0.0".to_string()
                ),
                (
                    "packages/app/node_modules/c".to_string(),
                    "link:vendor/c".to_string()
                ),
            ]
        );
    }

    /// Yarn links every workspace member at the root; a root dependency on
    /// a registry package of the same name but another version cannot sit
    /// beside it.
    #[test]
    fn yarn_root_dependency_and_workspace_member_of_one_name_conflict() {
        let dir = project();
        fs::write(
            dir.0.join("packages/lib/package.json"),
            r#"{"name":"lib","version":"1.0.0"}"#,
        )
        .unwrap();
        let lock = format!(
            "# yarn lockfile v1\nlib@^2.0.0:\n  version \"2.0.0\"\n  resolved \"https://r/lib-2.0.0.tgz\"\n  integrity {SRI}\n"
        );
        let error = plan_yarn(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            r#"{"workspaces":["packages/*"],"dependencies":{"lib":"^2.0.0"}}"#,
            &held(&dir.0),
            node_version(),
        )
        .map(drop)
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "lib: workspace hoisting conflict between lib@2.0.0 and link:packages/lib"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// A pnpm importer keyed `node_modules/foo` while the root links foo:
    /// its nested dependency would be written through the link into the
    /// user's source tree.
    #[test]
    fn a_package_beneath_a_link_is_refused() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      c:
        specifier: 1.0.0
        version: 1.0.0
      foo:
        specifier: link:vendor/foo
        version: link:vendor/foo
  node_modules/foo:
    dependencies:
      c:
        specifier: 2.0.0
        version: 2.0.0
packages:
  c@1.0.0:
    resolution: {{integrity: {SRI}}}
  c@2.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  c@1.0.0: {{}}
  c@2.0.0: {{}}
"#
        );
        let error = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .map(drop)
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "node_modules/foo/node_modules/c would be placed inside the linked source directory node_modules/foo; refusing to write into it"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// The mirror image: an importer keyed `node_modules/x` under a
    /// registry package x whose link would be planted in store content.
    #[test]
    fn a_link_beneath_a_package_is_refused() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      x:
        specifier: 1.0.0
        version: 1.0.0
  node_modules/x:
    dependencies:
      lib:
        specifier: link:../../vendor/lib
        version: link:../../vendor/lib
packages:
  x@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  x@1.0.0: {{}}
"#
        );
        let error = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .map(drop)
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "link node_modules/x/node_modules/lib -> vendor/lib would be planted inside the package node_modules/x, which is store content; tog cannot project a local package nested under a registry package that does not depend on it"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

/// pnpm lockfile shapes. The checks live in pnpm.rs; the tests live here
/// because pnpm.rs has no `mod tests` and its whole text counts against the
/// size ratchet in tests/size_baseline.txt.
#[cfg(test)]
mod pnpm_lock_shape_tests {
    use super::pnpm::patch_path;
    use super::tests::{held, node_version, project, SRI};
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn plan(dir: &Path, lock: &str) -> io::Result<NpmPlan> {
        plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            &held(dir),
            node_version(),
        )
    }

    fn refused(dir: &Path, lock: &str) -> io::Error {
        plan(dir, lock).map(drop).unwrap_err()
    }

    fn assert_invalid(error: io::Error, expected: &str) {
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{expected}");
    }

    #[test]
    fn unsupported_pnpm_lockfile_versions_are_refused() {
        let dir = project();
        for (line, shown) in [
            ("lockfileVersion: '5.4'\n", "5.4"),
            ("lockfileVersion: '10.0'\n", "10.0"),
            ("lockfileVersion: '9.1'\n", "9.1"),
            ("lockfileVersion: '90'\n", "90"),
            ("lockfileVersion: 7\n", "7"),
            ("", ""),
        ] {
            let lock = format!("{line}importers:\n  .: {{}}\n");
            assert_invalid(
                refused(&dir.0, &lock),
                &format!("unsupported pnpm lockfileVersion {shown:?} (tog supports 9.0 and 6.0)"),
            );
        }
    }

    #[test]
    fn pnpm_lockfile_versions_9_and_6_are_accepted_in_every_spelling() {
        let dir = project();
        for version in ["'9.0'", "9.0", "9", "'9'", "'9.0.0'", "'6.0'", "6.0"] {
            let lock = format!("lockfileVersion: {version}\nimporters:\n  .: {{}}\n");
            let plan = plan(&dir.0, &lock).unwrap_or_else(|error| panic!("{version}: {error}"));
            assert!(plan.packages.is_empty(), "{version}");
        }
    }

    /// Two peer variants of is-number and an edge that names only its
    /// version: choosing one would be a guess, so the edge is unresolved.
    fn ambiguous_peer_lock(field: &str) -> String {
        format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      is-odd:
        specifier: 3.0.1
        version: 3.0.1
packages:
  is-odd@3.0.1:
    resolution: {{integrity: {SRI}}}
  is-number@6.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  is-odd@3.0.1:
    {field}:
      is-number: 6.0.0
  is-number@6.0.0(peer@1.0.0): {{}}
  is-number@6.0.0(peer@2.0.0): {{}}
"#
        )
    }

    #[test]
    fn an_ambiguous_peer_edge_is_refused_when_required() {
        let dir = project();
        assert_invalid(
            refused(&dir.0, &ambiguous_peer_lock("dependencies")),
            "is-number: missing snapshot for is-number@6.0.0",
        );
    }

    #[test]
    fn an_ambiguous_peer_edge_is_dropped_when_optional() {
        let dir = project();
        let plan = plan(&dir.0, &ambiguous_peer_lock("optionalDependencies")).unwrap();
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["node_modules/is-odd"]);
    }

    /// With a single peer variant the version-only edge is unambiguous.
    #[test]
    fn a_single_peer_variant_resolves_a_version_only_edge() {
        let dir = project();
        let lock =
            ambiguous_peer_lock("dependencies").replace("  is-number@6.0.0(peer@2.0.0): {}\n", "");
        let plan = plan(&dir.0, &lock).unwrap();
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["node_modules/is-number", "node_modules/is-odd"]);
    }

    fn link_lock(importer: &str, field: &str, reference: &str) -> String {
        format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      keep:
        specifier: 1.0.0
        version: 1.0.0
  {importer}:
    {field}:
      evil:
        specifier: {reference}
        version: {reference}
packages:
  keep@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  keep@1.0.0: {{}}
"#
        )
    }

    /// A project with a symlink `escape` that leads outside it.
    fn project_with_escape() -> (TempDir, TempDir) {
        let dir = project();
        let outside = TempDir::named("lock-import-outside");
        std::os::unix::fs::symlink(&outside.0, dir.0.join("escape")).unwrap();
        (dir, outside)
    }

    #[test]
    fn a_link_outside_the_project_is_refused_on_an_importer_edge() {
        let (dir, _outside) = project_with_escape();
        for (importer, reference, raw) in [
            ("packages/lib", "link:../../../x", "../../../x"),
            ("packages/lib", "link:/etc", "/etc"),
            ("packages/lib", "link:~/x", "~/x"),
            ("packages/lib", "link:../../escape", "../../escape"),
            ("packages/lib", "file:../../../x", "../../../x"),
            ("packages/lib", "evil@file:../../../x", "../../../x"),
        ] {
            let error = refused(&dir.0, &link_lock(importer, "dependencies", reference));
            assert_invalid(
                error,
                &format!(
                    "evil: workspace link target {raw:?} is outside the project (reference {reference:?}, importer {importer:?})"
                ),
            );
        }
    }

    /// A target that does not exist yet is judged by its deepest existing
    /// ancestor, so `escape/missing` is outside once `escape` leads out. A
    /// dangling symlink could lead anywhere once its target appears.
    #[test]
    fn a_link_through_an_unresolved_target_is_refused() {
        let (dir, outside) = project_with_escape();
        std::os::unix::fs::symlink(outside.0.join("absent"), dir.0.join("dangling")).unwrap();
        for (reference, raw, reason) in [
            (
                "link:../../escape/missing",
                "../../escape/missing",
                "is outside the project",
            ),
            (
                "link:../../escape/missing/deeper",
                "../../escape/missing/deeper",
                "is outside the project",
            ),
            (
                "link:../../dangling",
                "../../dangling",
                "passes through a dangling symlink; tog cannot tell whether it stays in the project",
            ),
            (
                "link:../../dangling/child",
                "../../dangling/child",
                "passes through a dangling symlink; tog cannot tell whether it stays in the project",
            ),
        ] {
            let error = refused(&dir.0, &link_lock("packages/lib", "dependencies", reference));
            assert_invalid(
                error,
                &format!(
                    "evil: workspace link target {raw:?} {reason} (reference {reference:?}, importer \"packages/lib\")"
                ),
            );
        }
        // A symlink loop resolves nowhere either; the OS error is carried.
        std::os::unix::fs::symlink(dir.0.join("loop"), dir.0.join("loop")).unwrap();
        let error = refused(
            &dir.0,
            &link_lock("packages/lib", "dependencies", "link:../../loop"),
        );
        assert_invalid(
            error,
            &format!(
                "evil: workspace link target \"../../loop\": {} (reference \"link:../../loop\", importer \"packages/lib\")",
                io::Error::from_raw_os_error(libc::ELOOP)
            ),
        );
        // A missing target below a real directory stays a link.
        let plan = plan(
            &dir.0,
            &link_lock("packages/lib", "dependencies", "link:../other/missing"),
        )
        .unwrap();
        assert_eq!(plan.links[0].target, "packages/other/missing");
    }

    #[test]
    fn an_optional_link_outside_the_project_is_dropped() {
        let dir = project();
        let plan = plan(
            &dir.0,
            &link_lock("packages/lib", "optionalDependencies", "link:../../../x"),
        )
        .unwrap();
        assert!(plan.links.is_empty(), "{:?}", plan.links);
    }

    /// Inside the project, the same relative spelling is a link.
    #[test]
    fn a_link_inside_the_project_is_accepted() {
        let dir = project();
        let plan = plan(
            &dir.0,
            &link_lock("packages/lib", "dependencies", "link:../other"),
        )
        .unwrap();
        let links: Vec<(&str, &str)> = plan
            .links
            .iter()
            .map(|link| (link.path.as_str(), link.target.as_str()))
            .collect();
        assert_eq!(
            links,
            vec![("packages/lib/node_modules/evil", "packages/other")]
        );
    }

    #[test]
    fn a_link_outside_the_project_is_refused_on_a_snapshot_edge() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      parent:
        specifier: 1.0.0
        version: 1.0.0
packages:
  parent@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  parent@1.0.0:
    dependencies:
      evil: link:../x
"#
        );
        assert_invalid(
            refused(&dir.0, &lock),
            r#"evil: workspace link target "../x" is outside the project (reference "link:../x", importer ".")"#,
        );
    }

    /// A local snapshot key names its target directly; an escaping one is
    /// refused unwrapped, even when nothing depends on it.
    #[test]
    fn a_local_snapshot_outside_the_project_is_refused() {
        let (dir, _outside) = project_with_escape();
        for raw in ["../x", "link:../x", "/etc", "escape"] {
            let (version, target) = match raw.strip_prefix("link:") {
                Some(target) => (raw.to_string(), target),
                None => (format!("file:{raw}"), raw),
            };
            let lock = format!(
                "lockfileVersion: '9.0'\nimporters:\n  .: {{}}\nsnapshots:\n  a@{version}: {{}}\n"
            );
            assert_invalid(
                refused(&dir.0, &lock),
                &format!("workspace link target {target:?} is outside the project"),
            );
        }
    }

    fn patch_project() -> (TempDir, TempDir) {
        let (dir, outside) = project_with_escape();
        fs::create_dir_all(dir.0.join("patches")).unwrap();
        fs::write(dir.0.join("patches/foo.patch"), "diff\n").unwrap();
        fs::write(outside.0.join("secret.patch"), "diff\n").unwrap();
        std::os::unix::fs::symlink(
            outside.0.join("secret.patch"),
            dir.0.join("patches/evil.patch"),
        )
        .unwrap();
        (dir, outside)
    }

    #[test]
    fn a_patch_path_that_is_not_project_relative_is_refused() {
        let (dir, outside) = patch_project();
        let secret = outside.0.join("secret.patch");
        for raw in [
            String::new(),
            "../secret.patch".to_string(),
            "patches/../../secret.patch".to_string(),
            secret.display().to_string(),
            "/etc/passwd".to_string(),
            "~/secret.patch".to_string(),
            "~".to_string(),
        ] {
            let error = patch_path(&held(&dir.0), &raw).unwrap_err();
            assert_invalid(
                error,
                &format!("pnpm patch path {raw:?} must be a project-relative file"),
            );
        }
    }

    #[test]
    fn a_patch_path_escaping_through_a_symlink_or_naming_a_directory_is_refused() {
        let (dir, _outside) = patch_project();
        for raw in [
            "patches/evil.patch",
            "escape/secret.patch",
            "patches",
            "./patches/",
        ] {
            let error = patch_path(&held(&dir.0), raw).unwrap_err();
            assert_invalid(
                error,
                &format!("pnpm patch path {raw:?} is outside the project or is not a file"),
            );
        }
    }

    #[test]
    fn a_project_relative_patch_file_is_accepted() {
        let (dir, _outside) = patch_project();
        let expected = dir.0.join("patches/foo.patch").canonicalize().unwrap();
        for raw in [
            "patches/foo.patch",
            "./patches/foo.patch",
            "patches/./foo.patch",
        ] {
            assert_eq!(patch_path(&held(&dir.0), raw).unwrap(), expected, "{raw}");
        }
    }

    /// An alias (`foo: bar@1.0.0`) is placed under the name the importer
    /// uses while the package keeps its real name and version.
    #[test]
    fn a_pnpm_alias_is_placed_by_its_alias_and_named_by_its_package() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      foo:
        specifier: npm:bar@^1.0.0
        version: bar@1.0.0
      '@s/alias':
        specifier: npm:@t/real@2.0.0
        version: '@t/real@2.0.0'
packages:
  bar@1.0.0:
    resolution: {{integrity: {SRI}, tarball: https://r/bar-1.0.0.tgz}}
  '@t/real@2.0.0':
    resolution: {{integrity: {SRI}, tarball: https://r/real-2.0.0.tgz}}
snapshots:
  bar@1.0.0: {{}}
  '@t/real@2.0.0': {{}}
"#
        );
        let plan = plan(&dir.0, &lock).unwrap();
        let placed: Vec<(&str, &str, &str, &str)> = plan
            .packages
            .iter()
            .map(|p| {
                (
                    p.path.as_str(),
                    p.name.as_str(),
                    p.version.as_str(),
                    p.url.as_str(),
                )
            })
            .collect();
        assert_eq!(
            placed,
            vec![
                (
                    "node_modules/@s/alias",
                    "@t/real",
                    "2.0.0",
                    "https://r/real-2.0.0.tgz"
                ),
                (
                    "node_modules/foo",
                    "bar",
                    "1.0.0",
                    "https://r/bar-1.0.0.tgz"
                ),
            ]
        );
    }

    /// `a` (required) and `o` (optional) with tarball URLs `a_url` and
    /// `o_url`, beside a plain https package `b`.
    fn tarball_lock(a_url: &str, o_url: &str) -> String {
        format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1.0.0
        version: 1.0.0
      b:
        specifier: 1.0.0
        version: 1.0.0
    optionalDependencies:
      o:
        specifier: 1.0.0
        version: 1.0.0
packages:
  a@1.0.0:
    resolution: {{integrity: {SRI}, tarball: {a_url}}}
  b@1.0.0:
    resolution: {{integrity: {SRI}, tarball: 'https://r/@s/b-1.0.0.tgz'}}
  o@1.0.0:
    resolution: {{integrity: {SRI}, tarball: {o_url}}}
snapshots:
  a@1.0.0: {{}}
  b@1.0.0: {{}}
  o@1.0.0: {{}}
"#
        )
    }

    /// pnpm tarballs are https-only and carry no credentials, as npm's and
    /// Yarn's are: a required one is refused, an optional one dropped.
    #[test]
    fn a_non_https_or_credentialed_tarball_is_refused_or_dropped() {
        let dir = project();
        let credentials =
            "tarball URL carries credentials (user:pass@ before its host); tog will not record them";
        for (url, detail) in [
            (
                "http://r/x.tgz",
                "non-https tarball URL http://r/x.tgz".to_string(),
            ),
            (
                "ftp://r/x.tgz",
                "non-https tarball URL ftp://r/x.tgz".to_string(),
            ),
            ("https://u:secret@r/x.tgz", credentials.to_string()),
            ("https://token@r/x.tgz", credentials.to_string()),
            ("https://user@r/x.tgz", credentials.to_string()),
            ("https:///user:secret@r/x.tgz", credentials.to_string()),
            ("http://user:secret@r/x.tgz", credentials.to_string()),
            (
                "http://user:secret@",
                "non-https tarball URL <URL withheld: it may carry credentials>".to_string(),
            ),
        ] {
            let error = refused(&dir.0, &tarball_lock(url, "https://r/o.tgz"));
            assert!(!error.to_string().contains("secret"), "{error}");
            assert_invalid(error, &format!("a@1.0.0: {detail}"));
            let plan = plan(&dir.0, &tarball_lock("https://r/a.tgz", url)).unwrap();
            let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
            assert_eq!(paths, vec!["node_modules/a", "node_modules/b"], "{url}");
        }
        let upper = plan(&dir.0, &tarball_lock("HTTPS://r/a.tgz", "https://r/o.tgz")).unwrap();
        assert_eq!(upper.packages[0].url, "HTTPS://r/a.tgz");
        let plan = plan(&dir.0, &tarball_lock("https://r/a.tgz", "https://r/o.tgz")).unwrap();
        let urls: Vec<&str> = plan.packages.iter().map(|p| p.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://r/a.tgz",
                "https://r/@s/b-1.0.0.tgz",
                "https://r/o.tgz"
            ]
        );
    }

    /// A tarball identity keeps its URL as the version; the refusal
    /// names the package without the URL's credentials.
    #[test]
    fn a_credentialed_tarball_identity_is_refused_without_its_secret() {
        let dir = project();
        let lock = |version: &str| {
            format!(
                r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: https://user:secret@r/a.tgz
        version: {version}
packages:
  a@https://user:secret@r/a.tgz:
    resolution: {{integrity: {SRI}, tarball: https://user:secret@r/a.tgz}}
snapshots:
  a@https://user:secret@r/a.tgz: {{}}
"#
            )
        };
        for (version, expected) in [
            (
                "a@https://user:secret@r/a.tgz",
                "a@https://***:***@r/a.tgz: tarball URL carries credentials (user:pass@ before its host); tog will not record them",
            ),
            // The bare URL does not name the snapshot; the miss is
            // reported without the secret too.
            (
                "https://user:secret@r/a.tgz",
                "a: missing snapshot for a@https://***:***@r/a.tgz",
            ),
        ] {
            let error = refused(&dir.0, &lock(version));
            assert!(!error.to_string().contains("secret"), "{error}");
            assert_invalid(error, expected);
        }
    }

    /// Two importers' dependencies placed at `node_modules/Foo` and
    /// `node_modules/foo` would share one directory on macOS.
    #[test]
    fn pnpm_destinations_differing_only_in_case_are_refused() {
        let dir = project();
        let lock = |second: &str| {
            format!(
                r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      Foo:
        specifier: 1.0.0
        version: 1.0.0
      {second}:
        specifier: 1.0.0
        version: 1.0.0
packages:
  Foo@1.0.0:
    resolution: {{integrity: {SRI}}}
  {second}@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  Foo@1.0.0: {{}}
  {second}@1.0.0: {{}}
"#
            )
        };
        assert_invalid(
            refused(&dir.0, &lock("foo")),
            "lockfile paths node_modules/Foo and node_modules/foo differ only in letter case; a case-insensitive filesystem would put both in one directory",
        );
        let plan = plan(&dir.0, &lock("bar")).unwrap();
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["node_modules/Foo", "node_modules/bar"]);
    }

    /// An alias naming one peer variant of its package resolves by the
    /// exact snapshot key, not by a version-only lookup that would find
    /// two candidates.
    #[test]
    fn a_pnpm_alias_to_a_peer_variant_resolves_its_exact_snapshot() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      foo:
        specifier: npm:bar@^1.0.0
        version: bar@1.0.0(peer@2.0.0)
packages:
  bar@1.0.0:
    resolution: {{integrity: {SRI}, tarball: https://r/bar-1.0.0.tgz}}
  one@1.0.0:
    resolution: {{integrity: {SRI}}}
  two@1.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  bar@1.0.0(peer@1.0.0):
    dependencies:
      one: 1.0.0
  bar@1.0.0(peer@2.0.0):
    dependencies:
      two: 1.0.0
  one@1.0.0: {{}}
  two@1.0.0: {{}}
"#
        );
        let plan = plan(&dir.0, &lock).unwrap();
        let placed: Vec<(&str, &str, &str)> = plan
            .packages
            .iter()
            .map(|p| (p.path.as_str(), p.name.as_str(), p.version.as_str()))
            .collect();
        // Only the chosen variant's child is installed.
        assert_eq!(
            placed,
            vec![
                ("node_modules/foo", "bar", "1.0.0"),
                ("node_modules/two", "two", "1.0.0"),
            ]
        );
    }
}
