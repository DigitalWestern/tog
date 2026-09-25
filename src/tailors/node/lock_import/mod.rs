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
    let digest = Digest::from_sri(integrity)?;
    if digest.algo() == "sha1" {
        crate::kernel::policy::record(
            crate::kernel::policy::WEAK_INTEGRITY,
            path,
            "sha1 integrity accepted and verified, but is cryptographically weak",
        )?;
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

fn platform_values_compatible(platform: Platform, values: &[String], ours: &str) -> bool {
    if values.is_empty() {
        return true;
    }
    if platform.is_macos() {
        if values
            .iter()
            .any(|value| value.strip_prefix('!') == Some(ours))
        {
            return false;
        }
        !values.iter().any(|value| !value.starts_with('!'))
            || values.iter().any(|value| value == ours)
    } else {
        if values
            .iter()
            .any(|value| value.strip_prefix('!') == Some(ours))
        {
            return false;
        }
        values.iter().any(|value| value == ours)
            || values.iter().all(|value| value.starts_with('!'))
    }
}

fn node_compatible(platform: Platform, node: &Node) -> bool {
    platform_values_compatible(platform, &node.os, platform.npm_os())
        && platform_values_compatible(platform, &node.cpu, platform.npm_cpu())
        && (platform.is_macos() || platform_values_compatible(platform, &node.libc, "glibc"))
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
fn skip_external_dependency(dependency: &Dependency, detail: &str) -> io::Result<()> {
    if !dependency.optional {
        return Err(err(format!("{}: {detail}", dependency.name)));
    }
    if detail.starts_with("npm_git_dep:") {
        crate::kernel::policy::record(
            crate::kernel::policy::GIT_DEPENDENCY,
            &dependency.name,
            detail,
        )?;
    }
    Ok(())
}

/// The graph node this dependency names, once it is known to be realizable on
/// this host. `Ok(None)` means the traversal skips it: an optional package
/// that is platform-incompatible, unresolvable, or carries no integrity.
fn realizable_node<'a>(
    platform: Platform,
    nodes: &'a BTreeMap<String, Node>,
    node_key: &str,
    dependency: &Dependency,
    lock_source: &str,
) -> io::Result<Option<&'a Node>> {
    let node = nodes.get(node_key).ok_or_else(|| {
        err(format!(
            "{}: missing graph node {node_key}",
            dependency.name
        ))
    })?;
    if !node_compatible(platform, node) {
        if dependency.optional || node.optional {
            // pnpm records every platform variant in one lockfile;
            // incompatible optional packages are omitted.
            return Ok(None);
        }
        return Err(err(format!(
            "{}@{}: required dependency does not support host {} (os={:?}, cpu={:?}, libc={:?})",
            node.name,
            node.version,
            platform.triple(),
            node.os,
            node.cpu,
            node.libc
        )));
    }
    if let Some(detail) = &node.external {
        if dependency.optional || node.optional {
            if detail.starts_with("npm_git_dep:") {
                crate::kernel::policy::record(
                    crate::kernel::policy::GIT_DEPENDENCY,
                    &node.name,
                    detail,
                )?;
            }
            return Ok(None);
        }
        return Err(err(format!("{}@{}: {detail}", node.name, node.version)));
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
            node.name, node.version
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
                "{}: root dependencies conflict between {} and {}",
                dependency.name,
                occupied_description(existing),
                format!("{}@{}", node.name, node.version)
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
                "{}: two versions conflict at {} ({} and {})",
                dependency.name,
                path,
                occupied_description(existing),
                format!("{}@{}", node.name, node.version)
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
    occupied: BTreeMap<String, Occupied>,
    nodes: &BTreeMap<String, Node>,
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
            path,
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
            optional: node.optional,
        });
    }
    packages.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(packages)
}

fn build_plan(
    platform: Platform,
    graph: Graph,
    lock_source: &str,
    node_version: &str,
) -> io::Result<NpmPlan> {
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
                skip_external_dependency(&dependency, detail)?;
                continue;
            }
            Target::Node(node_key) => {
                // A platform-skipped optional dependency is not placed, so it
                // is no requirement either.
                let Some(node) =
                    realizable_node(platform, &graph.nodes, node_key, &dependency, lock_source)?
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
    // A link below a package would be planted inside that package's
    // directory, which projection reaches through a symlink into a
    // read-only store object.
    for (path, link) in &links {
        if let Some(package) = occupied.iter().find_map(|(package, entry)| {
            (matches!(entry, Occupied::Package { .. }) && path.starts_with(&format!("{package}/")))
                .then_some(package)
        }) {
            return Err(err(format!(
                "link {path} -> {} would be planted inside the package {package}, which is store content; tog cannot project a local package nested under a registry package",
                link.target
            )));
        }
    }
    let packages = resolved_packages(occupied, &graph.nodes)?;
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
    Ok(NpmPlan {
        node_version: node_version.to_string(),
        packages,
        links: links.into_values().collect(),
        workspaces: workspace_paths.into_iter().collect(),
        lock_source: lock_source.to_string(),
    })
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

    const SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

    fn project() -> TempDir {
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
    fn pnpm_v9_catalog_peer_link_and_optional_platform() {
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
            assert!(!package.optional);
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
    }

    #[test]
    fn pnpm_required_git_errors_but_optional_git_is_skipped() {
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

        let optional = required
            .replace("dependencies:", "optionalDependencies:")
            .replace("git-required:", "git-optional:");
        let plan = plan_pnpm(
            Platform::X86_64UnknownLinuxGnu,
            &optional,
            &held(&dir.0),
            node_version(),
        )
        .unwrap();
        assert!(plan.packages.is_empty());
    }

    #[test]
    fn hoisting_has_one_root_and_one_nested_version() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: 1
        version: 1.0.0
      b:
        specifier: 1
        version: 1.0.0
packages:
  a@1.0.0:
    resolution: {{integrity: {SRI}}}
  b@1.0.0:
    resolution: {{integrity: {SRI}}}
  c@1.0.0:
    resolution: {{integrity: {SRI}}}
  c@2.0.0:
    resolution: {{integrity: {SRI}}}
snapshots:
  a@1.0.0:
    dependencies:
      c: 1.0.0
  b@1.0.0:
    dependencies:
      c: 2.0.0
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
        let paths: Vec<_> = plan
            .packages
            .iter()
            .map(|package| package.path.as_str())
            .collect();
        assert!(paths.contains(&"node_modules/c"));
        assert!(paths
            .iter()
            .any(|path| path.contains("node_modules/b/node_modules/c")));
        assert_eq!(paths, {
            let mut sorted = paths.clone();
            sorted.sort();
            sorted
        });
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

    #[test]
    fn yarn_v1_multi_key_sha1_and_berry_rejection() {
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
        let package_json = r#"{"dependencies":{"is-odd":"3.0.1"}}"#;
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

    #[test]
    fn semver_ordering_preserves_prereleases_and_ignores_build_metadata() {
        let ordered = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
        ];
        for pair in ordered.windows(2) {
            let left = parse_semver(pair[0], false).unwrap();
            let right = parse_semver(pair[1], false).unwrap();
            assert_eq!(semver_cmp(&left, &right), std::cmp::Ordering::Less);
        }
        let release = parse_semver("1.0.0", false).unwrap();
        let built = parse_semver("1.0.0+ci.7", false).unwrap();
        assert_eq!(semver_cmp(&release, &built), std::cmp::Ordering::Equal);
        assert!(!yarn_workspace_spec_matches("1.0.0-beta.1", "1.0.0"));
        assert!(yarn_workspace_spec_matches("1.0.0-beta.1", "1.0.0-beta.1"));
    }

    #[test]
    fn required_pnpm_platform_dependency_fails_on_foreign_platform() {
        let dir = project();
        let lock = format!(
            r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      linux-only:
        specifier: 1.0.0
        version: 1.0.0
packages:
  linux-only@1.0.0:
    resolution: {{integrity: {SRI}}}
    os: [linux]
snapshots:
  linux-only@1.0.0: {{}}
"#
        );
        let error = plan_pnpm(
            Platform::Aarch64AppleDarwin,
            &lock,
            &held(&dir.0),
            node_version(),
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("linux-only@1.0.0"));
        assert!(text.contains("aarch64-apple-darwin"));
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
            let error = result
                .err()
                .expect("malformed fragment refused")
                .to_string();
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
