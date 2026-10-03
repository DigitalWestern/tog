//! yarn.lock (v1) import (node tailor): the entry grammar, workspace
//! manifests, semver matching for workspace specifiers, and the graph.

use super::*;

pub(super) fn parse_yarn_header(header: &str, line: usize) -> io::Result<Vec<String>> {
    let header = header.trim_end_matches(':').trim();
    let selectors = split_top_level(header, ',')
        .into_iter()
        .map(|selector| yaml_unquote(selector.trim()))
        .filter(|selector| !selector.is_empty())
        .collect::<Vec<_>>();
    if selectors.is_empty() {
        return Err(err(format!("yarn.lock line {line}: empty entry header")));
    }
    Ok(selectors)
}

#[derive(Debug, Clone)]
pub(super) struct YarnEntry {
    pub(super) selectors: Vec<String>,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) resolved: String,
    pub(super) integrity: Option<String>,
    pub(super) dependencies: BTreeMap<String, String>,
    pub(super) optional_dependencies: BTreeMap<String, String>,
}

pub(super) fn selector_name(selector: &str) -> String {
    if selector.starts_with('@') {
        selector
            .find('@')
            .and_then(|first| {
                selector[first + 1..]
                    .find('@')
                    .map(|second| first + 1 + second)
            })
            .map(|at| selector[..at].to_string())
            .unwrap_or_else(|| selector.to_string())
    } else {
        selector
            .find('@')
            .map(|at| selector[..at].to_string())
            .unwrap_or_else(|| selector.to_string())
    }
}

/// The package a selector installs: the target of an alias
/// (`foo@npm:bar@^1` installs `bar`), else the selector's own name. The
/// alias stays the install path, which comes from the dependency's name,
/// as npm and pnpm record aliases.
pub(super) fn selector_package(selector: &str) -> String {
    let name = selector_name(selector);
    match selector[name.len()..].strip_prefix("@npm:") {
        Some(target) => selector_name(target),
        None => name,
    }
}

pub(super) fn parse_yarn_value(value: &str) -> String {
    yaml_unquote(value.trim())
}

pub(super) fn split_yarn_field(value: &str) -> Option<(String, String)> {
    if let Some(pair) = split_key_value(value) {
        return Some(pair);
    }
    let value = value.trim();
    if value.starts_with('"') || value.starts_with('\'') {
        let quote = value.chars().next()?;
        let end = value[1..].find(quote)? + 1;
        return Some((
            yaml_unquote(&value[..=end]),
            value[end + 1..].trim().to_string(),
        ));
    }
    let (key, value) = value.split_once(char::is_whitespace)?;
    Some((key.to_string(), value.trim().to_string()))
}

pub(super) fn parse_yarn_entries(lock: &str) -> io::Result<Vec<YarnEntry>> {
    let raw_lines: Vec<(usize, String)> = lock
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim_end_matches('\r').to_string()))
        .collect();
    for (line, text) in &raw_lines {
        let trimmed = text.trim();
        if trimmed.starts_with("__metadata:") || trimmed.starts_with("checksum:") {
            return Err(err(format!(
                "yarn berry lockfiles carry cache-zip checksums, not tarball hashes (line {line}); run npm install --package-lock-only or pnpm import"
            )));
        }
    }
    let mut entries = Vec::new();
    let mut index = 0;
    while index < raw_lines.len() {
        let (line, text) = &raw_lines[index];
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            index += 1;
            continue;
        }
        if text.starts_with(' ') || !trimmed.ends_with(':') {
            return Err(err(format!("yarn.lock line {line}: expected entry header")));
        }
        let selectors = parse_yarn_header(trimmed, *line)?;
        index += 1;
        let mut version = None;
        let mut resolved = None;
        let mut integrity = None;
        let mut dependencies = BTreeMap::new();
        let mut optional_dependencies = BTreeMap::new();
        let mut section = None::<&str>;
        while index < raw_lines.len() {
            let (child_line, child) = &raw_lines[index];
            if child.trim().is_empty() || child.trim().starts_with('#') {
                index += 1;
                continue;
            }
            if !child.starts_with(' ') {
                break;
            }
            let indent = child.chars().take_while(|c| *c == ' ').count();
            let value = child.trim();
            if indent == 2
                && value.ends_with(':')
                && (value == "dependencies:" || value == "optionalDependencies:")
            {
                section = Some(value.trim_end_matches(':'));
                index += 1;
                continue;
            }
            if indent >= 4 && section.is_some() {
                let Some((name, spec)) = split_yarn_field(value) else {
                    return Err(err(format!(
                        "yarn.lock line {child_line}: malformed dependency"
                    )));
                };
                let spec = parse_yarn_value(&spec);
                if section == Some("optionalDependencies") {
                    optional_dependencies.insert(name, spec);
                } else {
                    dependencies.insert(name, spec);
                }
                index += 1;
                continue;
            }
            section = None;
            let Some((field, field_value)) = split_yarn_field(value) else {
                return Err(err(format!("yarn.lock line {child_line}: malformed field")));
            };
            match field.as_str() {
                "version" => version = Some(parse_yarn_value(&field_value)),
                "resolved" => resolved = Some(parse_yarn_value(&field_value)),
                "integrity" => integrity = Some(parse_yarn_value(&field_value)),
                _ => {}
            }
            index += 1;
        }
        let version =
            version.ok_or_else(|| err(format!("yarn.lock line {line}: missing version")))?;
        let resolved =
            resolved.ok_or_else(|| err(format!("yarn.lock line {line}: missing resolved URL")))?;
        entries.push(YarnEntry {
            name: selector_package(&selectors[0]),
            selectors,
            version,
            resolved,
            integrity,
            dependencies,
            optional_dependencies,
        });
    }
    Ok(entries)
}

pub(super) fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (a << 16) | (b << 8) | c;
        output.push(TABLE[((value >> 18) & 63) as usize] as char);
        output.push(TABLE[((value >> 12) & 63) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

pub(super) fn yarn_integrity(
    resolved: &str,
    integrity: Option<String>,
    path: &str,
) -> io::Result<String> {
    yarn_integrity_with(
        resolved,
        integrity,
        path,
        &mut crate::kernel::policy::record,
    )
}

/// `yarn_integrity` recording through `record`, so a test can pass a
/// policy of its own instead of the process one.
fn yarn_integrity_with(
    resolved: &str,
    integrity: Option<String>,
    path: &str,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
) -> io::Result<String> {
    if let Some(integrity) = integrity {
        let selected = integrity
            .split_whitespace()
            .find(|value| value.starts_with("sha512-"))
            .or_else(|| {
                integrity
                    .split_whitespace()
                    .find(|value| value.starts_with("sha256-"))
            })
            .or_else(|| {
                integrity
                    .split_whitespace()
                    .find(|value| value.starts_with("sha1-"))
            })
            .ok_or_else(|| err(format!("{path}: malformed Yarn integrity")))?;
        integrity_policy_with(path, selected, record)?;
        Digest::from_sri(selected)?;
        return Ok(selected.to_string());
    }
    let fragment = resolved
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .filter(|fragment| !fragment.is_empty())
        .ok_or_else(|| {
            err(format!(
                "{path}: yarn entry has neither integrity nor a #sha1 fragment"
            ))
        })?;
    let fragment = fragment.strip_prefix("sha1-").unwrap_or(fragment);
    let bytes = if fragment.len() == 40 && fragment.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        (0..fragment.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&fragment[index..index + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| err(format!("{path}: malformed yarn sha1 fragment")))?
    } else {
        return Err(err(format!("{path}: malformed yarn sha1 fragment")));
    };
    let sri = format!("sha1-{}", base64_encode(&bytes));
    integrity_policy_with(path, &sri, record)?;
    Ok(sri)
}

#[derive(Debug, Clone)]
pub(super) struct YarnWorkspace {
    pub(super) path: String,
    pub(super) name: String,
    pub(super) version: String,
    pub(super) package: JsonValue,
}

pub(super) fn workspace_segment_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let mut row = vec![false; value.len() + 1];
    row[0] = true;
    for character in pattern {
        let mut next = vec![false; value.len() + 1];
        for (index, matched) in row.iter().enumerate() {
            if !matched {
                continue;
            }
            if character == '*' {
                for slot in &mut next[index..] {
                    *slot = true;
                }
            } else if character == '?' {
                if index < value.len() {
                    next[index + 1] = true;
                }
            } else if index < value.len() && value[index] == character {
                next[index + 1] = true;
            }
        }
        row = next;
    }
    row[value.len()]
}

pub(super) fn workspace_glob_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim_matches('/');
    let path = path.trim_matches('/');
    if pattern.is_empty() {
        return path.is_empty();
    }
    let patterns: Vec<&str> = pattern.split('/').collect();
    let paths: Vec<&str> = if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    };
    fn matches(pattern: &[&str], path: &[&str]) -> bool {
        if pattern.is_empty() {
            return path.is_empty();
        }
        if pattern[0] == "**" {
            matches(&pattern[1..], path) || (!path.is_empty() && matches(pattern, &path[1..]))
        } else {
            !path.is_empty()
                && workspace_segment_matches(pattern[0], path[0])
                && matches(&pattern[1..], &path[1..])
        }
    }
    matches(&patterns, &paths)
}

/// Every directory under `directory` (project-relative, `.` for the root)
/// holding a package.json. The project is walked through the held
/// descriptor; a symlinked directory is not descended into.
pub(super) fn collect_workspace_manifests(
    project: &ProjectRoot,
    directory: &Path,
    result: &mut Vec<String>,
) -> io::Result<()> {
    let Some(entries) = project.read_input_dir(directory)? else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", project.path().join(directory).display()),
        ));
    };
    for file_name in entries {
        let name = file_name.to_string_lossy().into_owned();
        if name == "node_modules" || name == ".git" || name == ".tog" {
            continue;
        }
        let path = if directory == Path::new(".") {
            PathBuf::from(&file_name)
        } else {
            directory.join(&file_name)
        };
        if project.entry(&path)? != Entry::Directory {
            continue;
        }
        if project.is_input_file(&path.join("package.json")) {
            let relative = path.to_string_lossy().into_owned();
            if !relative.is_empty() {
                result.push(relative);
            }
        }
        collect_workspace_manifests(project, &path, result)?;
    }
    Ok(())
}

pub(super) fn yarn_workspace_manifests(
    package: &JsonValue,
    project: &ProjectRoot,
) -> io::Result<Vec<YarnWorkspace>> {
    let Some(value) = package.get("workspaces") else {
        return Ok(Vec::new());
    };
    let patterns = if let Some(values) = value.as_array() {
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| err("package.json workspaces entries must be strings"))
            })
            .collect::<io::Result<Vec<_>>>()?
    } else if let Some(object) = value.as_object() {
        let Some(values) = object.get("packages").and_then(JsonValue::as_array) else {
            return Err(err(
                "Yarn workspaces object must contain a string-array packages field",
            ));
        };
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| err("package.json workspaces entries must be strings"))
            })
            .collect::<io::Result<Vec<_>>>()?
    } else {
        return Err(err("package.json workspaces must be an array or object"));
    };
    if patterns.is_empty() {
        return Err(err(
            "Yarn workspaces declared with no package patterns; unsupported monorepo shape",
        ));
    }

    let mut candidates = Vec::new();
    collect_workspace_manifests(project, Path::new("."), &mut candidates)?;
    candidates.sort();
    candidates.dedup();
    let mut selected = BTreeSet::new();
    for raw_pattern in patterns {
        let exclude = raw_pattern.starts_with('!');
        let pattern = raw_pattern.trim_start_matches('!').trim_start_matches("./");
        if pattern.starts_with('/') || pattern.split('/').any(|part| part == "..") {
            return Err(err(format!(
                "Yarn workspaces pattern {raw_pattern:?} escapes the project"
            )));
        }
        for candidate in &candidates {
            if workspace_glob_matches(pattern, candidate) {
                if exclude {
                    selected.remove(candidate);
                } else {
                    selected.insert(candidate.clone());
                }
            }
        }
    }
    if selected.is_empty() {
        return Err(err(
            "Yarn workspaces declared but no workspace package.json matched the supported patterns",
        ));
    }
    let mut workspaces = Vec::new();
    for path in selected {
        // A backslash is an ordinary filename byte here, but a Windows
        // separator to anyone reading the path back; `..\x` must not be
        // mistaken for, or turned into, `../x`.
        if path.contains('\\') {
            return Err(err(format!(
                "Yarn workspace {path:?} has a backslash in its path; rename the directory"
            )));
        }
        let text = crate::tailors::node::inputs::read_input(
            project,
            Path::new(&path).join("package.json"),
        )
        .map_err(|error| err(format!("Yarn workspace {path}: read package.json: {error}")))?;
        let package: JsonValue = serde_json::from_str(&text)
            .map_err(|error| err(format!("Yarn workspace {path}: package.json: {error}")))?;
        let name = package["name"].as_str().ok_or_else(|| {
            err(format!(
                "Yarn workspace {path}: package.json has no string name"
            ))
        })?;
        let version = package["version"].as_str().ok_or_else(|| {
            err(format!(
                "Yarn workspace {path}: package.json has no string version"
            ))
        })?;
        workspaces.push(YarnWorkspace {
            path,
            name: name.to_string(),
            version: version.to_string(),
            package,
        });
    }
    Ok(workspaces)
}

/// Whether a manifest specifier resolves to the workspace member at
/// `version`. Yarn classic links the member when node-semver's `satisfies`
/// admits its version, so the range goes through the kernel's node-semver.
/// A bare `*` or `latest` names whatever the member is, prereleases
/// included, and so do the `workspace:` protocol's bare forms.
pub(super) fn yarn_workspace_spec_matches(specifier: &str, version: &str) -> bool {
    let mut specifier = specifier.trim();
    if let Some(protocol) = specifier.strip_prefix("workspace:") {
        specifier = protocol;
        if matches!(specifier, "" | "*" | "^" | "~") {
            return true;
        }
    }
    if matches!(specifier, "*" | "latest") {
        return true;
    }
    crate::kernel::semver::Range::parse(specifier).is_ok_and(|range| range.satisfies_text(version))
}

/// Parse a Yarn classic v1 lockfile. The package.json is needed because Yarn
/// lock headers are selectors, not a root dependency graph.
pub fn plan_yarn(
    platform: Platform,
    lock: &str,
    package_json: &str,
    project: &ProjectRoot,
    node_version: &str,
) -> io::Result<NpmPlan> {
    let entries = parse_yarn_entries(lock)?;
    let package: JsonValue = serde_json::from_str(package_json)
        .map_err(|error| err(format!("package.json: {error}")))?;
    let mut selector_to_node = BTreeMap::<String, String>::new();
    let mut nodes = BTreeMap::<String, Node>::new();
    for (index, entry) in entries.iter().enumerate() {
        let key = format!("yarn:{index}");
        let url = entry
            .resolved
            .split_once('#')
            .map(|(url, _)| url)
            .unwrap_or(entry.resolved.as_str());
        // Yarn 1 attests a GitHub archive tarball by the sha1 in its
        // fragment, as it does any other tarball. Those bytes are what the
        // lock pins, so the entry is a verified tarball, not a git checkout
        // of the path commit. A malformed fragment fails in yarn_integrity.
        let attested = entry.integrity.is_some()
            || (crate::tailors::node::is_github_archive_url(&entry.resolved)
                && entry
                    .resolved
                    .split_once('#')
                    .is_some_and(|(_, fragment)| !fragment.is_empty()));
        let pinned_git = lock_git_source(&entry.resolved, attested);
        let git_detail = if pinned_git.is_some() || attested {
            None
        } else {
            crate::tailors::node::git_dependency_detail(&entry.name, &entry.resolved)
        };
        let integrity = if git_detail.is_some() || pinned_git.is_some() {
            String::new()
        } else {
            yarn_integrity(&entry.resolved, entry.integrity.clone(), &key)?
        };
        let url = match &pinned_git {
            Some(source) => format!("git+{}#{}", source.url, source.commit),
            None => url.to_string(),
        };
        let external = git_detail.or_else(|| {
            pinned_git
                .is_none()
                .then(|| crate::tailors::node::tarball_url_detail(&url, "non-https resolved URL"))
                .flatten()
        });
        let mut deps = Vec::new();
        let mut all_deps = entry.dependencies.clone();
        for (name, spec) in &entry.optional_dependencies {
            all_deps.insert(name.clone(), spec.clone());
        }
        for (name, spec) in all_deps {
            let selector = format!("{name}@{spec}");
            deps.push(Dependency {
                name,
                target: Target::External(format!("missing yarn selector {selector}")),
                optional: entry
                    .optional_dependencies
                    .contains_key(&selector_name(&selector)),
            });
        }
        nodes.insert(
            key.clone(),
            Node {
                key: key.clone(),
                name: entry.name.clone(),
                version: entry.version.clone(),
                url: url.to_string(),
                integrity,
                optional: false,
                os: Vec::new(),
                cpu: Vec::new(),
                libc: Vec::new(),
                external,
                patch: None,
                deps,
            },
        );
        for selector in &entry.selectors {
            selector_to_node.insert(selector.clone(), key.clone());
        }
    }

    // Dependencies can reference entries that occur later in the lockfile.
    for node in nodes.values_mut() {
        for dependency in &mut node.deps {
            if let Target::External(marker) = &dependency.target {
                if let Some(selector) = marker.strip_prefix("missing yarn selector ") {
                    dependency.target = selector_to_node
                        .get(selector)
                        .cloned()
                        .map(Target::Node)
                        .unwrap_or_else(|| Target::External(marker.clone()));
                }
            }
        }
    }

    let workspaces = yarn_workspace_manifests(&package, project)?;
    let dependencies_of = |package: &JsonValue, dir: Option<&str>, dev: bool| {
        yarn_package_dependencies(package, &selector_to_node, &workspaces, dir, project, dev)
    };
    let mut root_deps: Vec<RootDependency> = dependencies_of(&package, None, true)?
        .into_iter()
        .map(|dependency| RootDependency {
            dependency,
            workspace: None,
        })
        .collect();
    // Yarn classic links every discovered workspace into the root, including
    // members that no other manifest mentions. Keep these as root-local links
    // so `require("member")` works from the repository root just as it does
    // after a real Yarn install.
    for workspace in &workspaces {
        root_deps.push(RootDependency {
            dependency: Dependency {
                name: workspace.name.clone(),
                target: Target::Link(workspace.path.clone()),
                optional: false,
            },
            workspace: None,
        });
    }
    let mut workspace_roots = Vec::new();
    for workspace in &workspaces {
        for dependency in dependencies_of(&workspace.package, Some(&workspace.path), true)? {
            workspace_roots.push(RootDependency {
                dependency,
                workspace: Some(workspace.path.clone()),
            });
        }
    }
    let all_roots = [root_deps.as_slice(), workspace_roots.as_slice()].concat();
    let local_link_deps =
        yarn_link_dependencies(&all_roots, &workspaces, project, &dependencies_of)?;
    yarn_unused_entry(&entries, &nodes, &all_roots, &local_link_deps)?;
    let graph = Graph {
        nodes,
        roots: root_deps,
        workspace_roots,
        workspace_paths: workspaces
            .iter()
            .map(|workspace| workspace.path.clone())
            .collect(),
        local_link_deps,
    };
    build_plan(platform, graph, "yarn.lock", node_version)
}

/// The lock entry a manifest's direct dependency names. yarn.lock keys each
/// entry by the `name@spec` selectors that resolved to it, so a selector
/// with no entry means the manifest changed after the lock was written.
/// `link:` is the one form Yarn classic never locks: it is a symlink to a
/// directory, read relative to the directory holding yarn.lock whichever
/// manifest names it (Yarn's link resolver resolves against its
/// `lockfileFolder`). It becomes the same link a pnpm `link:` does, held to
/// the same rule that the directory is inside the project.
fn yarn_direct_target(
    selector_to_node: &BTreeMap<String, String>,
    manifest: &str,
    field: &str,
    name: &str,
    spec: &str,
    project: &ProjectRoot,
) -> io::Result<Target> {
    let selector = format!("{name}@{spec}");
    match (selector_to_node.get(&selector), spec.strip_prefix("link:")) {
        (Some(node), _) => Ok(Target::Node(node.clone())),
        (None, Some("")) => Err(err(format!(
            "{manifest} {field} {name}: link: names no directory"
        ))),
        (None, Some(raw)) => super::pnpm::workspace_target(project, ".", raw).map(Target::Link),
        (None, None) => Err(crate::tailors::node::freshness::stale(
            manifest,
            field,
            &crate::tailors::node::freshness::YARN,
        )),
    }
}

/// The dependencies of every directory a manifest reaches through `link:`,
/// by link target. Yarn reads a linked directory's package.json, when it has
/// one, and resolves its `dependencies` and `optionalDependencies` into the
/// lock like any package's (never its `devDependencies`), so those entries
/// are part of the graph: they are placed where Node finds them from the
/// linked directory, and they keep their lock entries reachable. A linked
/// manifest is held to the lock as the project's own are. A workspace
/// member is not read here: it is an importer with roots of its own.
fn yarn_link_dependencies(
    roots: &[RootDependency],
    workspaces: &[YarnWorkspace],
    project: &ProjectRoot,
    dependencies_of: &dyn Fn(&JsonValue, Option<&str>, bool) -> io::Result<Vec<Dependency>>,
) -> io::Result<BTreeMap<String, Vec<Dependency>>> {
    fn link_targets<'a>(deps: impl Iterator<Item = &'a Dependency>) -> Vec<String> {
        deps.filter_map(|dependency| match &dependency.target {
            Target::Link(target) => Some(target.clone()),
            _ => None,
        })
        .collect()
    }
    let mut found = BTreeMap::<String, Vec<Dependency>>::new();
    let mut queue = link_targets(roots.iter().map(|root| &root.dependency));
    while let Some(target) = queue.pop() {
        let importer = target == "." || workspaces.iter().any(|member| member.path == target);
        if importer || found.contains_key(&target) {
            continue;
        }
        let manifest = crate::tailors::node::freshness::manifest_path(&target);
        let deps = match project.read_input_string(Path::new(&manifest))? {
            // A linked directory without a package.json depends on nothing.
            None => Vec::new(),
            Some(text) => {
                let package: JsonValue = serde_json::from_str(&text)
                    .map_err(|error| err(format!("{manifest}: {error}")))?;
                dependencies_of(&package, Some(&target), false)?
            }
        };
        queue.extend(link_targets(deps.iter()));
        found.insert(target, deps);
    }
    Ok(found)
}

/// Every lock entry is reachable from some manifest's dependencies: `yarn
/// install` drops the ones nothing needs, so one left over means a manifest
/// lost a dependency after the lock was written. `linked` holds the
/// dependencies of the directories reached through `link:`.
fn yarn_unused_entry(
    entries: &[YarnEntry],
    nodes: &BTreeMap<String, Node>,
    roots: &[RootDependency],
    linked: &BTreeMap<String, Vec<Dependency>>,
) -> io::Result<()> {
    let mut reached = BTreeSet::<String>::new();
    let mut queue: Vec<String> = roots
        .iter()
        .map(|root| &root.dependency)
        .chain(linked.values().flatten())
        .filter_map(|dependency| match &dependency.target {
            Target::Node(key) => Some(key.clone()),
            _ => None,
        })
        .collect();
    while let Some(key) = queue.pop() {
        if !reached.insert(key.clone()) {
            continue;
        }
        if let Some(node) = nodes.get(&key) {
            for dependency in &node.deps {
                if let Target::Node(child) = &dependency.target {
                    queue.push(child.clone());
                }
            }
        }
    }
    for (index, entry) in entries.iter().enumerate() {
        if !reached.contains(&format!("yarn:{index}")) {
            let format = &crate::tailors::node::freshness::YARN;
            return Err(err(format!(
                "yarn.lock locks {}, which no package.json depends on; regenerate the lock ({})",
                entry.selectors[0],
                format.regenerate()
            )));
        }
    }
    Ok(())
}

pub(super) fn yarn_package_dependencies(
    package: &JsonValue,
    selector_to_node: &BTreeMap<String, String>,
    workspaces: &[YarnWorkspace],
    importer: Option<&str>,
    project: &ProjectRoot,
    dev: bool,
) -> io::Result<Vec<Dependency>> {
    let manifest = crate::tailors::node::freshness::manifest_path(importer.unwrap_or("."));
    let mut deps = BTreeMap::<String, Dependency>::new();
    for (field, optional) in [
        ("dependencies", false),
        ("devDependencies", false),
        ("optionalDependencies", true),
    ] {
        let Some(map) = package[field].as_object() else {
            continue;
        };
        if field == "devDependencies" && !dev {
            continue;
        }
        for (name, spec) in map {
            let spec = spec.as_str().ok_or_else(|| {
                err(format!(
                    "package.json {field} {name}: specifier must be a string"
                ))
            })?;
            let workspace = workspaces.iter().find(|workspace| workspace.name == *name);
            let target = if let Some(workspace) = workspace {
                if yarn_workspace_spec_matches(spec, &workspace.version) {
                    Target::Link(workspace.path.clone())
                } else if spec.starts_with("workspace:") {
                    return Err(err(format!(
                        "Yarn workspace dependency {name}@{spec} does not match workspace {}@{}",
                        workspace.name, workspace.version
                    )));
                } else {
                    yarn_direct_target(selector_to_node, &manifest, field, name, spec, project)?
                }
            } else if spec.starts_with("workspace:") {
                return Err(err(format!(
                    "Yarn workspace dependency {name}@{spec} has no matching workspace member"
                )));
            } else {
                yarn_direct_target(selector_to_node, &manifest, field, name, spec, project)?
            };
            deps.insert(
                name.clone(),
                Dependency {
                    name: name.clone(),
                    target,
                    optional,
                },
            );
        }
    }
    Ok(deps.into_values().collect())
}

#[cfg(test)]
mod lock_shape_tests {
    use super::super::tests::{held, node_version, project, SRI};
    use super::*;

    /// sha1 and sha256 of zero bytes as SRIs: well-formed digests.
    const SHA1_SRI: &str = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const SHA256_SRI: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn plan(lock: &str, package_json: &str) -> io::Result<NpmPlan> {
        let dir = project();
        plan_yarn(
            Platform::X86_64UnknownLinuxGnu,
            lock,
            package_json,
            &held(&dir.0),
            node_version(),
        )
    }

    fn assert_invalid(error: io::Error, expected: &str) {
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{expected}");
    }

    #[test]
    fn selector_names_keep_scopes_and_drop_alias_targets() {
        for (selector, name) in [
            ("plain@^1.0.0", "plain"),
            ("plain", "plain"),
            ("@s/n@^1.0.0", "@s/n"),
            ("@s/n", "@s/n"),
            ("foo@npm:bar@1", "foo"),
            ("@s/foo@npm:@t/bar@^2", "@s/foo"),
        ] {
            assert_eq!(selector_name(selector), name, "{selector}");
        }
    }

    #[test]
    fn selector_packages_are_alias_targets() {
        for (selector, package) in [
            ("plain@^1.0.0", "plain"),
            ("plain", "plain"),
            ("@s/n@^1.0.0", "@s/n"),
            ("foo@npm:bar@1", "bar"),
            ("foo@npm:bar", "bar"),
            ("@s/foo@npm:@t/bar@^2", "@t/bar"),
            ("foo@npm:@t/bar", "@t/bar"),
        ] {
            assert_eq!(selector_package(selector), package, "{selector}");
        }
    }

    #[test]
    fn a_scoped_entry_is_placed_under_its_scope() {
        let lock = format!(
            "# yarn lockfile v1\n\"@s/n@^1.0.0\":\n  version \"1.2.0\"\n  resolved \"https://r/n-1.2.0.tgz\"\n  integrity {SRI}\n"
        );
        let plan = plan(&lock, r#"{"dependencies":{"@s/n":"^1.0.0"}}"#).unwrap();
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.packages[0].path, "node_modules/@s/n");
        assert_eq!(plan.packages[0].name, "@s/n");
        assert_eq!(plan.packages[0].version, "1.2.0");
    }

    /// `foo@npm:bar@^1.0.0` lands at node_modules/foo and is the package
    /// bar: realization provisions and names it by its real name.
    #[test]
    fn a_yarn_alias_is_placed_by_its_alias_and_fetches_the_real_package() {
        let lock = format!(
            "# yarn lockfile v1\n\"foo@npm:bar@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/bar/-/bar-1.0.0.tgz\"\n  integrity {SRI}\n\"@s/alias@npm:@t/real@^2.0.0\":\n  version \"2.0.0\"\n  resolved \"https://registry.yarnpkg.com/@t/real/-/real-2.0.0.tgz\"\n  integrity {SRI}\n"
        );
        let plan = plan(
            &lock,
            r#"{"dependencies":{"foo":"npm:bar@^1.0.0","@s/alias":"npm:@t/real@^2.0.0"}}"#,
        )
        .unwrap();
        let placed: Vec<(&str, &str, &str, &str, &str)> = plan
            .packages
            .iter()
            .map(|p| {
                (
                    p.path.as_str(),
                    p.name.as_str(),
                    p.version.as_str(),
                    p.url.as_str(),
                    p.integrity.as_str(),
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
                    "https://registry.yarnpkg.com/@t/real/-/real-2.0.0.tgz",
                    SRI
                ),
                (
                    "node_modules/foo",
                    "bar",
                    "1.0.0",
                    "https://registry.yarnpkg.com/bar/-/bar-1.0.0.tgz",
                    SRI
                ),
            ]
        );
    }

    /// The strongest listed digest wins: sha512, then sha256, then sha1.
    #[test]
    fn yarn_integrity_prefers_the_strongest_digest() {
        let url = "https://r/a.tgz";
        let all = format!("{SHA1_SRI} {SHA256_SRI} {SRI}");
        assert_eq!(yarn_integrity(url, Some(all), "yarn:0").unwrap(), SRI);
        let reversed = format!("{SRI} {SHA256_SRI} {SHA1_SRI}");
        assert_eq!(yarn_integrity(url, Some(reversed), "yarn:0").unwrap(), SRI);
        let weaker = format!("{SHA1_SRI} {SHA256_SRI}");
        assert_eq!(
            yarn_integrity(url, Some(weaker), "yarn:0").unwrap(),
            SHA256_SRI
        );
        // An integrity field wins over a #sha1 fragment.
        let fragment = "https://r/a.tgz#0000000000000000000000000000000000000000";
        assert_eq!(
            yarn_integrity(fragment, Some(SRI.to_string()), "yarn:0").unwrap(),
            SRI
        );
    }

    #[test]
    fn a_sha1_yarn_integrity_is_recorded_inside_an_attribution() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        // An explicit permissive policy: TOG_STRICT=1 in the environment
        // would otherwise refuse the exception this test expects recorded.
        let permissive = crate::kernel::policy::Policy::default();
        let mut record = |kind: &str, subject: &str, detail: &str| {
            crate::kernel::policy::record_with(&permissive, kind, subject, detail)
        };
        for (url, integrity) in [
            ("https://r/a.tgz", Some(SHA1_SRI.to_string())),
            (
                "https://r/a.tgz#0000000000000000000000000000000000000000",
                None,
            ),
        ] {
            assert_eq!(
                yarn_integrity_with(url, integrity, "yarn:3", &mut record).unwrap(),
                SHA1_SRI
            );
            let exceptions = crate::kernel::policy::drain();
            assert_eq!(exceptions.len(), 1, "{exceptions:?}");
            assert_eq!(exceptions[0].kind, crate::kernel::policy::WEAK_INTEGRITY);
            assert_eq!(exceptions[0].subject, "yarn:3");
        }
    }

    /// Outside an attribution the weak digest is refused with the policy
    /// error itself (unlike npm, not wrapped in an algorithm message).
    #[test]
    fn a_sha1_yarn_integrity_is_refused_outside_any_attribution() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let error =
            yarn_integrity("https://r/a.tgz", Some(SHA1_SRI.to_string()), "yarn:0").unwrap_err();
        assert_eq!(
            error.to_string(),
            "exception recorded outside any attribution"
        );
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn an_integrity_with_no_supported_digest_is_malformed() {
        for integrity in [
            "md5-AAAAAAAAAAAAAAAAAAAAAA==",
            "sha384-AAAA",
            "",
            "sha5120-x",
        ] {
            let error = yarn_integrity("https://r/a.tgz", Some(integrity.to_string()), "yarn:2")
                .unwrap_err();
            assert_invalid(error, "yarn:2: malformed Yarn integrity");
        }
        // And through plan_yarn: the subject is the entry's index key.
        let lock = "# yarn lockfile v1\na@1.0.0:\n  version \"1.0.0\"\n  resolved \"https://r/a.tgz\"\n  integrity md5-AAAAAAAAAAAAAAAAAAAAAA==\n";
        let error = plan(lock, r#"{"dependencies":{"a":"1.0.0"}}"#)
            .map(drop)
            .unwrap_err();
        assert_invalid(error, "yarn:0: malformed Yarn integrity");
    }

    #[test]
    fn an_entry_with_neither_integrity_nor_fragment_is_refused() {
        for url in ["https://r/a.tgz", "https://r/a.tgz#"] {
            let error = yarn_integrity(url, None, "yarn:1").unwrap_err();
            assert_invalid(
                error,
                "yarn:1: yarn entry has neither integrity nor a #sha1 fragment",
            );
        }
        for url in ["https://r/a.tgz#abc", "https://r/a.tgz#sha1-zz"] {
            let error = yarn_integrity(url, None, "yarn:1").unwrap_err();
            assert_invalid(error, "yarn:1: malformed yarn sha1 fragment");
        }
    }

    fn http_lock() -> String {
        format!(
            "# yarn lockfile v1\na@1.0.0:\n  version \"1.0.0\"\n  resolved \"http://r/a-1.0.0.tgz\"\n  integrity {SRI}\nb@1.0.0:\n  version \"1.0.0\"\n  resolved \"https://r/b-1.0.0.tgz\"\n  integrity {SRI}\n"
        )
    }

    #[test]
    fn a_required_non_https_entry_is_refused() {
        let error = plan(
            &http_lock(),
            r#"{"dependencies":{"a":"1.0.0","b":"1.0.0"}}"#,
        )
        .map(drop)
        .unwrap_err();
        assert_invalid(
            error,
            "a@1.0.0: non-https resolved URL http://r/a-1.0.0.tgz",
        );
    }

    #[test]
    fn an_optional_non_https_entry_is_dropped() {
        let plan = plan(
            &http_lock(),
            r#"{"dependencies":{"b":"1.0.0"},"optionalDependencies":{"a":"1.0.0"}}"#,
        )
        .unwrap();
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["node_modules/b"]);
    }

    fn credentials_lock() -> String {
        http_lock().replace("http://r/a-1.0.0.tgz", "https://u:secret@r/a-1.0.0.tgz")
    }

    /// Credentials win over the scheme, so an http URL's secret is not
    /// echoed in the non-https message either.
    #[test]
    fn a_required_entry_with_url_credentials_is_refused() {
        for lock in [
            credentials_lock(),
            http_lock().replace("http://r/", "http://u:secret@r/"),
        ] {
            let error = plan(&lock, r#"{"dependencies":{"a":"1.0.0","b":"1.0.0"}}"#)
                .map(drop)
                .unwrap_err();
            assert!(!error.to_string().contains("secret"), "{error}");
            assert_invalid(
                error,
                "a@1.0.0: tarball URL carries credentials (user:pass@ before its host); tog will not record them",
            );
        }
    }

    #[test]
    fn an_optional_entry_with_url_credentials_is_dropped() {
        let plan = plan(
            &credentials_lock(),
            r#"{"dependencies":{"b":"1.0.0"},"optionalDependencies":{"a":"1.0.0"}}"#,
        )
        .unwrap();
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["node_modules/b"]);
    }

    /// A project with members at packages/a, packages/b and packages/deep/c.
    fn members() -> crate::kernel::testutil::TempDir {
        let dir = project();
        for (path, name) in [
            ("packages/a", "a"),
            ("packages/b", "b"),
            ("packages/deep/c", "c"),
        ] {
            fs::create_dir_all(dir.0.join(path)).unwrap();
            fs::write(
                dir.0.join(path).join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            )
            .unwrap();
        }
        dir
    }

    fn workspaces(dir: &Path, declared: &str) -> io::Result<Vec<String>> {
        let package: JsonValue =
            serde_json::from_str(&format!(r#"{{"workspaces":{declared}}}"#)).unwrap();
        yarn_workspace_manifests(&package, &held(dir))
            .map(|found| found.into_iter().map(|member| member.path).collect())
    }

    #[test]
    fn a_workspace_pattern_escaping_the_project_is_refused() {
        let dir = members();
        for pattern in [
            "../x",
            "/abs/*",
            "!../x",
            "packages/../../x",
            "./../x",
            "packages/..",
        ] {
            let error = workspaces(&dir.0, &format!(r#"["packages/*",{pattern:?}]"#)).unwrap_err();
            assert_invalid(
                error,
                &format!("Yarn workspaces pattern {pattern:?} escapes the project"),
            );
        }
    }

    /// On Unix `..\outside` is one directory name. Read back as `../outside`
    /// it would name the project's sibling, whose manifest must not be read.
    #[test]
    fn a_workspace_directory_with_a_backslash_is_refused() {
        let wrapper = crate::kernel::testutil::TempDir::named("yarn-backslash");
        let project = wrapper.0.join("project");
        for (path, name) in [("project/..\\outside", "inside"), ("outside", "sibling")] {
            fs::create_dir_all(wrapper.0.join(path)).unwrap();
            fs::write(
                wrapper.0.join(path).join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            )
            .unwrap();
        }
        let error = workspaces(&project, r#"["**"]"#).unwrap_err();
        assert_invalid(
            error,
            r#"Yarn workspace "..\\outside" has a backslash in its path; rename the directory"#,
        );
        fs::create_dir_all(project.join("packages/a")).unwrap();
        fs::write(
            project.join("packages/a/package.json"),
            r#"{"name":"a","version":"1.0.0"}"#,
        )
        .unwrap();
        assert_eq!(
            workspaces(&project, r#"["packages/*"]"#).unwrap(),
            vec!["packages/a"]
        );
    }

    #[test]
    fn a_workspace_declaration_with_no_patterns_is_refused() {
        let dir = members();
        for declared in ["[]", r#"{"packages":[]}"#] {
            let error = workspaces(&dir.0, declared).unwrap_err();
            assert_invalid(
                error,
                "Yarn workspaces declared with no package patterns; unsupported monorepo shape",
            );
        }
    }

    #[test]
    fn a_workspace_declaration_matching_nothing_is_refused() {
        let dir = members();
        for declared in [
            r#"["nope/*"]"#,
            r#"["packages/*","!packages/*"]"#,
            r#"["packages/a","!packages/a"]"#,
        ] {
            let error = workspaces(&dir.0, declared).unwrap_err();
            assert_invalid(
                error,
                "Yarn workspaces declared but no workspace package.json matched the supported patterns",
            );
        }
    }

    #[test]
    fn workspace_globs_exclude_with_bang_and_recurse_with_double_star() {
        let dir = members();
        assert_eq!(
            workspaces(&dir.0, r#"["packages/*"]"#).unwrap(),
            vec!["packages/a", "packages/b"]
        );
        assert_eq!(
            workspaces(&dir.0, r#"["packages/*","!packages/b"]"#).unwrap(),
            vec!["packages/a"]
        );
        assert_eq!(
            workspaces(&dir.0, r#"{"packages":["./packages/**"]}"#).unwrap(),
            vec!["packages/a", "packages/b", "packages/deep/c"]
        );
        assert_eq!(
            workspaces(&dir.0, r#"["packages/**","!packages/deep/**"]"#).unwrap(),
            vec!["packages/a", "packages/b"]
        );
        assert!(workspace_glob_matches("packages/**", "packages/deep/c"));
        assert!(workspace_glob_matches("**", "a"));
        assert!(workspace_glob_matches("packages/?", "packages/a"));
        assert!(!workspace_glob_matches("packages/*", "packages/deep/c"));
        assert!(!workspace_glob_matches("packages/?", "packages/ab"));
    }
}
