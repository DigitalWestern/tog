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
            name: selector_name(&selectors[0]),
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
        integrity_policy(path, selected)?;
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
    integrity_policy(path, &sri)?;
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

pub(super) fn collect_workspace_manifests(
    root: &Path,
    directory: &Path,
    result: &mut Vec<String>,
) -> io::Result<()> {
    let entries = fs::read_dir(directory)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "node_modules" || name == ".git" || name == ".blanket" {
            continue;
        }
        let path = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if path.join("package.json").is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| err("workspace manifest escaped project root"))?
                .to_string_lossy()
                .replace('\\', "/");
            if !relative.is_empty() {
                result.push(relative);
            }
        }
        collect_workspace_manifests(root, &path, result)?;
    }
    Ok(())
}

pub(super) fn yarn_workspace_manifests(
    package: &JsonValue,
    project_dir: &Path,
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
    collect_workspace_manifests(project_dir, project_dir, &mut candidates)?;
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
        let manifest_path = project_dir.join(&path).join("package.json");
        let text = fs::read_to_string(&manifest_path)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SemverIdentifier {
    Numeric(u64),
    Alpha(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Semver {
    pub(super) major: u64,
    pub(super) minor: u64,
    pub(super) patch: u64,
    pub(super) prerelease: Vec<SemverIdentifier>,
}

pub(super) fn parse_semver(value: &str, allow_partial: bool) -> Option<Semver> {
    let value = value.trim().trim_start_matches('v');
    let (value, _) = value.split_once('+').unwrap_or((value, ""));
    let (core, prerelease) = value.split_once('-').unwrap_or((value, ""));
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 3 || (!allow_partial && parts.len() != 3) {
        return None;
    }
    let mut numbers = Vec::new();
    for part in &parts {
        if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        numbers.push(part.parse::<u64>().ok()?);
    }
    while numbers.len() < 3 {
        numbers.push(0);
    }
    let prerelease = if prerelease.is_empty() {
        Vec::new()
    } else {
        prerelease
            .split('.')
            .map(|part| {
                if part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || part.len() > 1
                        && part.starts_with('0')
                        && part.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    Some(SemverIdentifier::Numeric(part.parse().ok()?))
                } else {
                    Some(SemverIdentifier::Alpha(part.to_string()))
                }
            })
            .collect::<Option<Vec<_>>>()?
    };
    Some(Semver {
        major: numbers[0],
        minor: numbers[1],
        patch: numbers[2],
        prerelease,
    })
}

pub(super) fn semver_cmp(left: &Semver, right: &Semver) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left.major, left.minor, left.patch).cmp(&(right.major, right.minor, right.patch)) {
        Ordering::Equal => {}
        ordering => return ordering,
    }
    match (left.prerelease.is_empty(), right.prerelease.is_empty()) {
        (true, true) | (false, false) => {}
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
    }
    for (left, right) in left.prerelease.iter().zip(&right.prerelease) {
        let ordering = match (left, right) {
            (SemverIdentifier::Numeric(left), SemverIdentifier::Numeric(right)) => left.cmp(right),
            (SemverIdentifier::Numeric(_), SemverIdentifier::Alpha(_)) => Ordering::Less,
            (SemverIdentifier::Alpha(_), SemverIdentifier::Numeric(_)) => Ordering::Greater,
            (SemverIdentifier::Alpha(left), SemverIdentifier::Alpha(right)) => left.cmp(right),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.prerelease.len().cmp(&right.prerelease.len())
}

pub(super) fn yarn_workspace_spec_matches(specifier: &str, version: &str) -> bool {
    let mut specifier = specifier.trim();
    let workspace_protocol = specifier.strip_prefix("workspace:");
    if let Some(protocol) = workspace_protocol {
        specifier = protocol;
        if matches!(specifier, "" | "*" | "^" | "~") {
            return true;
        }
    }
    if matches!(specifier, "*" | "latest") {
        return true;
    }
    let Some(candidate) = parse_semver(version, false) else {
        return false;
    };
    let (operator, requested) = if let Some(value) = specifier.strip_prefix('^') {
        ('^', value)
    } else if let Some(value) = specifier.strip_prefix('~') {
        ('~', value)
    } else {
        ('=', specifier)
    };
    let Some(requested) = parse_semver(requested, true) else {
        return false;
    };
    match operator {
        '=' => semver_cmp(&candidate, &requested) == std::cmp::Ordering::Equal,
        '~' => {
            semver_cmp(&candidate, &requested) != std::cmp::Ordering::Less
                && candidate.major == requested.major
                && candidate.minor == requested.minor
        }
        '^' if requested.major != 0 => {
            semver_cmp(&candidate, &requested) != std::cmp::Ordering::Less
                && candidate.major == requested.major
        }
        '^' if requested.minor != 0 => {
            semver_cmp(&candidate, &requested) != std::cmp::Ordering::Less
                && candidate.major == 0
                && candidate.minor == requested.minor
        }
        '^' => semver_cmp(&candidate, &requested) == std::cmp::Ordering::Equal,
        _ => false,
    }
}

/// Parse a Yarn classic v1 lockfile. The package.json is needed because Yarn
/// lock headers are selectors, not a root dependency graph.
pub fn plan_yarn(
    platform: Platform,
    lock: &str,
    package_json: &str,
    project_dir: &Path,
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
        let pinned_git = lock_git_source(&entry.resolved, entry.integrity.is_some());
        let git_detail = if pinned_git.is_some() {
            None
        } else if entry.integrity.is_some() {
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
        let external = if let Some(detail) = git_detail {
            Some(detail)
        } else if pinned_git.is_none() && !url.starts_with("https://") {
            Some(format!("non-https resolved URL {url}"))
        } else {
            None
        };
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

    let workspaces = yarn_workspace_manifests(&package, project_dir)?;
    let mut root_deps: Vec<RootDependency> =
        yarn_package_dependencies(&package, &selector_to_node, &workspaces, None)?
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
        for dependency in yarn_package_dependencies(
            &workspace.package,
            &selector_to_node,
            &workspaces,
            Some(&workspace.path),
        )? {
            workspace_roots.push(RootDependency {
                dependency,
                workspace: Some(workspace.path.clone()),
            });
        }
    }
    let graph = Graph {
        nodes,
        roots: root_deps,
        workspace_roots,
        workspace_paths: workspaces
            .iter()
            .map(|workspace| workspace.path.clone())
            .collect(),
        local_link_deps: BTreeMap::new(),
    };
    build_plan(platform, graph, "yarn.lock")
}

pub(super) fn yarn_package_dependencies(
    package: &JsonValue,
    selector_to_node: &BTreeMap<String, String>,
    workspaces: &[YarnWorkspace],
    _importer: Option<&str>,
) -> io::Result<Vec<Dependency>> {
    let mut deps = BTreeMap::<String, Dependency>::new();
    for (field, optional) in [
        ("dependencies", false),
        ("devDependencies", false),
        ("optionalDependencies", true),
    ] {
        let Some(map) = package[field].as_object() else {
            continue;
        };
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
                    let selector = format!("{name}@{spec}");
                    selector_to_node
                        .get(&selector)
                        .cloned()
                        .map(Target::Node)
                        .unwrap_or_else(|| {
                            Target::External(format!("missing yarn selector {selector}"))
                        })
                }
            } else if spec.starts_with("workspace:") {
                return Err(err(format!(
                    "Yarn workspace dependency {name}@{spec} has no matching workspace member"
                )));
            } else {
                let selector = format!("{name}@{spec}");
                selector_to_node
                    .get(&selector)
                    .cloned()
                    .map(Target::Node)
                    .unwrap_or_else(|| {
                        Target::External(format!("missing yarn selector {selector}"))
                    })
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
