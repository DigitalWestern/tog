//! Importers for pnpm lockfiles and Yarn classic lockfiles.
//!
//! This is deliberately a small parser for the machine-written subsets used
//! here. It is not a general YAML implementation: anchors, aliases, folded
//! scalars, and arbitrary YAML tags are rejected. The graph is normalized to
//! the npm tailor's literal node_modules paths before realization.

use crate::fetch::Digest;
use crate::npm::{NpmLink, NpmPackage, NpmPatch, NpmPlan};
use crate::platform::Platform;
use serde_json::Value as JsonValue;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

fn err(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum YamlValue {
    Scalar(String),
    Map(BTreeMap<String, YamlValue>),
    Seq(Vec<YamlValue>),
}

#[derive(Debug, Clone)]
struct YamlLine {
    number: usize,
    indent: usize,
    text: String,
}

fn yaml_unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        serde_json::from_str(value).unwrap_or_else(|_| value[1..value.len() - 1].to_string())
    } else if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        value[1..value.len() - 1].replace("''", "'")
    } else {
        value.to_string()
    }
}

fn split_top_level(value: &str, separator: char) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    let chars: Vec<char> = value.chars().collect();
    for (i, ch) in chars.iter().enumerate() {
        match quote {
            Some('\'') if *ch == '\'' => {
                if chars.get(i + 1) == Some(&'\'') {
                    continue;
                }
                quote = None;
            }
            Some('"') if *ch == '"' => quote = None,
            Some(_) => {}
            None => match ch {
                '\'' | '"' => quote = Some(*ch),
                '[' | '{' | '(' => depth += 1,
                ']' | '}' | ')' => depth -= 1,
                c if *c == separator && depth == 0 => {
                    result.push(chars[start..i].iter().collect::<String>());
                    start = i + 1;
                }
                _ => {}
            },
        }
    }
    result.push(chars[start..].iter().collect());
    result
}

fn split_key_value(value: &str) -> Option<(String, String)> {
    let mut depth = 0i32;
    let mut quote = None;
    let mut at_scalar_start = true;
    let chars: Vec<char> = value.chars().collect();
    for (i, ch) in chars.iter().enumerate() {
        match quote {
            Some('\'') if *ch == '\'' => {
                if chars.get(i + 1) == Some(&'\'') {
                    continue;
                }
                quote = None;
            }
            Some('"') if *ch == '"' => quote = None,
            Some(_) => {}
            None => match ch {
                '\'' | '"' if at_scalar_start => {
                    quote = Some(*ch);
                    at_scalar_start = false;
                }
                '[' | '{' | '(' => {
                    depth += 1;
                    at_scalar_start = true;
                }
                ']' | '}' | ')' => {
                    depth -= 1;
                    at_scalar_start = false;
                }
                ',' => at_scalar_start = true,
                ':' if depth == 0 && (i + 1 == chars.len() || chars[i + 1].is_whitespace()) => {
                    return Some((
                        yaml_unquote(&chars[..i].iter().collect::<String>()),
                        chars[i + 1..].iter().collect::<String>().trim().to_string(),
                    ));
                }
                ':' => at_scalar_start = true,
                c if c.is_whitespace() => {}
                _ => at_scalar_start = false,
            },
        }
    }
    None
}

fn yaml_inline(value: &str, line: usize) -> io::Result<YamlValue> {
    let value = value.trim();
    if value.starts_with('[') && value.ends_with(']') {
        let inner = &value[1..value.len() - 1];
        return Ok(YamlValue::Seq(if inner.trim().is_empty() {
            Vec::new()
        } else {
            split_top_level(inner, ',')
                .into_iter()
                .map(|v| Ok(YamlValue::Scalar(yaml_unquote(&v))))
                .collect::<io::Result<Vec<_>>>()?
        }));
    }
    if value.starts_with('{') && value.ends_with('}') {
        let inner = &value[1..value.len() - 1];
        let mut map = BTreeMap::new();
        if !inner.trim().is_empty() {
            for item in split_top_level(inner, ',') {
                let (key, val) = split_key_value(&item)
                    .ok_or_else(|| err(format!("YAML line {line}: malformed inline map")))?;
                if map.insert(key.clone(), yaml_inline(&val, line)?).is_some() {
                    return Err(err(format!("YAML line {line}: duplicate key {key:?}")));
                }
            }
        }
        return Ok(YamlValue::Map(map));
    }
    if value == "" || value == "null" || value == "~" {
        return Ok(YamlValue::Scalar(String::new()));
    }
    Ok(YamlValue::Scalar(yaml_unquote(value)))
}

fn strip_yaml_comment(raw: &str) -> &str {
    let mut quote = None;
    for (i, ch) in raw.char_indices() {
        match quote {
            Some('\'') if ch == '\'' => quote = None,
            Some('"') if ch == '"' => quote = None,
            Some(_) => {}
            None if ch == '\'' || ch == '"' => quote = Some(ch),
            None if ch == '#' && (i == 0 || raw.as_bytes()[i - 1].is_ascii_whitespace()) => {
                return &raw[..i]
            }
            None => {}
        }
    }
    raw
}

fn yaml_lines(text: &str) -> io::Result<Vec<YamlLine>> {
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_yaml_comment(raw.trim_end_matches('\r'));
        if line.trim().is_empty() || line.trim() == "---" {
            continue;
        }
        let indent = line.chars().take_while(|c| *c == ' ').count();
        if indent % 2 != 0 || line[..indent].contains('\t') {
            return Err(err(format!(
                "YAML line {}: expected 2-space indentation",
                index + 1
            )));
        }
        lines.push(YamlLine {
            number: index + 1,
            indent,
            text: line[indent..].trim_end().to_string(),
        });
    }
    Ok(lines)
}

fn parse_yaml_block(lines: &[YamlLine], index: &mut usize, indent: usize) -> io::Result<YamlValue> {
    if *index >= lines.len() || lines[*index].indent != indent {
        return Err(err("YAML: missing block"));
    }
    let sequence = lines[*index].text == "-" || lines[*index].text.starts_with("- ");
    if sequence {
        let mut values = Vec::new();
        while *index < lines.len() && lines[*index].indent == indent {
            let line = &lines[*index];
            if !line.text.starts_with('-') {
                return Err(err(format!(
                    "YAML line {}: mixed map and list",
                    line.number
                )));
            }
            let rest = line.text[1..].trim();
            *index += 1;
            if rest.is_empty() {
                if *index < lines.len() && lines[*index].indent > indent {
                    values.push(parse_yaml_block(lines, index, lines[*index].indent)?);
                } else {
                    values.push(YamlValue::Scalar(String::new()));
                }
            } else if let Some((key, val)) = split_key_value(rest) {
                let mut map = BTreeMap::new();
                map.insert(key, yaml_inline(&val, line.number)?);
                if *index < lines.len() && lines[*index].indent > indent {
                    let child_indent = lines[*index].indent;
                    let child = parse_yaml_block(lines, index, child_indent)?;
                    let YamlValue::Map(child) = child else {
                        return Err(err(format!(
                            "YAML line {}: list map expected map",
                            line.number
                        )));
                    };
                    for (k, v) in child {
                        if map.insert(k.clone(), v).is_some() {
                            return Err(err(format!(
                                "YAML line {}: duplicate key {k:?}",
                                line.number
                            )));
                        }
                    }
                }
                values.push(YamlValue::Map(map));
            } else {
                values.push(yaml_inline(rest, line.number)?);
                if *index < lines.len() && lines[*index].indent > indent {
                    return Err(err(format!(
                        "YAML line {}: scalar list item cannot have children",
                        lines[*index].number
                    )));
                }
            }
        }
        return Ok(YamlValue::Seq(values));
    }

    let mut map = BTreeMap::new();
    while *index < lines.len() && lines[*index].indent == indent {
        let line = &lines[*index];
        if line.text.starts_with('-') {
            return Err(err(format!(
                "YAML line {}: mixed list and map",
                line.number
            )));
        }
        let (key, val) = split_key_value(&line.text)
            .ok_or_else(|| err(format!("YAML line {}: expected key: value", line.number)))?;
        *index += 1;
        let parsed = if val.is_empty() {
            if *index < lines.len() && lines[*index].indent > indent {
                parse_yaml_block(lines, index, lines[*index].indent)?
            } else {
                YamlValue::Scalar(String::new())
            }
        } else {
            yaml_inline(&val, line.number)?
        };
        if map.insert(key.clone(), parsed).is_some() {
            return Err(err(format!(
                "YAML line {}: duplicate key {key:?}",
                line.number
            )));
        }
    }
    Ok(YamlValue::Map(map))
}

fn parse_yaml(text: &str) -> io::Result<YamlValue> {
    let lines = yaml_lines(text)?;
    if lines.is_empty() {
        return Err(err("YAML lockfile is empty"));
    }
    let mut index = 0;
    let value = parse_yaml_block(&lines, &mut index, lines[0].indent)?;
    if index != lines.len() {
        return Err(err(format!(
            "YAML line {}: unexpected indentation",
            lines[index].number
        )));
    }
    Ok(value)
}

fn yaml_map<'a>(
    value: &'a YamlValue,
    context: &str,
) -> io::Result<&'a BTreeMap<String, YamlValue>> {
    match value {
        YamlValue::Map(map) => Ok(map),
        _ => Err(err(format!("{context} must be a map"))),
    }
}

fn yaml_str<'a>(value: Option<&'a YamlValue>) -> Option<&'a str> {
    match value {
        Some(YamlValue::Scalar(value)) => Some(value),
        _ => None,
    }
}

fn yaml_bool(value: Option<&YamlValue>) -> bool {
    yaml_str(value) == Some("true")
}

fn yaml_list(value: Option<&YamlValue>) -> Vec<String> {
    match value {
        Some(YamlValue::Seq(values)) => values
            .iter()
            .filter_map(|value| yaml_str(Some(value)).map(str::to_string))
            .collect(),
        Some(YamlValue::Scalar(value)) if !value.is_empty() => vec![value.to_string()],
        _ => Vec::new(),
    }
}

/// Every importer `pnpm-lock.yaml` enumerates, as paths relative to the lock
/// root (`.` is the root itself).
///
/// This is the authoritative membership list for a pnpm workspace: pnpm
/// produced it with its own glob engine, so consulting it settles membership
/// exactly rather than reimplementing that engine's syntax.
pub fn pnpm_lock_importers(lock_yaml: &str) -> io::Result<Vec<String>> {
    let parsed = parse_yaml(lock_yaml)?;
    let root = yaml_map(&parsed, "pnpm-lock.yaml")?;
    Ok(importer_map(root)?.into_keys().collect())
}

fn trim_peer_suffix(value: &str) -> &str {
    let parenthesis = value.find('(');
    // pnpm v9 also encodes peer context as `_peer@version`. An underscore
    // before the package/version separator is an ordinary npm package-name
    // character (for example `evp_bytestokey@1.0.3`) and is not a suffix.
    let underscore = {
        let delimiter = if value.starts_with('@') {
            value[1..].find('@').map(|index| index + 1)
        } else {
            value.find('@')
        };
        delimiter
            .and_then(|index| {
                value[index + 1..]
                    .find('_')
                    .map(|offset| index + 1 + offset)
            })
            .or_else(|| delimiter.is_none().then(|| value.find('_')).flatten())
    };
    [parenthesis, underscore]
        .into_iter()
        .flatten()
        .min()
        .map(|index| &value[..index])
        .unwrap_or(value)
}

fn split_identity(value: &str) -> Option<(String, String)> {
    let value = trim_peer_suffix(value.trim().trim_start_matches('/'));
    let at = if value.starts_with('@') {
        value[1..].find('@')? + 1
    } else {
        value.find('@')?
    };
    if at == 0 || at + 1 >= value.len() {
        return None;
    }
    Some((value[..at].to_string(), value[at + 1..].to_string()))
}

fn normalize_pnpm_identity(key: &str) -> Option<(String, String)> {
    if let Some(identity) = split_identity(key) {
        return Some(identity);
    }
    let value = key.trim().trim_start_matches('/');
    let slash = value.rfind('/')?;
    if slash == 0 || slash + 1 >= value.len() {
        return None;
    }
    Some((value[..slash].to_string(), value[slash + 1..].to_string()))
}

/// Normalize the spelling of a pnpm snapshot key once, while retaining its
/// peer suffix. Package metadata is keyed by the base identity below; the
/// graph is keyed by this full identity. pnpm v6 used `/name/version` and
/// `/name@version`, while newer lockfiles generally use `name@version`.
fn normalize_pnpm_snapshot_key(key: &str) -> Option<String> {
    let raw = key.trim().trim_start_matches('/');
    if raw.is_empty() {
        return None;
    }
    let (name, version) = if let Some((name, _version)) = split_identity(raw) {
        // split_identity deliberately strips peer suffixes, so recover the
        // exact version from the separator in the original spelling.
        let name_end = if raw.starts_with('@') {
            raw[1..].find('@').map(|index| index + 1)?
        } else {
            raw.find('@')?
        };
        (name, raw[name_end + 1..].to_string())
    } else {
        let slash = raw.rfind('/')?;
        if slash == 0 || slash + 1 >= raw.len() {
            return None;
        }
        (raw[..slash].to_string(), raw[slash + 1..].to_string())
    };
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some(format!("{name}@{version}"))
}

fn identity_key(name: &str, version: &str) -> String {
    format!("{name}@{}", trim_peer_suffix(version))
}

fn identity_key_for_snapshot(key: &str) -> String {
    normalize_pnpm_identity(key)
        .map(|(name, version)| identity_key(&name, &version))
        .unwrap_or_else(|| key.to_string())
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

fn patch_path(project_dir: &Path, raw: &str) -> io::Result<PathBuf> {
    let path = Path::new(raw);
    if raw.is_empty()
        || raw.starts_with('/')
        || raw.starts_with('~')
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(err(format!(
            "pnpm patch path {raw:?} must be a project-relative file"
        )));
    }
    let root = project_dir.canonicalize()?;
    let path = project_dir.join(path).canonicalize()?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(err(format!(
            "pnpm patch path {raw:?} is outside the project or is not a file"
        )));
    }
    Ok(path)
}

fn verify_patch_hash(package: &str, path: &Path, declared: &str) -> io::Result<()> {
    let bytes = fs::read(path)?;
    let actual = hex::encode(Sha256::digest(&bytes));
    let expected = declared.strip_prefix("sha256-").unwrap_or(declared);
    if expected.len() != 64
        || !expected.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !expected.eq_ignore_ascii_case(&actual)
    {
        return Err(err(format!(
            "pnpm patch {package} hash mismatch for {} (expected {declared}, got {actual})",
            path.display()
        )));
    }
    Ok(())
}

fn pnpm_patches(
    root: &BTreeMap<String, YamlValue>,
    project_dir: &Path,
) -> io::Result<Vec<(String, NpmPatch)>> {
    let Some(value) = root.get("patchedDependencies") else {
        return Ok(Vec::new());
    };
    let patches = yaml_map(value, "pnpm patchedDependencies")?;
    let mut result = Vec::new();
    for (package, value) in patches {
        // pnpm 9 writes the hash in the lockfile and uses the conventional
        // patches/<package>@<version>.patch path. Also accept the explicit
        // {path, hash} shape used by older/generated lockfile variants.
        let (raw_path, hash) = if let Some(hash) = yaml_str(Some(value)) {
            let escaped = format!("patches/{}.patch", package.replace('/', "__"));
            let conventional = format!("patches/{package}.patch");
            let raw_path = if project_dir.join(&escaped).is_file() {
                escaped
            } else {
                conventional
            };
            (raw_path, hash)
        } else {
            let entry = yaml_map(value, &format!("pnpm patch {package}"))?;
            let raw_path = yaml_str(entry.get("path"))
                .ok_or_else(|| err(format!("pnpm patch {package} has no string path")))?;
            let hash = yaml_str(entry.get("hash"))
                .ok_or_else(|| err(format!("pnpm patch {package} has no string sha256 hash")))?;
            (raw_path.to_string(), hash)
        };
        let path = patch_path(project_dir, &raw_path)?;
        verify_patch_hash(package, &path, hash)?;
        let identity = normalize_pnpm_snapshot_key(package).ok_or_else(|| {
            err(format!(
                "pnpm patch {package} has no package@version identity"
            ))
        })?;
        result.push((
            identity,
            NpmPatch {
                path: path.to_string_lossy().into_owned(),
                hash: hash.to_string(),
            },
        ));
    }
    Ok(result)
}

fn attach_pnpm_patches(
    nodes: &mut BTreeMap<String, Node>,
    patches: &[(String, NpmPatch)],
) -> io::Result<()> {
    let mut applied = BTreeSet::new();
    for node in nodes.values_mut() {
        let Some((identity, patch)) = patches.iter().find(|(identity, _)| {
            identity_key_for_snapshot(identity) == identity_key_for_snapshot(&node.key)
        }) else {
            continue;
        };
        node.patch = Some(patch.clone());
        applied.insert(identity);
    }
    if applied.len() != patches.len() {
        let missing = patches
            .iter()
            .filter(|(identity, _)| !applied.contains(identity))
            .map(|(identity, _)| identity)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err(err(format!(
            "pnpm patchedDependencies has no matching locked package: {missing}"
        )));
    }
    Ok(())
}

fn integrity_policy(path: &str, integrity: &str) -> io::Result<()> {
    let digest = Digest::from_sri(integrity)?;
    if digest.algo() == "sha1" {
        crate::policy::record(
            crate::policy::WEAK_INTEGRITY,
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
) -> Option<crate::gitsrc::GitSource> {
    let resolution = resolution?;
    if let (Some(repo), Some(commit)) = (
        yaml_str(resolution.get("repo")),
        yaml_str(resolution.get("commit")),
    ) {
        if crate::gitsrc::is_full_commit(commit) {
            return Some(crate::gitsrc::GitSource {
                url: crate::gitsrc::normalize_url(repo),
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
    crate::npm::explicit_git_source(tarball).or_else(|| {
        integrity
            .is_none()
            .then(|| crate::npm::git_source_from_url(tarball))
            .flatten()
    })
}

fn source_error(name: &str, resolution: Option<&BTreeMap<String, YamlValue>>) -> Option<String> {
    // A commit hash is a fingerprint: pinned git sources are realized (item 4).
    if pinned_git_source(resolution).is_some() {
        return None;
    }
    let resolution = resolution?;
    let kind = yaml_str(resolution.get("type")).unwrap_or_default();
    let repo = yaml_str(resolution.get("repo"));
    if kind == "git" || repo.is_some() {
        let repo = repo.unwrap_or("(unknown repository)");
        let commit = yaml_str(resolution.get("commit")).unwrap_or("unspecified commit");
        return Some(
            crate::npm::git_dependency_detail(name, &format!("git+{repo}#{commit}"))
                .unwrap_or_else(|| {
                    format!(
                        "npm_git_dep: {name}: repo {repo}, commit {commit}; \
                     git sources are deferred to NEXT.md item 4"
                    )
                }),
        );
    }
    let tarball = yaml_str(resolution.get("tarball")).unwrap_or_default();
    let has_integrity = yaml_str(resolution.get("integrity")).is_some();
    if !has_integrity {
        if let Some(detail) = crate::npm::git_dependency_detail(name, tarball) {
            return Some(detail);
        }
    }
    if tarball.starts_with("file:") || tarball.starts_with("link:") {
        return Some(format!("local dependency {tarball}"));
    }
    None
}

fn lock_git_source(url: &str, has_integrity: bool) -> Option<crate::gitsrc::GitSource> {
    crate::npm::explicit_git_source(url).or_else(|| {
        (!has_integrity)
            .then(|| crate::npm::git_source_from_url(url))
            .flatten()
    })
}

fn dep_version_key(
    name: &str,
    version: &str,
    snapshots: &BTreeMap<String, Node>,
) -> Option<String> {
    let version = version.trim();
    let direct = normalize_pnpm_snapshot_key(&format!("{name}@{version}"))
        .unwrap_or_else(|| format!("{name}@{version}"));
    if snapshots.contains_key(&direct) {
        return Some(direct);
    }
    let identity = identity_key(name, version);
    let candidates: Vec<String> = snapshots
        .keys()
        .filter(|key| identity_key_for_snapshot(key) == identity)
        .cloned()
        .collect();
    // A version-only edge is unambiguous only when the lockfile has one
    // snapshot for that package identity. If peer variants exist, choosing
    // one lexicographically is a wrong graph; pnpm normally writes the peer
    // suffix into the edge and the exact lookup above handles it.
    (candidates.len() == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

fn workspace_target(project_dir: &Path, importer: &str, raw: &str) -> io::Result<String> {
    // pnpm v6 collapses a workspace package's `file:../..` importer
    // reference to the synthetic `file:` package. That entry denotes the
    // project root, not an empty/unsafe path.
    if raw.is_empty() {
        return Ok(".".into());
    }
    if raw.starts_with('/') || raw.starts_with('~') {
        return Err(err(format!(
            "workspace link target {raw:?} is outside the project"
        )));
    }
    let mut relative = Vec::<String>::new();
    if importer != "." {
        for component in Path::new(importer).components() {
            if let Component::Normal(value) = component {
                relative.push(value.to_string_lossy().into_owned());
            }
        }
    }
    for component in Path::new(raw).components() {
        match component {
            Component::Normal(value) => relative.push(value.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                if relative.pop().is_none() {
                    return Err(err(format!(
                        "workspace link target {raw:?} is outside the project"
                    )));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(err(format!(
                    "workspace link target {raw:?} is outside the project"
                )))
            }
        }
    }
    let target = if relative.is_empty() {
        ".".to_string()
    } else {
        relative.join("/")
    };
    let root = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    let target_path = root.join(&target);
    if target_path.exists() {
        let canonical = target_path.canonicalize()?;
        if !canonical.starts_with(&root) {
            return Err(err(format!(
                "workspace link target {raw:?} is outside the project"
            )));
        }
    }
    Ok(target)
}

fn target_for_ref(
    name: &str,
    reference: &str,
    importer: &str,
    snapshots: &BTreeMap<String, Node>,
    project_dir: &Path,
) -> Target {
    let reference = reference.trim();
    let local_reference = reference
        .find("file:")
        .map(|index| &reference[index..])
        .or_else(|| reference.find("link:").map(|index| &reference[index..]))
        .or_else(|| reference.strip_prefix("link:").map(|_| reference));
    if let Some(local_reference) = local_reference {
        let raw = local_reference
            .split_once(':')
            .map(|(_, value)| value)
            .unwrap_or("");
        // pnpm v9 writes `file:` versions as project-relative paths even
        // when the importer is nested, while `link:` versions remain
        // importer-relative. Prefer the existing project-root target for the
        // former and retain the importer-relative fallback for older locks.
        let target = if local_reference.starts_with("file:") {
            workspace_target(project_dir, ".", raw)
                .ok()
                .filter(|target| project_dir.join(target).exists())
                .map(Ok)
                .unwrap_or_else(|| workspace_target(project_dir, importer, raw))
        } else {
            workspace_target(project_dir, importer, raw)
        };
        return match target {
            Ok(target) => Target::Link(target),
            Err(error) => Target::External(format!(
                "{error} (reference {reference:?}, importer {importer:?})"
            )),
        };
    }
    if reference.starts_with("workspace:") || reference.starts_with("catalog:") {
        return Target::External(format!("unresolved {reference} dependency for {name}"));
    }
    // pnpm represents npm aliases as logical-name: real-name@version. The
    // physical package is keyed by the real name, while placement still uses
    // the logical dependency name.
    if let Some(snapshot_key) = normalize_pnpm_snapshot_key(reference) {
        if snapshots.contains_key(&snapshot_key) {
            return Target::Node(snapshot_key);
        }
    }
    if let Some((real_name, real_version)) = split_identity(reference) {
        return match dep_version_key(&real_name, &real_version, snapshots) {
            Some(key) => Target::Node(key),
            None => Target::External(format!("missing snapshot for {name}@{reference}")),
        };
    }
    match dep_version_key(name, reference, snapshots) {
        Some(key) => Target::Node(key),
        None => Target::External(format!("missing snapshot for {name}@{reference}")),
    }
}

fn importer_dependencies(
    importer: &BTreeMap<String, YamlValue>,
    importer_name: &str,
    snapshots: &BTreeMap<String, Node>,
    project_dir: &Path,
    catalogs: &BTreeMap<String, BTreeMap<String, String>>,
    local_snapshots: &BTreeMap<String, Vec<Dependency>>,
    local_link_deps: &mut BTreeMap<String, Vec<Dependency>>,
) -> io::Result<Vec<Dependency>> {
    let mut deps = BTreeMap::<String, Dependency>::new();
    for (field, optional) in [
        ("dependencies", false),
        ("devDependencies", false),
        ("optionalDependencies", true),
    ] {
        let Some(value) = importer.get(field) else {
            continue;
        };
        let map = yaml_map(value, &format!("importer {importer_name} {field}"))?;
        for (name, value) in map {
            let item = yaml_map(value, &format!("importer {importer_name} {field} {name}"))?;
            let specifier = yaml_str(item.get("specifier")).unwrap_or_default();
            if let Some(catalog) = specifier.strip_prefix("catalog:") {
                let catalog_name = if catalog.is_empty() {
                    "default"
                } else {
                    catalog
                };
                if catalogs
                    .get(catalog_name)
                    .and_then(|catalog| catalog.get(name))
                    .is_none()
                {
                    return Err(err(format!(
                        "importer {importer_name} dependency {name}: catalog:{catalog} is not defined"
                    )));
                }
            }
            let version = yaml_str(item.get("version")).ok_or_else(|| {
                err(format!(
                    "importer {importer_name} dependency {name}: missing version"
                ))
            })?;
            let target = target_for_ref(name, version, importer_name, snapshots, project_dir);
            if let Target::Link(target_path) = &target {
                if let Some(dependencies) = local_snapshots.get(
                    &normalize_pnpm_snapshot_key(&format!("{name}@{version}")).unwrap_or_default(),
                ) {
                    local_link_deps
                        .entry(target_path.clone())
                        .or_insert_with(|| dependencies.clone());
                }
            }
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

fn pnpm_catalogs(
    root: &BTreeMap<String, YamlValue>,
) -> io::Result<BTreeMap<String, BTreeMap<String, String>>> {
    let mut catalogs = BTreeMap::new();
    let Some(value) = root.get("catalogs") else {
        return Ok(catalogs);
    };
    let map = yaml_map(value, "catalogs")?;
    for (name, value) in map {
        let entries = yaml_map(value, &format!("catalog {name}"))?;
        let mut catalog = BTreeMap::new();
        for (package, value) in entries {
            let selected = yaml_str(Some(value))
                .or_else(|| {
                    yaml_map(value, "")
                        .ok()
                        .and_then(|map| yaml_str(map.get("version")))
                })
                .unwrap_or_default()
                .to_string();
            catalog.insert(package.clone(), selected);
        }
        catalogs.insert(name.clone(), catalog);
    }
    Ok(catalogs)
}

fn snapshot_dependencies(
    snapshot: &BTreeMap<String, YamlValue>,
    snapshot_key: &str,
    lookup: &BTreeMap<String, Node>,
    project_dir: &Path,
) -> io::Result<Vec<Dependency>> {
    let mut deps = BTreeMap::<String, Dependency>::new();
    for (field, optional) in [("dependencies", false), ("optionalDependencies", true)] {
        if let Some(value) = snapshot.get(field) {
            let map = yaml_map(value, &format!("snapshot {snapshot_key} {field}"))?;
            for (name, value) in map {
                let reference = yaml_str(Some(value)).unwrap_or_default();
                deps.insert(
                    name.clone(),
                    Dependency {
                        name: name.clone(),
                        target: target_for_ref(name, reference, ".", lookup, project_dir),
                        optional,
                    },
                );
            }
        }
    }
    Ok(deps.into_values().collect())
}

fn is_local_snapshot(snapshot_key: &str) -> bool {
    normalize_pnpm_identity(snapshot_key)
        .map(|(_, version)| version.starts_with("file:") || version.starts_with("link:"))
        .unwrap_or(false)
}

fn local_snapshot_target(snapshot_key: &str, project_dir: &Path) -> io::Result<Option<String>> {
    let Some((_, version)) = normalize_pnpm_identity(snapshot_key) else {
        return Ok(None);
    };
    let Some(raw) = version
        .strip_prefix("file:")
        .or_else(|| version.strip_prefix("link:"))
    else {
        return Ok(None);
    };
    workspace_target(project_dir, ".", raw).map(Some)
}

fn pnpm_nodes(
    packages: &BTreeMap<String, YamlValue>,
    snapshots_value: Option<&YamlValue>,
    project_dir: &Path,
) -> io::Result<(BTreeMap<String, Node>, BTreeMap<String, Vec<Dependency>>)> {
    // Keep one metadata record per canonical package key. These records are
    // tarball facts only; they are never graph nodes until a snapshot selects
    // them. This prevents a v6 `/a@1` package entry from shadowing the real
    // dependency-bearing snapshot with an empty placeholder.
    let mut package_nodes = BTreeMap::<String, Node>::new();
    for (raw_key, value) in packages {
        let entry = yaml_map(value, &format!("packages {raw_key}"))?;
        let resolution = entry.get("resolution").and_then(|value| match value {
            YamlValue::Map(map) => Some(map),
            _ => None,
        });
        if yaml_str(resolution.and_then(|map| map.get("type"))) == Some("directory") {
            // pnpm 6 represents workspace source roots as a synthetic
            // packages entry such as 'file:'; importer edges become NpmLink.
            continue;
        }
        let Some(snapshot_key) = normalize_pnpm_snapshot_key(raw_key) else {
            return Err(err(format!(
                "packages entry {raw_key:?} has no name@version identity"
            )));
        };
        let Some((name, version)) = normalize_pnpm_identity(&snapshot_key) else {
            return Err(err(format!(
                "packages entry {raw_key:?} has no name@version identity"
            )));
        };
        let integrity = resolution
            .and_then(|resolution| yaml_str(resolution.get("integrity")))
            .unwrap_or_default()
            .to_string();
        let external = source_error(&name, resolution);
        // A pinned git source is recorded as a git+ URL so the package builder
        // (which parses it back) realizes the commit.
        let url = match pinned_git_source(resolution) {
            Some(source) => format!("git+{}#{}", source.url, source.commit),
            None => package_url(&name, &version, resolution).unwrap_or_default(),
        };
        if package_nodes
            .insert(
                snapshot_key.clone(),
                Node {
                    key: snapshot_key,
                    name,
                    version,
                    url,
                    integrity,
                    optional: yaml_bool(entry.get("optional")),
                    os: yaml_list(entry.get("os")),
                    cpu: yaml_list(entry.get("cpu")),
                    libc: yaml_list(entry.get("libc")),
                    external,
                    patch: None,
                    deps: Vec::new(),
                },
            )
            .is_some()
        {
            return Err(err(format!(
                "duplicate normalized pnpm package key {raw_key:?}"
            )));
        }
    }

    let mut snapshots = BTreeMap::<String, BTreeMap<String, YamlValue>>::new();
    if let Some(value) = snapshots_value {
        for (raw_key, value) in yaml_map(value, "snapshots")? {
            let snapshot_key = normalize_pnpm_snapshot_key(raw_key).ok_or_else(|| {
                err(format!(
                    "snapshots entry {raw_key:?} has no name@version identity"
                ))
            })?;
            if snapshots
                .insert(
                    snapshot_key,
                    yaml_map(value, &format!("snapshots {raw_key}"))?.clone(),
                )
                .is_some()
            {
                return Err(err(format!(
                    "duplicate normalized pnpm snapshot key {raw_key:?}"
                )));
            }
        }
    } else {
        // pnpm 6 stores dependency edges on the package entries. Normalize
        // those keys into the same full snapshot namespace before lookup.
        for (raw_key, value) in packages {
            let Some(snapshot_key) = normalize_pnpm_snapshot_key(raw_key) else {
                continue;
            };
            if package_nodes.contains_key(&snapshot_key) {
                snapshots.insert(
                    snapshot_key,
                    yaml_map(value, &format!("packages {raw_key}"))?.clone(),
                );
            }
        }
    }

    let snapshot_metadata: BTreeMap<String, Node> = snapshots
        .keys()
        .filter_map(|snapshot_key| {
            let base = identity_key_for_snapshot(snapshot_key);
            package_nodes
                .get(snapshot_key)
                .or_else(|| {
                    package_nodes
                        .values()
                        .find(|node| identity_key(&node.name, &node.version) == base)
                })
                .map(|node| {
                    let mut node = node.clone();
                    node.key = snapshot_key.clone();
                    (snapshot_key.clone(), node)
                })
        })
        .collect();

    if snapshots.is_empty() {
        // Some v9 lockfiles legitimately carry an empty snapshots map for a
        // graph with no package-to-package edges. The package entries are
        // then the complete set of real nodes, not metadata placeholders.
        return Ok((package_nodes, BTreeMap::new()));
    }

    let local_snapshots = snapshots
        .iter()
        .filter(|(snapshot_key, _)| is_local_snapshot(snapshot_key))
        .map(|(snapshot_key, snapshot)| {
            Ok((
                snapshot_key.clone(),
                snapshot_dependencies(snapshot, snapshot_key, &snapshot_metadata, project_dir)?,
            ))
        })
        .collect::<io::Result<BTreeMap<_, _>>>()?;
    let mut nodes = BTreeMap::new();
    for (snapshot_key, snapshot) in snapshots {
        let Some(mut node) = snapshot_metadata.get(&snapshot_key).cloned() else {
            if is_local_snapshot(&snapshot_key) {
                // Local file/link snapshots are workspace source projections,
                // not fetchable package nodes. Empty local snapshots are
                // represented by their importer Target::Link edges; their
                // dependency edges are retained in local_snapshots below.
                continue;
            }
            // A snapshot without package metadata cannot be fetched faithfully.
            return Err(err(format!(
                "pnpm snapshot {snapshot_key} has no matching packages metadata"
            )));
        };
        node.deps =
            snapshot_dependencies(&snapshot, &snapshot_key, &snapshot_metadata, project_dir)?;
        nodes.insert(snapshot_key, node);
    }
    Ok((nodes, local_snapshots))
}

fn importer_map(
    root: &BTreeMap<String, YamlValue>,
) -> io::Result<BTreeMap<String, BTreeMap<String, YamlValue>>> {
    let Some(value) = root.get("importers") else {
        return Ok(BTreeMap::new());
    };
    let map = yaml_map(value, "importers")?;
    map.iter()
        .map(|(key, value)| {
            Ok((
                key.clone(),
                yaml_map(value, &format!("importer {key}"))?.clone(),
            ))
        })
        .collect()
}

fn pnpm_legacy_root(root: &BTreeMap<String, YamlValue>) -> BTreeMap<String, YamlValue> {
    let mut importer = BTreeMap::new();
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(value) = root.get(field) {
            importer.insert(field.to_string(), value.clone());
        }
    }
    importer
}

/// Parse pnpm lockfile versions 9 and the compatible importer shape of v6.
pub fn plan_pnpm(platform: Platform, lock_yaml: &str, project_dir: &Path) -> io::Result<NpmPlan> {
    // pnpm can append a second document when a lock is merged from a
    // package-manager-generated prelude. The last document is the effective
    // lock graph.
    let lock_yaml = lock_yaml.rsplit("\n---").next().unwrap_or(lock_yaml);
    let parsed = parse_yaml(lock_yaml)?;
    let root = yaml_map(&parsed, "pnpm lockfile")?;
    let version = yaml_str(root.get("lockfileVersion")).unwrap_or_default();
    let version = version.trim_end_matches(".0");
    if version != "9" && version != "6" {
        return Err(err(format!(
            "unsupported pnpm lockfileVersion {:?} (item 7 supports 9.0 and 6.0)",
            yaml_str(root.get("lockfileVersion")).unwrap_or_default()
        )));
    }
    // A project with no dependencies has no `packages` map at all: pnpm writes
    // only `importers: { .: {} }`. That is an empty graph, not a broken lock.
    let empty_packages = BTreeMap::new();
    let packages = match root.get("packages") {
        Some(value) => yaml_map(value, "packages")?,
        None => &empty_packages,
    };
    let snapshots = root.get("snapshots");
    let patches = pnpm_patches(root, project_dir)?;
    let (mut nodes, local_snapshots) = pnpm_nodes(packages, snapshots, project_dir)?;
    attach_pnpm_patches(&mut nodes, &patches)?;
    let catalogs = pnpm_catalogs(root)?;
    let importers = importer_map(root)?;
    let root_importer = importers
        .get(".")
        .cloned()
        .unwrap_or_else(|| pnpm_legacy_root(root));
    let mut local_link_deps = BTreeMap::new();
    for (snapshot_key, dependencies) in &local_snapshots {
        if let Some(target) = local_snapshot_target(snapshot_key, project_dir)? {
            local_link_deps
                .entry(target)
                .or_insert_with(|| dependencies.clone());
        }
    }
    let mut roots = importer_dependencies(
        &root_importer,
        ".",
        &nodes,
        project_dir,
        &catalogs,
        &local_snapshots,
        &mut local_link_deps,
    )?
    .into_iter()
    .map(|dependency| RootDependency {
        dependency,
        workspace: None,
    })
    .collect::<Vec<_>>();
    let mut workspace_roots = Vec::new();
    let workspace_paths = importers
        .keys()
        .filter(|name| name.as_str() != ".")
        .cloned()
        .collect::<BTreeSet<_>>();
    for (importer_name, importer) in importers {
        if importer_name == "." {
            continue;
        }
        for dependency in importer_dependencies(
            &importer,
            &importer_name,
            &nodes,
            project_dir,
            &catalogs,
            &local_snapshots,
            &mut local_link_deps,
        )? {
            workspace_roots.push(RootDependency {
                dependency,
                workspace: Some(importer_name.clone()),
            });
        }
    }
    roots.sort_by(|a, b| a.dependency.name.cmp(&b.dependency.name));
    workspace_roots.sort_by(|a, b| {
        a.workspace
            .cmp(&b.workspace)
            .then_with(|| a.dependency.name.cmp(&b.dependency.name))
    });
    build_plan(
        platform,
        Graph {
            nodes,
            roots,
            workspace_roots,
            workspace_paths,
            local_link_deps,
        },
        "pnpm-lock.yaml",
    )
}

fn parse_yarn_header(header: &str, line: usize) -> io::Result<Vec<String>> {
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
struct YarnEntry {
    selectors: Vec<String>,
    name: String,
    version: String,
    resolved: String,
    integrity: Option<String>,
    dependencies: BTreeMap<String, String>,
    optional_dependencies: BTreeMap<String, String>,
}

fn selector_name(selector: &str) -> String {
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

fn parse_yarn_value(value: &str) -> String {
    yaml_unquote(value.trim())
}

fn split_yarn_field(value: &str) -> Option<(String, String)> {
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

fn parse_yarn_entries(lock: &str) -> io::Result<Vec<YarnEntry>> {
    let raw_lines: Vec<(usize, String)> = lock
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim_end_matches('\r').to_string()))
        .collect();
    for (line, text) in &raw_lines {
        let trimmed = text.trim();
        if trimmed.starts_with("__metadata:") || trimmed.starts_with("checksum:") {
            return Err(err(format!(
                "yarn berry lockfiles carry cache-zip checksums, not tarball hashes (item 7, line {line}); run npm install --package-lock-only or pnpm import"
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

fn base64_encode(bytes: &[u8]) -> String {
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

fn yarn_integrity(resolved: &str, integrity: Option<String>, path: &str) -> io::Result<String> {
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
struct YarnWorkspace {
    path: String,
    name: String,
    version: String,
    package: JsonValue,
}

fn workspace_segment_matches(pattern: &str, value: &str) -> bool {
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

fn workspace_glob_matches(pattern: &str, path: &str) -> bool {
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

fn collect_workspace_manifests(
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

fn yarn_workspace_manifests(
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
enum SemverIdentifier {
    Numeric(u64),
    Alpha(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Semver {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Vec<SemverIdentifier>,
}

fn parse_semver(value: &str, allow_partial: bool) -> Option<Semver> {
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

fn semver_cmp(left: &Semver, right: &Semver) -> std::cmp::Ordering {
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

fn yarn_workspace_spec_matches(specifier: &str, version: &str) -> bool {
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
            crate::npm::git_dependency_detail(&entry.name, &entry.resolved)
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

fn yarn_package_dependencies(
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

fn build_plan(platform: Platform, graph: Graph, lock_source: &str) -> io::Result<NpmPlan> {
    let workspace_paths = graph.workspace_paths.clone();
    let mut occupied = BTreeMap::<String, Occupied>::new();
    let mut queue = VecDeque::<(String, Dependency, Option<String>)>::new();
    let enqueue_roots = |roots: Vec<RootDependency>, queue: &mut VecDeque<_>| {
        for root in roots {
            let parent = root.workspace.clone().unwrap_or_default();
            queue.push_back((parent, root.dependency, root.workspace));
        }
    };
    enqueue_roots(graph.roots, &mut queue);
    let mut workspace_queue = VecDeque::new();
    enqueue_roots(graph.workspace_roots, &mut workspace_queue);
    let mut expanded = BTreeSet::<(String, String)>::new();
    let mut links = BTreeMap::<String, NpmLink>::new();

    while !queue.is_empty() || !workspace_queue.is_empty() {
        if queue.is_empty() {
            std::mem::swap(&mut queue, &mut workspace_queue);
        }
        let (parent, dependency, workspace) = queue.pop_front().unwrap();
        let in_workspace =
            workspace.is_some() || (!parent.is_empty() && !parent.starts_with("node_modules/"));
        let (path, should_expand) = match &dependency.target {
            Target::External(detail) => {
                if dependency.optional {
                    if detail.starts_with("npm_git_dep:") {
                        crate::policy::record(
                            crate::policy::GIT_DEPENDENCY,
                            &dependency.name,
                            detail,
                        )?;
                    }
                    continue;
                }
                return Err(err(format!("{}: {detail}", dependency.name)));
            }
            Target::Node(node_key) => {
                let node = graph.nodes.get(node_key).ok_or_else(|| {
                    err(format!(
                        "{}: missing graph node {node_key}",
                        dependency.name
                    ))
                })?;
                if !node_compatible(platform, node) {
                    if dependency.optional || node.optional {
                        // pnpm records every platform variant in one lockfile;
                        // incompatible optional packages are omitted.
                        continue;
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
                            crate::policy::record(
                                crate::policy::GIT_DEPENDENCY,
                                &node.name,
                                detail,
                            )?;
                        }
                        continue;
                    }
                    return Err(err(format!("{}@{}: {detail}", node.name, node.version)));
                }
                // A git source is verified by its commit, so it legitimately
                // has no tarball integrity (item 4).
                let node_git = lock_git_source(&node.url, !node.integrity.is_empty());
                if node.integrity.is_empty() && node_git.is_none() {
                    if dependency.optional || node.optional {
                        continue;
                    }
                    return Err(err(format!(
                        "{}@{}: pnpm package has no resolution.integrity",
                        node.name, node.version
                    )));
                }
                // Git sources carry `git:<commit>` instead of an SRI.
                if node_git.is_none() {
                    integrity_policy(&format!("{lock_source}/{node_key}"), &node.integrity)?;
                }
                let ancestor = existing_ancestor(
                    &parent,
                    &dependency.name,
                    &dependency.target,
                    &occupied,
                    &graph.nodes,
                    &workspace_paths,
                );
                if let Ok(Some(path)) = &ancestor {
                    (path.clone(), true)
                } else {
                    let blocked_by_nearer_conflict = ancestor.is_err();
                    let root = dependency_path("", &dependency.name);
                    let path = if let Some(existing) = occupied.get(&root) {
                        if !blocked_by_nearer_conflict
                            && same_target(existing, &dependency.target, &graph.nodes)
                        {
                            root
                        } else if in_workspace {
                            dependency_path(&parent, &dependency.name)
                        } else if parent.is_empty() {
                            return Err(err(format!(
                                "{}: root dependencies conflict between {} and {}",
                                dependency.name,
                                occupied_description(existing),
                                format!("{}@{}", node.name, node.version)
                            )));
                        } else {
                            dependency_path(&parent, &dependency.name)
                        }
                    } else {
                        root
                    };
                    if let Some(existing) = occupied.get(&path) {
                        if !same_target(existing, &dependency.target, &graph.nodes) {
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
                                node_key: node_key.clone(),
                                name: node.name.clone(),
                                version: node.version.clone(),
                            },
                        );
                    }
                    (path, true)
                }
            }
            Target::Link(target) => {
                let root = dependency_path("", &dependency.name);
                if let Some(existing) = occupied.get(&root) {
                    if same_target(existing, &dependency.target, &graph.nodes) {
                        (root, false)
                    } else if in_workspace {
                        let path = dependency_path(&parent, &dependency.name);
                        if let Some(existing) = occupied.get(&path) {
                            if !same_target(existing, &dependency.target, &graph.nodes) {
                                return Err(err(format!(
                                    "{}: two workspace versions conflict at {} ({} and link:{})",
                                    dependency.name,
                                    path,
                                    occupied_description(existing),
                                    target
                                )));
                            }
                        } else {
                            occupied.insert(
                                path.clone(),
                                Occupied::Link {
                                    target: target.clone(),
                                    name: dependency.name.clone(),
                                },
                            );
                            links.insert(
                                path.clone(),
                                NpmLink {
                                    path: path.clone(),
                                    target: target.clone(),
                                },
                            );
                        }
                        (path, false)
                    } else if parent.is_empty() {
                        return Err(err(format!(
                            "{}: workspace hoisting conflict between {} and link:{}",
                            dependency.name,
                            occupied_description(existing),
                            target
                        )));
                    } else {
                        let path = dependency_path(&parent, &dependency.name);
                        occupied.insert(
                            path.clone(),
                            Occupied::Link {
                                target: target.clone(),
                                name: dependency.name.clone(),
                            },
                        );
                        links.insert(
                            path.clone(),
                            NpmLink {
                                path: path.clone(),
                                target: target.clone(),
                            },
                        );
                        (path, false)
                    }
                } else {
                    let path = if in_workspace {
                        dependency_path(&parent, &dependency.name)
                    } else {
                        root.clone()
                    };
                    occupied.insert(
                        path.clone(),
                        Occupied::Link {
                            target: target.clone(),
                            name: dependency.name.clone(),
                        },
                    );
                    links.insert(
                        path.clone(),
                        NpmLink {
                            path: path.clone(),
                            target: target.clone(),
                        },
                    );
                    (path, false)
                }
            }
        };
        if should_expand {
            let Target::Node(node_key) = dependency.target else {
                continue;
            };
            if expanded.insert((path.clone(), node_key.clone())) {
                if let Some(node) = graph.nodes.get(&node_key) {
                    for child in &node.deps {
                        queue.push_back((path.clone(), child.clone(), None));
                    }
                }
            }
        } else if let Target::Link(target) = &dependency.target {
            if expanded.insert((path.clone(), format!("link:{target}"))) {
                if let Some(children) = graph.local_link_deps.get(target) {
                    for child in children {
                        queue.push_back((path.clone(), child.clone(), None));
                    }
                }
            }
        }
    }

    let mut packages = Vec::new();
    for (path, occupied) in occupied {
        crate::npm::validate_lock_path(&path)?;
        let Occupied::Package { node_key, .. } = occupied else {
            continue;
        };
        let node = graph
            .nodes
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
    for link in links.values() {
        crate::npm::validate_lock_path(&link.path)?;
    }
    Ok(NpmPlan {
        node_version: crate::npm::node_pin(platform)?.version.to_string(),
        packages,
        links: links.into_values().collect(),
        workspaces: workspace_paths.into_iter().collect(),
        lock_source: lock_source.to_string(),
    })
}

#[cfg(test)]
mod tests {

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
    use std::fs;
    use std::path::PathBuf;

    const SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

    fn project() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blanket-lock-import-{}-{nonce}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(path.join("packages/lib"));
        path
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
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
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
        assert!(plan
            .packages
            .iter()
            .any(|package| package.path == "node_modules/a"));
        assert!(plan.packages.iter().any(|package| package.name == "b"));
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
        assert!(plan.packages.is_empty(), "{:?}", plan.packages);
        assert!(plan.links.is_empty(), "{:?}", plan.links);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn patched_dependencies_are_verified_and_change_the_package_identity() {
        let dir = project();
        let patch_path = dir.join("patches/foo@1.0.0.patch");
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
        assert_eq!(
            plan.packages[0]
                .patch
                .as_ref()
                .map(|patch| patch.hash.as_str()),
            Some(hash.as_str())
        );
        fs::write(&patch_path, b"changed patch").unwrap();
        let error = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap_err();
        assert!(error.to_string().contains("patch foo@1.0.0 hash mismatch"));
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
        assert!(plan.links.iter().any(|link| link.target == "vendor/a"));
        assert!(plan
            .packages
            .iter()
            .any(|package| package.path == "node_modules/b" && package.name == "b"));
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
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
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
        assert!(plan.packages.iter().any(|package| {
            package.path == "node_modules/b/node_modules/d/node_modules/c"
                && package.version == "1.0.0"
        }));
        assert!(!plan
            .packages
            .iter()
            .any(|package| { package.path == "node_modules/c" && package.version == "2.0.0" }));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn pnpm_required_git_errors_but_optional_git_is_skipped() {
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
        let error = plan_pnpm(Platform::X86_64UnknownLinuxGnu, required, &dir).unwrap_err();
        assert!(error.to_string().contains("item 4"));

        let optional = required
            .replace("dependencies:", "optionalDependencies:")
            .replace("git-required:", "git-optional:");
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &optional, &dir).unwrap();
        assert!(plan.packages.is_empty());
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
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
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
        assert!(plan
            .packages
            .iter()
            .any(|package| package.path == "node_modules/shared" && package.version == "1.0.0"));
        assert!(plan.packages.iter().any(|package| {
            package.path == "packages/lib/node_modules/shared" && package.version == "2.0.0"
        }));
        let _ = fs::remove_dir_all(dir);
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
        let plan = plan_pnpm(Platform::X86_64UnknownLinuxGnu, &lock, &dir).unwrap();
        assert!(plan
            .packages
            .iter()
            .any(|package| { package.path == "p/node_modules/c" && package.version == "2.0.0" }));
        assert!(plan.packages.iter().any(|package| {
            package.path == "p/child/node_modules/c" && package.version == "1.0.0"
        }));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn yarn_v1_multi_key_sha1_and_berry_rejection() {
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
        let plan = plan_yarn(Platform::X86_64UnknownLinuxGnu, lock, package_json, &dir).unwrap();
        assert_eq!(plan.packages.len(), 2);
        assert!(plan
            .packages
            .iter()
            .all(|package| package.integrity.starts_with("sha1-")));
        let berry = "__metadata:\n  version: 6\n";
        let error =
            plan_yarn(Platform::X86_64UnknownLinuxGnu, berry, package_json, &dir).unwrap_err();
        assert!(error.to_string().contains("item 7"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn yarn_v1_workspace_manifests_supply_roots_and_links() {
        let dir = project();
        fs::write(
            dir.join("package.json"),
            r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"@fixture/lib":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("packages/lib/package.json"),
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
        let package = fs::read_to_string(dir.join("package.json")).unwrap();
        let plan = plan_yarn(Platform::X86_64UnknownLinuxGnu, &lock, &package, &dir).unwrap();
        assert!(plan.packages.iter().any(|package| package.name == "dep"));
        assert!(plan
            .links
            .iter()
            .any(|link| link.path == "node_modules/@fixture/lib" && link.target == "packages/lib"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn yarn_links_every_discovered_member_at_the_root() {
        let dir = project();
        fs::create_dir_all(dir.join("packages/a")).unwrap();
        fs::create_dir_all(dir.join("packages/b")).unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{"name":"root","version":"1.0.0","workspaces":["packages/*"]}"#,
        )
        .unwrap();
        fs::write(
            dir.join("packages/a/package.json"),
            r#"{"name":"workspace-a","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            dir.join("packages/b/package.json"),
            r#"{"name":"workspace-b","version":"1.0.0"}"#,
        )
        .unwrap();
        let package = fs::read_to_string(dir.join("package.json")).unwrap();
        let plan = plan_yarn(
            Platform::X86_64UnknownLinuxGnu,
            "# yarn lockfile v1\n",
            &package,
            &dir,
        )
        .unwrap();
        assert!(plan.links.iter().any(|link| {
            link.path == "node_modules/workspace-a" && link.target == "packages/a"
        }));
        assert!(plan.links.iter().any(|link| {
            link.path == "node_modules/workspace-b" && link.target == "packages/b"
        }));
        let _ = fs::remove_dir_all(dir);
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
        let error = plan_pnpm(Platform::Aarch64AppleDarwin, &lock, &dir).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("linux-only@1.0.0"));
        assert!(text.contains("aarch64-apple-darwin"));
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod git_import_tests {
    const SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

    fn project() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "blanket-lock-git-import-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
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
            crate::platform::Platform::X86_64UnknownLinuxGnu,
            &lock,
            &project,
        )
        .unwrap();
        let package = plan.packages.iter().find(|p| p.name == "plugin").unwrap();
        assert!(package.git.is_none());
        assert_eq!(package.integrity, SRI);
        let _ = crate::store::remove_tree(&project);
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
            crate::platform::Platform::X86_64UnknownLinuxGnu,
            &lock,
            r#"{"dependencies":{"plugin":"1.0.0"}}"#,
            &project,
        )
        .unwrap();
        let package = plan.packages.iter().find(|p| p.name == "plugin").unwrap();
        assert!(package.git.is_none());
        assert_eq!(package.integrity, SRI);
        let _ = crate::store::remove_tree(&project);
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
        let project = std::env::temp_dir().join(format!(
            "blanket-gitimport-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            r#"{"name":"root","version":"1.0.0"}"#,
        )
        .unwrap();
        let result = super::plan_pnpm(
            crate::platform::Platform::X86_64UnknownLinuxGnu,
            &lock,
            &project,
        );
        let _ = crate::store::remove_tree(&project);
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
