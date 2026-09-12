//! pnpm-lock.yaml import (node tailor): importers, snapshots, catalogs,
//! patches, and the graph they resolve to.

use super::*;

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

pub(super) fn trim_peer_suffix(value: &str) -> &str {
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

pub(super) fn split_identity(value: &str) -> Option<(String, String)> {
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

pub(super) fn normalize_pnpm_identity(key: &str) -> Option<(String, String)> {
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
pub(super) fn normalize_pnpm_snapshot_key(key: &str) -> Option<String> {
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

pub(super) fn identity_key_for_snapshot(key: &str) -> String {
    normalize_pnpm_identity(key)
        .map(|(name, version)| identity_key(&name, &version))
        .unwrap_or_else(|| key.to_string())
}

pub(super) fn patch_path(project_dir: &Path, raw: &str) -> io::Result<PathBuf> {
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

pub(super) fn verify_patch_hash(package: &str, path: &Path, declared: &str) -> io::Result<()> {
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

pub(super) fn pnpm_patches(
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

pub(super) fn attach_pnpm_patches(
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

pub(super) fn source_error(
    name: &str,
    resolution: Option<&BTreeMap<String, YamlValue>>,
) -> Option<String> {
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
            crate::tailors::node::git_dependency_detail(name, &format!("git+{repo}#{commit}"))
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
        if let Some(detail) = crate::tailors::node::git_dependency_detail(name, tarball) {
            return Some(detail);
        }
    }
    if tarball.starts_with("file:") || tarball.starts_with("link:") {
        return Some(format!("local dependency {tarball}"));
    }
    None
}

pub(super) fn dep_version_key(
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

pub(super) fn workspace_target(
    project_dir: &Path,
    importer: &str,
    raw: &str,
) -> io::Result<String> {
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

pub(super) fn target_for_ref(
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

pub(super) fn importer_dependencies(
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

pub(super) fn pnpm_catalogs(
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

pub(super) fn snapshot_dependencies(
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

pub(super) fn is_local_snapshot(snapshot_key: &str) -> bool {
    normalize_pnpm_identity(snapshot_key)
        .map(|(_, version)| version.starts_with("file:") || version.starts_with("link:"))
        .unwrap_or(false)
}

pub(super) fn local_snapshot_target(
    snapshot_key: &str,
    project_dir: &Path,
) -> io::Result<Option<String>> {
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

pub(super) fn pnpm_nodes(
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

pub(super) fn importer_map(
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

pub(super) fn pnpm_legacy_root(root: &BTreeMap<String, YamlValue>) -> BTreeMap<String, YamlValue> {
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
