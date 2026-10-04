//! What `pnpm-lock.yaml` records about the manifests it was generated
//! from (node tailor): each importer's dependencies, the settings and
//! overrides pnpm applies before comparing, and the workspace members
//! `pnpm-workspace.yaml` names. The freshness check reads these.

use super::*;

/// The directories pnpm's own package search skips (`DEFAULT_IGNORE` in
/// `@pnpm/fs.find-packages`), on top of a workspace's `!` globs.
const PNPM_DEFAULT_IGNORE: [&str; 4] = [
    "**/node_modules/**",
    "**/bower_components/**",
    "**/test/**",
    "**/tests/**",
];

/// The workspace members `pnpm-workspace.yaml` names, the root left out:
/// every directory holding a package.json that one of its `packages` globs
/// matches and no `!` glob, nor pnpm's default ignores, excludes. pnpm
/// applies the `!` globs as an ignore list, so their order does not matter.
/// No workspace file, or one without `packages`, is a single project.
pub(crate) fn pnpm_workspace_members(project: &ProjectRoot) -> io::Result<Vec<String>> {
    const FILE: &str = "pnpm-workspace.yaml";
    let Some(text) = project.read_input_string(Path::new(FILE))? else {
        return Ok(Vec::new());
    };
    if yaml_lines(&text, 0)?.is_empty() {
        return Ok(Vec::new());
    }
    let parsed = parse_yaml(&text).map_err(|error| err(format!("{FILE}: {error}")))?;
    let Some(packages) = yaml_map(&parsed, FILE)?.get("packages") else {
        return Ok(Vec::new());
    };
    let YamlValue::Seq(packages) = packages else {
        return Err(err(format!("{FILE}: packages must be a list")));
    };
    let (mut include, mut exclude) = (Vec::new(), PNPM_DEFAULT_IGNORE.map(String::from).to_vec());
    for package in packages {
        let raw = yaml_str(Some(package))
            .ok_or_else(|| err(format!("{FILE}: packages entries must be strings")))?;
        let negated = raw.starts_with('!');
        let pattern = raw.trim_start_matches('!').trim_start_matches("./");
        if pattern.starts_with('/') || pattern.split('/').any(|part| part == "..") {
            return Err(err(format!(
                "{FILE}: packages pattern {raw:?} escapes the project"
            )));
        }
        if negated { &mut exclude } else { &mut include }.push(pattern.to_string());
    }
    let mut candidates = Vec::new();
    collect_workspace_manifests(project, Path::new("."), &mut candidates)?;
    candidates.sort();
    candidates.dedup();
    let matches = |patterns: &[String], candidate: &str| {
        patterns
            .iter()
            .any(|pattern| workspace_glob_matches(pattern, candidate))
    };
    Ok(candidates
        .into_iter()
        .filter(|candidate| matches(&include, candidate) && !matches(&exclude, candidate))
        .collect())
}

/// A dependency as an importer of `pnpm-lock.yaml` records it: the
/// specifier its package.json wrote, verbatim, and the version pnpm resolved
/// it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PnpmLockedDependency {
    pub(crate) specifier: String,
    pub(crate) version: String,
}

/// What `pnpm-lock.yaml` records about the package.json files it was
/// generated from: each importer's dependency fields, and the settings and
/// overrides pnpm applies to a manifest before it compares one with the lock.
#[derive(Debug, Default)]
pub(crate) struct PnpmManifestRecord {
    /// importer path (`.` for the root) -> dependency field -> name -> entry.
    pub(crate) importers:
        BTreeMap<String, BTreeMap<&'static str, BTreeMap<String, PnpmLockedDependency>>>,
    pub(crate) auto_install_peers: bool,
    pub(crate) exclude_links: bool,
    pub(crate) overrides: BTreeMap<String, String>,
}

impl PnpmManifestRecord {
    /// Does an override the lock records rewrite the direct dependency
    /// `name`, which `package` (an importer's package.json) declares as
    /// `spec`, to `value`? pnpm applies overrides to each manifest before
    /// comparing it with the lock, so the importer holds the override's
    /// specifier, and an override of `-` removes the dependency altogether.
    ///
    /// The selector grammar is pnpm's `[parent[@range]>]name[@range]`. A
    /// ranged target applies only when `spec` is that range or a subrange of
    /// it (pnpm's `isSubRange`), and a parent applies only when it is the
    /// importer itself, by name and, if ranged, by version.
    pub(crate) fn overrides_to(
        &self,
        package: &JsonValue,
        name: &str,
        spec: &str,
        value: &str,
    ) -> bool {
        self.overrides.iter().any(|(selector, replacement)| {
            replacement == value && override_applies(selector, package, name, spec)
        })
    }
}

/// `name[@range]`, with the scope's leading `@` kept in the name.
fn name_and_range(text: &str) -> (&str, Option<&str>) {
    let at = match text.strip_prefix('@') {
        Some(rest) => rest.find('@').map(|index| index + 1),
        None => text.find('@'),
    };
    match at {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    }
}

/// Split `parent[@range]>target` the way pnpm's selector pattern does: the
/// `>` ends the parent right after its name, or after a non-empty range
/// that holds no `>`. So `a@>=1 <3` is a target alone, and in a deeper
/// chain (`a>b>name`) the target keeps its `>`, so it names no direct
/// dependency.
fn split_parent(selector: &str) -> (Option<&str>, &str) {
    let start = usize::from(selector.starts_with('@'));
    let Some(end) = selector[start..]
        .find(['@', '>'])
        .map(|index| start + index)
    else {
        return (None, selector);
    };
    let separator = if selector[end..].starts_with('>') {
        Some(end)
    } else {
        selector[end + 1..]
            .find('>')
            .filter(|&length| length > 0)
            .map(|length| end + 1 + length)
    };
    match separator {
        Some(at) => (Some(&selector[..at]), &selector[at + 1..]),
        None => (None, selector),
    }
}

fn override_applies(selector: &str, package: &JsonValue, name: &str, spec: &str) -> bool {
    let (parent, target) = split_parent(selector);
    let (target_name, target_range) = name_and_range(target);
    if target_name != name {
        return false;
    }
    let target_fits = match target_range {
        None => true,
        Some(range) => {
            range == spec
                || matches!(
                    (
                        crate::kernel::semver::Range::parse(spec),
                        crate::kernel::semver::Range::parse(range),
                    ),
                    (Ok(spec), Ok(range)) if spec.subset_of(&range)
                )
        }
    };
    let parent_fits = match parent {
        None => true,
        Some(parent) => {
            let (parent_name, parent_range) = name_and_range(parent);
            package["name"].as_str() == Some(parent_name)
                && parent_range.is_none_or(|range| {
                    crate::kernel::semver::Range::parse(range).is_ok_and(|range| {
                        package["version"]
                            .as_str()
                            .is_some_and(|version| range.satisfies_text(version))
                    })
                })
        }
    };
    target_fits && parent_fits
}

/// Read the manifest side of a pnpm lock. The effective document is the
/// last one, as for planning, and a single-project v6 lock without an
/// `importers` map records the root's dependencies at the top level.
pub(crate) fn pnpm_manifest_record(lock_yaml: &str) -> io::Result<PnpmManifestRecord> {
    let parsed = parse_yaml(lock_yaml)?;
    let root = yaml_map(&parsed, "pnpm-lock.yaml")?;
    let mut importers = importer_map(root)?;
    if !importers.contains_key(".") {
        importers.insert(".".to_string(), pnpm_legacy_root(root));
    }
    let mut record = PnpmManifestRecord::default();
    for (importer_name, importer) in importers {
        let mut fields = BTreeMap::new();
        for field in ["dependencies", "devDependencies", "optionalDependencies"] {
            let mut entries = BTreeMap::new();
            if let Some(value) = importer.get(field) {
                let map = yaml_map(value, &format!("importer {importer_name} {field}"))?;
                for (name, value) in map {
                    let item =
                        yaml_map(value, &format!("importer {importer_name} {field} {name}"))?;
                    entries.insert(
                        name.clone(),
                        PnpmLockedDependency {
                            specifier: yaml_str(item.get("specifier"))
                                .unwrap_or_default()
                                .to_string(),
                            version: yaml_str(item.get("version"))
                                .unwrap_or_default()
                                .to_string(),
                        },
                    );
                }
            }
            fields.insert(field, entries);
        }
        record.importers.insert(importer_name, fields);
    }
    if let Some(settings) = root.get("settings") {
        let settings = yaml_map(settings, "settings")?;
        record.auto_install_peers = yaml_bool(settings.get("autoInstallPeers"));
        record.exclude_links = yaml_bool(settings.get("excludeLinksFromLockfile"));
    }
    if let Some(overrides) = root.get("overrides") {
        for (selector, value) in yaml_map(overrides, "overrides")? {
            if let Some(value) = yaml_str(Some(value)) {
                record.overrides.insert(selector.clone(), value.to_string());
            }
        }
    }
    Ok(record)
}
