//! What `pnpm-lock.yaml` records about the manifests it was generated
//! from (node tailor): each importer's dependencies, the settings and
//! overrides pnpm applies before comparing, and the workspace members
//! `pnpm-workspace.yaml` names. The freshness check reads these.

use super::*;

mod workspace;
pub(crate) use workspace::*;

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

/// Split `parent[@range]>target` where pnpm's selector pattern does: at
/// the first `>` that follows a character other than a space, `|` or `@`
/// (`/[^ |@]>/`), so the `>` of a range (`a@>=1`, `a@^1 >b`) never splits
/// it, and `a@>=1 <2>b` is parent `a@>=1 <2`, target `b`. In a deeper chain
/// (`a>b>name`) the target keeps its `>`, so it names no direct dependency.
fn split_parent(selector: &str) -> (Option<&str>, &str) {
    let bytes = selector.as_bytes();
    match (1..bytes.len())
        .find(|&at| bytes[at] == b'>' && !matches!(bytes[at - 1], b' ' | b'|' | b'@'))
    {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parent_ends_at_the_first_gt_after_a_name_or_range_character() {
        for (selector, parent, target) in [
            ("a@>=1 <2>b", Some("a@>=1 <2"), "b"),
            ("a@^1 >b", None, "a@^1 >b"),
            ("a@>=1 <3", None, "a@>=1 <3"),
            ("a@1 || >2", None, "a@1 || >2"),
            ("@s/a@2>@s/b@^1", Some("@s/a@2"), "@s/b@^1"),
            ("x>app>a", Some("x"), "app>a"),
        ] {
            assert_eq!(split_parent(selector), (parent, target), "{selector}");
        }
    }
}
