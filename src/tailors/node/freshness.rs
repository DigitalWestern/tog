//! Whether a Node lock still matches the package.json files it was
//! generated from. A lock that lacks a dependency a manifest names plans a
//! closure without that package, so a disagreement is refused before
//! anything is planned, the way `npm ci`, `pnpm install --frozen-lockfile`
//! and `yarn install --frozen-lockfile` refuse it. No solver is needed:
//! each lock records what every manifest asked for.

use crate::kernel::fsroot::ProjectRoot;
use crate::tailors::node::{inputs, lock_import, NpmPlan};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

const FIELDS: [&str; 3] = ["dependencies", "devDependencies", "optionalDependencies"];

/// A lock format: its file name and the command that regenerates it.
pub(crate) struct LockFormat {
    lock: &'static str,
    regenerate: &'static str,
}

const NPM: LockFormat = LockFormat {
    lock: "package-lock.json",
    regenerate: "npm install --package-lock-only",
};
const PNPM: LockFormat = LockFormat {
    lock: "pnpm-lock.yaml",
    regenerate: "pnpm install --lockfile-only",
};
pub(crate) const YARN: LockFormat = LockFormat {
    lock: "yarn.lock",
    regenerate: "yarn install",
};

impl LockFormat {
    pub(crate) fn regenerate(&self) -> &'static str {
        self.regenerate
    }
}

/// One package.json a lock was generated from: its directory relative to
/// the project (`.` for the root) and its text, `None` when it is absent.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub dir: String,
    pub text: Option<String>,
}

/// The project-relative path of the package.json in `dir`.
pub(crate) fn manifest_path(dir: &str) -> String {
    if dir == "." || dir.is_empty() {
        "package.json".to_string()
    } else {
        format!("{dir}/package.json")
    }
}

/// Refuse a planned lock that disagrees with the project's package.json
/// files. Every manifest is read through the held descriptor; a read error
/// is fatal, since skipping the manifest would skip the check.
pub fn check_lock_freshness(project: &ProjectRoot, plan: &NpmPlan) -> io::Result<()> {
    match plan.lock_source.as_str() {
        "package-lock.json" => npm(
            &inputs::read_input(project, NPM.lock)?,
            &read_manifests(project, &plan.workspaces)?,
        ),
        "pnpm-lock.yaml" => {
            let lock = inputs::read_input(project, PNPM.lock)?;
            match lock_import::pnpm_workspace_members(project)? {
                Some(members) => pnpm_members(&lock, &members)?,
                None => crate::kernel::ui::note(
                    "pnpm-workspace.yaml: packages is not a list tog can read; \
                     not checking pnpm-lock.yaml for members added since it was generated",
                ),
            }
            pnpm(&lock, &read_manifests(project, &plan.workspaces)?)
        }
        // plan_yarn resolves every manifest's dependencies through the
        // lock's selectors and refuses a stale lock while planning, since
        // yarn.lock has no graph of its own to plan from; a yarn plan exists
        // only for a lock that matches.
        "yarn.lock" => Ok(()),
        other => Err(io::Error::other(format!(
            "internal: no freshness check for lock source {other}"
        ))),
    }
}

/// The root package.json and each workspace member's.
fn read_manifests(project: &ProjectRoot, workspaces: &[String]) -> io::Result<Vec<Manifest>> {
    std::iter::once(".")
        .chain(workspaces.iter().map(String::as_str))
        .map(|dir| {
            Ok(Manifest {
                dir: dir.to_string(),
                text: project.read_input_string(Path::new(&manifest_path(dir)))?,
            })
        })
        .collect()
}

/// The refusal for a manifest whose `field` disagrees with the lock.
pub(crate) fn stale(manifest: &str, field: &str, format: &LockFormat) -> io::Error {
    crate::kernel::error::stale(
        io::ErrorKind::InvalidData,
        format!(
            "{manifest} {field} disagree with {}; regenerate the lock ({})",
            format.lock, format.regenerate
        ),
    )
}

/// The refusal for a manifest the lock was generated from that is gone.
fn missing(manifest: &str, format: &LockFormat) -> io::Error {
    crate::kernel::error::stale(
        io::ErrorKind::InvalidData,
        format!(
            "{manifest} is missing but {} lists it; regenerate the lock ({})",
            format.lock, format.regenerate
        ),
    )
}

fn parse_manifest(
    path: &str,
    manifest: Option<&Manifest>,
    format: &LockFormat,
) -> io::Result<Value> {
    let text = manifest
        .and_then(|manifest| manifest.text.as_deref())
        .ok_or_else(|| missing(path, format))?;
    serde_json::from_str(text)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, format!("{path}: {error}")))
}

/// package-lock.json records each manifest's dependency maps verbatim: the
/// root's under `packages[""]`, a workspace member's under its directory.
pub fn npm(lock: &str, manifests: &[Manifest]) -> io::Result<()> {
    let lock: Value = serde_json::from_str(lock).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package-lock.json: {error}"),
        )
    })?;
    for manifest in manifests {
        let path = manifest_path(&manifest.dir);
        let package = parse_manifest(&path, Some(manifest), &NPM)?;
        let key = if manifest.dir == "." {
            ""
        } else {
            manifest.dir.as_str()
        };
        let entry = &lock["packages"][key];
        for field in FIELDS {
            let declared = package[field].as_object().cloned().unwrap_or_default();
            let locked = entry[field].as_object().cloned().unwrap_or_default();
            if declared != locked {
                return Err(stale(&path, field, &NPM));
            }
        }
    }
    Ok(())
}

/// A manifest's dependency map for `field` as name -> specifier.
fn string_map(path: &str, package: &Value, field: &str) -> io::Result<BTreeMap<String, String>> {
    let Some(value) = package.get(field) else {
        return Ok(BTreeMap::new());
    };
    let Some(map) = value.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{path}: {field} must be an object"),
        ));
    };
    map.iter()
        .map(|(name, spec)| {
            let spec = spec.as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{path}: {field} {name}: specifier must be a string"),
                )
            })?;
            Ok((name.clone(), spec.to_string()))
        })
        .collect()
}

/// pnpm writes an importer for every workspace member, even one with no
/// dependencies, so a member `pnpm-workspace.yaml` names without one was
/// added after the lock was generated and its dependencies are missing.
pub fn pnpm_members(lock: &str, members: &[String]) -> io::Result<()> {
    let record = lock_import::pnpm_manifest_record(lock)?;
    match members
        .iter()
        .find(|member| !record.importers.contains_key(*member))
    {
        Some(member) => Err(crate::kernel::error::stale(
            io::ErrorKind::InvalidData,
            format!(
                "{} is a pnpm workspace member but {} has no importer for it; regenerate the lock ({})",
                manifest_path(member),
                PNPM.lock,
                PNPM.regenerate
            ),
        )),
        None => Ok(()),
    }
}

/// pnpm-lock.yaml has one importer per manifest, and each dependency under
/// an importer carries `specifier`, the manifest's own string. The
/// comparison follows pnpm's own: a name in several fields counts in the
/// most specific one (optional over dependencies over devDependencies),
/// `autoInstallPeers` adds undeclared peers to dependencies,
/// `excludeLinksFromLockfile` leaves `link:` dependencies out, and a
/// recorded override stands in for the manifest's specifier.
pub fn pnpm(lock: &str, manifests: &[Manifest]) -> io::Result<()> {
    let record = lock_import::pnpm_manifest_record(lock)?;
    for (importer, locked) in &record.importers {
        let path = manifest_path(importer);
        let manifest = manifests.iter().find(|manifest| manifest.dir == *importer);
        let package = parse_manifest(&path, manifest, &PNPM)?;
        let optional = string_map(&path, &package, "optionalDependencies")?;
        let mut dependencies = string_map(&path, &package, "dependencies")?;
        dependencies.retain(|name, _| !optional.contains_key(name));
        let mut dev = string_map(&path, &package, "devDependencies")?;
        dev.retain(|name, _| !optional.contains_key(name) && !dependencies.contains_key(name));
        if record.auto_install_peers {
            for (name, spec) in string_map(&path, &package, "peerDependencies")? {
                if !optional.contains_key(&name) && !dev.contains_key(&name) {
                    dependencies.entry(name).or_insert(spec);
                }
            }
        }
        for (field, mut declared) in [
            ("dependencies", dependencies),
            ("devDependencies", dev),
            ("optionalDependencies", optional),
        ] {
            if record.exclude_links {
                declared.retain(|_, spec| !spec.starts_with("link:"));
            }
            let entries = &locked[field];
            for (name, spec) in &declared {
                let fresh = match entries.get(name) {
                    Some(entry) => {
                        entry.specifier == *spec
                            || record.overrides_to(&package, name, spec, &entry.specifier)
                    }
                    None => record.overrides_to(&package, name, spec, "-"),
                };
                if !fresh {
                    return Err(stale(&path, field, &PNPM));
                }
            }
            // A linked dependency recorded without a specifier is pnpm's own
            // addition, not something a manifest asked for.
            let extra = entries.iter().any(|(name, entry)| {
                !declared.contains_key(name)
                    && !(entry.specifier.is_empty() && entry.version.starts_with("link:"))
            });
            if extra {
                return Err(stale(&path, field, &PNPM));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(text: &str) -> Manifest {
        member(".", text)
    }

    fn member(dir: &str, text: &str) -> Manifest {
        Manifest {
            dir: dir.to_string(),
            text: Some(text.to_string()),
        }
    }

    fn message(result: io::Result<()>) -> String {
        result.unwrap_err().to_string()
    }

    const NPM_STALE: &str = "package.json dependencies disagree with package-lock.json; \
                             regenerate the lock (npm install --package-lock-only)";

    #[test]
    fn npm_refuses_an_added_changed_or_removed_dependency() {
        let lock = r#"{"packages":{"":{"dependencies":{"a":"^1.0.0","b":"2.0.0"}}}}"#;
        npm(
            lock,
            &[root(r#"{"dependencies":{"a":"^1.0.0","b":"2.0.0"}}"#)],
        )
        .unwrap();
        for package in [
            r#"{"dependencies":{"a":"^1.0.0","b":"2.0.0","c":"1.0.0"}}"#,
            r#"{"dependencies":{"a":"^1.1.0","b":"2.0.0"}}"#,
            r#"{"dependencies":{"a":"^1.0.0"}}"#,
        ] {
            assert_eq!(message(npm(lock, &[root(package)])), NPM_STALE, "{package}");
        }
        let dev = message(npm(
            lock,
            &[root(
                r#"{"dependencies":{"a":"^1.0.0","b":"2.0.0"},"devDependencies":{"t":"1"}}"#,
            )],
        ));
        assert!(
            dev.starts_with("package.json devDependencies disagree with package-lock.json"),
            "{dev}"
        );
    }

    #[test]
    fn npm_checks_each_workspace_member_against_its_own_entry() {
        let lock = r#"{"packages":{
            "":{"workspaces":["packages/lib"]},
            "packages/lib":{"dependencies":{"a":"1.0.0"}}}}"#;
        let package = r#"{"workspaces":["packages/lib"]}"#;
        npm(
            lock,
            &[
                root(package),
                member("packages/lib", r#"{"dependencies":{"a":"1.0.0"}}"#),
            ],
        )
        .unwrap();
        let error = message(npm(
            lock,
            &[
                root(package),
                member("packages/lib", r#"{"dependencies":{"a":"1.0.0","b":"1"}}"#),
            ],
        ));
        assert_eq!(
            error,
            "packages/lib/package.json dependencies disagree with package-lock.json; \
             regenerate the lock (npm install --package-lock-only)"
        );
        let gone = Manifest {
            dir: "packages/lib".into(),
            text: None,
        };
        assert_eq!(
            message(npm(lock, &[root(package), gone])),
            "packages/lib/package.json is missing but package-lock.json lists it; \
             regenerate the lock (npm install --package-lock-only)"
        );
    }

    #[test]
    fn a_malformed_manifest_is_an_error_naming_it() {
        let lock = r#"{"packages":{"":{},"packages/lib":{}}}"#;
        let error = message(npm(lock, &[root("{ nope")]));
        assert!(error.starts_with("package.json: "), "{error}");
        let error = message(npm(lock, &[root("{}"), member("packages/lib", "[")]));
        assert!(error.starts_with("packages/lib/package.json: "), "{error}");

        let pnpm_lock = "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/lib: {}\n";
        let error = message(pnpm(pnpm_lock, &[root("{ nope")]));
        assert!(error.starts_with("package.json: "), "{error}");
        let error = message(pnpm(pnpm_lock, &[root("{}"), member("packages/lib", "[")]));
        assert!(error.starts_with("packages/lib/package.json: "), "{error}");
        let error = message(pnpm(
            pnpm_lock,
            &[
                root(r#"{"dependencies":{"a":1}}"#),
                member("packages/lib", "{}"),
            ],
        ));
        assert_eq!(
            error,
            "package.json: dependencies a: specifier must be a string"
        );
    }

    const PNPM_LOCK: &str = "\
lockfileVersion: '9.0'

settings:
  autoInstallPeers: false
  excludeLinksFromLockfile: false

importers:
  .:
    dependencies:
      '@fixture/lib':
        specifier: workspace:*
        version: link:packages/lib
      react:
        specifier: 'catalog:'
        version: 18.3.1
    devDependencies:
      is-odd:
        specifier: ^3.0.0
        version: 3.0.1
  packages/lib:
    dependencies:
      is-number:
        specifier: 7.0.0
        version: 7.0.0
";

    const PNPM_ROOT: &str = r#"{"dependencies":{"@fixture/lib":"workspace:*","react":"catalog:"},
        "devDependencies":{"is-odd":"^3.0.0"}}"#;
    const PNPM_LIB: &str = r#"{"name":"@fixture/lib","dependencies":{"is-number":"7.0.0"}}"#;

    fn pnpm_stale(manifest: &str, field: &str) -> String {
        format!(
            "{manifest} {field} disagree with pnpm-lock.yaml; \
             regenerate the lock (pnpm install --lockfile-only)"
        )
    }

    #[test]
    fn pnpm_compares_every_importer_specifier_verbatim() {
        pnpm(
            PNPM_LOCK,
            &[root(PNPM_ROOT), member("packages/lib", PNPM_LIB)],
        )
        .unwrap();
        for package in [
            // added
            r#"{"dependencies":{"@fixture/lib":"workspace:*","react":"catalog:","left-pad":"^1.3.0"},
                "devDependencies":{"is-odd":"^3.0.0"}}"#,
            // changed: a catalog reference is a specifier like any other
            r#"{"dependencies":{"@fixture/lib":"workspace:*","react":"catalog:react18"},
                "devDependencies":{"is-odd":"^3.0.0"}}"#,
            // removed
            r#"{"dependencies":{"react":"catalog:"},"devDependencies":{"is-odd":"^3.0.0"}}"#,
        ] {
            assert_eq!(
                message(pnpm(
                    PNPM_LOCK,
                    &[root(package), member("packages/lib", PNPM_LIB)]
                )),
                pnpm_stale("package.json", "dependencies"),
                "{package}"
            );
        }
        let moved = r#"{"dependencies":{"@fixture/lib":"workspace:*","react":"catalog:","is-odd":"^3.0.0"}}"#;
        assert_eq!(
            message(pnpm(
                PNPM_LOCK,
                &[root(moved), member("packages/lib", PNPM_LIB)]
            )),
            pnpm_stale("package.json", "dependencies")
        );
        let edited = r#"{"dependencies":{"is-number":"7.0.0","left-pad":"^1.3.0"}}"#;
        assert_eq!(
            message(pnpm(
                PNPM_LOCK,
                &[root(PNPM_ROOT), member("packages/lib", edited)]
            )),
            pnpm_stale("packages/lib/package.json", "dependencies")
        );
        assert_eq!(
            message(pnpm(PNPM_LOCK, &[root(PNPM_ROOT)])),
            "packages/lib/package.json is missing but pnpm-lock.yaml lists it; \
             regenerate the lock (pnpm install --lockfile-only)"
        );
    }

    /// pnpm reads a name listed in several fields from the most specific one,
    /// so a manifest that lists it twice still matches a lock that records it
    /// once.
    #[test]
    fn pnpm_counts_a_duplicated_name_in_its_most_specific_field() {
        let lock = "\
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0
    optionalDependencies:
      b:
        specifier: ^2.0.0
        version: 2.0.0
";
        pnpm(
            lock,
            &[root(
                r#"{"dependencies":{"a":"^1.0.0","b":"^2.0.0"},
                    "devDependencies":{"a":"^1.0.0"},
                    "optionalDependencies":{"b":"^2.0.0"}}"#,
            )],
        )
        .unwrap();
    }

    #[test]
    fn pnpm_applies_the_settings_and_overrides_the_lock_records() {
        let lock = "\
lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: true
overrides:
  a: 1.2.3
  gone: '-'
importers:
  .:
    dependencies:
      a:
        specifier: 1.2.3
        version: 1.2.3
      peer:
        specifier: ^4.0.0
        version: 4.1.0
";
        let package = r#"{"dependencies":{"a":"^1.0.0","gone":"^1.0.0","local":"link:../x"},
            "peerDependencies":{"peer":"^4.0.0"}}"#;
        pnpm(lock, &[root(package)]).unwrap();
        let without_settings = lock.replace("true", "false");
        assert_eq!(
            message(pnpm(&without_settings, &[root(package)])),
            pnpm_stale("package.json", "dependencies")
        );
    }

    /// A single-project v6 lock records the root's dependencies at the top
    /// level rather than under `importers`.
    #[test]
    fn pnpm_reads_a_v6_lock_without_importers() {
        let lock = "\
lockfileVersion: '6.0'
dependencies:
  a:
    specifier: ^1.0.0
    version: 1.0.0
";
        pnpm(lock, &[root(r#"{"dependencies":{"a":"^1.0.0"}}"#)]).unwrap();
        assert_eq!(
            message(pnpm(lock, &[root(r#"{"dependencies":{"a":"^1.1.0"}}"#)])),
            pnpm_stale("package.json", "dependencies")
        );
    }

    #[test]
    fn pnpm_overrides_apply_only_to_the_range_and_parent_they_select() {
        let lock = |selector: &str| {
            format!(
                "lockfileVersion: '9.0'\noverrides:\n  '{selector}': 1.2.3\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: 1.2.3\n        version: 1.2.3\n"
            )
        };
        let package = |spec: &str| {
            root(&format!(
                r#"{{"name":"app","version":"2.0.0","dependencies":{{"a":"{spec}"}}}}"#
            ))
        };
        for (selector, spec) in [
            ("a", "^9.0.0"),
            ("a@^1", "^1.0.0"),
            ("a@^1", "1.4.0"),
            ("a@>=1 <3", "^2.1.0"),
            ("app>a", "^1.0.0"),
            ("app@2>a@^1", "^1.1.0"),
        ] {
            pnpm(&lock(selector), &[package(spec)])
                .unwrap_or_else(|error| panic!("{selector} over {spec}: {error}"));
        }
        for (selector, spec) in [
            ("a@^1", "^2.0.0"),
            ("a@^1", "*"),
            ("a@^1", "latest"),
            ("b", "^1.0.0"),
            ("other>a", "^1.0.0"),
            ("app@^3>a", "^1.0.0"),
            ("x>app>a", "^1.0.0"),
        ] {
            assert_eq!(
                message(pnpm(&lock(selector), &[package(spec)])),
                pnpm_stale("package.json", "dependencies"),
                "{selector} over {spec}"
            );
        }
    }

    #[test]
    fn pnpm_refuses_a_workspace_member_without_an_importer() {
        let scratch = crate::kernel::testutil::TempDir::named("pnpm-members");
        let dir = &scratch.0;
        for member in [
            "packages/lib",
            "packages/new",
            "packages/skip",
            "packages/lib/test",
            "examples/demo",
        ] {
            std::fs::create_dir_all(dir.join(member)).unwrap();
            std::fs::write(dir.join(member).join("package.json"), "{}").unwrap();
        }
        let project = ProjectRoot::open(dir).unwrap();
        let members = || {
            lock_import::pnpm_workspace_members(&project)
                .unwrap()
                .unwrap()
        };
        assert!(members().is_empty(), "no workspace file is one project");
        std::fs::write(
            dir.join("pnpm-workspace.yaml"),
            "# members\npackages:\n  - '!packages/skip'\n  - ./packages/**\n",
        )
        .unwrap();
        assert_eq!(members(), ["packages/lib", "packages/new"]);
        let lock = "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/lib: {}\n";
        assert_eq!(
            message(pnpm_members(lock, &members())),
            "packages/new/package.json is a pnpm workspace member but pnpm-lock.yaml has no importer for it; regenerate the lock (pnpm install --lockfile-only)"
        );
        let regenerated = format!("{lock}  packages/new: {{}}\n");
        pnpm_members(&regenerated, &members()).unwrap();
        std::fs::write(dir.join("pnpm-workspace.yaml"), "packages:\n  - ../out\n").unwrap();
        let error = lock_import::pnpm_workspace_members(&project).unwrap_err();
        assert!(error.to_string().contains("escapes the project"), "{error}");
        std::fs::write(dir.join("pnpm-workspace.yaml"), "catalog:\n  a: ^1.0.0\n").unwrap();
        assert!(members().is_empty(), "settings alone name no members");
    }

    #[test]
    fn the_pnpm_freshness_check_refuses_a_new_member_and_skips_an_unread_packages_value() {
        let scratch = crate::kernel::testutil::TempDir::named("pnpm-fresh-members");
        let dir = &scratch.0;
        for member in ["packages/lib", "packages/new"] {
            std::fs::create_dir_all(dir.join(member)).unwrap();
            std::fs::write(dir.join(member).join("package.json"), "{}").unwrap();
        }
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        std::fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/lib: {}\n",
        )
        .unwrap();
        let plan = NpmPlan {
            node_version: "22.0.0".into(),
            packages: Vec::new(),
            links: Vec::new(),
            workspaces: vec!["packages/lib".into()],
            lock_source: "pnpm-lock.yaml".into(),
        };
        let project = ProjectRoot::open(dir).unwrap();
        let check = || check_lock_freshness(&project, &plan);
        check().unwrap();
        std::fs::write(
            dir.join("pnpm-workspace.yaml"),
            "packages:\n- packages/*\ncatalog: &shared\n  a: ^1\n",
        )
        .unwrap();
        assert_eq!(
            message(check()),
            "packages/new/package.json is a pnpm workspace member but pnpm-lock.yaml has no importer for it; regenerate the lock (pnpm install --lockfile-only)"
        );
        std::fs::write(
            dir.join("pnpm-workspace.yaml"),
            "packages: &all\n  - packages/*\n",
        )
        .unwrap();
        check().unwrap();
    }
}
