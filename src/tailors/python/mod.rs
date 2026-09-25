//! The Python tailor: CPython pin lookup and the tailor-facing wrappers
//! over `kernel::provider::cpython` (this file) and, in the sibling
//! modules, PyPI locking, wheel installs, manifest discovery, and sandboxed
//! sdist builds.

pub mod build;
pub(crate) mod build_requires;
pub mod env;
pub mod inputs;
pub mod manifest;
pub mod objects;
pub mod pep440;
pub mod pypi;
pub mod pyselect;
pub mod registry_tool;
pub mod run_refusal;
pub mod tailor;
pub mod wheel;

use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::toolchain::{LegacyEvidence, Selected};
#[cfg(test)]
use crate::kernel::types::Identity;
#[cfg(test)]
use crate::kernel::types::{ArtifactKind, LockedPackage, Plan};
#[cfg(test)]
use std::fs;
use std::io;
use std::path::PathBuf;

#[cfg(test)]
pub(crate) use crate::kernel::provider::cpython::uv_identity;
pub use crate::kernel::provider::cpython::{
    cpython_identity, cpython_identity_input, cpython_object_id, pythons, runtime_object_id,
    shipped_newest, shipped_selection, toolchain_catalog, uv_pins, PinnedPython, PinnedUv,
};

/// Realize the CPython this selection names (interpreter at
/// `<path>/bin/python3`); see `kernel::provider::cpython::realize_runtime`.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::provider::cpython::realize_runtime(store, activity, platform, selected)
}

/// Realize the uv this selection names (binary at `<obj>/uv`).
pub fn realize_uv(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::provider::cpython::realize_uv(store, activity, platform, selected)
}

/// Ensure the shipped uv is realized in the store (binary at <obj>/uv), for
/// work with no project selection to honor.
pub fn ensure_uv_for(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
) -> io::Result<PathBuf> {
    realize_uv(store, activity, platform, &shipped_newest()?)
}

pub fn lookup(platform: Platform, version: &str) -> Option<&'static PinnedPython> {
    lookup_in_pins(pythons().ok()?, platform, version)
}

/// Return the number of release components when `version` is written in the
/// canonical form accepted for CPython selection. Components are decimal and
/// cannot have leading zeroes; no suffixes, prefixes, or surrounding text are
/// accepted.
pub(crate) fn canonical_release_len(version: &str) -> Option<usize> {
    let pieces: Vec<_> = version.split('.').collect();
    if !(2..=3).contains(&pieces.len())
        || pieces.iter().any(|piece| {
            piece.is_empty()
                || (piece.len() > 1 && piece.starts_with('0'))
                || !piece.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    Some(pieces.len())
}

/// Match only a complete pinned version or a major.minor request. The slice
/// is supplied by the caller so matching remains independent of the table's
/// row order and can be tested with synthetic pin tables.
fn lookup_in_pins<'a>(
    pins: &'a [PinnedPython],
    platform: Platform,
    version: &str,
) -> Option<&'a PinnedPython> {
    let release_len = canonical_release_len(version)?;
    let requested = crate::tailors::python::pep440::Version::parse(version).ok()?;
    if requested.has_epoch() || requested.is_prerelease() || requested.has_local() {
        return None;
    }

    match release_len {
        3 => pins
            .iter()
            .find(|pin| pin.platform == platform && pin.version == version),
        2 => pins
            .iter()
            .filter(|pin| {
                pin.platform == platform
                    && parse_pinned_version(pin.version).is_some_and(|pinned| {
                        pinned.major() == requested.major() && pinned.minor() == requested.minor()
                    })
            })
            .max_by(|left, right| {
                parse_pinned_version(left.version)
                    .expect("pinned CPython version")
                    .cmp(&parse_pinned_version(right.version).expect("pinned CPython version"))
            }),
        _ => None,
    }
}

fn parse_pinned_version(version: &str) -> Option<crate::tailors::python::pep440::Version> {
    let parsed = crate::tailors::python::pep440::Version::parse(version).ok()?;
    (parsed.release_len() == 3
        && !parsed.has_epoch()
        && !parsed.is_prerelease()
        && !parsed.has_local())
    .then_some(parsed)
}

pub(crate) fn object_id_for(platform: Platform, version: &str) -> io::Result<String> {
    let pin =
        lookup(platform, version).ok_or_else(|| no_pin(&format!("cpython {version}"), platform))?;
    Ok(cpython_identity(pin).object_id())
}

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let cpython_pin = lookup(platform, "3.12.14").expect("pinned CPython for test platform");
    let cpython = cpython_identity(cpython_pin);
    let selected = shipped_selection(cpython_pin.version).expect("shipped CPython release");
    let uv = uv_identity(
        uv_pins()
            .unwrap()
            .iter()
            .find(|pin| pin.platform == platform)
            .expect("pinned uv for test platform"),
    );
    let fixture = crate::kernel::testutil::TempDir::named("python-identity");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        fs::create_dir_all(fixture.0.join(sub)).expect("Python identity fixture store");
    }
    let store = Store {
        root: fixture.0.clone(),
    };
    let activity = &store
        .activity(crate::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let empty_plan = Plan {
        ecosystem: "python".into(),
        python_version: cpython_pin.version.into(),
        packages: Vec::new(),
    };
    let wheel_plan = Plan {
        packages: vec![LockedPackage {
            name: "example".into(),
            version: "1.0.0".into(),
            filename: "example-1.0.0-py3-none-any.whl".into(),
            url: "https://files.pythonhosted.org/example.whl".into(),
            sha256: "a".repeat(64),
            kind: ArtifactKind::Wheel,
            git: None,
        }],
        ..empty_plan.clone()
    };
    let env_empty = env::environment_identity(
        &store,
        activity,
        platform,
        &empty_plan,
        &cpython.object_id(),
        &selected,
        None,
    )
    .expect("empty Python environment identity");
    let env_wheel = env::environment_identity(
        &store,
        activity,
        platform,
        &wheel_plan,
        &cpython.object_id(),
        &selected,
        None,
    )
    .expect("Python wheel environment identity");
    let mut cases = vec![cpython.clone(), uv, env_empty, env_wheel];
    if platform == Platform::X86_64UnknownLinuxGnu {
        let native_pkg = build::local_native_sdist_for_test(&store, "matrix-python-native");
        let native_plan = Plan {
            packages: vec![native_pkg],
            ..empty_plan.clone()
        };
        let env_native = env::environment_identity(
            &store,
            activity,
            platform,
            &native_plan,
            &cpython.object_id(),
            &selected,
            None,
        )
        .expect("Python native-sdist environment identity");
        cases.push(env_native);
        cases.push(
            crate::kernel::provider::nativelibs::live_identity_for_test(&store, platform)
                .expect("pinned native library identity"),
        );
    } else {
        // Native libraries are unsupported on Darwin, so the local native
        // sdist would take plan_sdist_identity_input's schema-2 fast path.
        // It is intentionally omitted here; the Darwin isolated-build matrix case
        // uses a Rust sdist whose Cargo.toml selects that path.
    }
    cases.extend(build::live_identity_cases(platform));
    cases
}

/// A pre-lock Python closure records the selected CPython version under
/// `python.version` (older closures: `plan.python_version`), and its
/// environment object under `env_object`, whose `cpython` input is the
/// interpreter object: the artifact that object was built from is the
/// proof.
pub fn legacy_toolchain_evidence(
    platform: Option<Platform>,
    body: &serde_json::Value,
    store: Option<&crate::kernel::store::Store>,
) -> LegacyEvidence {
    use crate::comforter::toolchain::{self as project_toolchain, LegacyRuntime};
    let mut evidence = crate::comforter::legacy_toolchain_evidence(
        platform,
        body,
        &[
            ("cpython", "/python/version"),
            ("cpython", "/plan/python_version"),
        ],
    );
    project_toolchain::prove_legacy_runtime(
        &mut evidence,
        store,
        body,
        LegacyRuntime {
            pointer: "/env_object",
            via: &[("python-env", "cpython")],
            kind: "cpython",
        },
        |identity, evidence| {
            project_toolchain::expect_legacy_version(
                identity,
                evidence,
                "cpython",
                &identity.version,
            )?;
            // A CPython identity carries no schema: its layout is the one
            // the catalog names `cpython/legacy`.
            Ok(vec![project_toolchain::proved_from_identity(
                identity,
                "cpython",
                "artifact_sha256",
                "sha256",
                crate::kernel::provider::cpython::CPYTHON_RECIPE,
            )?])
        },
    );
    evidence
}

/// The objects a pre-lock Python sync from `selected` left for legacy
/// seeding to read: the interpreter the producer builds and an environment
/// naming it, and the body field that names the environment.
#[cfg(test)]
pub(crate) fn legacy_runtime_for_test(
    platform: Platform,
    selected: &Selected,
    store: &Store,
) -> (serde_json::Value, Vec<Identity>) {
    use crate::kernel::provider::cpython::{cpython_identity_of, row, CPYTHON_RECIPE};
    let cpython = cpython_identity_of(
        &row(selected, platform, "cpython", CPYTHON_RECIPE).unwrap(),
        platform,
    )
    .unwrap();
    let env = Identity {
        kind: "python-env".into(),
        name: "env".into(),
        version: cpython.version.clone(),
        inputs: std::collections::BTreeMap::from([
            ("schema".to_string(), "python-env/3".to_string()),
            ("cpython".to_string(), cpython.object_id()),
        ]),
    };
    let body = serde_json::json!({"env_object": store.object_path(&env.object_id())});
    (body, vec![cpython, env])
}

pub fn preflight(platform: Platform, version: &str) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "CPython")?;
    lookup(platform, version)
        .map(|_| ())
        .ok_or_else(|| no_pin(&format!("cpython {version}"), platform))
}

/// Realize a pinned CPython for a caller that holds no selection: the
/// shipped catalog row for that pin's version.
pub fn ensure_python_for(
    store: &Store,
    activity: &StoreActivity,
    pin: &PinnedPython,
    platform: Platform,
) -> io::Result<PathBuf> {
    realize_runtime(store, activity, platform, &shipped_selection(pin.version)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit. If it does not, a migrated record stops
    /// matching what a re-sync publishes and every later cache hit becomes a
    /// hard error (`store::validate_cached_dependency_evidence`), which is
    /// what made a migrated store un-syncable in the rejected implementation.
    #[test]
    fn legacy_adapters_recover_the_pinned_cpython_and_uv_artifacts() {
        for platform in Platform::ALL {
            for pin in pythons()
                .unwrap()
                .iter()
                .filter(|pin| pin.platform == *platform)
            {
                let expected = vec![format!("sha256:{}", pin.sha256)];
                assert_eq!(recovered_cache(cpython_identity(pin)), expected);
            }
            for pin in uv_pins()
                .unwrap()
                .iter()
                .filter(|pin| pin.platform == *platform)
            {
                let expected = vec![format!("sha256:{}", pin.sha256)];
                assert_eq!(recovered_cache(uv_identity(pin)), expected);
            }
        }
    }

    fn recovered_cache(identity: crate::kernel::types::Identity) -> Vec<String> {
        match crate::kernel::objmeta::adapt_identity_for_test(identity, Vec::new()) {
            crate::kernel::objmeta::Adaptation::Proven(deps) => {
                assert!(
                    deps.objects.is_empty(),
                    "a pinned artifact has no object deps"
                );
                deps.cache
                    .iter()
                    .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                    .collect()
            }
            crate::kernel::objmeta::Adaptation::Unresolved(reason) => panic!("{reason}"),
        }
    }

    #[test]
    fn every_cpython_release_has_one_row_per_platform_and_the_default_uv() {
        let catalog = toolchain_catalog().unwrap();
        let uv_version = crate::kernel::provider::cpython::uv_version().unwrap();
        let mut python_keys = std::collections::HashSet::new();
        for &platform in Platform::ALL {
            let python_rows: Vec<_> = pythons()
                .unwrap()
                .iter()
                .filter(|pin| pin.platform == platform)
                .collect();
            assert_eq!(
                python_rows.len(),
                catalog.bundles().len(),
                "CPython rows for {platform:?}"
            );
            for pin in python_rows {
                assert!(
                    python_keys.insert((pin.platform, pin.version)),
                    "duplicate CPython pin for {platform:?}: {}",
                    pin.version
                );
            }
            let uv_rows: Vec<_> = uv_pins()
                .unwrap()
                .iter()
                .filter(|pin| pin.platform == platform)
                .collect();
            assert_eq!(uv_rows.len(), 1, "uv rows for {platform:?}");
        }
        // Every release carries the one pinned uv.
        for bundle in catalog.bundles() {
            assert_eq!(bundle.component("uv").unwrap().version, uv_version);
        }
        assert_eq!(uv_version, "0.12.7");
    }

    #[test]
    fn darwin_identity_unchanged() {
        // The goldens minted before the catalog grew: every one is still
        // shipped with the same bytes, among the newer patches around it.
        for (version, expected) in [
            (
                "3.12.14",
                "a1a7472f00bcc8e7432dcaf8e088192eab9ddb63-cpython-3.12.14",
            ),
            (
                "3.13.15",
                "3d4cd599c6aa947638318fba6a27cdf922d71e91-cpython-3.13.15",
            ),
            (
                "3.10.21",
                "2d325d7de98a5ef468887be7a900ba353393e6d4-cpython-3.10.21",
            ),
            (
                "3.11.16",
                "4f5f15e85142c23c54ceb171e28eed8e37868d58-cpython-3.11.16",
            ),
            (
                "3.14.7",
                "a08604ddc4f60d6a41bfde528123267824647022-cpython-3.14.7",
            ),
        ] {
            let pin = lookup(Platform::Aarch64AppleDarwin, version).unwrap();
            assert_eq!(cpython_identity(pin).object_id(), expected);
        }
        let uv = uv_pins()
            .unwrap()
            .iter()
            .find(|pin| pin.platform == Platform::Aarch64AppleDarwin)
            .expect("Darwin uv pin");
        let identity = uv_identity(uv);
        assert_eq!(
            identity.object_id(),
            "d43528ee22f3027d76f93b39716982e6cabcbe9f-uv-0.12.7"
        );
    }

    #[test]
    fn lookup_rejects_bare_major_and_accepts_minor_and_exact_versions() {
        for &platform in Platform::ALL {
            assert!(lookup(platform, "3").is_none());
            assert!(lookup(platform, "3.1").is_none());
            assert!(lookup(platform, "not-a-version").is_none());
            assert!(lookup(platform, "3.12.post1").is_none());
            assert!(lookup(platform, "3.12-dev").is_none());
            for invalid in [
                "03.12",
                "3.12.014",
                "3.9.25",
                "3.12.14.0",
                "v3.12",
                "3.12.14 ",
                "3.12.",
            ] {
                assert!(lookup(platform, invalid).is_none(), "{invalid}");
            }
            assert_eq!(lookup(platform, "3.12").unwrap().version, "3.12.14");
            assert_eq!(lookup(platform, "3.12.14").unwrap().version, "3.12.14");
        }
    }

    #[test]
    fn lookup_uses_the_newest_numeric_patch_in_a_wrongly_ordered_table() {
        let pins = [
            PinnedPython {
                platform: Platform::X86_64UnknownLinuxGnu,
                version: "3.12.9",
                url: "https://example.invalid/3.12.9.tar.gz",
                sha256: "9",
            },
            PinnedPython {
                platform: Platform::X86_64UnknownLinuxGnu,
                version: "3.12.14",
                url: "https://example.invalid/3.12.14.tar.gz",
                sha256: "14",
            },
        ];
        assert_eq!(
            lookup_in_pins(&pins, Platform::X86_64UnknownLinuxGnu, "3.12")
                .unwrap()
                .version,
            "3.12.14"
        );
        assert_eq!(
            lookup_in_pins(&pins, Platform::X86_64UnknownLinuxGnu, "3.12.9")
                .unwrap()
                .version,
            "3.12.9"
        );
        assert!(lookup_in_pins(&pins, Platform::Aarch64AppleDarwin, "3.12").is_none());
        assert!(lookup_in_pins(&pins, Platform::X86_64UnknownLinuxGnu, "3.12.3").is_none());
    }
}

#[cfg(test)]
mod toolchain_tests {
    use super::*;
    use crate::kernel::provider::cpython::{
        cpython_identity_of, row, uv_identity_of, CPYTHON_RECIPE, UV_RECIPE,
    };

    /// A selection whose CPython row names a layout this tog does not
    /// implement: the bytes it locked are not the bytes this code would
    /// produce, so realization refuses instead of guessing.
    fn with_recipe(platform: Platform, component: &str, recipe: &str) -> Selected {
        let mut selected = shipped_selection("3.12.14").expect("shipped CPython release");
        for row in &mut selected.bundle.artifacts {
            if row.component == component && row.platform == platform {
                row.recipe = recipe.to_string();
            }
        }
        selected
    }

    #[test]
    fn realization_refuses_an_unknown_recipe_and_another_ecosystem() {
        let store = Store {
            root: std::env::temp_dir().join("tog-python-recipe-refusal"),
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        // The row check is per platform; realization can only run for the
        // host, which `require_host` refuses first for the other one.
        for platform in Platform::ALL {
            let error = row(
                &with_recipe(*platform, "cpython", "cpython/2"),
                *platform,
                "cpython",
                CPYTHON_RECIPE,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("recipe cpython/2"), "{error}");
            assert!(error.contains("upgrade tog"), "{error}");
        }
        let platform = Platform::host().unwrap();
        let error = realize_runtime(
            &store,
            activity,
            platform,
            &with_recipe(platform, "cpython", "cpython/2"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("recipe cpython/2"), "{error}");
        assert!(error.contains("upgrade tog"), "{error}");
        let error = realize_uv(
            &store,
            activity,
            platform,
            &with_recipe(platform, "uv", "uv/2"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("recipe uv/2"), "{error}");

        let mut node = shipped_selection("3.12.14").unwrap();
        node.ecosystem = "node".into();
        let error = realize_runtime(&store, activity, platform, &node)
            .unwrap_err()
            .to_string();
        assert!(error.contains("a node toolchain"), "{error}");
        assert!(!store.root.exists(), "a refusal touched the store");
    }

    /// The row and the pin describe the same bytes, so the object a locked
    /// project realizes is the object every existing store already holds.
    #[test]
    fn an_identity_from_a_selected_row_equals_the_identity_from_the_pin() {
        for platform in Platform::ALL {
            for pin in pythons()
                .unwrap()
                .iter()
                .filter(|pin| pin.platform == *platform)
            {
                let selected = shipped_selection(pin.version).unwrap();
                let spec = row(&selected, *platform, "cpython", CPYTHON_RECIPE).unwrap();
                assert_eq!(
                    cpython_identity_of(&spec, *platform).unwrap().object_id(),
                    cpython_identity(pin).object_id(),
                    "cpython {} on {}",
                    pin.version,
                    platform.triple()
                );
                assert_eq!(
                    cpython_object_id(&selected, *platform).unwrap(),
                    cpython_identity(pin).object_id()
                );
                assert_eq!(
                    cpython_identity_input(&selected, *platform).unwrap(),
                    format!("{}:{}", pin.version, pin.sha256)
                );
            }
            for pin in uv_pins()
                .unwrap()
                .iter()
                .filter(|pin| pin.platform == *platform)
            {
                let selected = shipped_newest().unwrap();
                let spec = row(&selected, *platform, "uv", UV_RECIPE).unwrap();
                assert_eq!(
                    uv_identity_of(&spec, *platform).unwrap().object_id(),
                    uv_identity(pin).object_id(),
                    "uv on {}",
                    platform.triple()
                );
            }
        }
    }

    /// A lock naming a version this tog has no build for is refused by the
    /// planner, naming the file and the command that rewrites it.
    #[test]
    fn a_version_with_no_pinned_build_is_refused_by_the_planner() {
        let platform = Platform::host().unwrap();
        let error = pyselect::locked(platform, "3.9.1", &pyselect::PythonInputs::default())
            .unwrap_err()
            .to_string();
        assert!(error.contains("3.9.1"), "{error}");
        assert!(error.contains("tog-toolchain.toml"), "{error}");
        assert!(error.contains("tog update --toolchain python"), "{error}");
    }
}
