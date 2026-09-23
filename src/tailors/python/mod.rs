//! The Python tailor: the pinned CPython toolchain (this file) and, in the
//! sibling modules, PyPI locking, wheel installs, manifest discovery, and
//! sandboxed sdist builds.

pub mod artifacts;
pub mod build;
pub(crate) mod build_requires;
pub mod env;
pub mod inputs;
pub mod manifest;
pub mod nativelibs;
pub mod objects;
pub mod pep440;
pub mod pypi;
pub mod pyselect;
pub mod registry_tool;
pub mod tailor;
pub mod wheel;

use crate::kernel::fetch::{download_verified_held, Digest};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::toolchain::{
    ArtifactRow, ArtifactSpec, Bundle, Catalog, Component, LegacyEvidence, Request, Selected,
    Source, Version, VersionRequest,
};
use crate::kernel::types::Identity;
#[cfg(test)]
use crate::kernel::types::{ArtifactKind, LockedPackage, Plan};
use std::collections::BTreeMap;
#[cfg(test)]
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

/// Pinned CPython builds from astral-sh/python-build-standalone (release
/// 20260825, per-platform rows, install_only). Checksums verified at pin
/// time (trust-on-first-use; a signed provider manifest replaces this table
/// post-MVP).
#[derive(Debug)]
pub struct PinnedPython {
    pub platform: Platform,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const PYTHONS: &[PinnedPython] = &[
    // Keep the existing Darwin rows byte-for-byte and append new rows after
    // them; their object ids are compatibility goldens.
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.12.14",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.12.14%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "62eef3fcf48fa4f792d0d6d267c140b81aaea0edca4ae0641d8021854314f966",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.13.15",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.13.15%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "d681f7cebf4885637242cba807d22f476b9ea8555ac2dc7307172426dbf161e1",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.10.21",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.10.21%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "7fedf2035ce497b0ce01643cc5e8ed2aabfb8cfa730440e97af0330b56ce0608",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.11.16",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.11.16%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "2e50ed6ec49d8714a83c093e9ce74e1b8b21a2c64a49c3b603471d9c4caac76b",
    },
    PinnedPython {
        platform: Platform::Aarch64AppleDarwin,
        version: "3.14.7",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.14.7%2B20260825-aarch64-apple-darwin-install_only.tar.gz",
        sha256: "4c4a4114bc35f9d76d194fd72f43d8375b2f30686ddfe6b40c9258cfe6c16e40",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.12.14",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.12.14%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "cbdd2f0cf02f941bc5c81e546f377275e322733abffe805ac29d2b7e8a58f7e3",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.13.15",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.13.15%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "8a70011ae25276a9925f89304cdc086466cd269ee6cfe68a9506694ca5ff4f9c",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.10.21",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.10.21%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "b3cfb164a81b8fb16125cc7703689a6181e06983db3220a1765da68ebe430aff",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.11.16",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.11.16%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "25844eb97cdc72cdc78addaad0969ce3b2133a4de54bfcfa4d57f8a6d095eaab",
    },
    PinnedPython {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "3.14.7",
        url: "https://github.com/astral-sh/python-build-standalone/releases/download/20260825/cpython-3.14.7%2B20260825-x86_64-unknown-linux-gnu-install_only.tar.gz",
        sha256: "d68dfa9c5d37afec0a4c8ffbf5c20d05d34492bd4561c94d7c3c7578e21a7f71",
    },
];

pub fn lookup(platform: Platform, version: &str) -> Option<&'static PinnedPython> {
    lookup_in_pins(PYTHONS, platform, version)
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

/// The store object id of the CPython a selection names, from the
/// selection's own row and without realizing it: the same id
/// `realize_runtime` commits, so a cache key that carries it names the
/// interpreter the environment will run on rather than the one a version
/// number would find in today's pin table.
pub fn runtime_object_id(platform: Platform, selected: &Selected) -> io::Result<String> {
    let spec = row(selected, platform, "cpython", CPYTHON_RECIPE)?;
    Ok(cpython_identity_of(&spec, platform)?.object_id())
}

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let cpython_pin = lookup(platform, "3.12.14").expect("pinned CPython for test platform");
    let cpython = cpython_identity(cpython_pin);
    let selected = shipped_selection(cpython_pin.version).expect("shipped CPython release");
    let uv = uv_identity(
        UV.iter()
            .find(|pin| pin.platform == platform)
            .expect("pinned uv for test platform"),
    );
    let root = std::env::temp_dir().join(format!(
        "tog-python-identity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        fs::create_dir_all(root.join(sub)).expect("Python identity fixture store");
    }
    let store = Store {
        root: root
            .canonicalize()
            .expect("canonical Python identity fixture store"),
    };
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
        platform,
        &empty_plan,
        &cpython.object_id(),
        &selected,
    )
    .expect("empty Python environment identity");
    let env_wheel = env::environment_identity(
        &store,
        platform,
        &wheel_plan,
        &cpython.object_id(),
        &selected,
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
            platform,
            &native_plan,
            &cpython.object_id(),
            &selected,
        )
        .expect("Python native-sdist environment identity");
        cases.push(env_native);
        cases.push(
            nativelibs::live_identity_for_test(&store, platform)
                .expect("pinned native library identity"),
        );
    } else {
        // Native libraries are unsupported on Darwin, so the local native
        // sdist would take plan_sdist_identity_input's schema-2 fast path.
        // It is intentionally omitted here; the Darwin isolated-build matrix case
        // uses a Rust sdist whose Cargo.toml selects that path.
    }
    cases.extend(build::live_identity_cases(platform));
    let _ = crate::kernel::store::remove_tree(&store.root);
    cases
}

/// The python-build-standalone release every CPython row is taken from.
const CPYTHON_BUILD: &str = "20260825";

/// The shipped Python catalog: one release bundle per pinned CPython
/// version, each carrying the pinned uv, so a lock minted from it names the
/// resolver too. Rows carry the pin's URL and digest unchanged; the recipe
/// ids name the layouts the existing identities already commit to.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    // Catalog order is pin-table order: the newest-appended row wins a tie.
    let mut versions: Vec<&str> = Vec::new();
    for version in PYTHONS.iter().map(|pin| pin.version) {
        if !versions.contains(&version) {
            versions.push(version);
        }
    }
    let mut bundles = Vec::new();
    for version in versions {
        let mut artifacts = Vec::new();
        for pin in PYTHONS.iter().filter(|pin| pin.version == version) {
            artifacts.push(ArtifactRow::new(
                pin.platform,
                "cpython",
                "python-build-standalone",
                CPYTHON_BUILD,
                "cpython/legacy",
                pin.url,
                Digest::sha256(pin.sha256)?,
            ));
        }
        for pin in UV {
            artifacts.push(ArtifactRow::new(
                pin.platform,
                "uv",
                "uv",
                UV_VERSION,
                "uv/legacy",
                pin.url,
                Digest::sha256(pin.sha256)?,
            ));
        }
        bundles.push(Bundle {
            release: format!("cpython-{version}"),
            revision: None,
            primary: vec!["cpython".into()],
            components: vec![
                Component::new("cpython", version),
                Component::new("uv", UV_VERSION),
            ],
            artifacts,
        });
    }
    // An unconstrained project keeps the shipped default; a range that the
    // default satisfies keeps it too. Only an explicit request moves it.
    let default = crate::kernel::toolchain::Request::exact("cpython", pyselect::DEFAULT_VERSION)?;
    Ok(Catalog::new("python", bundles)?.with_preference(default))
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
                CPYTHON_RECIPE,
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
    let cpython = cpython_identity_of(
        &row(selected, platform, "cpython", CPYTHON_RECIPE).unwrap(),
        platform,
    )
    .unwrap();
    let env = Identity {
        kind: "python-env".into(),
        name: "env".into(),
        version: cpython.version.clone(),
        inputs: BTreeMap::from([
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

/// Pinned uv (resolver delegation target). Single static binary per platform;
/// realized like any toolchain so a bare machine needs nothing besides
/// tog.
const UV_VERSION: &str = "0.12.7";
pub(crate) struct PinnedUv {
    pub platform: Platform,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub(crate) const UV: &[PinnedUv] = &[
    PinnedUv {
        platform: Platform::Aarch64AppleDarwin,
        url: "https://github.com/astral-sh/uv/releases/download/0.12.7/uv-aarch64-apple-darwin.tar.gz",
        sha256: "127ebdda7ad953cdf198e964b570ea5771b85467ea93eb7cb6d6f8e6f55408f3",
    },
    PinnedUv {
        platform: Platform::X86_64UnknownLinuxGnu,
        url: "https://github.com/astral-sh/uv/releases/download/0.12.7/uv-x86_64-unknown-linux-gnu.tar.gz",
        sha256: "788f18abea7c5f55d6216e4f5613fd89d4d59b631efeec117b2b07fe72f1da21",
    },
];

/// The recipe ids this tailor knows how to lay out. A lock row naming
/// anything else was written by a tog that extracts or relocates these
/// artifacts differently, so the bytes it locked are not the bytes this
/// code would produce.
const CPYTHON_RECIPE: &str = "cpython/legacy";
const UV_RECIPE: &str = "uv/legacy";

fn not_python(selected: &Selected) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "python: asked to realize a {} toolchain",
            selected.ecosystem
        ),
    )
}

/// One component's row from the selection, checked against the layout this
/// tailor implements.
fn row(
    selected: &Selected,
    platform: Platform,
    component: &str,
    recipe: &str,
) -> io::Result<ArtifactSpec> {
    if selected.ecosystem != "python" {
        return Err(not_python(selected));
    }
    let spec = selected.artifact(platform, component)?;
    if spec.recipe != recipe {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "python: recipe {} in tog-toolchain.toml is not known to this tog; upgrade tog",
                spec.recipe
            ),
        ));
    }
    Ok(spec)
}

/// The shipped catalog's selection for one CPython version, exact
/// (`3.12.14`) or by line (`3.12`). For work with no project lock to
/// honor: `x` outside a project, a nested build environment, node-gyp's
/// interpreter, and tests.
pub fn shipped_selection(version: &str) -> io::Result<Selected> {
    let catalog = toolchain_catalog()?;
    let parsed = Version::parse(version)?;
    let request = Request::newest().with(
        "cpython",
        if parsed.parts().len() >= 3 {
            VersionRequest::Exact(parsed)
        } else {
            VersionRequest::Prefix(parsed)
        },
    );
    Ok(Selected {
        ecosystem: "python".into(),
        bundle: catalog.select(&request)?.clone(),
        lock_sha256: None,
        source: Source::Shipped,
    })
}

/// The shipped catalog's newest complete release.
pub fn shipped_newest() -> io::Result<Selected> {
    crate::kernel::toolchain::shipped(&toolchain_catalog()?)
}

/// The CPython row's `<version>:<artifact sha256>`, the `python` input
/// every sdist-build identity carries.
pub(crate) fn cpython_identity_input(
    selected: &Selected,
    platform: Platform,
) -> io::Result<String> {
    let spec = row(selected, platform, "cpython", CPYTHON_RECIPE)?;
    Ok(format!("{}:{}", spec.version, artifact_sha256(&spec)?))
}

/// The object id this selection's CPython realizes to, without realizing
/// it. Planning uses it; realization returns the same id.
pub(crate) fn cpython_object_id(selected: &Selected, platform: Platform) -> io::Result<String> {
    let spec = row(selected, platform, "cpython", CPYTHON_RECIPE)?;
    Ok(cpython_identity_of(&spec, platform)?.object_id())
}

/// The sha256 an artifact row names, refused when the row names another
/// algorithm: CPython and uv are published as sha256 and the identity input
/// is that bare hex.
fn artifact_sha256(spec: &ArtifactSpec) -> io::Result<&str> {
    if spec.digest.algo() != "sha256" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} {}: tog realizes this component from a sha256 digest, not {}",
                spec.component,
                spec.version,
                spec.digest.algo()
            ),
        ));
    }
    Ok(spec.digest.hex())
}

/// The CPython object identity, from the row the selection names. It is
/// byte-identical to the one the pin table produced: the row carries the
/// same version and the same artifact digest.
fn cpython_identity_of(spec: &ArtifactSpec, platform: Platform) -> io::Result<Identity> {
    Ok(Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: spec.version.clone(),
        inputs: BTreeMap::from([
            (
                "artifact_sha256".to_string(),
                artifact_sha256(spec)?.to_string(),
            ),
            ("platform".to_string(), platform.triple().to_string()),
        ]),
    })
}

fn uv_identity_of(spec: &ArtifactSpec, platform: Platform) -> io::Result<Identity> {
    Ok(Identity {
        kind: "uv".into(),
        name: "uv".into(),
        version: spec.version.clone(),
        inputs: BTreeMap::from([
            (
                "artifact_sha256".to_string(),
                artifact_sha256(spec)?.to_string(),
            ),
            ("platform".to_string(), platform.triple().to_string()),
        ]),
    })
}

fn cpython_identity(pin: &PinnedPython) -> Identity {
    Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: pin.version.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), pin.sha256.to_string()),
            ("platform".to_string(), pin.platform.triple().to_string()),
        ]),
    }
}

#[cfg(test)]
pub(crate) fn uv_identity(pin: &PinnedUv) -> Identity {
    Identity {
        kind: "uv".into(),
        name: "uv".into(),
        version: UV_VERSION.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), pin.sha256.to_string()),
            ("platform".to_string(), pin.platform.triple().to_string()),
        ]),
    }
}

/// Ensure the shipped uv is realized in the store (binary at <obj>/uv), for
/// work with no project selection to honor.
pub fn ensure_uv_for(store: &Store, platform: Platform) -> io::Result<PathBuf> {
    realize_uv(store, platform, &shipped_newest()?)
}

/// Realize the uv this selection names (binary at <obj>/uv). uv is the
/// resolver this tailor delegates to, so it is a component of the same
/// release bundle as the interpreter.
pub fn realize_uv(store: &Store, platform: Platform, selected: &Selected) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "uv")?;
    let spec = &row(selected, platform, "uv", UV_RECIPE)?;
    let identity = uv_identity_of(spec, platform)?;
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let sha256 = artifact_sha256(spec)?;
    let tarball = download_verified_held(store, &spec.url, sha256)?;
    let staged = store.stage()?;
    // Tarball root is platform-specific; strip it.
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::kernel::supervise::status_owned(&mut command, store)?;
    if !status.success() || !staged.join("uv").is_file() {
        return Err(io::Error::other("uv tarball extraction failed"));
    }
    store
        .commit_with_deps(&identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(sha256)?);
            deps
        })
        .map(|(path, _)| path)
}

/// Realize the CPython this selection names. Returns the object path
/// (interpreter at <path>/bin/python3).
///
/// This is the one place a Python run learns which bytes its interpreter
/// is made of: the row carries the version, the URL and the digest, so a
/// refreshed catalog cannot change a locked project's interpreter.
pub fn realize_runtime(
    store: &Store,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "CPython")?;
    let spec = &row(selected, platform, "cpython", CPYTHON_RECIPE)?;
    let identity = cpython_identity_of(spec, platform)?;
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let sha256 = artifact_sha256(spec)?;
    let tarball = download_verified_held(store, &spec.url, sha256)?;
    let staged = store.stage()?;
    // Tarball root is "python/"; strip it so the object root IS the prefix.
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::kernel::supervise::status_owned(&mut command, store)?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "tar extraction failed",
        ));
    }
    store
        .commit_with_deps(&identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(sha256)?);
            deps
        })
        .map(|(path, _)| path)
}

/// Realize a pinned CPython for a caller that holds no selection: the
/// shipped catalog row for that pin's version.
pub fn ensure_python_for(
    store: &Store,
    pin: &PinnedPython,
    platform: Platform,
) -> io::Result<PathBuf> {
    realize_runtime(store, platform, &shipped_selection(pin.version)?)
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
            for pin in PYTHONS.iter().filter(|pin| pin.platform == *platform) {
                let expected = vec![format!("sha256:{}", pin.sha256)];
                assert_eq!(recovered_cache(cpython_identity(pin)), expected);
            }
            for pin in UV.iter().filter(|pin| pin.platform == *platform) {
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
    fn pin_tables_have_five_cpython_and_one_uv_row_per_platform() {
        let mut python_keys = std::collections::HashSet::new();
        let mut uv_keys = std::collections::HashSet::new();
        for &platform in Platform::ALL {
            let python_rows: Vec<_> = PYTHONS
                .iter()
                .filter(|pin| pin.platform == platform)
                .collect();
            assert_eq!(python_rows.len(), 5, "CPython rows for {platform:?}");
            for pin in python_rows {
                assert!(
                    python_keys.insert((pin.platform, pin.version)),
                    "duplicate CPython pin for {platform:?}: {}",
                    pin.version
                );
            }

            let uv_rows: Vec<_> = UV.iter().filter(|pin| pin.platform == platform).collect();
            assert_eq!(uv_rows.len(), 1, "uv rows for {platform:?}");
            for pin in uv_rows {
                assert!(
                    uv_keys.insert((pin.platform, UV_VERSION)),
                    "duplicate uv pin for {platform:?}"
                );
            }
        }
    }

    #[test]
    fn darwin_identity_unchanged() {
        let darwin_pins: Vec<_> = PYTHONS
            .iter()
            .filter(|pin| pin.platform == Platform::Aarch64AppleDarwin)
            .collect();
        assert_eq!(darwin_pins.len(), 5);
        for pin in darwin_pins {
            let identity = cpython_identity(pin);
            let expected = match pin.version {
                "3.12.14" => "a1a7472f00bcc8e7432dcaf8e088192eab9ddb63-cpython-3.12.14",
                "3.13.15" => "3d4cd599c6aa947638318fba6a27cdf922d71e91-cpython-3.13.15",
                "3.10.21" => "2d325d7de98a5ef468887be7a900ba353393e6d4-cpython-3.10.21",
                "3.11.16" => "4f5f15e85142c23c54ceb171e28eed8e37868d58-cpython-3.11.16",
                "3.14.7" => "a08604ddc4f60d6a41bfde528123267824647022-cpython-3.14.7",
                other => panic!("unexpected Darwin CPython pin {other}"),
            };
            assert_eq!(identity.object_id(), expected);
        }
        let uv = UV
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
                "3.12.0",
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
            platform,
            &with_recipe(platform, "cpython", "cpython/2"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("recipe cpython/2"), "{error}");
        assert!(error.contains("upgrade tog"), "{error}");
        let error = realize_uv(&store, platform, &with_recipe(platform, "uv", "uv/2"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("recipe uv/2"), "{error}");

        let mut node = shipped_selection("3.12.14").unwrap();
        node.ecosystem = "node".into();
        let error = realize_runtime(&store, platform, &node)
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
            for pin in PYTHONS.iter().filter(|pin| pin.platform == *platform) {
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
            for pin in UV.iter().filter(|pin| pin.platform == *platform) {
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
