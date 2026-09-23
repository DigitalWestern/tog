//! Pinned CPython provisioning (kernel provider layer): the
//! python-build-standalone and uv pin tables, the shipped Python catalog
//! they form, and realization of the interpreter a selection names.
//!
//! The Python tailor runs its projects on it and the npm tailor runs
//! node-gyp on it, so it lives below both. Choosing a version for a project
//! (`requires-python`, `.python-version`) stays in the Python tailor; this
//! module only turns a selection into bytes and an object id. Callers
//! install the object-kind rows (`tailors::install_kinds`) before they
//! realize, as every realization entry point does.
//!
//! The pin rows and identity constructors are `pub` so the owning
//! tailor keeps its identity goldens and object-kind rows beside it.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{download_verified_held, Digest};
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use crate::kernel::toolchain::{
    ArtifactRow, ArtifactSpec, Bundle, Catalog, Component, Request, Selected, Source, Version,
    VersionRequest,
};
use crate::kernel::types::Identity;
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::process::Command;

/// The CPython an unconstrained project gets: the shipped catalog prefers
/// it, so a range it satisfies keeps it too.
pub const DEFAULT_VERSION: &str = "3.12.14";

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

/// The store object id of the CPython a selection names, from the
/// selection's own row and without realizing it: the same id
/// `realize_runtime` commits, so a cache key that carries it names the
/// interpreter the environment will run on rather than the one a version
/// number would find in today's pin table.
pub fn runtime_object_id(platform: Platform, selected: &Selected) -> io::Result<String> {
    let spec = row(selected, platform, "cpython", CPYTHON_RECIPE)?;
    Ok(cpython_identity_of(&spec, platform)?.object_id())
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
    let default = crate::kernel::toolchain::Request::exact("cpython", DEFAULT_VERSION)?;
    Ok(Catalog::new("python", bundles)?.with_preference(default))
}

/// Pinned uv (resolver delegation target). Single static binary per platform;
/// realized like any toolchain so a bare machine needs nothing besides
/// tog.
pub const UV_VERSION: &str = "0.12.7";
pub struct PinnedUv {
    pub platform: Platform,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const UV: &[PinnedUv] = &[
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
pub const CPYTHON_RECIPE: &str = "cpython/legacy";
pub const UV_RECIPE: &str = "uv/legacy";

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
pub fn row(
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
pub fn cpython_identity_input(selected: &Selected, platform: Platform) -> io::Result<String> {
    let spec = row(selected, platform, "cpython", CPYTHON_RECIPE)?;
    Ok(format!("{}:{}", spec.version, artifact_sha256(&spec)?))
}

/// The object id this selection's CPython realizes to, without realizing
/// it. Planning uses it; realization returns the same id.
pub fn cpython_object_id(selected: &Selected, platform: Platform) -> io::Result<String> {
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
pub fn cpython_identity_of(spec: &ArtifactSpec, platform: Platform) -> io::Result<Identity> {
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

pub fn uv_identity_of(spec: &ArtifactSpec, platform: Platform) -> io::Result<Identity> {
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

pub fn cpython_identity(pin: &PinnedPython) -> Identity {
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
pub fn uv_identity(pin: &PinnedUv) -> Identity {
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
pub fn ensure_uv_for(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
) -> io::Result<PathBuf> {
    realize_uv(store, activity, platform, &shipped_newest()?)
}

/// Realize the uv this selection names (binary at <obj>/uv). uv is the
/// resolver this tailor delegates to, so it is a component of the same
/// release bundle as the interpreter.
pub fn realize_uv(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::kernel::platform::require_host(platform, "uv")?;
    let spec = &row(selected, platform, "uv", UV_RECIPE)?;
    let identity = uv_identity_of(spec, platform)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let sha256 = artifact_sha256(spec)?;
    let tarball = download_verified_held(store, activity, &spec.url, sha256)?;
    let staged = store.stage_with_activity(activity)?;
    // Tarball root is platform-specific; strip it.
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    if !status.success() || !staged.join("uv").is_file() {
        return Err(io::Error::other("uv tarball extraction failed"));
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
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
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::kernel::platform::require_host(platform, "CPython")?;
    let spec = &row(selected, platform, "cpython", CPYTHON_RECIPE)?;
    let identity = cpython_identity_of(spec, platform)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    let sha256 = artifact_sha256(spec)?;
    let tarball = download_verified_held(store, activity, &spec.url, sha256)?;
    let staged = store.stage_with_activity(activity)?;
    // Tarball root is "python/"; strip it so the object root IS the prefix.
    let mut command = Command::new("/usr/bin/tar");
    command
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "tar extraction failed",
        ));
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(sha256)?);
            deps
        })
        .map(|(path, _)| path)
}
