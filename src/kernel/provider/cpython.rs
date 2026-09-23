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
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::{
    ArtifactSpec, Bundle, Catalog, Request, Selected, Source, Version, VersionRequest,
};
use crate::kernel::types::Identity;
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// The shipped Python catalog: every python-build-standalone build of the
/// CPython lines still maintained, each bundled with the pinned uv, and the
/// default, generated and verified by `tools/catalog.py python` (each
/// digest from that PBS release's SHA256SUMS, cross-checked with GitHub's
/// asset digest; trust-on-first-use, not a signature).
static CATALOG: Shipped = Shipped::new(include_str!("cpython.catalog.toml"));

/// The shipped default CPython, the object-id golden the identity tests
/// hold: adding a newer patch to the catalog must not move it.
#[cfg(test)]
pub const DEFAULT_VERSION: &str = "3.12.14";

/// The CPython an unconstrained project gets: the catalog's named default,
/// which a range or a line prefix it satisfies keeps too.
pub fn default_version() -> io::Result<&'static str> {
    component_version(CATALOG.default_bundle()?, "cpython")
}

fn component_version(bundle: &'static Bundle, name: &str) -> io::Result<&'static str> {
    bundle
        .component(name)
        .map(|c| c.version.as_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("python catalog: {} has no {name} component", bundle.release),
            )
        })
}

/// One platform's python-build-standalone `install_only` build of one
/// CPython release, as the shipped catalog lists it.
#[derive(Debug)]
pub struct PinnedPython {
    pub platform: Platform,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

/// Every shipped CPython build: one row per release and supported platform.
pub fn pythons() -> io::Result<&'static [PinnedPython]> {
    static PINS: OnceLock<Vec<PinnedPython>> = OnceLock::new();
    if let Some(pins) = PINS.get() {
        return Ok(pins);
    }
    let document = CATALOG.document()?;
    let mut rows = Vec::new();
    for bundle in &document.bundles {
        let version = component_version(bundle, "cpython")?;
        for row in bundle.artifacts.iter().filter(|r| r.component == "cpython") {
            rows.push(PinnedPython {
                platform: row.platform,
                version,
                url: row.url.as_str(),
                sha256: row.digest.hex(),
            });
        }
    }
    Ok(PINS.get_or_init(|| rows))
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

/// The shipped Python catalog: one release bundle per CPython release,
/// each carrying the pinned uv, so a lock minted from it names the resolver
/// too. The recipe ids name the layouts the object identities commit to.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

/// The pinned uv (resolver delegation target) the default release carries:
/// a single static binary per platform, realized like any toolchain so a
/// bare machine needs nothing besides tog.
pub fn uv_version() -> io::Result<&'static str> {
    component_version(CATALOG.default_bundle()?, "uv")
}

pub struct PinnedUv {
    pub platform: Platform,
    pub url: &'static str,
    pub sha256: &'static str,
}

/// The default release's uv rows, one per supported platform.
pub fn uv_pins() -> io::Result<&'static [PinnedUv]> {
    static PINS: OnceLock<Vec<PinnedUv>> = OnceLock::new();
    if let Some(pins) = PINS.get() {
        return Ok(pins);
    }
    let bundle = CATALOG.default_bundle()?;
    let rows = bundle
        .artifacts
        .iter()
        .filter(|r| r.component == "uv")
        .map(|r| PinnedUv {
            platform: r.platform,
            url: r.url.as_str(),
            sha256: r.digest.hex(),
        })
        .collect();
    Ok(PINS.get_or_init(|| rows))
}

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

/// The shipped catalog's default release.
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
        version: uv_version().expect("shipped uv").into(),
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
