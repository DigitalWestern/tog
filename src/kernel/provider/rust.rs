//! The pinned Rust toolchain (kernel provider layer): the shipped Rust
//! catalog (`rust.catalog.toml`: every stable release's rustc, rust-std,
//! cargo and rustfmt archives and its channel manifest), realization of the base
//! toolchain a selection names, and the rustup-style toolchain-file reading
//! that maps a channel onto the pins. Optional components and cross targets
//! a toolchain file asks for are assembled on top of that base in
//! [`super::rust_extras`].
//!
//! The cargo tailor builds projects with it and the Python tailor builds
//! sdists with Rust extensions with it, so it lives below both. Callers
//! install the object-kind rows (`tailors::install_kinds`) before they
//! realize, as every realization entry point does.
//!
//! The identity constructors are `pub` so the owning tailor keeps its
//! identity goldens and object-kind rows beside it.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::download_toolchain_artifact_held;
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::input;
use crate::kernel::toolchain::{ArtifactSpec, Catalog, Selected};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use super::rust_extras::{
    project_extras, project_extras_in, realize_toolchain, toolchain_file_extras_within,
    toolchain_object_id, Extras,
};

/// The shipped Rust catalog: every stable release from 1.70.0 on, with its
/// rustc, rust-std, cargo and rustfmt archives and its channel manifest,
/// and the release a project with no Rust pin gets. Generated and verified
/// by `tools/catalog.py cargo`, which checks each manifest's signature
/// against the Rust release key before it writes a row.
static CATALOG: Shipped = Shipped::new(include_str!("rust.catalog.toml"));

/// The release the checked-in channel manifest fixture trims and the
/// identity goldens pin. Any shipped release realizes the same way.
pub const RUST_VERSION: &str = "1.96.1";

/// The catalog component that pins a release's official channel manifest,
/// `channel-rust-<version>.toml`, by the sha256 of its bytes. Every optional
/// component and cross target is provisioned from that file's rows
/// (`rust_channel`), so pinning it pins them all. tog checks the sha256 only;
/// the generator verified the manifest's signature before writing the row.
pub const CHANNEL_MANIFEST: &str = "channel-manifest";

/// The recipe of a channel manifest row: a file read, never laid out.
pub const CHANNEL_MANIFEST_RECIPE: &str = "rust-channel-manifest/1";

/// The pinned channel manifest of the release `selected` names. A lock
/// written before the manifest was a catalog row has none of its own; the
/// shipped release of the same version answers then, and the manifest is
/// still held to every row of the lock before anything is read from it.
pub fn channel_manifest(platform: Platform, selected: &Selected) -> io::Result<ArtifactSpec> {
    let row = match selected.artifact(platform, CHANNEL_MANIFEST) {
        Ok(row) => row,
        Err(_) => {
            let version = selected.version("rustc")?;
            shipped_selection(version)
                .and_then(|shipped| shipped.artifact(platform, CHANNEL_MANIFEST))
                .map_err(|_| {
                    err(format!(
                        "this tog pins no channel manifest for Rust {version}, so it cannot \
                         provision the components, targets or profile rust-toolchain.toml asks \
                         for; upgrade tog"
                    ))
                })?
        }
    };
    row.check("cargo", CHANNEL_MANIFEST_RECIPE, "sha256")?;
    Ok(row)
}

/// The extraction/layout recipe this binary knows for a Rust toolchain: the
/// catalog emits it, the object identity commits to it, and a locked row
/// naming anything else is refused rather than guessed at.
pub const RUST_RECIPE: &str = "rust-toolchain/1";

/// The layout recipe this binary knows for the rustfmt component. The
/// catalog emits it and the object identity commits to it; a locked row
/// naming another one is refused rather than laid out by guess.
pub const RUSTFMT_RECIPE: &str = "rustfmt/1";

/// The shipped Rust catalog: one release bundle per stable release, and the
/// release a project with no Rust pin gets.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "Rust toolchain")?;
    rust_pins(platform).map(|_| ())
}

/// Every shipped Rust version with a complete base toolchain on `platform`.
fn rust_pins(platform: Platform) -> io::Result<Vec<&'static str>> {
    let mut pins = Vec::new();
    for bundle in &CATALOG.document()?.bundles {
        let complete = RUNTIME_COMPONENTS
            .iter()
            .all(|name| bundle.artifact(platform, name).is_some());
        if let (true, Some(rustc)) = (complete, bundle.component("rustc")) {
            pins.push(rustc.version.as_str());
        }
    }
    if pins.is_empty() {
        return Err(no_pin("rust toolchain", platform));
    }
    pins.sort_unstable_by_key(|pin| version_key(pin));
    pins.dedup();
    Ok(pins)
}

/// The Rust version a project with no toolchain file, or one naming
/// `stable`, gets: the catalog's explicit default.
fn default_pin(platform: Platform) -> io::Result<&'static str> {
    let bundle = CATALOG.default_bundle()?;
    if !RUNTIME_COMPONENTS
        .iter()
        .all(|name| bundle.artifact(platform, name).is_some())
    {
        return Err(no_pin("rust toolchain", platform));
    }
    bundle
        .component("rustc")
        .map(|rustc| rustc.version.as_str())
        .ok_or_else(|| err("rust catalog: the default release has no rustc"))
}

/// The version a file with no channel (or none at all, or `stable`)
/// resolves to: `default` when the caller has one (the Rust a Python
/// project's lock pins for its sdists), the catalog's default otherwise.
fn fallback_pin(platform: Platform, default: Option<&str>) -> io::Result<&'static str> {
    let Some(version) = default else {
        return default_pin(platform);
    };
    rust_pins(platform)?
        .into_iter()
        .find(|pin| *pin == version)
        .ok_or_else(|| {
            err(format!(
                "tog-toolchain.toml pins Rust {version} for building sdists, which this tog \
                 does not ship for {}; run `tog update --toolchain python`",
                platform.triple()
            ))
        })
}

/// One base-toolchain row of the [`RUST_VERSION`] release, as the tests
/// that pin its digests and ids read it.
#[cfg(test)]
pub struct RustComponent {
    pub platform: Platform,
    pub component: &'static str,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

/// The [`RUST_VERSION`] release's rustc, rust-std and cargo rows on
/// `platform`, in extraction order, read from the shipped document.
#[cfg(test)]
pub fn rust_components(platform: Platform) -> io::Result<Vec<&'static RustComponent>> {
    static ROWS: std::sync::OnceLock<Vec<RustComponent>> = std::sync::OnceLock::new();
    let rows = ROWS.get_or_init(|| {
        let document = CATALOG.document().expect("the shipped Rust catalog parses");
        let bundle = document
            .bundles
            .iter()
            .find(|bundle| bundle.release == format!("rust-{RUST_VERSION}"))
            .expect("the fixture release is shipped");
        let mut rows = Vec::new();
        for name in RUNTIME_COMPONENTS {
            for row in bundle.artifacts.iter().filter(|row| row.component == name) {
                rows.push(RustComponent {
                    platform: row.platform,
                    component: name,
                    version: RUST_VERSION,
                    url: row.url.as_str(),
                    sha256: row.digest.hex(),
                });
            }
        }
        rows
    });
    let components: Vec<_> = rows.iter().filter(|c| c.platform == platform).collect();
    if components.len() != RUNTIME_COMPONENTS.len() {
        return Err(no_pin("rust toolchain", platform));
    }
    Ok(components)
}

/// The base object identity of [`rust_components`] rows.
#[cfg(test)]
pub fn rust_identity(platform: Platform, components: &[&'static RustComponent]) -> Identity {
    let sha = |name: &str| {
        components
            .iter()
            .find(|component| component.component == name)
            .expect("validated Rust component set")
            .sha256
    };
    runtime_identity(
        platform,
        RUST_VERSION,
        sha("rustc"),
        sha("rust-std"),
        sha("cargo"),
    )
}

/// The Rust object's identity, from the three component digests that went
/// into it. The pin table and a locked bundle row reach this with the same
/// bytes, so a toolchain realized from a lock lands on the object the pin
/// already built.
fn runtime_identity(
    platform: Platform,
    version: &str,
    rustc_sha256: &str,
    rust_std_sha256: &str,
    cargo_sha256: &str,
) -> Identity {
    Identity {
        kind: "rust".into(),
        name: "rust".into(),
        version: version.into(),
        inputs: BTreeMap::from([
            // Schema commits the extraction/layout recipe, not just the
            // bytes: changing how components merge must change the id.
            ("schema".to_string(), RUST_RECIPE.to_string()),
            ("cargo_sha256".to_string(), cargo_sha256.to_string()),
            ("platform".to_string(), platform.triple().to_string()),
            ("rust_std_sha256".to_string(), rust_std_sha256.to_string()),
            ("rustc_sha256".to_string(), rustc_sha256.to_string()),
        ]),
    }
}

/// The components the Rust object is built from, in the order the extractor
/// applies them.
pub const RUNTIME_COMPONENTS: [&str; 3] = ["rustc", "rust-std", "cargo"];

/// The rows of `selected` this tailor realizes from, checked before any of
/// them is fetched: the selection must be a Rust one, every component must
/// be present for this platform, and every recipe must be one this binary
/// knows how to lay out.
pub fn runtime_rows(platform: Platform, selected: &Selected) -> io::Result<Vec<ArtifactSpec>> {
    if selected.runtime() != "rustc" {
        return Err(err(format!(
            "internal: a {} selection (runtime {}) reached the Rust tailor",
            selected.ecosystem,
            selected.runtime()
        )));
    }
    let mut rows = Vec::new();
    for component in RUNTIME_COMPONENTS {
        // Checked as `cargo`, the name users know this ecosystem by; the
        // selection's own ecosystem is `rust`.
        let row = selected.artifact(platform, component)?;
        row.check("cargo", RUST_RECIPE, "sha256")?;
        rows.push(row);
    }
    Ok(rows)
}

fn row_of<'a>(rows: &'a [ArtifactSpec], component: &str) -> &'a ArtifactSpec {
    rows.iter()
        .find(|row| row.component == component)
        .expect("checked Rust component set")
}

/// The identity of the Rust object `selected` names, without realizing it.
/// A local tree's is read from its locked row.
pub fn runtime_object_id(platform: Platform, selected: &Selected) -> io::Result<String> {
    if super::rust_path::is_path(selected) {
        return Ok(super::rust_path::identity(platform, selected)?.object_id());
    }
    let rows = runtime_rows(platform, selected)?;
    Ok(identity_of(platform, &rows).object_id())
}

pub fn identity_of(platform: Platform, rows: &[ArtifactSpec]) -> Identity {
    runtime_identity(
        platform,
        &row_of(rows, "rustc").version,
        row_of(rows, "rustc").digest.hex(),
        row_of(rows, "rust-std").digest.hex(),
        row_of(rows, "cargo").digest.hex(),
    )
}

/// The id of the base Rust object the shipped release of `version` names.
pub fn rust_object_id(platform: Platform, version: &str) -> io::Result<String> {
    runtime_object_id(platform, &shipped_selection(version)?)
}

pub(super) fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Realize the Rust toolchain `selected` names: its bytes, its layout
/// recipe and its version all come from the selection's rows, so a catalog
/// refresh cannot move a project's compiler under it. Inside a project this
/// is the only way a Rust object is built.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::kernel::platform::require_host(platform, "Rust toolchain")?;
    if super::rust_path::is_path(selected) {
        return super::rust_path::realize(store, activity, platform, selected);
    }
    let rows = runtime_rows(platform, selected)?;
    let identity = identity_of(platform, &rows);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    let mut tarballs = Vec::new();
    for row in &rows {
        tarballs.push(download_toolchain_artifact_held(
            store,
            activity,
            &row.provider,
            &row.url,
            &row.digest,
        )?);
    }

    let names: Vec<&str> = rows.iter().map(|row| row.component.as_str()).collect();
    let staged = store.stage_with_activity(activity)?;
    extract_rust_components_for(activity, &staged, platform, &names, &tarballs)?;

    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            for row in &rows {
                deps.cache_digest(row.digest.clone());
            }
            deps
        })
        .map(|(path, _)| path)
        .map_err(|e| io::Error::new(e.kind(), format!("commit rust object: {e}")))
}

/// The shipped catalog's release for one exact Rust version, as a selection.
/// This is what a caller outside any project gets: there is no lock to
/// honor, so the shipped catalog is both the catalog and the answer.
pub fn shipped_selection(version: &str) -> io::Result<Selected> {
    let catalog = toolchain_catalog()?;
    let bundle = catalog
        .bundles()
        .iter()
        .find(|bundle| {
            bundle
                .component("rustc")
                .is_some_and(|component| component.version == version)
        })
        .ok_or_else(|| err(format!("internal: no shipped Rust release for {version}")))?
        .clone();
    Ok(Selected {
        helpers: Default::default(),
        ecosystem: catalog.ecosystem().to_string(),
        bundle,
        lock_sha256: None,
        source: crate::kernel::toolchain::Source::Shipped,
    })
}

fn extract_rust_components_for(
    activity: &crate::kernel::activity::StoreActivity,
    staged: &Path,
    platform: Platform,
    components: &[&str],
    tarballs: &[impl AsRef<Path>],
) -> io::Result<()> {
    if components.len() != tarballs.len() {
        return Err(err("Rust component/archive count mismatch"));
    }
    for (component, tarball) in components.iter().zip(tarballs) {
        let tarball: &Path = tarball.as_ref();
        crate::kernel::archive::extract_with_activity_and_options(
            activity,
            tarball,
            staged,
            &crate::kernel::archive::ExtractOptions::platform_build(2),
            crate::kernel::archive::Compression::Xz,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("extract tarball for {component}: {e}")))?;
    }
    validate_rust_layout(staged, platform)
}

#[cfg(test)]
pub fn extract_rust_components(
    staged: &Path,
    platform: Platform,
    components: &[&str],
    tarballs: &[impl AsRef<Path>],
) -> io::Result<()> {
    if components.len() != tarballs.len() {
        return Err(err("Rust component/archive count mismatch"));
    }
    for (component, tarball) in components.iter().zip(tarballs) {
        let tarball: &Path = tarball.as_ref();
        crate::kernel::archive::extract_with_options(
            tarball,
            staged,
            &crate::kernel::archive::ExtractOptions::platform_build(2),
            crate::kernel::archive::Compression::Xz,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("extract tarball for {component}: {e}")))?;
    }
    validate_rust_layout(staged, platform)
}

pub(super) fn validate_rust_layout(staged: &Path, platform: Platform) -> io::Result<()> {
    if !staged.join("bin/rustc").is_file()
        || !staged.join("bin/cargo").is_file()
        || !staged
            .join(format!("lib/rustlib/{}", platform.triple()))
            .is_dir()
    {
        return Err(err(
            "Rust toolchain extraction has an unexpected layout; refusing to commit",
        ));
    }
    Ok(())
}

/// Resolve the nearest rustup-style toolchain file to the pinned version.
///
/// This is the pre-lock answer, kept for the tests that pin how a file maps
/// onto the catalog. No command resolves a project this way: a project's
/// Rust is its lock's selection, and the Python sdist build of a project whose lock names no Rust uses
/// [`resolve_toolchain_within_or`]: its tree is a store scratch directory
/// that is nobody's tog project.
/// Every entry point that is handed a [`Selected`] takes the version from it
/// instead (`toolchain.version("rustc")`), so the lock decides the toolchain.
/// What the file asks for beyond the channel is read from the lock's rows
/// ([`project_extras`]) or, for an sdist, [`toolchain_file_extras_within`].
pub fn resolve_toolchain(platform: Platform, project_dir: &Path) -> io::Result<&'static str> {
    resolve_toolchain_with(
        platform,
        nearest_toolchain_file(project_dir, None),
        true,
        None,
    )
}

/// `resolve_toolchain` for an unpacked sdist: only a toolchain file inside
/// `root` is read. A file above it belongs to whoever owns the store's
/// parent directories (`$HOME`, a repository the store sits in) and must
/// not reach a build whose identity names only the sdist. With none, the
/// catalog's default, whatever lies above the store.
pub fn resolve_toolchain_within(platform: Platform, root: &Path) -> io::Result<&'static str> {
    resolve_toolchain_within_or(platform, root, None)
}

/// [`resolve_toolchain_within`] with the default a project locked: an
/// sdist whose own file names a channel gets that channel, and one with no
/// file, no channel, or `stable` gets `default` (the Rust the Python
/// section of `tog-toolchain.toml` pins for sdists) rather than whatever
/// this tog's catalog calls its default today. `None` is the catalog's.
pub fn resolve_toolchain_within_or(
    platform: Platform,
    root: &Path,
    default: Option<&str>,
) -> io::Result<&'static str> {
    resolve_toolchain_with(
        platform,
        nearest_toolchain_file(root, Some(root)),
        true,
        default,
    )
}

/// The version `resolve_toolchain` would choose, without its narration.
#[cfg(test)]
pub fn resolve_toolchain_quiet(platform: Platform, project_dir: &Path) -> io::Result<&'static str> {
    resolve_toolchain_with(
        platform,
        nearest_toolchain_file(project_dir, None),
        false,
        None,
    )
}

fn resolve_toolchain_with(
    platform: Platform,
    found: Option<(PathBuf, bool)>,
    effects: bool,
    default: Option<&str>,
) -> io::Result<&'static str> {
    let _ = rust_pins(platform)?;
    let Some((path, legacy)) = found else {
        return fallback_pin(platform, default);
    };
    let bytes = read_toolchain_file(&path)?;
    let located =
        |error: io::Error| io::Error::new(error.kind(), format!("{}: {error}", path.display()));
    // A local toolchain has no pin to resolve to: only a project lock
    // records one (its content hash), and this resolver has no lock.
    if let Some(table) = input::rust_toolchain_table(&bytes, legacy).map_err(located)? {
        if let Some(tree) = input::toolchain_path(&table, legacy).map_err(located)? {
            return Err(err(format!(
                "{}: names the local toolchain {tree}, which a project sync locks in \
                 tog-toolchain.toml; there is no pinned Rust to resolve it to here",
                path.display()
            )));
        }
    }
    // The channel is read by the same reader the toolchain lock records it
    // with, so a file this refuses is one the lock refuses too.
    let channel = if legacy {
        input::read_rust_toolchain_legacy(&bytes)
    } else {
        input::read_rust_toolchain(&bytes)
    }
    .map_err(located)?;
    // A table with no channel (only components, targets or a profile) means
    // rustup's default toolchain: here, the catalog's explicit default.
    let Some(channel) = channel else {
        return fallback_pin(platform, default);
    };
    resolve_channel(platform, &path, channel.trim(), effects, default)
}

/// The components and cross targets the nearest toolchain file inside
/// `root` asks for: an unpacked sdist's own request, read with the same
/// readers and normalization the toolchain lock uses. A bare channel line
/// asks for none.
pub(super) fn file_extras_within(root: &Path) -> io::Result<Extras> {
    let Some((path, legacy)) = nearest_toolchain_file(root, Some(root)) else {
        return Ok(Extras::default());
    };
    let bytes = read_toolchain_file(&path)?;
    let located =
        |error: io::Error| io::Error::new(error.kind(), format!("{}: {error}", path.display()));
    let Some(table) = input::rust_toolchain_table(&bytes, legacy).map_err(located)? else {
        return Ok(Extras::default());
    };
    let list = |key: &str| -> io::Result<Vec<String>> {
        Ok(input::toolchain_list(&table, key, legacy)
            .map_err(located)?
            .map(|value| input::split_list(&value))
            .unwrap_or_default())
    };
    Ok(Extras {
        components: list("components")?,
        targets: list("targets")?,
        profile: input::toolchain_profile(&table, legacy).map_err(located)?,
    })
}

fn read_toolchain_file(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path).map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))
}

/// The nearest rustup-style toolchain file at or above `project_dir`, and
/// whether it is the legacy `rust-toolchain` spelling. With a `ceiling`, the
/// search stops there instead of at the filesystem root.
fn nearest_toolchain_file(project_dir: &Path, ceiling: Option<&Path>) -> Option<(PathBuf, bool)> {
    let mut dir = project_dir;
    loop {
        let legacy = dir.join("rust-toolchain");
        if legacy.exists() {
            return Some((legacy, true));
        }
        let toml = dir.join("rust-toolchain.toml");
        if toml.exists() {
            return Some((toml, false));
        }
        if ceiling == Some(dir) {
            return None;
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => return None,
        }
    }
}

fn resolve_channel(
    platform: Platform,
    path: &Path,
    channel: &str,
    effects: bool,
    default: Option<&str>,
) -> io::Result<&'static str> {
    if channel == "stable" {
        let pin = fallback_pin(platform, default)?;
        if effects {
            ui::note(&format!(
                "{} resolves stable to pinned Rust {pin}",
                path.display()
            ));
        }
        return Ok(pin);
    }

    let prefix = format!("{channel}.");
    let pins = rust_pins(platform)?;
    if let Some(pin) = pins
        .iter()
        .copied()
        .filter(|pin| *pin == channel || pin.starts_with(&prefix))
        .max_by_key(|pin| version_key(pin))
    {
        return Ok(pin);
    }

    Err(err(format!(
        "{}: unsupported Rust toolchain {channel:?}; pinned versions available: {}",
        path.display(),
        pins.join(", ")
    )))
}

fn version_key(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}
