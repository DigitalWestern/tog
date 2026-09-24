//! The pinned Rust toolchain (kernel provider layer): the rustc, rust-std,
//! cargo and rustfmt pin tables and the channel manifest pinned beside
//! them, the shipped Rust catalog they form, realization of the base
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
//! The pin rows and identity constructors are `pub` so the owning
//! tailor keeps its identity goldens and object-kind rows beside it.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{download_verified_digest_held, Digest};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::toolchain::input;
use crate::kernel::toolchain::{
    ArtifactRow, ArtifactSpec, Bundle, Catalog, Component as BundleComponent, Selected,
};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use super::rust_extras::{
    project_extras, realize_toolchain, toolchain_file_extras_within, toolchain_object_id, Extras,
};

pub const RUST_VERSION: &str = "1.96.1";

/// The official channel manifest of one shipped Rust release, pinned by the
/// sha256 of its bytes: `https://static.rust-lang.org/dist/channel-rust-<version>.toml`.
/// Every optional component and cross target is provisioned from the rows
/// of this file (`rust_channel`), so pinning it pins them all.
///
/// A row is produced by `tools/rust_channel_pin.py`, which verifies the
/// manifest's detached signature with `gpgv` against the Rust release key
/// checked in at `tools/keys/rust-release-signing-key.asc` before printing
/// the sha256; `--check` re-verifies every row here. tog itself checks the
/// sha256 only.
pub struct ChannelManifestPin {
    pub version: &'static str,
    pub sha256: &'static str,
}

pub const CHANNEL_MANIFESTS: &[ChannelManifestPin] = &[ChannelManifestPin {
    version: "1.96.1",
    sha256: "87eb76c53073e72b766083bed5530820694253b832a762d8385bda5759f03975",
}];

/// The pinned manifest digest for Rust `version`. A release this binary
/// pins no manifest for cannot have extras assembled, and says so.
pub fn channel_manifest_pin(version: &str) -> io::Result<Digest> {
    let pin = CHANNEL_MANIFESTS
        .iter()
        .find(|pin| pin.version == version)
        .ok_or_else(|| {
            err(format!(
                "this tog pins no channel manifest for Rust {version}, so it cannot provision \
                 the components or targets rust-toolchain.toml asks for; upgrade tog"
            ))
        })?;
    Digest::sha256(pin.sha256)
}

/// The extraction/layout recipe this binary knows for a Rust toolchain: the
/// catalog emits it, the object identity commits to it, and a locked row
/// naming anything else is refused rather than guessed at.
pub const RUST_RECIPE: &str = "rust-toolchain/1";

pub struct RustComponent {
    pub platform: Platform,
    pub component: &'static str,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

const RUST_COMPONENTS: &[RustComponent] = &[
    RustComponent {
        platform: Platform::Aarch64AppleDarwin,
        component: "rustc",
        version: RUST_VERSION,
        url: "https://static.rust-lang.org/dist/rustc-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "9b548f0665f85f3c7fd45165611e3dea79f048c69d163be193986310d204fc2c",
    },
    RustComponent {
        platform: Platform::Aarch64AppleDarwin,
        component: "rust-std",
        version: RUST_VERSION,
        url: "https://static.rust-lang.org/dist/rust-std-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "0d433a74c303febc915f8fa1091ef166445706461d0c96984ecb7303aa8208f5",
    },
    RustComponent {
        platform: Platform::Aarch64AppleDarwin,
        component: "cargo",
        version: RUST_VERSION,
        url: "https://static.rust-lang.org/dist/cargo-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "2f43d75e9ad3febae5022c6f295cf93b74131cfdb1293a83e291f878ea9585a0",
    },
    RustComponent {
        platform: Platform::X86_64UnknownLinuxGnu,
        component: "rustc",
        version: RUST_VERSION,
        url: "https://static.rust-lang.org/dist/rustc-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
        sha256: "3545a0efad2355ecb0a3b9ac02efee96e27f1f9d24b7ce2fc3f279b2efb0d923",
    },
    RustComponent {
        platform: Platform::X86_64UnknownLinuxGnu,
        component: "rust-std",
        version: RUST_VERSION,
        url: "https://static.rust-lang.org/dist/rust-std-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
        sha256: "1bf4fde5048cca33e6ea00c7471281ed96d792f6923141e3db45072743a1afae",
    },
    RustComponent {
        platform: Platform::X86_64UnknownLinuxGnu,
        component: "cargo",
        version: RUST_VERSION,
        url: "https://static.rust-lang.org/dist/cargo-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
        sha256: "ecc53a3c49fab5ab8c9301b3bbc8fb1dff9be6c65287add3f57a0fe8fddfea9e",
    },
];

pub fn rust_components(platform: Platform) -> io::Result<Vec<&'static RustComponent>> {
    let components: Vec<_> = RUST_COMPONENTS
        .iter()
        .filter(|component| component.platform == platform)
        .collect();
    let complete = components.len() == 3
        && ["rustc", "rust-std", "cargo"]
            .iter()
            .all(|name| components.iter().filter(|c| c.component == *name).count() == 1);
    if !complete {
        return Err(no_pin("rust toolchain", platform));
    }
    Ok(components)
}

/// The shipped Rust catalog: one release bundle per pinned Rust version,
/// with rustc, rust-std and cargo under the toolchain recipe and rustfmt (the
/// `tog fmt` component of the same version) under its own.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    // Catalog order is pin-table order: the newest-appended row wins a tie.
    let mut versions: Vec<&str> = Vec::new();
    for version in RUST_COMPONENTS.iter().map(|c| c.version) {
        if !versions.contains(&version) {
            versions.push(version);
        }
    }
    let mut bundles = Vec::new();
    for version in versions {
        let mut components = Vec::new();
        let mut artifacts = Vec::new();
        for row in RUST_COMPONENTS.iter().filter(|c| c.version == version) {
            if !components
                .iter()
                .any(|c: &BundleComponent| c.name == row.component)
            {
                components.push(BundleComponent::new(row.component, version));
            }
            artifacts.push(ArtifactRow::new(
                row.platform,
                row.component,
                "static.rust-lang.org",
                version,
                RUST_RECIPE,
                row.url,
                Digest::sha256(row.sha256)?,
            ));
        }
        if RUSTFMT_VERSION == version {
            components.push(BundleComponent::new("rustfmt", version));
            for row in RUSTFMT_COMPONENTS {
                artifacts.push(ArtifactRow::new(
                    row.platform,
                    "rustfmt",
                    "static.rust-lang.org",
                    version,
                    "rustfmt/1",
                    row.url,
                    Digest::sha256(row.sha256)?,
                ));
            }
        }
        bundles.push(Bundle {
            release: format!("rust-{version}"),
            revision: None,
            primary: vec!["rustc".into()],
            components,
            artifacts,
        });
    }
    Catalog::new("cargo", bundles)
}

pub const RUSTFMT_VERSION: &str = "1.96.1";

/// The layout recipe this binary knows for the rustfmt component. The
/// catalog emits it and the object identity commits to it; a locked row
/// naming another one is refused rather than laid out by guess.
pub const RUSTFMT_RECIPE: &str = "rustfmt/1";

pub struct RustfmtComponent {
    pub platform: Platform,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const RUSTFMT_COMPONENTS: &[RustfmtComponent] = &[
    RustfmtComponent {
        platform: Platform::Aarch64AppleDarwin,
        url: "https://static.rust-lang.org/dist/rustfmt-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "ed0cc9d72c04e7c3c4b7a82ab7f1ce5e33132017d062d8f9be6adf6472e8f165",
    },
    RustfmtComponent {
        platform: Platform::X86_64UnknownLinuxGnu,
        url: "https://static.rust-lang.org/dist/rustfmt-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
        sha256: "dcee5627f709f387cdca416a1d2ae9e6c2581cd117cdb4fd097c56c196384662",
    },
];

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "Rust toolchain")?;
    rust_components(platform).map(|_| ())
}

fn rust_pins(platform: Platform) -> io::Result<Vec<&'static str>> {
    let mut pins: Vec<_> = rust_components(platform)?
        .into_iter()
        .map(|component| component.version)
        .collect();
    pins.sort_unstable();
    pins.dedup();
    Ok(pins)
}

fn rust_component<'a>(components: &'a [&'static RustComponent], name: &str) -> &'a RustComponent {
    components
        .iter()
        .find(|component| component.component == name)
        .expect("validated Rust component set")
}

pub fn rust_identity(platform: Platform, components: &[&'static RustComponent]) -> Identity {
    runtime_identity(
        platform,
        RUST_VERSION,
        rust_component(components, "rustc").sha256,
        rust_component(components, "rust-std").sha256,
        rust_component(components, "cargo").sha256,
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
        let row = selected.artifact(platform, component)?;
        if row.recipe != RUST_RECIPE {
            return Err(err(format!(
                "cargo: recipe {} in tog-toolchain.toml is not known to this tog; upgrade tog",
                row.recipe
            )));
        }
        if row.digest.algo() != "sha256" {
            return Err(err(format!(
                "cargo: {} artifact is a {} digest; this tog realizes Rust from sha256 artifacts",
                row.component,
                row.digest.algo()
            )));
        }
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
pub fn runtime_object_id(platform: Platform, selected: &Selected) -> io::Result<String> {
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

pub fn rust_object_id(platform: Platform, version: &str) -> io::Result<String> {
    if version != RUST_VERSION {
        return Err(err(format!(
            "internal: resolved Rust {version} but only {RUST_VERSION} is realizable"
        )));
    }
    Ok(rust_identity(platform, &rust_components(platform)?).object_id())
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
    let rows = runtime_rows(platform, selected)?;
    let identity = identity_of(platform, &rows);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    let mut tarballs = Vec::new();
    for row in &rows {
        tarballs.push(download_verified_digest_held(
            store,
            activity,
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
/// honor, so the compiled pin table is both the catalog and the answer.
pub fn shipped_selection(version: &str) -> io::Result<Selected> {
    if version != RUST_VERSION {
        return Err(err(format!(
            "internal: resolved Rust {version} but only {RUST_VERSION} is realizable"
        )));
    }
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
        let mut command = Command::new("/usr/bin/tar");
        command
            .args(["-xJf"])
            .arg(tarball.as_os_str())
            .args(["-C"])
            .arg(staged)
            .args(["--strip-components", "2"]);
        let status = crate::kernel::supervise::status(&mut command, activity)
            .map_err(|e| io::Error::new(e.kind(), format!("spawn tar for {component}: {e}")))?;
        if !status.success() {
            return Err(err(format!("{component} tarball extraction failed")));
        }
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
        let status = Command::new("/usr/bin/tar")
            .args(["-xJf"])
            .arg(tarball.as_os_str())
            .args(["-C"])
            .arg(staged)
            .args(["--strip-components", "2"])
            .status()
            .map_err(|e| io::Error::new(e.kind(), format!("spawn tar for {component}: {e}")))?;
        if !status.success() {
            return Err(err(format!("{component} tarball extraction failed")));
        }
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
/// This is the pre-lock answer, and the only callers left are the ones that
/// have no project selection to honor, such as `tog deps`, which reports on
/// a project it never syncs. The Python sdist build of a project whose lock
/// names no Rust uses [`resolve_toolchain_within`] instead: its tree is a
/// store scratch directory that is nobody's tog project.
/// Every entry point that is handed a [`Selected`] takes the version from it
/// instead (`toolchain.version("rustc")`), so the lock decides the toolchain.
/// What the file asks for beyond the channel is read from the lock's rows
/// ([`project_extras`]) or, for an sdist, [`toolchain_file_extras_within`].
pub fn resolve_toolchain(platform: Platform, project_dir: &Path) -> io::Result<&'static str> {
    resolve_toolchain_with(platform, nearest_toolchain_file(project_dir, None), true)
}

/// `resolve_toolchain` for an unpacked sdist: only a toolchain file inside
/// `root` is read. A file above it belongs to whoever owns the store's
/// parent directories (`$HOME`, a repository the store sits in) and must
/// not reach a build whose identity names only the sdist. With none, the
/// newest pin, whatever lies above the store.
pub fn resolve_toolchain_within(platform: Platform, root: &Path) -> io::Result<&'static str> {
    resolve_toolchain_with(platform, nearest_toolchain_file(root, Some(root)), true)
}

/// The version `resolve_toolchain` would choose, without its narration, so
/// a read-only caller (`tog status`, `tog audit`) can ask.
pub fn resolve_toolchain_quiet(platform: Platform, project_dir: &Path) -> io::Result<&'static str> {
    resolve_toolchain_with(platform, nearest_toolchain_file(project_dir, None), false)
}

fn resolve_toolchain_with(
    platform: Platform,
    found: Option<(PathBuf, bool)>,
    effects: bool,
) -> io::Result<&'static str> {
    let _ = rust_pins(platform)?;
    let Some((path, legacy)) = found else {
        return newest_pin(platform);
    };
    let bytes = read_toolchain_file(&path)?;
    // The channel is read by the same reader the toolchain lock records it
    // with, so a file this refuses is one the lock refuses too.
    let channel = if legacy {
        input::read_rust_toolchain_legacy(&bytes)
    } else {
        input::read_rust_toolchain(&bytes)
    }
    .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?
    .ok_or_else(|| err(format!("{}: names no channel", path.display())))?;
    resolve_channel(platform, &path, channel.trim(), effects)
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
) -> io::Result<&'static str> {
    if channel == "stable" {
        let pin = newest_pin(platform)?;
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

fn newest_pin(platform: Platform) -> io::Result<&'static str> {
    rust_pins(platform)?
        .iter()
        .copied()
        .max_by_key(|pin| version_key(pin))
        .ok_or_else(|| no_pin("rust toolchain", platform))
}
