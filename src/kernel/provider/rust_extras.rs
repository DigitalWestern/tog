//! Optional Rust components and cross targets (kernel provider layer): what
//! a rust-toolchain file asks for beyond the base toolchain (rustc, cargo
//! and the host's rust-std), resolved against the release's pinned channel
//! manifest and assembled with the base into the toolchain a project uses.
//!
//! The structure has three kinds of object:
//!
//! - The **base** Rust object (`rust-toolchain/1`), unchanged. A project
//!   that asks for nothing extra uses exactly it, under the id it always had.
//! - One **component** object (`rust-component/1`) per extra archive:
//!   `clippy`, `rust-src`, the `rust-std` of `wasm32-unknown-unknown`, and so
//!   on, each the archive's payload as the Rust installer lays it out. Its
//!   identity is the archive's sha256, the manifest package it came from and
//!   the target, so two projects asking for clippy share one object.
//! - An **assembled** toolchain (`rust-toolchain/2`) per distinct request:
//!   the base and every component merged into one tree, which is what a
//!   project's environment points at. Its identity names the base object,
//!   each component object and the pinned manifest, so a change to any of
//!   them is a new id.
//!
//! Why assembly is a real merged tree rather than the parts composed at
//! projection time: rustc, rustdoc and clippy-driver find their sysroot
//! (the standard libraries, `rust-src`, the LLVM tools) by canonicalizing
//! the path of the `librustc_driver` they loaded and walking up from it. A
//! symlink farm or a PATH of separate objects would resolve back into the
//! base object and never see a cross target's library. A hard link is a
//! second name for the same file, not a pointer to another path, so the
//! merge hard-links every file from the base and component objects: the
//! assembled tree costs directory entries, not bytes, and rustc still
//! resolves to the assembled object. Store objects are immutable, and
//! removing one never changes a file's mode (only its directories are made
//! writable), so a shared inode cannot be altered through either name. Where
//! a link cannot be made (another filesystem, a link-count limit, a hardened
//! link policy) the file is copied with `std::fs::copy`, which clones
//! extents on copy-on-write filesystems (APFS, btrfs, XFS).
//!
//! Where the bytes come from: a component the selected release bundle
//! already carries (rustfmt) is taken from the bundle's own row, the same
//! row `tog fmt` realizes, so the lock stays the one source of truth for
//! it. Everything else comes from the manifest. Before either is used, the
//! manifest is checked against every row of the bundle for this host, so a
//! manifest and a lock that disagree about any byte refuse to assemble.

use super::rust::{self, err};
use super::rust_channel::{self, Archive, ChannelManifest, ANY_TARGET, STD_PACKAGE};
use crate::kernel::activity::StoreActivity;
use crate::kernel::archive::{self, Compression};
use crate::kernel::digest::Digest;
use crate::kernel::fetch::download_verified_digest_held;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::store::{ObjectDeps, Store};
use crate::kernel::toolchain::input::{
    self, InputRow, RUST_TOOLCHAIN_LISTS, RUST_TOOLCHAIN_PROFILE,
};
use crate::kernel::toolchain::{ArtifactSpec, Selected};
use crate::kernel::types::Identity;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The layout recipe of a component object: the archive's payload,
/// extracted with the installer's two leading directories stripped.
pub const COMPONENT_RECIPE: &str = "rust-component/1";

/// The layout recipe of an assembled toolchain: the base object, then every
/// component object in identity order, merged into one tree.
pub const ASSEMBLED_RECIPE: &str = "rust-toolchain/2";

/// The kind of a component object.
pub const COMPONENT_KIND: &str = "rust-component";

/// The installer's per-component file list, which every archive places at
/// the root of its payload. The base keeps its own; a component's would
/// overwrite it, so the merge leaves it in the component object.
const INSTALLER_MANIFEST: &str = "manifest.in";

/// What a toolchain file asks for beyond the channel: component names as
/// written (`clippy`, `rust-analyzer-preview`) and target triples, each
/// sorted and deduplicated, and a rustup profile.
///
/// A profile is a named component set the manifest defines. It is expanded
/// against the manifest when the toolchain is planned, so it never enters an
/// identity: `profile = "default"` and the same components listed by name
/// are one toolchain. No profile means tog's base (rustc, cargo and the
/// host's rust-std, which is rustup's `minimal`), as it always has; rustup
/// itself would install its configured default there.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Extras {
    pub components: Vec<String>,
    pub targets: Vec<String>,
    pub profile: Option<String>,
}

impl Extras {
    /// The request recorded in a project's consulted rows. When both
    /// toolchain files exist, selection has already refused lists that
    /// disagree, so their union is either one.
    pub fn from_rows(rows: &[InputRow]) -> Extras {
        let mut lists: [BTreeSet<String>; 2] = Default::default();
        let mut profile = None;
        for row in rows {
            let Some(value) = row.value.as_deref() else {
                continue;
            };
            if row.field == RUST_TOOLCHAIN_PROFILE.1 {
                profile = Some(value.to_string());
            }
            if let Some(index) = RUST_TOOLCHAIN_LISTS
                .iter()
                .position(|(_, field)| *field == row.field)
            {
                lists[index].extend(input::split_list(value));
            }
        }
        let [components, targets] = lists;
        Extras {
            components: components.into_iter().collect(),
            targets: targets.into_iter().collect(),
            profile,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty() && self.targets.is_empty() && self.profile.is_none()
    }

    /// The part of the request the base object does not already answer:
    /// the base's own components by name and the host's own target.
    fn beyond_base(&self, platform: Platform) -> Extras {
        Extras {
            components: self
                .components
                .iter()
                .filter(|name| !rust::RUNTIME_COMPONENTS.contains(&name.as_str()))
                .cloned()
                .collect(),
            targets: self
                .targets
                .iter()
                .filter(|triple| triple.as_str() != platform.triple())
                .cloned()
                .collect(),
            profile: self.profile.clone(),
        }
    }
}

/// What the project at `project_dir` asks for, read through the same
/// discovery the toolchain lock records and is checked against. A run that
/// honors a lock only gets here after staleness passed, so these are the
/// lock's own rows; the publication recheck refuses the write if the file
/// moves after this read.
pub fn project_extras(project_dir: &Path) -> io::Result<Extras> {
    let root = ProjectRoot::open(project_dir)?;
    Ok(Extras::from_rows(&input::discover(&root, "rust")?))
}

/// What an unpacked sdist's own toolchain file inside `root` asks for.
pub fn toolchain_file_extras_within(root: &Path) -> io::Result<Extras> {
    rust::file_extras_within(root)
}

/// One archive the assembled toolchain adds, and the component object
/// realized from it.
#[derive(Clone, Debug)]
pub(crate) struct Extension {
    pub archive: Archive,
    pub identity: Identity,
}

/// The toolchain one selection and one request name, before anything is
/// fetched but the manifest.
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    /// The pinned manifest the extensions were read from; `None` when the
    /// request needs nothing beyond the base.
    pub manifest: Option<Digest>,
    pub extensions: Vec<Extension>,
    /// The base identity when there are no extensions, the assembled one
    /// otherwise.
    pub identity: Identity,
}

/// Plan the toolchain for `extras`. A request the base already answers
/// reads nothing, so it needs no network and no manifest pin.
fn plan(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
    extras: &Extras,
) -> io::Result<Plan> {
    let rows = rust::runtime_rows(platform, selected)?;
    let wanted = extras.beyond_base(platform);
    if wanted.is_empty() {
        return Ok(Plan {
            manifest: None,
            extensions: Vec::new(),
            identity: rust::identity_of(platform, &rows),
        });
    }
    let version = selected.version("rustc")?;
    let pin = rust::channel_manifest_pin(version)?;
    let manifest = load_manifest(
        store,
        activity,
        version,
        &rust_channel::manifest_url(version),
        &pin,
    )?;
    plan_with_manifest(platform, selected, &wanted, &manifest, &pin)
}

/// The pinned manifest, from the store's content-addressed cache (keyed by
/// the pinned sha256) when it is there, fetched and verified once
/// otherwise. A cached manifest needs no network, so planning an sdist or
/// a sync that has seen this release before works offline; the assembled
/// toolchain lists the entry as a dependency, so GC keeps it while any
/// toolchain built from it lives.
fn load_manifest(
    store: &Store,
    activity: &StoreActivity,
    version: &str,
    url: &str,
    pin: &Digest,
) -> io::Result<ChannelManifest> {
    let lease = download_verified_digest_held(store, activity, url, pin).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("fetch the channel manifest for Rust {version}: {error}"),
        )
    })?;
    let text = fs::read_to_string(&*lease).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("read the channel manifest for Rust {version}: {error}"),
        )
    })?;
    ChannelManifest::parse(version, &text)
}

/// The plan from an already verified manifest: the pure half of [`plan`],
/// which the identity goldens reach with the checked-in fixture.
pub(crate) fn plan_with_manifest(
    platform: Platform,
    selected: &Selected,
    wanted: &Extras,
    manifest: &ChannelManifest,
    pin: &Digest,
) -> io::Result<Plan> {
    let rows = rust::runtime_rows(platform, selected)?;
    let base = rust::identity_of(platform, &rows);
    let version = selected.version("rustc")?.to_string();
    check_bundle_against_manifest(platform, selected, manifest)?;
    let host = platform.triple();
    // The packages the base object already is, spelled as the manifest
    // spells them.
    let base_packages: BTreeSet<&str> = rust::RUNTIME_COMPONENTS
        .iter()
        .map(|name| manifest.package_name(name))
        .collect();
    // Named components are refused when the release lacks them; a profile's
    // packages are the manifest's own list, installed where published, as
    // rustup installs them.
    let mut names: Vec<&str> = wanted.components.iter().map(String::as_str).collect();
    if let Some(profile) = &wanted.profile {
        names.extend(
            manifest
                .profile(profile)?
                .iter()
                .map(String::as_str)
                .filter(|package| manifest.publishes(package, host)),
        );
    }
    let mut archives: BTreeMap<(String, String), Archive> = BTreeMap::new();
    for name in names {
        let package = manifest.package_name(name);
        if base_packages.contains(package) {
            continue;
        }
        let archive = match bundle_component(selected, manifest, package) {
            Some(component) => bundle_archive(platform, selected, component, package)?,
            None => manifest.component(name, host)?,
        };
        archives.insert((archive.package.clone(), archive.target.clone()), archive);
    }
    for triple in &wanted.targets {
        let archive = manifest.target_std(triple)?;
        archives.insert((archive.package.clone(), archive.target.clone()), archive);
    }
    if archives.is_empty() {
        return Ok(Plan {
            manifest: None,
            extensions: Vec::new(),
            identity: base,
        });
    }
    let extensions: Vec<Extension> = archives
        .into_values()
        .map(|archive| Extension {
            identity: component_identity(platform, &version, &archive),
            archive,
        })
        .collect();
    Ok(Plan {
        manifest: Some(pin.clone()),
        identity: assembled_identity(platform, &version, &base.object_id(), pin, &extensions),
        extensions,
    })
}

/// Every row the selected bundle names for this host must be the archive
/// the pinned manifest publishes. The base and rustfmt come from the lock,
/// everything else from the manifest; this is what keeps the two one source.
fn check_bundle_against_manifest(
    platform: Platform,
    selected: &Selected,
    manifest: &ChannelManifest,
) -> io::Result<()> {
    for component in &selected.bundle.components {
        let Some(row) = selected.bundle.artifact(platform, &component.name) else {
            continue;
        };
        let listed = manifest.component(&component.name, platform.triple())?;
        if listed.digest != row.digest {
            return Err(err(format!(
                "the pinned channel manifest for Rust {} lists {} for {} as sha256:{}, but the \
                 toolchain selection names {}:{}; run `tog update --toolchain rust`",
                manifest.version(),
                listed.package,
                platform.triple(),
                listed.digest.hex(),
                row.digest.algo(),
                row.digest.hex()
            )));
        }
    }
    Ok(())
}

/// The bundle component (not part of the base) the manifest publishes as
/// `package`: rustfmt, whose bytes the bundle already pins.
fn bundle_component<'a>(
    selected: &'a Selected,
    manifest: &ChannelManifest,
    package: &str,
) -> Option<&'a str> {
    selected
        .bundle
        .components
        .iter()
        .map(|component| component.name.as_str())
        .filter(|name| !rust::RUNTIME_COMPONENTS.contains(name))
        .find(|name| manifest.package_name(name) == package)
}

fn bundle_archive(
    platform: Platform,
    selected: &Selected,
    component: &str,
    package: &str,
) -> io::Result<Archive> {
    let row: ArtifactSpec = selected.artifact(platform, component)?;
    let compression = if row.url.ends_with(".tar.xz") {
        Compression::Xz
    } else if row.url.ends_with(".tar.gz") {
        Compression::Gzip
    } else {
        return Err(err(format!(
            "rust: the {component} artifact {} is not a .tar.xz or .tar.gz archive",
            row.url
        )));
    };
    Ok(Archive {
        package: package.to_string(),
        target: platform.triple().to_string(),
        url: row.url,
        digest: row.digest,
        compression,
    })
}

/// A component object's identity: the archive's bytes, the manifest package
/// and target they are, and the host they are laid out for.
pub(crate) fn component_identity(platform: Platform, version: &str, archive: &Archive) -> Identity {
    Identity {
        kind: COMPONENT_KIND.into(),
        name: archive.package.clone(),
        version: version.into(),
        inputs: BTreeMap::from([
            ("schema".to_string(), COMPONENT_RECIPE.to_string()),
            ("platform".to_string(), platform.triple().to_string()),
            ("target".to_string(), archive.target.clone()),
            (
                "archive_sha256".to_string(),
                archive.digest.hex().to_string(),
            ),
        ]),
    }
}

/// The input key naming one extension of an assembled toolchain.
pub(crate) fn extension_key(archive: &Archive) -> String {
    format!("ext:{}@{}", archive.package, archive.target)
}

/// An assembled toolchain's identity: the base object, each component
/// object under its package and target, the count of them (so a dropped
/// `ext:` key cannot collide with a smaller request), and the manifest
/// every component row was read from.
pub(crate) fn assembled_identity(
    platform: Platform,
    version: &str,
    base_id: &str,
    manifest: &Digest,
    extensions: &[Extension],
) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), ASSEMBLED_RECIPE.to_string()),
        ("platform".to_string(), platform.triple().to_string()),
        ("base".to_string(), base_id.to_string()),
        (
            "channel_manifest_sha256".to_string(),
            manifest.hex().to_string(),
        ),
        ("extensions".to_string(), extensions.len().to_string()),
    ]);
    for extension in extensions {
        inputs.insert(
            extension_key(&extension.archive),
            extension.identity.object_id(),
        );
    }
    Identity {
        kind: "rust".into(),
        name: "rust".into(),
        version: version.into(),
        inputs,
    }
}

/// The id of the toolchain `selected` and `extras` name, without realizing
/// it. With extras beyond the base this reads the pinned manifest (from the
/// store cache, or the network the first time).
pub fn toolchain_object_id(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
    extras: &Extras,
) -> io::Result<String> {
    Ok(plan(store, activity, platform, selected, extras)?
        .identity
        .object_id())
}

/// Realize the toolchain `selected` and `extras` name: the base object when
/// nothing beyond it is asked for, otherwise every component object and the
/// assembled toolchain over them. A component or target the pinned release
/// does not publish for this host is an error naming it; nothing is
/// substituted and nothing is skipped.
pub fn realize_toolchain(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
    extras: &Extras,
) -> io::Result<PathBuf> {
    crate::kernel::platform::require_host(platform, "Rust toolchain")?;
    let plan = plan(store, activity, platform, selected, extras)?;
    let Some(manifest) = plan.manifest.clone() else {
        return rust::realize_runtime(store, activity, platform, selected);
    };
    let id = plan.identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let base = rust::realize_runtime(store, activity, platform, selected)?;
    let mut parts = Vec::new();
    for extension in &plan.extensions {
        parts.push((extension, realize_component(store, activity, extension)?));
    }
    let staged = store.stage_with_activity(activity)?;
    let assembled = assemble(&staged, &base, &parts).and_then(|()| {
        rust::validate_rust_layout(&staged, platform)?;
        for (extension, _) in &parts {
            check_std_layout(&staged, &extension.archive)?;
        }
        Ok(())
    });
    if let Err(error) = assembled {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }
    let mut deps = ObjectDeps::new();
    deps.object_id(&base_id(&base)?)?;
    for (extension, _) in &parts {
        deps.object_id(&extension.identity.object_id())?;
    }
    deps.cache_digest(manifest);
    store
        .commit_with_activity_and_deps(activity, &plan.identity, &staged, &[], &deps)
        .map(|(path, _)| path)
        .map_err(|e| io::Error::new(e.kind(), format!("commit assembled Rust toolchain: {e}")))
}

fn base_id(base: &Path) -> io::Result<String> {
    base.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_string)
        .ok_or_else(|| err("the base Rust object has no UTF-8 id"))
}

/// Realize one component object from its archive.
fn realize_component(
    store: &Store,
    activity: &StoreActivity,
    extension: &Extension,
) -> io::Result<PathBuf> {
    let id = extension.identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let archive = &extension.archive;
    let lease = download_verified_digest_held(store, activity, &archive.url, &archive.digest)?;
    let entries = archive::list_with_activity(activity, &lease, archive.compression)?;
    check_installer_layout(&entries, archive)?;
    let staged = store.stage_with_activity(activity)?;
    let extracted = archive::extract_validated_with_activity(
        activity,
        &lease,
        &staged,
        2,
        archive.compression,
        &entries,
    )
    .and_then(|()| check_std_layout(&staged, archive))
    .and_then(|()| check_payload(&staged, archive));
    if let Err(error) = extracted {
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(error);
    }
    let mut deps = ObjectDeps::new();
    deps.cache_digest(archive.digest.clone());
    store
        .commit_with_activity_and_deps(activity, &extension.identity, &staged, &[], &deps)
        .map(|(path, _)| path)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("commit Rust component {}: {e}", archive.package),
            )
        })
}

/// A Rust installer archive has one root directory, and its payload is one
/// component directory under it; the two are what `--strip-components 2`
/// removes. More than one component directory would merge unrelated
/// payloads into one object, so it is refused.
fn check_installer_layout(entries: &[archive::Entry], archive: &Archive) -> io::Result<()> {
    let mut roots = BTreeSet::new();
    let mut payloads = BTreeSet::new();
    for entry in entries {
        let mut parts = entry.name.trim_end_matches('/').split('/');
        if let Some(root) = parts.next() {
            roots.insert(root.to_string());
        }
        if let (Some(directory), Some(_)) = (parts.next(), parts.next()) {
            payloads.insert(directory.to_string());
        }
    }
    if roots.len() != 1 || payloads.len() != 1 {
        return Err(err(format!(
            "Rust {} archive for {} has an unexpected layout (roots {roots:?}, payloads {payloads:?})",
            archive.package, archive.target
        )));
    }
    Ok(())
}

/// A standard library must land where rustc looks for its target.
fn check_std_layout(tree: &Path, archive: &Archive) -> io::Result<()> {
    if archive.package == STD_PACKAGE && archive.target != ANY_TARGET {
        let libdir = tree.join("lib/rustlib").join(&archive.target).join("lib");
        if !libdir.is_dir() {
            return Err(err(format!(
                "the rust-std archive for {} has no lib/rustlib/{}/lib; refusing to commit",
                archive.target, archive.target
            )));
        }
    }
    Ok(())
}

/// A component object holds something besides the installer's file list.
fn check_payload(staged: &Path, archive: &Archive) -> io::Result<()> {
    for entry in fs::read_dir(staged)? {
        if entry?.file_name() != INSTALLER_MANIFEST {
            return Ok(());
        }
    }
    Err(err(format!(
        "Rust {} archive for {} extracted nothing; refusing to commit",
        archive.package, archive.target
    )))
}

/// Merge the base, then each component in identity order, into `staged`.
fn assemble(staged: &Path, base: &Path, parts: &[(&Extension, PathBuf)]) -> io::Result<()> {
    merge_tree(base, staged, Path::new(""), "the base toolchain", false)?;
    for (extension, object) in parts {
        let owner = format!(
            "{} for {}",
            extension.archive.package, extension.archive.target
        );
        merge_tree(object, staged, Path::new(""), &owner, true)?;
    }
    Ok(())
}

/// Copy `source` into `dest`, merging directories. A file or link that is
/// already there is accepted only when it is the same bytes or the same
/// target: two parts of a toolchain that disagree about a path refuse to
/// assemble rather than let merge order decide, which is what rustup does
/// with conflicting components.
fn merge_tree(
    source: &Path,
    dest: &Path,
    relative: &Path,
    owner: &str,
    skip_installer_manifest: bool,
) -> io::Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        if skip_installer_manifest && relative.as_os_str().is_empty() && name == INSTALLER_MANIFEST
        {
            continue;
        }
        let from = entry.path();
        let to = dest.join(&name);
        let path = relative.join(&name);
        let conflict = || {
            err(format!(
                "{owner} and another part of the Rust toolchain both ship {} with different \
                 contents; refusing to assemble",
                path.display()
            ))
        };
        let kind = fs::symlink_metadata(&from)?.file_type();
        let existing = match fs::symlink_metadata(&to) {
            Ok(metadata) => Some(metadata.file_type()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if kind.is_symlink() {
            let target = fs::read_link(&from)?;
            match existing {
                None => std::os::unix::fs::symlink(&target, &to)?,
                Some(existing) if existing.is_symlink() && fs::read_link(&to)? == target => {}
                Some(_) => return Err(conflict()),
            }
        } else if kind.is_dir() {
            match existing {
                None => fs::create_dir(&to)?,
                Some(existing) if existing.is_dir() => {}
                Some(_) => return Err(conflict()),
            }
            merge_tree(&from, &to, &path, owner, skip_installer_manifest)?;
        } else if kind.is_file() {
            match existing {
                None => link_or_copy(&from, &to)?,
                Some(existing) if existing.is_file() && fs::read(&from)? == fs::read(&to)? => {}
                Some(_) => return Err(conflict()),
            }
        } else {
            return Err(err(format!(
                "{owner} ships {}, which is not a file, directory or symlink",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Give `to` the bytes of the immutable store file `from`: a hard link when
/// the filesystem allows one, a copy (a reflink where supported) otherwise.
fn link_or_copy(from: &Path, to: &Path) -> io::Result<()> {
    match fs::hard_link(from, to) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EXDEV | libc::EMLINK | libc::EPERM | libc::EACCES)
            ) =>
        {
            fs::copy(from, to).map(|_| ())
        }
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "link {} into the assembled toolchain: {error}",
                from.display()
            ),
        )),
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// The checked-in manifest fixture, parsed as the release it trims.
    pub fn manifest() -> ChannelManifest {
        ChannelManifest::parse(rust::RUST_VERSION, rust_channel::FIXTURE).unwrap()
    }

    pub fn pin() -> Digest {
        rust::channel_manifest_pin(rust::RUST_VERSION).unwrap()
    }

    pub fn shipped() -> Selected {
        rust::shipped_selection(rust::RUST_VERSION).unwrap()
    }

    pub fn extras(components: &[&str], targets: &[&str]) -> Extras {
        Extras {
            components: components.iter().map(|name| name.to_string()).collect(),
            targets: targets.iter().map(|name| name.to_string()).collect(),
            profile: None,
        }
    }

    /// The plan the shipped selection and `extras` give on `platform`.
    pub fn plan_for(platform: Platform, extras: &Extras) -> io::Result<Plan> {
        plan_with_manifest(
            platform,
            &shipped(),
            &extras.beyond_base(platform),
            &manifest(),
            &pin(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    const LINUX: Platform = Platform::X86_64UnknownLinuxGnu;
    const DARWIN: Platform = Platform::Aarch64AppleDarwin;

    fn row(path: &str, field: &str, value: Option<&str>) -> InputRow {
        InputRow {
            path: PathBuf::from(path),
            field: field.to_string(),
            value: value.map(str::to_string),
            absent: value.is_none(),
            sha256: Some("0".repeat(64)),
        }
    }

    #[test]
    fn extras_come_from_the_recorded_list_rows() {
        let rows = vec![
            row("rust-toolchain", "toolchain.channel", None),
            row("rust-toolchain.toml", "toolchain.channel", Some("1.96.1")),
            row(
                "rust-toolchain.toml",
                "toolchain.components",
                Some("clippy,rustfmt"),
            ),
            row(
                "rust-toolchain.toml",
                "toolchain.targets",
                Some("wasm32-unknown-unknown"),
            ),
        ];
        assert_eq!(
            Extras::from_rows(&rows),
            extras(&["clippy", "rustfmt"], &["wasm32-unknown-unknown"])
        );
        assert!(Extras::from_rows(&rows[..2]).is_empty());
    }

    /// The pinned catalog and the pinned manifest are one source: every row
    /// the catalog ships (the base three and rustfmt, both hosts) is the
    /// archive the manifest publishes.
    #[test]
    fn the_catalog_rows_are_the_manifest_rows() {
        let manifest = manifest();
        for platform in Platform::ALL {
            check_bundle_against_manifest(*platform, &shipped(), &manifest).unwrap();
        }
        // A selection naming other bytes than the manifest refuses.
        let mut drifted = shipped();
        for row in &mut drifted.bundle.artifacts {
            if row.component == "rustfmt" && row.platform == LINUX {
                row.digest = Digest::sha256(&"f".repeat(64)).unwrap();
            }
        }
        let error = check_bundle_against_manifest(LINUX, &drifted, &manifest).unwrap_err();
        assert!(error.to_string().contains("rustfmt-preview"), "{error}");
        assert!(
            error.to_string().contains("tog update --toolchain rust"),
            "{error}"
        );
        // Every shipped release has a pinned manifest.
        for bundle in rust::toolchain_catalog().unwrap().bundles() {
            let version = &bundle.component("rustc").unwrap().version;
            assert!(rust::channel_manifest_pin(version).is_ok(), "{version}");
        }
    }

    #[test]
    fn nothing_beyond_the_base_is_the_base_object() {
        let selected = shipped();
        for platform in Platform::ALL {
            let base = rust::runtime_object_id(*platform, &selected).unwrap();
            let request = extras(&["rustc", "cargo", "rust-std"], &[platform.triple()]);
            assert!(request.beyond_base(*platform).is_empty());
            let plan = plan_for(*platform, &request).unwrap();
            assert!(plan.extensions.is_empty());
            assert_eq!(plan.manifest, None);
            assert_eq!(plan.identity.object_id(), base);
        }
    }

    #[test]
    fn components_and_targets_become_extensions_in_identity_order() {
        let plan = plan_for(
            LINUX,
            &extras(
                &["rustfmt", "clippy", "rust-src", "clippy-preview"],
                &["wasm32-unknown-unknown", "x86_64-unknown-linux-gnu"],
            ),
        )
        .unwrap();
        let keys: Vec<String> = plan
            .extensions
            .iter()
            .map(|extension| extension_key(&extension.archive))
            .collect();
        assert_eq!(
            keys,
            vec![
                "ext:clippy-preview@x86_64-unknown-linux-gnu",
                "ext:rust-src@*",
                "ext:rust-std@wasm32-unknown-unknown",
                "ext:rustfmt-preview@x86_64-unknown-linux-gnu",
            ]
        );
        // rustfmt is the bundle's own row: the lock's URL, not the
        // manifest's dated one, with the bytes both agree on.
        let rustfmt = &plan.extensions[3].archive;
        let pinned = shipped().artifact(LINUX, "rustfmt").unwrap();
        assert_eq!(rustfmt.url, pinned.url);
        assert_eq!(rustfmt.digest, pinned.digest);
        assert_eq!(plan.manifest, Some(pin()));
        assert_eq!(plan.identity.inputs["extensions"], "4");
        assert_eq!(
            plan.identity.inputs["base"],
            rust::runtime_object_id(LINUX, &shipped()).unwrap()
        );
    }

    /// A profile expands to the manifest's list, installed where the host
    /// has it (rustup's rule), and is not itself part of any identity.
    #[test]
    fn profiles_expand_against_the_manifest() {
        let with_profile = |profile: &str, components: &[&str]| Extras {
            profile: Some(profile.to_string()),
            ..extras(components, &[])
        };
        let keys = |plan: &Plan| -> Vec<String> {
            plan.extensions
                .iter()
                .map(|extension| extension_key(&extension.archive))
                .collect()
        };
        for platform in Platform::ALL {
            // minimal is the base: rust-mingw exists only for Windows.
            let minimal = plan_for(*platform, &with_profile("minimal", &[])).unwrap();
            assert!(minimal.extensions.is_empty());
            assert_eq!(
                minimal.identity.object_id(),
                rust::runtime_object_id(*platform, &shipped()).unwrap()
            );
            // default is the same toolchain as its components by name.
            let default = plan_for(*platform, &with_profile("default", &[])).unwrap();
            let named =
                plan_for(*platform, &extras(&["clippy", "rustfmt", "rust-docs"], &[])).unwrap();
            assert_eq!(default.identity.object_id(), named.identity.object_id());
        }
        let default = plan_for(LINUX, &with_profile("default", &["rust-src"])).unwrap();
        assert_eq!(
            keys(&default),
            [
                "ext:clippy-preview@x86_64-unknown-linux-gnu",
                "ext:rust-docs@x86_64-unknown-linux-gnu",
                "ext:rust-src@*",
                "ext:rustfmt-preview@x86_64-unknown-linux-gnu",
            ]
        );
        // complete skips what this release marks unavailable (miri) or does
        // not publish in the fixture, where a named component would refuse.
        let complete = plan_for(LINUX, &with_profile("complete", &[])).unwrap();
        let complete = keys(&complete);
        assert!(complete.contains(&"ext:rust-analyzer-preview@x86_64-unknown-linux-gnu".into()));
        assert!(complete.contains(&"ext:llvm-tools-preview@x86_64-unknown-linux-gnu".into()));
        assert!(
            !complete.iter().any(|key| key.contains("miri")),
            "{complete:?}"
        );
        assert!(plan_for(LINUX, &extras(&["miri"], &[])).is_err());
        // A profile the manifest does not define is refused.
        let error = plan_for(LINUX, &with_profile("bespoke", &[])).unwrap_err();
        assert!(
            error.to_string().contains("profile named bespoke"),
            "{error}"
        );
    }

    #[test]
    fn what_the_release_does_not_publish_is_a_hard_error() {
        for (request, words) in [
            (
                extras(&["no-such-tool"], &[]),
                "component named no-such-tool",
            ),
            (extras(&["miri"], &[]), "marks it unavailable"),
            (extras(&["rust-mingw"], &[]), "component rust-mingw for"),
            (
                extras(&[], &["riscv99-unknown-none"]),
                "target riscv99-unknown-none",
            ),
        ] {
            let error = plan_for(LINUX, &request).unwrap_err();
            assert!(error.to_string().contains(words), "{error}");
        }
    }

    /// The assembled ids for one request on each host. They are new ids; the
    /// base ids they name are the existing goldens, unchanged.
    #[test]
    fn assembled_identity_goldens() {
        let request = extras(
            &["clippy", "rustfmt", "rust-src"],
            &["wasm32-unknown-unknown"],
        );
        let linux = plan_for(LINUX, &request).unwrap();
        let darwin = plan_for(DARWIN, &request).unwrap();
        assert_eq!(
            darwin.identity.inputs["base"],
            "b8418440835c4ec1f591381a17ae60ab12d1c727-rust-1.96.1"
        );
        let clippy = &linux.extensions[0].identity;
        assert_eq!(clippy.kind, COMPONENT_KIND);
        assert_eq!(
            clippy.inputs["archive_sha256"],
            "385644867534c30c490f4507d61485a799f81dfaec7e2a91290a41bf43d8286a"
        );
        assert_eq!(
            [
                linux.identity.object_id(),
                darwin.identity.object_id(),
                clippy.object_id(),
            ],
            [
                "f35a096aff38189658e04642246b36847e6525f5-rust-1.96.1".to_string(),
                "e15b8c4efca3cbf4dce9edbf5976f605691ae588-rust-1.96.1".to_string(),
                "7b1a92376dcd21523e257f662637a3a41b7af8b8-clippy-preview-1.96.1".to_string(),
            ]
        );
    }

    #[test]
    fn merging_refuses_a_path_two_parts_disagree_about() {
        let temp = crate::kernel::testutil::TempDir::new();
        let (base, part, dest) = (
            temp.0.join("base"),
            temp.0.join("part"),
            temp.0.join("dest"),
        );
        for dir in [&base, &part, &dest] {
            fs::create_dir_all(dir.join("share/doc")).unwrap();
        }
        fs::write(base.join("manifest.in"), "base\n").unwrap();
        fs::write(base.join("share/doc/LICENSE"), "same\n").unwrap();
        fs::write(part.join("manifest.in"), "part\n").unwrap();
        fs::write(part.join("share/doc/LICENSE"), "same\n").unwrap();
        fs::create_dir_all(part.join("bin")).unwrap();
        fs::write(part.join("bin/tool"), "tool\n").unwrap();
        merge_tree(&base, &dest, Path::new(""), "base", false).unwrap();
        merge_tree(&part, &dest, Path::new(""), "part", true).unwrap();
        // The base keeps its installer list; identical files are accepted.
        assert_eq!(
            fs::read_to_string(dest.join("manifest.in")).unwrap(),
            "base\n"
        );
        assert_eq!(fs::read_to_string(dest.join("bin/tool")).unwrap(), "tool\n");
        fs::write(part.join("share/doc/LICENSE"), "different\n").unwrap();
        let error = merge_tree(&part, &dest, Path::new(""), "part", true).unwrap_err();
        assert!(error.to_string().contains("share/doc/LICENSE"), "{error}");
    }

    /// A manifest the store has cached is read from the cache: an address
    /// nothing answers on is never contacted. Without the entry, the same
    /// call fails naming the manifest.
    #[test]
    fn a_cached_manifest_plans_offline() {
        let temp = crate::kernel::testutil::TempDir::new();
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let fixture = temp.0.join("channel-rust.toml");
        fs::write(&fixture, rust_channel::FIXTURE).unwrap();
        let pin = Digest::sha256(
            &crate::kernel::fetch::hash_file(&fixture, crate::kernel::digest::Algo::Sha256)
                .unwrap(),
        )
        .unwrap();
        let offline = "http://127.0.0.1:9/channel-rust-1.96.1.toml";
        let error =
            load_manifest(&store, &activity, rust::RUST_VERSION, offline, &pin).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("channel manifest for Rust 1.96.1"),
            "{error}"
        );
        crate::kernel::fetch::cache_insert(&store, &activity, &fixture).unwrap();
        let manifest = load_manifest(&store, &activity, rust::RUST_VERSION, offline, &pin).unwrap();
        let wanted = extras(&["clippy"], &["wasm32-unknown-unknown"]);
        let plan = plan_with_manifest(LINUX, &shipped(), &wanted, &manifest, &pin).unwrap();
        assert_eq!(plan.extensions.len(), 2);
        assert_eq!(plan.manifest, Some(pin));
    }

    /// The assembled tree links the parts' files instead of copying them,
    /// and removing it (a failed stage, or GC) leaves the parts' read-only
    /// files exactly as they were.
    #[test]
    fn assembly_links_files_and_removal_leaves_the_parts_intact() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let temp = crate::kernel::testutil::TempDir::new();
        let (base, dest) = (temp.0.join("base"), temp.0.join("dest"));
        fs::create_dir_all(base.join("lib")).unwrap();
        fs::create_dir_all(&dest).unwrap();
        let file = base.join("lib/librustc_driver.so");
        fs::write(&file, "driver\n").unwrap();
        crate::kernel::store::make_read_only_for_test(&base).unwrap();
        merge_tree(&base, &dest, Path::new(""), "base", false).unwrap();
        let linked = dest.join("lib/librustc_driver.so");
        assert_eq!(
            fs::metadata(&linked).unwrap().ino(),
            fs::metadata(&file).unwrap().ino()
        );
        crate::kernel::store::make_read_only_for_test(&dest).unwrap();
        crate::kernel::store::remove_tree(&dest).unwrap();
        assert!(!dest.exists());
        assert_eq!(fs::read_to_string(&file).unwrap(), "driver\n");
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o222, 0);
        crate::kernel::store::remove_tree(&base).unwrap();
    }
}
