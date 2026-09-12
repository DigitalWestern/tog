//! The Cargo tailor: Cargo.lock importer and registry vendor realization.

pub mod rustfmt;

use crate::fetch::{download_verified_held, Digest};
use crate::platform::{no_pin, Platform};
use crate::store::Store;
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const RUST_VERSION: &str = "1.96.1";

struct RustComponent {
    platform: Platform,
    component: &'static str,
    version: &'static str,
    url: &'static str,
    sha256: &'static str,
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

fn rust_components(platform: Platform) -> io::Result<Vec<&'static RustComponent>> {
    let components: Vec<_> = RUST_COMPONENTS
        .iter()
        .filter(|component| component.platform == platform)
        .collect();
    let complete = components.len() == 3
        && ["rustc", "rust-std", "cargo"]
            .iter()
            .all(|name| components.iter().filter(|c| c.component == *name).count() == 1);
    if !complete {
        return Err(no_pin("rust toolchain", platform, "stage 4"));
    }
    Ok(components)
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::platform::require_host(platform, "Rust toolchain", "stage 4")?;
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

fn rust_identity(platform: Platform, components: &[&'static RustComponent]) -> Identity {
    Identity {
        kind: "rust".into(),
        name: "rust".into(),
        version: RUST_VERSION.into(),
        inputs: BTreeMap::from([
            // Schema commits the extraction/layout recipe, not just the
            // bytes: changing how components merge must change the id.
            ("schema".to_string(), "rust-toolchain/1".to_string()),
            (
                "cargo_sha256".to_string(),
                rust_component(components, "cargo").sha256.to_string(),
            ),
            ("platform".to_string(), platform.triple().to_string()),
            (
                "rust_std_sha256".to_string(),
                rust_component(components, "rust-std").sha256.to_string(),
            ),
            (
                "rustc_sha256".to_string(),
                rust_component(components, "rustc").sha256.to_string(),
            ),
        ]),
    }
}

pub(crate) fn rust_object_id(platform: Platform, version: &str) -> io::Result<String> {
    if version != RUST_VERSION {
        return Err(err(format!(
            "internal: resolved Rust {version} but only {RUST_VERSION} is realizable"
        )));
    }
    Ok(rust_identity(platform, &rust_components(platform)?).object_id())
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Ensure the pinned Rust toolchain is realized in the store. Takes the
/// resolved version so a future second pin can't silently realize the
/// wrong toolchain (only RUST_VERSION is realizable today).
pub fn ensure_rust(store: &Store, version: &str) -> io::Result<PathBuf> {
    ensure_rust_for(store, Platform::host()?, version)
}

pub fn ensure_rust_for(store: &Store, platform: Platform, version: &str) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "Rust toolchain", "stage 4")?;
    let activity = store.activity(crate::activity::ActivityMode::Shared)?;
    let components = rust_components(platform)?;
    if version != RUST_VERSION {
        return Err(err(format!(
            "internal: resolved Rust {version} but only {RUST_VERSION} is realizable"
        )));
    }
    let identity = rust_identity(platform, &components);
    let id = identity.object_id();
    if store.has_with_activity(&activity, &id)? {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let mut tarballs = Vec::new();
    for component in &components {
        tarballs.push(download_verified_held(
            store,
            component.url,
            component.sha256,
        )?);
    }

    let staged = store.stage_with_activity(&activity)?;
    extract_rust_components_for(store, &staged, platform, &components, &tarballs)?;

    store
        .commit_with_activity_and_deps(&activity, &identity, &staged, &[], &{
            let mut deps = crate::store::ObjectDeps::new();
            for component in &components {
                deps.cache_digest(Digest::sha256(component.sha256)?);
            }
            deps
        })
        .map(|(path, _)| path)
        .map_err(|e| io::Error::new(e.kind(), format!("commit rust object: {e}")))
}

fn extract_rust_components_for(
    store: &Store,
    staged: &Path,
    platform: Platform,
    components: &[&RustComponent],
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
        let status = crate::supervise::status_owned(&mut command, store).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("spawn tar for {}: {e}", component.component),
            )
        })?;
        if !status.success() {
            return Err(err(format!(
                "{} tarball extraction failed",
                component.component
            )));
        }
    }
    validate_rust_layout(staged, platform)
}

#[cfg(test)]
fn extract_rust_components(
    staged: &Path,
    platform: Platform,
    components: &[&RustComponent],
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
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("spawn tar for {}: {e}", component.component),
                )
            })?;
        if !status.success() {
            return Err(err(format!(
                "{} tarball extraction failed",
                component.component
            )));
        }
    }
    validate_rust_layout(staged, platform)
}

fn validate_rust_layout(staged: &Path, platform: Platform) -> io::Result<()> {
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

#[derive(Debug, Deserialize)]
struct ToolchainDocument {
    toolchain: Option<ToolchainSpec>,
}

#[derive(Debug, Deserialize)]
struct ToolchainSpec {
    channel: Option<String>,
    components: Option<Vec<String>>,
    targets: Option<Vec<String>>,
}

/// Resolve the nearest rustup-style toolchain file to the pinned version.
pub fn resolve_toolchain(platform: Platform, project_dir: &Path) -> io::Result<&'static str> {
    let _ = rust_pins(platform)?;
    let mut dir = project_dir;
    loop {
        let legacy = dir.join("rust-toolchain");
        if legacy.exists() {
            return resolve_toolchain_file(platform, &legacy, true);
        }
        let toml = dir.join("rust-toolchain.toml");
        if toml.exists() {
            return resolve_toolchain_file(platform, &toml, false);
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => break,
        }
    }
    Ok(newest_pin(platform)?)
}

fn resolve_toolchain_file(
    platform: Platform,
    path: &Path,
    legacy: bool,
) -> io::Result<&'static str> {
    let text = fs::read_to_string(path)
        .map_err(|e| io::Error::new(e.kind(), format!("read {}: {e}", path.display())))?;
    if legacy {
        if let Ok(document) = toml::from_str::<ToolchainDocument>(&text) {
            if let Some(spec) = document.toolchain {
                return resolve_toolchain_spec(platform, path, spec);
            }
        }
        return resolve_channel(platform, path, text.trim());
    }
    let document = toml::from_str::<ToolchainDocument>(&text)
        .map_err(|e| err(format!("parse {}: {e}", path.display())))?;
    let spec = document
        .toolchain
        .ok_or_else(|| err(format!("{} has no [toolchain] table", path.display())))?;
    resolve_toolchain_spec(platform, path, spec)
}

fn resolve_toolchain_spec(
    platform: Platform,
    path: &Path,
    spec: ToolchainSpec,
) -> io::Result<&'static str> {
    if let Some(targets) = spec.targets {
        for target in targets {
            if target != platform.triple() {
                return Err(err(format!(
                    "{}: target {target:?} is unsupported; only {} is pinned",
                    path.display(),
                    platform.triple()
                )));
            }
        }
    }
    if let Some(components) = spec.components {
        let unavailable: Vec<String> = components
            .iter()
            .filter(|component| !matches!(component.as_str(), "rustc" | "cargo" | "rust-std"))
            .cloned()
            .collect();
        if !unavailable.is_empty() {
            crate::policy::record(
                crate::policy::TOOLCHAIN_COMPONENT_UNAVAILABLE,
                &path.display().to_string(),
                &format!("components unavailable: {}", unavailable.join(", ")),
            )?;
        }
    }
    let channel = spec
        .channel
        .ok_or_else(|| err(format!("{}: [toolchain] has no channel", path.display())))?;
    resolve_channel(platform, path, channel.trim())
}

fn resolve_channel(platform: Platform, path: &Path, channel: &str) -> io::Result<&'static str> {
    if channel == "stable" {
        let pin = newest_pin(platform)?;
        eprintln!(
            "blanket: {} resolves stable to pinned Rust {pin}",
            path.display()
        );
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
        .ok_or_else(|| no_pin("rust toolchain", platform, "stage 4"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CargoCrate {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub url: String,
    /// A git dependency pinned to a commit: the crate's files
    /// come from the realized commit instead of a registry `.crate` archive,
    /// and `source` is the lock's exact source string, which the generated
    /// cargo config must replace verbatim.
    pub git: Option<CargoGitSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CargoGitSource {
    /// The lockfile's `source` value, e.g. `git+https://host/o/r?rev=<sha>#<sha>`.
    pub source: String,
    /// The git reference the lock names: cargo keys source replacement on the
    /// SourceId (url plus reference kind), so a `?branch=`/`?tag=` source must
    /// be replaced with the same kind, not with `rev`.
    pub reference: CargoGitReference,
    #[serde(skip)]
    pub inner: crate::gitsrc::GitSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CargoGitReference {
    Branch(String),
    Tag(String),
    Rev(String),
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CargoPlan {
    pub rust_version: String,
    pub crates: Vec<CargoCrate>,
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CargoLock {
    version: Option<u64>,
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Debug, Deserialize)]
struct LockPackage {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
}

const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const SPARSE_SOURCE: &str = "sparse+https://index.crates.io/";

/// Parse the complete Cargo.lock closure into a registry-only vendor plan.
pub fn plan_cargo(lock_toml: &str, rust_version: &str) -> io::Result<CargoPlan> {
    let lock =
        toml::from_str::<CargoLock>(lock_toml).map_err(|e| err(format!("Cargo.lock: {e}")))?;
    let version = lock.version.ok_or_else(|| {
        err("Cargo.lock has no version (v1/v2-era lockfile); run cargo update or regenerate the lockfile")
    })?;
    if version != 3 && version != 4 {
        return Err(err(format!(
            "unsupported Cargo.lock version {version} (need 3 or 4; run cargo update or regenerate the lockfile)"
        )));
    }

    let mut crates = Vec::new();
    let mut members = Vec::new();
    let mut seen = BTreeSet::new();
    for package in lock.package {
        let name = package
            .name
            .ok_or_else(|| err("Cargo.lock package is missing name"))?;
        let version = package
            .version
            .ok_or_else(|| err(format!("Cargo.lock package {name:?} is missing version")))?;
        validate_crate_component("name", &name)?;
        validate_crate_component("version", &version)?;
        if !seen.insert((name.clone(), version.clone())) {
            return Err(err(format!(
                "duplicate Cargo.lock package {name}@{version}"
            )));
        }

        match package.source.as_deref() {
            None => members.push(name),
            Some(REGISTRY_SOURCE) | Some(SPARSE_SOURCE) => {
                let checksum = package.checksum.ok_or_else(|| {
                    err(format!(
                        "registry crate {name}@{version} is missing checksum"
                    ))
                })?;
                let checksum = normalize_checksum(&checksum)?;
                crates.push(CargoCrate {
                    url: format!("https://static.crates.io/crates/{name}/{name}-{version}.crate"),
                    name,
                    version,
                    sha256: checksum,
                    git: None,
                });
            }
            Some(source) if source.starts_with("git+") => {
                if let Some(git) = parse_cargo_git_source(source) {
                    crates.push(CargoCrate {
                        url: git.inner.url.clone(),
                        name,
                        version,
                        // The commit is the verification; there is no crate
                        // archive to checksum.
                        sha256: String::new(),
                        git: Some(git),
                    });
                    continue;
                }
                return Err(err(
                    "git dependency is not pinned to a commit; add a rev= or regenerate the lock",
                ));
            }
            Some(source) => {
                return Err(err(format!(
                    "unsupported Cargo source {source:?}; alternative registries are unsupported in v0"
                )));
            }
        }
    }

    Ok(CargoPlan {
        rust_version: rust_version.to_string(),
        crates,
        members,
    })
}

fn validate_crate_component(kind: &str, value: &str) -> io::Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(err(format!(
            "invalid crate {kind} {value:?}; only [A-Za-z0-9._+-] is allowed"
        )));
    }
    Ok(())
}

fn normalize_checksum(checksum: &str) -> io::Result<String> {
    let checksum = checksum.to_ascii_lowercase();
    if checksum.len() != 64 || !checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err(format!(
            "invalid Cargo crate checksum {checksum:?}; expected 64 hexadecimal characters"
        )));
    }
    Ok(checksum)
}

/// Realize the registry closure as a Cargo directory source.
///
/// The Rust toolchain is deliberately **not** a dependency of the result.
/// `realize_vendor_inner` runs `/usr/bin/tar` and nothing else — no part of
/// the toolchain is a build input — and `vendor_identity` does not commit to
/// one, so recording it would let the same identity be published with two
/// different dependency sets. That divergence is unrecoverable: the second
/// publication is a cache hit, and `validate_cached_dependency_evidence`
/// makes a cache hit with different evidence a hard error, so the store
/// stops being syncable. The toolchain object is retained by the project's
/// own `root/2` closure, which records `rust_object` directly.
///
/// This replaces the earlier `realize_vendor_with_rust`. The plan's D.2
/// table lists a rust object for row 6; the call-site audit it asks for
/// showed the pairing is not a realized build input. See the deviation note
/// in the ARCHITECTURE.md coverage matrix.
pub fn realize_vendor(store: &Store, plan: &CargoPlan) -> io::Result<PathBuf> {
    preflight_platform(Platform::host()?)?;
    realize_vendor_inner(store, plan)
}

/// Parse a Cargo lock `source` for a git dependency pinned to a commit.
///
/// Cargo writes `git+<url>?rev=<ref>#<commit>` (also `?branch=`/`?tag=`, and
/// sometimes no query at all). The fragment is always the resolved commit,
/// which is what blanket realizes; the whole string is kept because the
/// generated config's `[source."…"]` key must match it exactly.
pub(crate) fn parse_cargo_git_source(source: &str) -> Option<CargoGitSource> {
    let rest = source.strip_prefix("git+")?;
    let (locator, commit) = rest.rsplit_once('#')?;
    if !crate::gitsrc::is_full_commit(commit) {
        return None;
    }
    let (url, query) = match locator.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (locator, None),
    };
    let reference = query
        .and_then(|query| {
            query.split('&').find_map(|part| {
                let (key, value) = part.split_once('=')?;
                match key {
                    "branch" => Some(CargoGitReference::Branch(value.to_string())),
                    "tag" => Some(CargoGitReference::Tag(value.to_string())),
                    "rev" => Some(CargoGitReference::Rev(value.to_string())),
                    _ => None,
                }
            })
        })
        .unwrap_or(CargoGitReference::Default);
    Some(CargoGitSource {
        source: source.to_string(),
        reference,
        inner: crate::gitsrc::GitSource {
            url: crate::gitsrc::normalize_url(url),
            commit: commit.to_ascii_lowercase(),
            subdirectory: None,
        },
    })
}

/// Find the directory inside a realized repository that holds the crate with
/// this name and locked version: the root when its own Cargo.toml names it,
/// otherwise a matching workspace member (members live one or two levels
/// down).
fn crate_dir_in_repo(root: &Path, name: &str, version: &str) -> io::Result<PathBuf> {
    fn package_name(manifest: &Path) -> Option<String> {
        let text = fs::read_to_string(manifest).ok()?;
        let value: toml::Value = toml::from_str(&text).ok()?;
        value
            .get("package")?
            .get("name")?
            .as_str()
            .map(str::to_string)
    }
    fn package_info(manifest: &Path) -> Option<(String, String)> {
        let text = fs::read_to_string(manifest).ok()?;
        let value: toml::Value = toml::from_str(&text).ok()?;
        let package = value.get("package")?;
        value
            .get("package")?
            .get("name")?
            .as_str()
            .map(str::to_string)
            .zip(package.get("version")?.as_str().map(str::to_string))
    }
    let mut mismatches = Vec::new();
    let root_manifest = root.join("Cargo.toml");
    if package_name(&root_manifest).as_deref() == Some(name) {
        reject_workspace_inheritance(root, name)?;
        if let Some((_, package_version)) = package_info(&root_manifest) {
            if package_version == version {
                return Ok(root.to_path_buf());
            }
            mismatches.push((root.to_path_buf(), package_version));
        } else {
            return Err(err(format!(
                "git crate {name} at {} has no standalone package version",
                root.display()
            )));
        }
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 3 {
            continue;
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path();
            let manifest = path.join("Cargo.toml");
            if package_name(&manifest).as_deref() == Some(name) {
                reject_workspace_inheritance(&path, name)?;
                if let Some((_, package_version)) = package_info(&manifest) {
                    if package_version == version {
                        return Ok(path);
                    }
                    mismatches.push((path, package_version));
                } else {
                    return Err(err(format!(
                        "git crate {name} at {} has no standalone package version",
                        path.display()
                    )));
                }
                continue;
            }
            stack.push((path, depth + 1));
        }
    }
    let versions = mismatches
        .iter()
        .map(|(path, found)| format!("{} has {found}", path.display()))
        .collect::<Vec<_>>()
        .join(", ");
    let detail = if versions.is_empty() {
        format!("contains no crate named {name}")
    } else {
        format!("contains {name} at another version (expected {version}; {versions})")
    };
    Err(err(format!("git source {} {detail}", root.display())))
}

/// A workspace member can inherit package metadata or dependencies from its
/// root manifest. Once copied into Cargo's standalone directory source, those
/// `workspace = true` references have no parent workspace and produce a
/// broken vendor tree. Refuse this unsupported shape before publishing it.
fn reject_workspace_inheritance(crate_dir: &Path, name: &str) -> io::Result<()> {
    let manifest = crate_dir.join("Cargo.toml");
    let value: toml::Value = toml::from_str(&fs::read_to_string(&manifest)?).map_err(|e| {
        err(format!(
            "git crate {name}: parse {}: {e}",
            manifest.display()
        ))
    })?;
    fn contains_workspace_true(value: &toml::Value) -> bool {
        match value {
            toml::Value::Table(table) => table.iter().any(|(key, value)| {
                (key == "workspace" && value.as_bool() == Some(true))
                    || contains_workspace_true(value)
            }),
            toml::Value::Array(values) => values.iter().any(contains_workspace_true),
            _ => false,
        }
    }
    if contains_workspace_true(&value) {
        return Err(err(format!(
            "git crate {name} at {} inherits workspace metadata or dependencies; standalone Cargo vendor is unsupported",
            crate_dir.display()
        )));
    }
    Ok(())
}

fn realize_vendor_inner(store: &Store, plan: &CargoPlan) -> io::Result<PathBuf> {
    let activity = store.activity(crate::activity::ActivityMode::Shared)?;
    let (crates, identity) = vendor_identity(plan)?;
    let id = identity.object_id();
    if store.has_with_activity(&activity, &id)? {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    // Git crates are realized from their commit; registry crates are fetched
    // as .crate archives. Both end up as a vendored directory below.
    let mut archives = Vec::new();
    let mut git_roots = Vec::new();
    for krate in &crates {
        if let Some(git) = &krate.git {
            let object = crate::gitsrc::ensure_git_source(store, &git.inner).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "{}@{}: git source {}: {e}",
                        krate.name, krate.version, git.inner.url
                    ),
                )
            })?;
            crate::policy::record(
                crate::policy::GIT_DEPENDENCY,
                &format!("{}@{}", krate.name, krate.version),
                &format!("{} at {}", git.inner.url, git.inner.commit),
            )?;
            git_roots.push((krate.clone(), object));
            continue;
        }
        let archive = download_verified_held(store, &krate.url, &krate.sha256).map_err(|e| {
            err(format!(
                "{}@{}: fetch {}: {e}",
                krate.name, krate.version, krate.url
            ))
        })?;
        archives.push(archive);
    }

    let staged = store.stage_with_activity(&activity)?;
    for (krate, root) in &git_roots {
        // Cargo's directory source wants the crate's own directory, so a
        // workspace repository is searched for the crate the lock names.
        let crate_dir = staged.join(format!("{}-{}", krate.name, krate.version));
        let source_dir = crate_dir_in_repo(root, &krate.name, &krate.version)?;
        crate::project::clone_tree_for_store(store, &source_dir, &crate_dir, Platform::host()?)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}@{}: copy git crate: {e}", krate.name, krate.version),
                )
            })?;
        crate::gitsrc::validate_symlinks(&crate_dir).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "{}@{}: copied git crate contains escaping symlink: {e}",
                    krate.name, krate.version
                ),
            )
        })?;
        // A directory source's files are not checksummed by cargo (the commit
        // is the provenance), and `package: null` is what `cargo vendor`
        // writes for git sources.
        fs::write(
            crate_dir.join(".cargo-checksum.json"),
            br#"{"files":{},"package":null}"#,
        )
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "{}@{}: write .cargo-checksum.json: {e}",
                    krate.name, krate.version
                ),
            )
        })?;
    }
    for (krate, archive) in crates.iter().filter(|k| k.git.is_none()).zip(archives) {
        let crate_dir = staged.join(format!("{}-{}", krate.name, krate.version));
        fs::create_dir_all(&crate_dir).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{}@{}: create staging dir: {e}", krate.name, krate.version),
            )
        })?;
        let mut command = Command::new("/usr/bin/tar");
        command
            .args(["-xzf"])
            .arg(&*archive)
            .args(["-C"])
            .arg(&crate_dir)
            .args(["--strip-components", "1"]);
        let status = crate::supervise::status(&mut command, &activity).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{}@{}: spawn tar: {e}", krate.name, krate.version),
            )
        })?;
        if !status.success() {
            return Err(err(format!(
                "{}@{}: crate extraction failed",
                krate.name, krate.version
            )));
        }

        let (files, size) = inspect_crate(&crate_dir, krate)?;
        if size > 1 << 30 {
            return Err(err(format!(
                "{}@{}: package expands past 1 GiB; refusing",
                krate.name, krate.version
            )));
        }
        let checksum = CargoChecksum {
            files,
            package: &krate.sha256,
        };
        let json = serde_json::to_vec(&checksum).map_err(|e| {
            err(format!(
                "{}@{}: checksum JSON: {e}",
                krate.name, krate.version
            ))
        })?;
        fs::write(crate_dir.join(".cargo-checksum.json"), json).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "{}@{}: write .cargo-checksum.json: {e}",
                    krate.name, krate.version
                ),
            )
        })?;
    }

    let mut deps = crate::store::ObjectDeps::new();
    for krate in &crates {
        if krate.git.is_some() {
            let (_, object) = git_roots
                .iter()
                .find(|(candidate, _)| {
                    candidate.name == krate.name && candidate.version == krate.version
                })
                .ok_or_else(|| {
                    err(format!(
                        "missing realized git source for {}@{}",
                        krate.name, krate.version
                    ))
                })?;
            deps.object_id(&crate::store::object_id_from_path(object)?)?;
        } else {
            deps.cache_digest(Digest::sha256(&krate.sha256)?);
        }
    }
    store
        .commit_with_activity_and_deps(&activity, &identity, &staged, &[], &deps)
        .map(|(path, _)| path)
        .map_err(|e| io::Error::new(e.kind(), format!("commit cargo vendor object: {e}")))
}

fn vendor_identity(plan: &CargoPlan) -> io::Result<(Vec<CargoCrate>, Identity)> {
    let mut crates = plan.crates.clone();
    crates.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));

    let mut seen = BTreeSet::new();
    let mut inputs = BTreeMap::from([(String::from("schema"), String::from("cargo-vendor/1"))]);
    for krate in &mut crates {
        validate_crate_component("name", &krate.name)?;
        validate_crate_component("version", &krate.version)?;
        let checksum = match &krate.git {
            // The realized source tree depends on the normalized repository
            // URL as well as its commit (including relative submodule bases).
            Some(git) => format!("git:{}", crate::gitsrc::object_id(&git.inner)),
            None => normalize_checksum(&krate.sha256)?,
        };
        if !seen.insert((krate.name.clone(), krate.version.clone())) {
            return Err(err(format!(
                "duplicate Cargo crate {}@{}",
                krate.name, krate.version
            )));
        }
        if krate.git.is_none() {
            krate.sha256 = checksum.clone();
        }
        inputs.insert(format!("crate:{}@{}", krate.name, krate.version), checksum);
    }
    let identity = Identity {
        kind: "cargo-vendor".into(),
        name: "vendor".into(),
        version: if crates.is_empty() {
            "1".into()
        } else {
            crates.len().to_string()
        },
        inputs,
    };
    Ok((crates, identity))
}

pub(crate) fn vendor_object_id(plan: &CargoPlan) -> io::Result<String> {
    Ok(vendor_identity(plan)?.1.object_id())
}

#[derive(Serialize)]
struct CargoChecksum<'a> {
    files: BTreeMap<String, String>,
    package: &'a str,
}

fn inspect_crate(
    crate_dir: &Path,
    krate: &CargoCrate,
) -> io::Result<(BTreeMap<String, String>, u64)> {
    let mut files = BTreeMap::new();
    let mut size = 0u64;
    inspect_dir(crate_dir, crate_dir, krate, &mut files, &mut size)?;
    Ok((files, size))
}

fn inspect_dir(
    root: &Path,
    dir: &Path,
    krate: &CargoCrate,
    files: &mut BTreeMap<String, String>,
    size: &mut u64,
) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        let relative = relative_path(root, &path)?;
        if file_type.is_symlink() {
            return Err(err(format!(
                "{}@{}: hostile symlink at {relative}",
                krate.name, krate.version
            )));
        }
        if file_type.is_dir() {
            inspect_dir(root, &path, krate, files, size)?;
        } else if file_type.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if metadata.nlink() > 1 {
                    return Err(err(format!(
                        "{}@{}: hostile hardlink at {relative}",
                        krate.name, krate.version
                    )));
                }
            }
            *size = size.checked_add(metadata.len()).ok_or_else(|| {
                err(format!(
                    "{}@{}: extracted size overflow",
                    krate.name, krate.version
                ))
            })?;
            if relative != ".cargo-checksum.json" {
                files.insert(relative, hash_file(&path)?);
            }
        } else {
            return Err(err(format!(
                "{}@{}: hostile special entry at {relative}",
                krate.name, krate.version
            )));
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> io::Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|e| err(format!("relative crate path: {e}")))?;
    relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => name
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| err("crate contains a non-UTF-8 path")),
            _ => Err(err("crate contains an unsafe relative path")),
        })
        .collect::<io::Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// SHA-256 of the exact Cargo.lock text used for planning.
pub fn lock_digest(lock_toml: &str) -> String {
    hex::encode(Sha256::digest(lock_toml.as_bytes()))
}

/// The forced cargo config: source replacement into the vendor object plus
/// offline, applied via CLI `--config` (which outranks every config file).
/// Every git source in the plan gets its own `[source."git+…"]` stanza
/// replaced by the vendor directory, because cargo matches these keys against
/// the lockfile's source string verbatim; without them it would try to reach
/// the network for a git dependency.
pub(crate) fn blanket_config_text_for(
    vendor_obj: &Path,
    git_sources: &[CargoGitSource],
) -> io::Result<String> {
    let vendor = serde_json::to_string(&vendor_obj.to_string_lossy().to_string())?;
    let mut text = format!(
        "[source.crates-io]\n\
         replace-with = \"blanket-vendor\"\n\
         [source.blanket-vendor]\n\
         directory = {vendor}\n"
    );
    let mut seen = BTreeSet::new();
    for git in git_sources {
        if !seen.insert(git.source.clone()) {
            continue;
        }
        let key = serde_json::to_string(&git.source)?;
        let url = serde_json::to_string(&git.inner.url)?;
        let reference = match &git.reference {
            CargoGitReference::Branch(branch) => {
                format!("branch = {}\n", serde_json::to_string(branch)?)
            }
            CargoGitReference::Tag(tag) => format!("tag = {}\n", serde_json::to_string(tag)?),
            CargoGitReference::Rev(rev) => format!("rev = {}\n", serde_json::to_string(rev)?),
            // No reference in the lock means cargo's default branch.
            CargoGitReference::Default => String::new(),
        };
        text.push_str(&format!(
            "[source.{key}]\n\
             git = {url}\n\
             {reference}\
             replace-with = \"blanket-vendor\"\n"
        ));
    }
    text.push_str("[net]\noffline = true\n");
    Ok(text)
}

/// The git sources a plan needs stanzas for.
pub(crate) fn plan_git_sources(plan: &CargoPlan) -> Vec<CargoGitSource> {
    plan.crates
        .iter()
        .filter_map(|krate| krate.git.clone())
        .collect()
}

/// The git sources named by a project's own Cargo.lock. Used where no plan is
/// in hand (a sandboxed build); an unreadable or absent lock yields none, and
/// the build then fails the same way it did before git sources existed.
pub(crate) fn project_git_sources(project_dir: &Path) -> Vec<CargoGitSource> {
    let Ok(text) = fs::read_to_string(project_dir.join("Cargo.lock")) else {
        return Vec::new();
    };
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        return Vec::new();
    };
    value
        .get("package")
        .and_then(toml::Value::as_array)
        .map(|packages| {
            packages
                .iter()
                .filter_map(|package| package.get("source")?.as_str())
                .filter_map(parse_cargo_git_source)
                .collect()
        })
        .unwrap_or_default()
}

/// A later `--config` outranks ours; letting one through would let a hostile
/// invocation swap the vendor source while provenance still claims blanket's.
fn reject_user_config(args: &[String]) -> io::Result<()> {
    for arg in args {
        if arg == "--config" || arg.starts_with("--config=") {
            return Err(err(
                "--config is managed by blanket (it enforces the verified vendor source); \
                 put project settings in .cargo/config.toml instead",
            ));
        }
    }
    Ok(())
}

/// Project Cargo with a writable home, forced directory-source replacement,
/// and provenance for the exact toolchain/vendor closure.
pub fn project_cargo_env(
    project_dir: &Path,
    rust_obj: &Path,
    vendor_obj: &Path,
    plan: &CargoPlan,
    lock_digest: &str,
) -> io::Result<()> {
    let project_dir = project_dir.canonicalize()?;
    // The workspace root is what gets registered, and projecting a cargo-home
    // into a root no record can name leaves wrappers pointing at objects the
    // next sweep is free to remove.
    Store::check_registrable(&project_dir)?;
    let rust_obj = rust_obj.canonicalize()?;
    let vendor_obj = vendor_obj.canonicalize()?;
    let store = crate::project::store_from_object_path(&rust_obj)
        .ok_or_else(|| err("Rust object is not in a Blanket store"))?;
    let activity = store.activity(crate::activity::ActivityMode::Shared)?;
    let meta_dir = project_dir.join(".blanket");
    fs::create_dir_all(&meta_dir)?;
    let cargo_home = project_child_dir(&project_dir, ".blanket/cargo-home")?;
    // bin gets its own containment check: a symlinked bin would carry the
    // wrapper write outside the project.
    let bin_dir = project_child_dir(&project_dir, ".blanket/cargo-home/bin")?;
    let config = cargo_home.join("blanket-config.toml");
    let wrapper = bin_dir.join("cargo");

    write_atomic(
        &config,
        blanket_config_text_for(&vendor_obj, &plan_git_sources(plan))?.as_bytes(),
        None,
    )?;

    let cargo_bin = rust_obj.join("bin/cargo");
    let rustc_bin = rust_obj.join("bin/rustc");
    let wrapper_text = format!(
        "#!/bin/sh\n\
         for a in \"$@\"; do case \"$a\" in --config|--config=*)\n\
           echo 'blanket: --config is managed by blanket' >&2; exit 2;; esac; done\n\
         export CARGO_HOME=\"{}\"\n\
         export RUSTC=\"{}\"\n\
         export RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER=\n\
         unset RUSTUP_HOME RUSTUP_TOOLCHAIN\n\
         exec \"{}\" --frozen --config \"{}\" \"$@\"\n",
        shell_double_quote(&cargo_home),
        shell_double_quote(&rustc_bin),
        shell_double_quote(&cargo_bin),
        shell_double_quote(&config),
    );
    write_atomic(&wrapper, wrapper_text.as_bytes(), Some(0o755))?;

    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({
            "path": path.display().to_string(),
            "id": id,
        }))
    };
    let body = serde_json::json!({
        "rust_object": object_ref(&rust_obj)?,
        "vendor_object": object_ref(&vendor_obj)?,
        "cargo_lock_sha256": lock_digest,
        "plan": plan,
    });
    let valid_objects = [rust_obj.as_path(), vendor_obj.as_path()]
        .iter()
        .all(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(crate::store::is_object_id)
        });
    if !valid_objects {
        #[cfg(test)]
        {
            return crate::project::write_closure_legacy(&project_dir, "cargo", body);
        }
        #[cfg(not(test))]
        {
            return Err(err(
                "Cargo closure references must name complete store objects",
            ));
        }
    }
    let mut refs = crate::project::ClosureRefs::new();
    refs.object_path(&store, &activity, &rust_obj)?;
    refs.object_path(&store, &activity, &vendor_obj)?;
    crate::project::write_closure(&project_dir, "cargo", body, &store, &activity, refs)
}

/// Build a Cargo project in the existing network-denied seatbelt sandbox.
pub fn build_sandboxed(
    platform: Platform,
    project_dir: &Path,
    rust_obj: &Path,
    vendor_obj: &Path,
    args: &[String],
) -> io::Result<()> {
    let store = Store::open()?;
    reject_user_config(args)?;
    let project_dir = project_dir.canonicalize()?;
    let rust_obj = rust_obj.canonicalize()?;
    let vendor_obj = vendor_obj.canonicalize()?;
    let target = project_child_dir(&project_dir, "target")?;
    let cargo_bin = rust_obj.join("bin/cargo");
    if !cargo_bin.is_file() || !vendor_obj.is_dir() {
        return Err(err(
            "cargo environment is incomplete; run `blanket sync` first",
        ));
    }

    let store_tmp = rust_obj
        .parent()
        .and_then(Path::parent)
        .map(|path| path.join("tmp"))
        .ok_or_else(|| err("cannot locate store tmp for Cargo build"))?;
    let scratch = unique_dir(&store_tmp, "cargo-build")?;
    // Disposable per-build CARGO_HOME + config inside the scratch dir: the
    // projected cargo-home must never be writable in-sandbox, or a build
    // script could replace the wrapper that later runs UNsandboxed under
    // `blanket run`. (Sol review, reproduced.)
    let build_home = scratch.join("cargo-home");
    fs::create_dir_all(&build_home)?;
    let config = build_home.join("blanket-config.toml");
    fs::write(
        &config,
        blanket_config_text_for(&vendor_obj, &project_git_sources(&project_dir))?,
    )?;
    let mut argv = vec![
        cargo_bin
            .to_str()
            .ok_or_else(|| err("Cargo path is not UTF-8"))?
            .to_string(),
        "--frozen".to_string(),
        "--config".to_string(),
        config
            .to_str()
            .ok_or_else(|| err("Cargo config path is not UTF-8"))?
            .to_string(),
        "build".to_string(),
    ];
    argv.extend(args.iter().cloned());
    let spec = crate::sandbox::BuildSpec {
        argv,
        cwd: project_dir.clone(),
        env: vec![
            ("CARGO_HOME".to_string(), build_home.display().to_string()),
            ("CARGO_TARGET_DIR".to_string(), target.display().to_string()),
            // Env outranks a project's [build] rustc / rustc-wrapper config:
            // the pinned compiler is not negotiable (empty wrapper = none).
            (
                "RUSTC".to_string(),
                rust_obj.join("bin/rustc").display().to_string(),
            ),
            ("RUSTC_WRAPPER".to_string(), String::new()),
            ("RUSTC_WORKSPACE_WRAPPER".to_string(), String::new()),
        ],
        read: vec![project_dir.clone(), rust_obj.clone(), vendor_obj.clone()],
        write: vec![target],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", rust_obj.join("bin").display()),
    };
    let result = crate::sandbox::run_build_spec_on_for_store(platform, &spec, &store);
    let _ = fs::remove_dir_all(&scratch);
    result.map_err(|e| {
        io::Error::new(e.kind(), format!(
            "Cargo build failed: {e}; network is denied; external path dependencies outside the project and build scripts needing network are unsupported (declared-artifact support may come later)"
        ))
    })
}

fn project_child_dir(project_dir: &Path, relative: &str) -> io::Result<PathBuf> {
    let path = project_dir.join(relative);
    fs::create_dir_all(&path)?;
    let path = path.canonicalize()?;
    if !path.starts_with(project_dir) {
        return Err(err(format!(
            "Cargo path {} escapes project {}",
            path.display(),
            project_dir.display()
        )));
    }
    Ok(path)
}

fn unique_dir(parent: &Path, prefix: &str) -> io::Result<PathBuf> {
    fs::create_dir_all(parent)?;
    for attempt in 0..100 {
        let path = parent.join(format!(
            ".{prefix}.{}.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            attempt
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(err(format!("could not create {prefix} scratch directory")))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .ok_or_else(|| err(format!("path has no parent: {}", path.display())))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    let result = (|| {
        fs::write(&tmp, bytes)?;
        if let Some(mode) = mode {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
            }
        }
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn shell_double_quote(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
        .replace('`', "\\`")
}

#[cfg(test)]
mod tests {

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit, or a migrated record stops matching what
    /// a re-sync publishes and every later cache hit becomes a hard error.
    #[test]
    fn legacy_adapter_recovers_the_pinned_rust_components() {
        for platform in Platform::ALL {
            let components = rust_components(*platform).unwrap();
            let mut expected: Vec<String> = components
                .iter()
                .map(|component| format!("sha256:{}", component.sha256))
                .collect();
            expected.sort();
            expected.dedup();
            assert_eq!(
                recovered_cache(rust_identity(*platform, &components)),
                expected
            );
        }
    }

    fn recovered_cache(identity: crate::types::Identity) -> Vec<String> {
        match crate::objmeta::adapt_identity_for_test(identity, Vec::new()) {
            crate::objmeta::Adaptation::Proven(deps) => {
                assert!(
                    deps.objects.is_empty(),
                    "a pinned artifact has no object deps"
                );
                deps.cache
                    .iter()
                    .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                    .collect()
            }
            crate::objmeta::Adaptation::Unresolved(reason) => panic!("{reason}"),
        }
    }
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn darwin_identity_unchanged() {
        let platform = Platform::Aarch64AppleDarwin;
        let components = rust_components(platform).unwrap();
        let identity = rust_identity(platform, &components);
        assert_eq!(
            identity.object_id(),
            "b8418440835c4ec1f591381a17ae60ab12d1c727-rust-1.96.1"
        );
    }

    #[test]
    fn rust_component_sets_are_complete_unique_and_pinned() {
        let expected_names = BTreeSet::from(["cargo", "rust-std", "rustc"]);
        for platform in Platform::ALL {
            let components = rust_components(*platform).unwrap();
            assert_eq!(components.len(), 3);
            assert_eq!(
                components
                    .iter()
                    .map(|component| component.component)
                    .collect::<BTreeSet<_>>(),
                expected_names
            );
            assert!(components
                .iter()
                .all(|component| component.version == RUST_VERSION));
            assert!(components
                .iter()
                .all(|component| component.platform == *platform));
        }
    }

    #[test]
    fn linux_rust_component_urls_and_digests_are_exact() {
        let platform = Platform::X86_64UnknownLinuxGnu;
        let expected = [
            (
                "rustc",
                "https://static.rust-lang.org/dist/rustc-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
                "3545a0efad2355ecb0a3b9ac02efee96e27f1f9d24b7ce2fc3f279b2efb0d923",
            ),
            (
                "rust-std",
                "https://static.rust-lang.org/dist/rust-std-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
                "1bf4fde5048cca33e6ea00c7471281ed96d792f6923141e3db45072743a1afae",
            ),
            (
                "cargo",
                "https://static.rust-lang.org/dist/cargo-1.96.1-x86_64-unknown-linux-gnu.tar.xz",
                "ecc53a3c49fab5ab8c9301b3bbc8fb1dff9be6c65287add3f57a0fe8fddfea9e",
            ),
        ];
        let components = rust_components(platform).unwrap();
        for (name, url, sha256) in expected {
            let component = components
                .iter()
                .find(|component| component.component == name)
                .unwrap();
            assert_eq!(component.url, url);
            assert_eq!(component.sha256, sha256);
            assert!(component.url.contains("x86_64-unknown-linux-gnu"));
        }
        assert!(rust_components(Platform::Aarch64AppleDarwin)
            .unwrap()
            .iter()
            .all(|component| component.url.contains("aarch64-apple-darwin")));
    }

    #[test]
    fn rust_identity_is_platform_specific() {
        let darwin = rust_components(Platform::Aarch64AppleDarwin).unwrap();
        let linux = rust_components(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_ne!(
            rust_identity(Platform::Aarch64AppleDarwin, &darwin).object_id(),
            rust_identity(Platform::X86_64UnknownLinuxGnu, &linux).object_id()
        );
    }
    use std::env;
    use std::ffi::OsString;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!("{prefix}-{}-{suffix}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    use crate::store::STORE_ENV_LOCK;

    struct StoreEnv(Option<OsString>);

    impl Drop for StoreEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => env::set_var("BLANKET_STORE", value),
                None => env::remove_var("BLANKET_STORE"),
            }
        }
    }

    fn with_temp_store(f: impl FnOnce(&Store, &Path)) {
        let _lock = STORE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::new("blanket-cargo-store");
        let old = env::var_os("BLANKET_STORE");
        env::set_var("BLANKET_STORE", temp.path());
        let _env = StoreEnv(old);
        let store = Store::open().unwrap();
        f(&store, temp.path());
    }

    fn exception_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        crate::policy::clear();
        guard
    }

    fn package_lock(package: &str, version: u64) -> String {
        format!("version = {version}\n\n[[package]]\n{package}")
    }

    #[test]
    fn plans_registry_and_workspace_closure() {
        let hash_a = "a".repeat(64);
        let hash_b = "b".repeat(64);
        let lock = format!(
            r#"version = 4

[[package]]
name = "demo"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{hash_a}"

[[package]]
name = "workspace-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "sparse+https://index.crates.io/"
checksum = "{hash_b}"

[[package]]
name = "serde"
version = "1.0.1"
source = "sparse+https://index.crates.io/"
checksum = "{hash_b}"
"#
        );
        let plan = plan_cargo(&lock, "1.96.1").unwrap();
        assert_eq!(plan.rust_version, "1.96.1");
        assert_eq!(plan.members, vec!["workspace-app"]);
        assert_eq!(plan.crates.len(), 3);
        assert_eq!(
            plan.crates[0].url,
            "https://static.crates.io/crates/demo/demo-1.2.3.crate"
        );
        assert_eq!(plan.crates[1].version, "1.0.0");
        assert_eq!(plan.crates[2].version, "1.0.1");
    }

    #[test]
    fn cargo_plan_rejects_unsupported_or_hostile_lock_entries() {
        let hash = "a".repeat(64);
        let cases = [
            (
                "git source",
                format!(
                    "name = \"a\"\nversion = \"1.0.0\"\nsource = \"git+https://example.com/a\""
                ),
            ),
            (
                "alternative registry",
                format!(
                    "name = \"a\"\nversion = \"1.0.0\"\nsource = \"registry+https://example.com/index\"\nchecksum = \"{hash}\""
                ),
            ),
            (
                "missing checksum",
                "name = \"a\"\nversion = \"1.0.0\"\nsource = \"sparse+https://index.crates.io/\"".into(),
            ),
            (
                "bad checksum",
                "name = \"a\"\nversion = \"1.0.0\"\nsource = \"sparse+https://index.crates.io/\"\nchecksum = \"zz\"".into(),
            ),
            (
                "hostile name",
                format!("name = \"../evil\"\nversion = \"1.0.0\"\nchecksum = \"{hash}\""),
            ),
        ];
        for (label, package) in cases {
            assert!(
                plan_cargo(&package_lock(&package, 4), "1.96.1").is_err(),
                "{label} should fail"
            );
        }

        assert!(plan_cargo(
            &package_lock("name = \"a\"\nversion = \"1.0.0\"", 2),
            "1.96.1"
        )
        .is_err());
        let duplicate = format!(
            "name = \"a\"\nversion = \"1.0.0\"\nchecksum = \"{hash}\"\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nchecksum = \"{hash}\""
        );
        assert!(plan_cargo(&package_lock(&duplicate, 4), "1.96.1").is_err());
    }

    #[test]
    fn resolves_toolchain_files_and_pins() {
        let _exception_guard = exception_guard();
        let temp = TempDir::new("blanket-cargo-toolchain");
        let project = temp.path().join("project/child");
        fs::create_dir_all(&project).unwrap();
        let root = project.parent().unwrap();

        fs::write(root.join("rust-toolchain"), "1.96\n").unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\nprofile = \"minimal\"\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::write(root.join("rust-toolchain"), "1.96.1\n").unwrap();
        fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"beta\"\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::write(root.join("rust-toolchain"), "stable\n").unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::write(root.join("rust-toolchain"), "nightly-2026-01-01\n").unwrap();
        let error = resolve_toolchain(Platform::Aarch64AppleDarwin, &project)
            .unwrap_err()
            .to_string();
        assert!(error.contains("1.96.1"));

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"wasm32-unknown-unknown\"]\n",
        )
        .unwrap();
        assert!(resolve_toolchain(Platform::Aarch64AppleDarwin, &project).is_err());
        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"clippy\"]\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::remove_file(root.join("rust-toolchain.toml")).unwrap();
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, &project).unwrap(),
            "1.96.1"
        );
        crate::policy::clear();
    }

    #[test]
    fn resolves_linux_toolchain_files_targets_and_policy() {
        let temp = TempDir::new("blanket-cargo-linux-toolchain");
        let project = temp.path().join("project/child");
        fs::create_dir_all(&project).unwrap();
        let root = project.parent().unwrap();

        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        for channel in ["stable", "1.96", "1.96.1"] {
            fs::write(root.join("rust-toolchain"), format!("{channel}\n")).unwrap();
            assert_eq!(
                resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
                "1.96.1"
            );
        }

        fs::write(root.join("rust-toolchain"), "beta\n").unwrap();
        assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());
        fs::write(root.join("rust-toolchain"), "nightly-2026-01-01\n").unwrap();
        assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"x86_64-unknown-linux-gnu\"]\n",
        )
        .unwrap();
        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        for target in ["aarch64-apple-darwin", "wasm32-unknown-unknown"] {
            fs::write(
                root.join("rust-toolchain"),
                format!("[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"{target}\"]\n"),
            )
            .unwrap();
            assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());
        }

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"clippy\"]\n",
        )
        .unwrap();
        let _exception_guard = exception_guard();
        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        assert!(crate::policy::pending()
            .iter()
            .any(|exception| exception.kind == crate::policy::TOOLCHAIN_COMPONENT_UNAVAILABLE));
        crate::policy::clear();

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"aarch64-apple-darwin\"]\n",
        )
        .unwrap();
        assert!(resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).is_err());
    }

    #[test]
    fn rustfmt_toolchain_component_is_recorded_as_unavailable_under_permissive_policy() {
        let _exception_guard = exception_guard();
        let temp = TempDir::new("blanket-cargo-rustfmt-policy");
        let project = temp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"rustfmt\"]\n",
        )
        .unwrap();

        assert_eq!(
            resolve_toolchain(Platform::X86_64UnknownLinuxGnu, &project).unwrap(),
            "1.96.1"
        );
        assert!(crate::policy::pending().iter().any(|exception| {
            exception.kind == crate::policy::TOOLCHAIN_COMPONENT_UNAVAILABLE
                && exception.subject.ends_with("rust-toolchain.toml")
                && exception.detail.contains("rustfmt")
        }));
        crate::policy::clear();
    }

    fn make_component_archives(
        dir: &Path,
        components: &[&RustComponent],
        platform: Platform,
        rustlib_target: Option<&str>,
    ) -> Vec<PathBuf> {
        components
            .iter()
            .map(|component| {
                let root_name = format!(
                    "{}-{}-{}",
                    component.component,
                    RUST_VERSION,
                    platform.triple()
                );
                let root = dir.join(&root_name);
                let package = match component.component {
                    "rust-std" => root.join(format!("rust-std-{}", platform.triple())),
                    name => root.join(name),
                };
                fs::create_dir_all(&package).unwrap();
                match component.component {
                    "rustc" | "cargo" => {
                        fs::create_dir_all(package.join("bin")).unwrap();
                        fs::write(
                            package.join("bin").join(component.component),
                            component.component,
                        )
                        .unwrap();
                    }
                    "rust-std" => {
                        if let Some(target) = rustlib_target {
                            let rustlib = package.join("lib/rustlib").join(target);
                            fs::create_dir_all(&rustlib).unwrap();
                            fs::write(rustlib.join("marker"), b"synthetic").unwrap();
                        }
                    }
                    other => panic!("unexpected component {other}"),
                }
                let archive = dir.join(format!("{root_name}.tar.xz"));
                let status = std::process::Command::new("/usr/bin/tar")
                    .args(["-cJf"])
                    .arg(&archive)
                    .args(["-C"])
                    .arg(dir)
                    .arg(&root_name)
                    .status()
                    .unwrap();
                assert!(status.success());
                archive
            })
            .collect()
    }

    #[test]
    fn component_layout_is_validated_before_publication() {
        let platform = Platform::X86_64UnknownLinuxGnu;
        let components = rust_components(platform).unwrap();

        let correct = TempDir::new("blanket-rust-layout-correct");
        let archives = make_component_archives(
            correct.path(),
            &components,
            platform,
            Some(platform.triple()),
        );
        let staged = correct.path().join("staged");
        fs::create_dir(&staged).unwrap();
        extract_rust_components(&staged, platform, &components, &archives).unwrap();
        assert!(staged.join("bin/rustc").is_file());
        assert!(staged.join("bin/cargo").is_file());
        assert!(staged
            .join(format!("lib/rustlib/{}", platform.triple()))
            .is_dir());

        let missing = TempDir::new("blanket-rust-layout-missing");
        let archives = make_component_archives(missing.path(), &components, platform, None);
        let staged = missing.path().join("staged");
        fs::create_dir(&staged).unwrap();
        assert!(extract_rust_components(&staged, platform, &components, &archives).is_err());

        let wrong = TempDir::new("blanket-rust-layout-wrong");
        let archives = make_component_archives(
            wrong.path(),
            &components,
            platform,
            Some(Platform::Aarch64AppleDarwin.triple()),
        );
        let staged = wrong.path().join("staged");
        fs::create_dir(&staged).unwrap();
        assert!(extract_rust_components(&staged, platform, &components, &archives).is_err());
    }

    fn make_crate(dir: &Path, name: &str, version: &str, symlink: bool) -> (PathBuf, String) {
        let root_name = format!("{name}-{version}");
        let root = dir.join(&root_name);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"tiny\"\n").unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
        if symlink {
            std::os::unix::fs::symlink("../outside", root.join("escape")).unwrap();
        }
        let archive = dir.join(format!("{root_name}.crate"));
        let status = Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(dir)
            .arg(&root_name)
            .status()
            .unwrap();
        assert!(status.success());
        let hash = hex::encode(Sha256::digest(fs::read(&archive).unwrap()));
        (archive, hash)
    }

    #[test]
    fn realizes_vendor_and_writes_complete_checksums() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        with_temp_store(|store, root| {
            let source = root.join("source");
            fs::create_dir_all(&source).unwrap();
            let (archive, hash) = make_crate(&source, "tiny", "1.0.0", false);
            let plan = CargoPlan {
                rust_version: "1.96.1".into(),
                crates: vec![CargoCrate {
                    name: "tiny".into(),
                    version: "1.0.0".into(),
                    sha256: hash.clone(),
                    url: format!("file://{}", archive.display()),
                    git: None,
                }],
                members: vec![],
            };
            let object = realize_vendor_inner(store, &plan).unwrap();
            let crate_dir = object.join("tiny-1.0.0");
            assert_eq!(
                fs::read_to_string(crate_dir.join("src/lib.rs")).unwrap(),
                "pub fn answer() -> u32 { 42 }\n"
            );
            let checksum: serde_json::Value =
                serde_json::from_slice(&fs::read(crate_dir.join(".cargo-checksum.json")).unwrap())
                    .unwrap();
            assert_eq!(checksum["package"], hash);
            assert_eq!(
                checksum["files"]["src/lib.rs"],
                hex::encode(Sha256::digest(b"pub fn answer() -> u32 { 42 }\n"))
            );
            assert!(checksum["files"].get(".cargo-checksum.json").is_none());
        });
    }

    #[test]
    fn rejects_symlinked_crate_entries() {
        let _supervision = crate::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        with_temp_store(|store, root| {
            let source = root.join("source");
            fs::create_dir_all(&source).unwrap();
            let (archive, hash) = make_crate(&source, "tiny", "1.0.0", true);
            let plan = CargoPlan {
                rust_version: "1.96.1".into(),
                crates: vec![CargoCrate {
                    name: "tiny".into(),
                    version: "1.0.0".into(),
                    sha256: hash,
                    url: format!("file://{}", archive.display()),
                    git: None,
                }],
                members: vec![],
            };
            let error = realize_vendor_inner(store, &plan).unwrap_err().to_string();
            assert!(error.contains("tiny@1.0.0"));
            assert!(error.contains("symlink"));
        });
    }

    /// A Cargo workspace member sends its closure and its record to the
    /// workspace root, not to the directory sync ran in, so the root gets the
    /// same check — before a cargo-home is projected into a workspace no root
    /// record can name and no sweep will protect.
    #[test]
    fn cargo_env_is_refused_for_a_root_that_cannot_be_registered() {
        let temp = TempDir::new("blanket-cargo-unrecordable");
        let root = temp.path().join("ws ");
        fs::create_dir_all(&root).unwrap();
        let plan = CargoPlan {
            rust_version: "1.96.1".into(),
            crates: vec![],
            members: vec!["member".into()],
        };
        let error = project_cargo_env(
            &root,
            &temp.path().join("absent-rust"),
            &temp.path().join("absent-vendor"),
            &plan,
            &lock_digest("version = 4\n"),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(
            !root.join(".blanket").exists(),
            "projected into a workspace no record can name"
        );
    }

    #[test]
    fn projects_cargo_config_wrapper_and_closure() {
        let temp = TempDir::new("blanket-cargo-project");
        let project = temp.path().join("project");
        let rust = temp.path().join("objects/rust-id");
        let vendor = temp.path().join("objects/vendor-id");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(rust.join("bin")).unwrap();
        fs::create_dir_all(&vendor).unwrap();
        fs::write(rust.join("bin/cargo"), "fake cargo").unwrap();
        let plan = CargoPlan {
            rust_version: "1.96.1".into(),
            crates: vec![],
            members: vec!["app".into()],
        };
        let digest = lock_digest("version = 4\n");
        project_cargo_env(&project, &rust, &vendor, &plan, &digest).unwrap();

        let home = project.join(".blanket/cargo-home").canonicalize().unwrap();
        let vendor = vendor.canonicalize().unwrap();
        let rust = rust.canonicalize().unwrap();
        let config = fs::read_to_string(home.join("blanket-config.toml")).unwrap();
        assert!(config.contains("[source.crates-io]"));
        assert!(config.contains("replace-with = \"blanket-vendor\""));
        assert!(config.contains(&format!("directory = \"{}\"", vendor.display())));
        assert!(config.contains("[net]\noffline = true"));

        let wrapper_path = home.join("bin/cargo");
        let wrapper = fs::read_to_string(&wrapper_path).unwrap();
        assert!(wrapper.contains(&format!("export CARGO_HOME=\"{}\"", home.display())));
        assert!(wrapper.contains("unset RUSTUP_HOME RUSTUP_TOOLCHAIN"));
        assert!(wrapper.contains("--frozen --config"));
        assert!(wrapper.contains(&format!("\"{}\"", rust.join("bin/cargo").display())));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(wrapper_path).unwrap().permissions().mode() & 0o111,
                0o111
            );
        }

        let closure = crate::project::read_closure(&project, "cargo").unwrap();
        assert_eq!(closure["rust_object"]["id"], "rust-id");
        assert_eq!(closure["vendor_object"]["id"], "vendor-id");
        assert_eq!(closure["cargo_lock_sha256"], digest);
        assert_eq!(closure["plan"]["members"][0], "app");
        // Wrapper enforces the pinned compiler and refuses --config takeover.
        assert!(wrapper.contains(&format!(
            "export RUSTC=\"{}\"",
            rust.join("bin/rustc").display()
        )));
        assert!(wrapper.contains("--config|--config=*"));
    }

    #[test]
    fn projection_refuses_symlinked_bin_escape() {
        let temp = TempDir::new("blanket-cargo-symlink-bin");
        let project = temp.path().join("project");
        let outside = temp.path().join("outside");
        let rust = temp.path().join("objects/rust-id");
        let vendor = temp.path().join("objects/vendor-id");
        fs::create_dir_all(project.join(".blanket/cargo-home")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(rust.join("bin")).unwrap();
        fs::create_dir_all(&vendor).unwrap();
        std::os::unix::fs::symlink(&outside, project.join(".blanket/cargo-home/bin")).unwrap();
        let plan = CargoPlan {
            rust_version: "1.96.1".into(),
            crates: vec![],
            members: vec![],
        };
        let result = project_cargo_env(&project, &rust, &vendor, &plan, "digest");
        assert!(
            result.is_err(),
            "symlinked bin must not carry writes outside the project"
        );
        assert!(!outside.join("cargo").exists());
    }

    #[test]
    fn build_rejects_user_config_flag() {
        for bad in ["--config", "--config=net.offline=false"] {
            let error = build_sandboxed(
                Platform::Aarch64AppleDarwin,
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                &[bad.to_string()],
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("--config is managed by blanket"),
                "{bad}: {error}"
            );
        }
    }
}

#[cfg(test)]
mod git_source_tests {
    use super::*;

    #[test]
    fn cargo_git_sources_parse_only_when_pinned() {
        let commit = "a".repeat(40);
        for source in [
            format!("git+https://github.com/o/r?rev={commit}#{commit}"),
            format!("git+https://github.com/o/r?branch=main#{commit}"),
            format!("git+https://github.com/o/r?tag=v1#{commit}"),
            format!("git+https://github.com/o/r#{commit}"),
        ] {
            let parsed =
                parse_cargo_git_source(&source).unwrap_or_else(|| panic!("not parsed: {source}"));
            assert_eq!(parsed.inner.commit, commit);
            assert_eq!(parsed.inner.url, "https://github.com/o/r");
            // The key must be the lock's exact string, or cargo will not match it.
            assert_eq!(parsed.source, source);
        }
        assert!(parse_cargo_git_source("git+https://github.com/o/r?branch=main").is_none());
        assert!(
            parse_cargo_git_source("registry+https://github.com/rust-lang/crates.io-index")
                .is_none()
        );
    }

    #[test]
    fn the_config_replaces_each_git_source_verbatim() {
        let commit = "b".repeat(40);
        let source = format!("git+https://github.com/o/r?rev={commit}#{commit}");
        let git = parse_cargo_git_source(&source).unwrap();
        let text =
            blanket_config_text_for(Path::new("/store/vendor"), &[git.clone(), git]).unwrap();
        assert!(text.contains(&format!("[source.\"{source}\"]")), "{text}");
        assert_eq!(
            text.matches("replace-with").count(),
            2,
            "one per source plus crates-io: {text}"
        );
        assert!(text.contains("git = \"https://github.com/o/r\""), "{text}");
        assert!(text.contains(&format!("rev = \"{commit}\"")), "{text}");

        // cargo matches on the SourceId, so a branch/tag source must be
        // replaced with the same reference kind, not with rev.
        let branch_source = format!("git+https://github.com/o/r?branch=main#{commit}");
        let branch = parse_cargo_git_source(&branch_source).unwrap();
        let branch_text = blanket_config_text_for(Path::new("/store/vendor"), &[branch]).unwrap();
        assert!(branch_text.contains("branch = \"main\""), "{branch_text}");
        assert!(!branch_text.contains("rev = "), "{branch_text}");
        let tag_source = format!("git+https://github.com/o/r?tag=v1#{commit}");
        let tag = parse_cargo_git_source(&tag_source).unwrap();
        let tag_text = blanket_config_text_for(Path::new("/store/vendor"), &[tag]).unwrap();
        assert!(tag_text.contains("tag = \"v1\""), "{tag_text}");
        assert!(text.trim_end().ends_with("offline = true"), "{text}");
    }

    #[test]
    fn a_git_crate_commits_to_its_commit_in_the_vendor_identity() {
        let commit = "c".repeat(40);
        let git = parse_cargo_git_source(&format!("git+https://github.com/o/r#{commit}")).unwrap();
        let plan = |source: CargoGitSource| CargoPlan {
            rust_version: "1.96.1".into(),
            crates: vec![CargoCrate {
                name: "dep".into(),
                version: "1.0.0".into(),
                sha256: String::new(),
                url: "https://github.com/o/r".into(),
                git: Some(source),
            }],
            members: vec![],
        };
        let (_, first) = vendor_identity(&plan(git.clone())).unwrap();
        let other_commit =
            parse_cargo_git_source(&format!("git+https://github.com/o/r#{}", "d".repeat(40)))
                .unwrap();
        let (_, second) = vendor_identity(&plan(other_commit)).unwrap();
        assert_ne!(
            first.object_id(),
            second.object_id(),
            "a different commit must be a different vendor object"
        );
        let other_url =
            parse_cargo_git_source(&format!("git+https://github.com/o/other#{commit}")).unwrap();
        let (_, other) = vendor_identity(&plan(other_url)).unwrap();
        assert_ne!(
            first.object_id(),
            other.object_id(),
            "the repository URL must contribute to the vendor identity"
        );
    }

    #[test]
    fn git_crate_selection_uses_the_locked_version() {
        let root = std::env::temp_dir().join(format!(
            "blanket-cargo-selection-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("old")).unwrap();
        std::fs::create_dir_all(root.join("new")).unwrap();
        for (dir, version) in [("old", "1.0.0"), ("new", "2.0.0")] {
            std::fs::write(
                root.join(dir).join("Cargo.toml"),
                format!("[package]\nname = \"same\"\nversion = \"{version}\"\n"),
            )
            .unwrap();
        }
        let selected = crate_dir_in_repo(&root, "same", "2.0.0").unwrap();
        assert_eq!(selected, root.join("new"));
        let error = crate_dir_in_repo(&root, "same", "3.0.0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("another version"), "{error}");
        let _ = crate::store::remove_tree(&root);
    }

    #[test]
    fn workspace_inheritance_and_relocated_symlinks_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "blanket-cargo-workspace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"inherited\"\nversion.workspace = true\n",
        )
        .unwrap();
        let error = crate_dir_in_repo(&root, "inherited", "1.0.0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("inherits workspace"), "{error}");

        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"linked\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("../../outside", root.join("escape")).unwrap();
        assert!(crate::gitsrc::validate_symlinks(&root).is_err());
        let _ = crate::store::remove_tree(&root);
    }
}
