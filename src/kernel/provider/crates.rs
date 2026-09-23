//! Cargo.lock vendoring (kernel provider layer): a lock parsed into a
//! registry-and-git crate plan, the hash-verified `cargo-vendor` object it
//! realizes to, and the forced cargo config that points a build at it.
//!
//! The cargo tailor vendors projects with it and the Python tailor vendors
//! the crates of an sdist's Rust extension with it, so it lives below both.
//! Callers install the object-kind rows (`tailors::install_kinds`) before
//! they realize, as every realization entry point does.
//!
//! The pin rows and identity constructors are `pub` so the owning
//! tailor keeps its identity goldens and object-kind rows beside it.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{download_verified_held, Digest};
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use crate::kernel::types::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
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
    pub inner: crate::kernel::gitsrc::GitSource,
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
/// `realize_vendor_inner` shells out only to `/usr/bin/tar` and the
/// git-source realizer — no part of the toolchain is a build input — and
/// `vendor_identity` does not commit to one, so recording it would let the
/// same identity be published with two different dependency sets. That
/// divergence is unrecoverable: the second
/// publication is a cache hit, and `validate_cached_dependency_evidence`
/// makes a cache hit with different evidence a hard error, so the store
/// stops being syncable. The toolchain object is retained by the project's
/// own `root/2` closure, which records `rust_object` directly.
///
/// The Rust object remains a separate closure dependency because the vendor
/// tree is produced by the host tar, not by a build that reads the toolchain.
pub fn realize_vendor(
    store: &Store,
    activity: &StoreActivity,
    plan: &CargoPlan,
) -> io::Result<PathBuf> {
    crate::kernel::provider::rust::preflight_platform(Platform::host()?)?;
    realize_vendor_inner(store, activity, plan)
}

/// Parse a Cargo lock `source` for a git dependency pinned to a commit.
///
/// Cargo writes `git+<url>?rev=<ref>#<commit>` (also `?branch=`/`?tag=`, and
/// sometimes no query at all). The fragment is always the resolved commit,
/// which is what tog realizes; the whole string is kept because the
/// generated config's `[source."…"]` key must match it exactly.
pub fn parse_cargo_git_source(source: &str) -> Option<CargoGitSource> {
    let rest = source.strip_prefix("git+")?;
    let (locator, commit) = rest.rsplit_once('#')?;
    if !crate::kernel::gitsrc::is_full_commit(commit) {
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
        inner: crate::kernel::gitsrc::GitSource {
            url: crate::kernel::gitsrc::normalize_url(url),
            commit: commit.to_ascii_lowercase(),
            subdirectory: None,
        },
    })
}

/// Find the directory inside a realized repository that holds the crate with
/// this name and locked version: the root when its own Cargo.toml names it,
/// otherwise a matching workspace member (searched up to four levels down).
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

fn realize_vendor_inner(
    store: &Store,
    activity: &StoreActivity,
    plan: &CargoPlan,
) -> io::Result<PathBuf> {
    let (crates, identity) = vendor_identity(plan)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    // Git crates are realized from their commit; registry crates are fetched
    // as .crate archives. Both end up as a vendored directory below.
    let mut archives = Vec::new();
    let mut git_roots = Vec::new();
    for krate in &crates {
        if let Some(git) = &krate.git {
            let object = crate::kernel::gitsrc::ensure_git_source(store, activity, &git.inner)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "{}@{}: git source {}: {e}",
                            krate.name, krate.version, git.inner.url
                        ),
                    )
                })?;
            crate::kernel::policy::record(
                crate::kernel::policy::GIT_DEPENDENCY,
                &format!("{}@{}", krate.name, krate.version),
                &format!("{} at {}", git.inner.url, git.inner.commit),
            )?;
            git_roots.push((krate.clone(), object));
            continue;
        }
        let archive =
            download_verified_held(store, activity, &krate.url, &krate.sha256).map_err(|e| {
                err(format!(
                    "{}@{}: fetch {}: {e}",
                    krate.name, krate.version, krate.url
                ))
            })?;
        archives.push(archive);
    }

    let staged = store.stage_with_activity(activity)?;
    for (krate, root) in &git_roots {
        // Cargo's directory source wants the crate's own directory, so a
        // workspace repository is searched for the crate the lock names.
        let crate_dir = staged.join(format!("{}-{}", krate.name, krate.version));
        let source_dir = crate_dir_in_repo(root, &krate.name, &krate.version)?;
        crate::kernel::store::clone_tree_with_activity(
            activity,
            &source_dir,
            &crate_dir,
            Platform::host()?,
        )
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{}@{}: copy git crate: {e}", krate.name, krate.version),
            )
        })?;
        crate::kernel::gitsrc::validate_symlinks(&crate_dir).map_err(|e| {
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
        let status = crate::kernel::supervise::status(&mut command, activity).map_err(|e| {
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

    let mut deps = crate::kernel::store::ObjectDeps::new();
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
            deps.object_id(&crate::kernel::store::object_id_from_path(object)?)?;
        } else {
            deps.cache_digest(Digest::sha256(&krate.sha256)?);
        }
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &deps)
        .map(|(path, _)| path)
        .map_err(|e| io::Error::new(e.kind(), format!("commit cargo vendor object: {e}")))
}

pub fn vendor_identity(plan: &CargoPlan) -> io::Result<(Vec<CargoCrate>, Identity)> {
    let mut crates = plan.crates.clone();
    crates.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));

    let mut seen = BTreeSet::new();
    let mut inputs = BTreeMap::from([(String::from("schema"), String::from("cargo-vendor/2"))]);
    for krate in &mut crates {
        validate_crate_component("name", &krate.name)?;
        validate_crate_component("version", &krate.version)?;
        let checksum = match &krate.git {
            // The realized source tree depends on the normalized repository
            // URL as well as its commit (including relative submodule bases).
            Some(git) => format!("git:{}", crate::kernel::gitsrc::object_id(&git.inner)),
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
    // The explicit crate count `cargo-vendor/2` exists for: `version` is
    // max(1, count), so under /1 a one-crate plan that lost its only `crate:`
    // key hashed to the empty plan's object id.
    inputs.insert(String::from("crates"), crates.len().to_string());
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

pub fn vendor_object_id(plan: &CargoPlan) -> io::Result<String> {
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
pub fn tog_config_text_for(
    vendor_obj: &Path,
    git_sources: &[CargoGitSource],
) -> io::Result<String> {
    let vendor = serde_json::to_string(&vendor_obj.to_string_lossy().to_string())?;
    let mut text = format!(
        "[source.crates-io]\n\
         replace-with = \"tog-vendor\"\n\
         [source.tog-vendor]\n\
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
             replace-with = \"tog-vendor\"\n"
        ));
    }
    text.push_str("[net]\noffline = true\n");
    Ok(text)
}

/// The git sources a plan needs stanzas for.
pub fn plan_git_sources(plan: &CargoPlan) -> Vec<CargoGitSource> {
    plan.crates
        .iter()
        .filter_map(|krate| krate.git.clone())
        .collect()
}

/// The git sources named by a project's own Cargo.lock. Used where no plan is
/// in hand (a sandboxed build); an unreadable or absent lock yields none, and
/// the build then fails the same way it did before git sources existed.
pub fn project_git_sources(project_dir: &Path) -> Vec<CargoGitSource> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::provider::rust::RUST_VERSION;

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
        let text = tog_config_text_for(Path::new("/store/vendor"), &[git.clone(), git]).unwrap();
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
        let branch_text = tog_config_text_for(Path::new("/store/vendor"), &[branch]).unwrap();
        assert!(branch_text.contains("branch = \"main\""), "{branch_text}");
        assert!(!branch_text.contains("rev = "), "{branch_text}");
        let tag_source = format!("git+https://github.com/o/r?tag=v1#{commit}");
        let tag = parse_cargo_git_source(&tag_source).unwrap();
        let tag_text = tog_config_text_for(Path::new("/store/vendor"), &[tag]).unwrap();
        assert!(tag_text.contains("tag = \"v1\""), "{tag_text}");
        assert!(text.trim_end().ends_with("offline = true"), "{text}");
    }

    /// `cargo-vendor/2` golden, from fixed inputs. A vendor identity has no
    /// platform input, so there is one value for every host. The `/1`
    /// spelling of the same plan is a different object id, so the bump
    /// reissues every vendor tree; and the drift `/1` could not see — a
    /// one-crate plan losing its only `crate:` key — is now a contract
    /// error instead of the empty plan's identity.
    #[test]
    fn vendor_identity_golden_and_dropped_sole_crate() {
        crate::tailors::install_kinds();
        let plan = |crates: Vec<CargoCrate>| CargoPlan {
            rust_version: RUST_VERSION.into(),
            crates,
            members: Vec::new(),
        };
        let serde = CargoCrate {
            name: "serde".into(),
            version: "1.0.0".into(),
            sha256: "a".repeat(64),
            url: "https://crates.io/api/v1/crates/serde/1.0.0/download".into(),
            git: None,
        };
        let (_, empty) = vendor_identity(&plan(Vec::new())).unwrap();
        let (_, one) = vendor_identity(&plan(vec![serde])).unwrap();
        assert_eq!(empty.inputs["schema"], "cargo-vendor/2");
        assert_eq!(empty.inputs["crates"], "0");
        assert_eq!(one.inputs["crates"], "1");
        assert_eq!(
            empty.object_id(),
            "9935a7a14a1d0612bf26f0856d9e7647f89fc7f9-vendor-1"
        );
        assert_eq!(
            one.object_id(),
            "1609a9586c135ae1de6c388f8c128b2bb0afd788-vendor-1"
        );
        assert_eq!(crate::kernel::objmeta::check_identity_grammar(&one), Ok(()));

        // The `/1` spelling of the same one-crate plan: a different object
        // id, which is the store-wide rebuild this bump accepts.
        let mut old = one.clone();
        old.inputs.insert("schema".into(), "cargo-vendor/1".into());
        old.inputs.remove("crates");
        assert_ne!(old.object_id(), one.object_id());

        // The drift `/1` could not see.
        let mut dropped = one.clone();
        dropped.inputs.remove("crate:serde@1.0.0");
        let reason = crate::kernel::objmeta::check_identity_grammar(&dropped).unwrap_err();
        assert!(reason.contains("Cargo crate count relation"), "{reason}");
        assert_ne!(dropped.object_id(), empty.object_id());
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
            "tog-cargo-selection-{}-{}",
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
        let _ = crate::kernel::store::remove_tree(&root);
    }

    #[test]
    fn workspace_inheritance_and_relocated_symlinks_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "tog-cargo-workspace-{}-{}",
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
        assert!(crate::kernel::gitsrc::validate_symlinks(&root).is_err());
        let _ = crate::kernel::store::remove_tree(&root);
    }
}
