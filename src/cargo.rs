//! The Cargo tailor: Cargo.lock importer and registry vendor realization.

use crate::fetch::download_verified;
use crate::store::Store;
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

const PLATFORM: &str = "aarch64-apple-darwin";
const RUST_VERSION: &str = "1.96.1";
const RUST_PINS: &[&str] = &[RUST_VERSION];

struct RustComponent {
    name: &'static str,
    url: &'static str,
    sha256: &'static str,
}

const RUST_COMPONENTS: &[RustComponent] = &[
    RustComponent {
        name: "rustc",
        url: "https://static.rust-lang.org/dist/rustc-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "9b548f0665f85f3c7fd45165611e3dea79f048c69d163be193986310d204fc2c",
    },
    RustComponent {
        name: "rust_std",
        url: "https://static.rust-lang.org/dist/rust-std-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "0d433a74c303febc915f8fa1091ef166445706461d0c96984ecb7303aa8208f5",
    },
    RustComponent {
        name: "cargo",
        url: "https://static.rust-lang.org/dist/cargo-1.96.1-aarch64-apple-darwin.tar.xz",
        sha256: "2f43d75e9ad3febae5022c6f295cf93b74131cfdb1293a83e291f878ea9585a0",
    },
];

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Ensure the pinned Rust toolchain is realized in the store. Takes the
/// resolved version so a future second pin can't silently realize the
/// wrong toolchain (only RUST_VERSION is realizable today).
pub fn ensure_rust(store: &Store, version: &str) -> io::Result<PathBuf> {
    if version != RUST_VERSION {
        return Err(err(format!(
            "internal: resolved Rust {version} but only {RUST_VERSION} is realizable"
        )));
    }
    let identity = Identity {
        kind: "rust".into(),
        name: "rust".into(),
        version: RUST_VERSION.into(),
        inputs: BTreeMap::from([
            // Schema commits the extraction/layout recipe, not just the
            // bytes: changing how components merge must change the id.
            ("schema".to_string(), "rust-toolchain/1".to_string()),
            (
                "cargo_sha256".to_string(),
                RUST_COMPONENTS[2].sha256.to_string(),
            ),
            ("platform".to_string(), PLATFORM.to_string()),
            (
                "rust_std_sha256".to_string(),
                RUST_COMPONENTS[1].sha256.to_string(),
            ),
            (
                "rustc_sha256".to_string(),
                RUST_COMPONENTS[0].sha256.to_string(),
            ),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        return Ok(store.object_path(&id));
    }

    let mut tarballs = Vec::new();
    for component in RUST_COMPONENTS {
        tarballs.push(download_verified(store, component.url, component.sha256)?);
    }

    let staged = store.stage()?;
    for (component, tarball) in RUST_COMPONENTS.iter().zip(tarballs) {
        let status = Command::new("/usr/bin/tar")
            .args(["-xJf"])
            .arg(tarball)
            .args(["-C"])
            .arg(&staged)
            .args(["--strip-components", "2"])
            .status()
            .map_err(|e| err(format!("spawn tar for {}: {e}", component.name)))?;
        if !status.success() {
            return Err(err(format!("{} tarball extraction failed", component.name)));
        }
    }

    if !staged.join("bin/rustc").is_file()
        || !staged.join("bin/cargo").is_file()
        || !staged.join(format!("lib/rustlib/{PLATFORM}")).is_dir()
    {
        return Err(err(
            "Rust toolchain extraction has an unexpected layout; refusing to commit",
        ));
    }

    store
        .commit(&identity, &staged)
        .map_err(|e| err(format!("commit rust object: {e}")))
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
pub fn resolve_toolchain(project_dir: &Path) -> io::Result<&'static str> {
    let mut dir = project_dir;
    loop {
        let legacy = dir.join("rust-toolchain");
        if legacy.exists() {
            return resolve_toolchain_file(&legacy, true);
        }
        let toml = dir.join("rust-toolchain.toml");
        if toml.exists() {
            return resolve_toolchain_file(&toml, false);
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent,
            _ => break,
        }
    }
    Ok(newest_pin())
}

fn resolve_toolchain_file(path: &Path, legacy: bool) -> io::Result<&'static str> {
    let text =
        fs::read_to_string(path).map_err(|e| err(format!("read {}: {e}", path.display())))?;
    if legacy {
        if let Ok(document) = toml::from_str::<ToolchainDocument>(&text) {
            if let Some(spec) = document.toolchain {
                return resolve_toolchain_spec(path, spec);
            }
        }
        return resolve_channel(path, text.trim());
    }
    let document = toml::from_str::<ToolchainDocument>(&text)
        .map_err(|e| err(format!("parse {}: {e}", path.display())))?;
    let spec = document
        .toolchain
        .ok_or_else(|| err(format!("{} has no [toolchain] table", path.display())))?;
    resolve_toolchain_spec(path, spec)
}

fn resolve_toolchain_spec(path: &Path, spec: ToolchainSpec) -> io::Result<&'static str> {
    if let Some(targets) = spec.targets {
        for target in targets {
            if target != PLATFORM {
                return Err(err(format!(
                    "{}: target {target:?} is unsupported; only {PLATFORM} is pinned",
                    path.display()
                )));
            }
        }
    }
    if let Some(components) = spec.components {
        for component in components {
            if !matches!(component.as_str(), "rustc" | "cargo" | "rust-std") {
                return Err(err(format!(
                    "{}: component {component:?} is unsupported; only rustc, cargo, and rust-std are available",
                    path.display()
                )));
            }
        }
    }
    let channel = spec
        .channel
        .ok_or_else(|| err(format!("{}: [toolchain] has no channel", path.display())))?;
    resolve_channel(path, channel.trim())
}

fn resolve_channel(path: &Path, channel: &str) -> io::Result<&'static str> {
    if channel == "stable" {
        let pin = newest_pin();
        eprintln!(
            "blanket: {} resolves stable to pinned Rust {pin}",
            path.display()
        );
        return Ok(pin);
    }

    let prefix = format!("{channel}.");
    if let Some(pin) = RUST_PINS
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
        RUST_PINS.join(", ")
    )))
}

fn version_key(version: &str) -> Vec<u64> {
    version
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}

fn newest_pin() -> &'static str {
    RUST_PINS
        .iter()
        .copied()
        .max_by_key(|pin| version_key(pin))
        .expect("at least one Rust pin")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CargoCrate {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub url: String,
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
                });
            }
            Some(source) if source.starts_with("git+") => {
                return Err(err(
                    "git dependencies are not supported yet; vendor the crate or use a registry release",
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
pub fn realize_vendor(store: &Store, plan: &CargoPlan) -> io::Result<PathBuf> {
    let mut crates = plan.crates.clone();
    crates.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));

    let mut seen = BTreeSet::new();
    let mut inputs = BTreeMap::from([(String::from("schema"), String::from("cargo-vendor/1"))]);
    for krate in &mut crates {
        validate_crate_component("name", &krate.name)?;
        validate_crate_component("version", &krate.version)?;
        let checksum = normalize_checksum(&krate.sha256)?;
        if !seen.insert((krate.name.clone(), krate.version.clone())) {
            return Err(err(format!(
                "duplicate Cargo crate {}@{}",
                krate.name, krate.version
            )));
        }
        krate.sha256 = checksum.clone();
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
    let id = identity.object_id();
    if store.has(&id) {
        return Ok(store.object_path(&id));
    }

    let mut archives = Vec::new();
    for krate in &crates {
        let archive = download_verified(store, &krate.url, &krate.sha256).map_err(|e| {
            err(format!(
                "{}@{}: fetch {}: {e}",
                krate.name, krate.version, krate.url
            ))
        })?;
        archives.push(archive);
    }

    let staged = store.stage()?;
    for (krate, archive) in crates.iter().zip(archives) {
        let crate_dir = staged.join(format!("{}-{}", krate.name, krate.version));
        fs::create_dir_all(&crate_dir).map_err(|e| {
            err(format!(
                "{}@{}: create staging dir: {e}",
                krate.name, krate.version
            ))
        })?;
        let status = Command::new("/usr/bin/tar")
            .args(["-xzf"])
            .arg(archive)
            .args(["-C"])
            .arg(&crate_dir)
            .args(["--strip-components", "1"])
            .status()
            .map_err(|e| err(format!("{}@{}: spawn tar: {e}", krate.name, krate.version)))?;
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
            err(format!(
                "{}@{}: write .cargo-checksum.json: {e}",
                krate.name, krate.version
            ))
        })?;
    }

    store
        .commit(&identity, &staged)
        .map_err(|e| err(format!("commit cargo vendor object: {e}")))
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

/// The forced policy config: source replacement into the vendor object plus
/// offline. Applied via CLI `--config` (outranks every config file).
fn blanket_config_text(vendor_obj: &Path) -> io::Result<String> {
    let vendor = serde_json::to_string(&vendor_obj.to_string_lossy().to_string())?;
    Ok(format!(
        "[source.crates-io]\n\
         replace-with = \"blanket-vendor\"\n\
         [source.blanket-vendor]\n\
         directory = {vendor}\n\
         [net]\n\
         offline = true\n"
    ))
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
    let rust_obj = rust_obj.canonicalize()?;
    let vendor_obj = vendor_obj.canonicalize()?;
    let meta_dir = project_dir.join(".blanket");
    fs::create_dir_all(&meta_dir)?;
    let cargo_home = project_child_dir(&project_dir, ".blanket/cargo-home")?;
    // bin gets its own containment check: a symlinked bin would carry the
    // wrapper write outside the project.
    let bin_dir = project_child_dir(&project_dir, ".blanket/cargo-home/bin")?;
    let config = cargo_home.join("blanket-config.toml");
    let wrapper = bin_dir.join("cargo");

    write_atomic(&config, blanket_config_text(&vendor_obj)?.as_bytes(), None)?;

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
    crate::project::write_closure(
        &project_dir,
        "cargo",
        serde_json::json!({
            "rust_object": object_ref(&rust_obj)?,
            "vendor_object": object_ref(&vendor_obj)?,
            "cargo_lock_sha256": lock_digest,
            "plan": plan,
        }),
    )
}

/// Build a Cargo project in the existing network-denied seatbelt sandbox.
pub fn build_sandboxed(
    project_dir: &Path,
    rust_obj: &Path,
    vendor_obj: &Path,
    args: &[String],
) -> io::Result<()> {
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
    fs::write(&config, blanket_config_text(&vendor_obj)?)?;
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
    let result = crate::sandbox::run_build_spec(&spec);
    let _ = fs::remove_dir_all(&scratch);
    result.map_err(|e| {
        err(format!(
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
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
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
    use super::*;
    use std::env;
    use std::ffi::OsString;
    use std::sync::Mutex;
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

    static STORE_ENV_LOCK: Mutex<()> = Mutex::new(());

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
        let _lock = STORE_ENV_LOCK.lock().unwrap();
        let temp = TempDir::new("blanket-cargo-store");
        let old = env::var_os("BLANKET_STORE");
        env::set_var("BLANKET_STORE", temp.path());
        let _env = StoreEnv(old);
        let store = Store::open().unwrap();
        f(&store, temp.path());
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
        let temp = TempDir::new("blanket-cargo-toolchain");
        let project = temp.path().join("project/child");
        fs::create_dir_all(&project).unwrap();
        let root = project.parent().unwrap();

        fs::write(root.join("rust-toolchain"), "1.96\n").unwrap();
        assert_eq!(resolve_toolchain(&project).unwrap(), "1.96.1");

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96.1\"\nprofile = \"minimal\"\n",
        )
        .unwrap();
        assert_eq!(resolve_toolchain(&project).unwrap(), "1.96.1");

        fs::write(root.join("rust-toolchain"), "1.96.1\n").unwrap();
        fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"beta\"\n",
        )
        .unwrap();
        assert_eq!(resolve_toolchain(&project).unwrap(), "1.96.1");

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::write(root.join("rust-toolchain"), "stable\n").unwrap();
        assert_eq!(resolve_toolchain(&project).unwrap(), "1.96.1");

        fs::write(root.join("rust-toolchain"), "nightly-2026-01-01\n").unwrap();
        let error = resolve_toolchain(&project).unwrap_err().to_string();
        assert!(error.contains("1.96.1"));

        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ntargets = [\"wasm32-unknown-unknown\"]\n",
        )
        .unwrap();
        assert!(resolve_toolchain(&project).is_err());
        fs::write(
            root.join("rust-toolchain"),
            "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"clippy\"]\n",
        )
        .unwrap();
        assert!(resolve_toolchain(&project).is_err());

        fs::remove_file(root.join("rust-toolchain")).unwrap();
        fs::remove_file(root.join("rust-toolchain.toml")).unwrap();
        assert_eq!(resolve_toolchain(&project).unwrap(), "1.96.1");
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
                }],
                members: vec![],
            };
            let object = realize_vendor(store, &plan).unwrap();
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
                }],
                members: vec![],
            };
            let error = realize_vendor(store, &plan).unwrap_err().to_string();
            assert!(error.contains("tiny@1.0.0"));
            assert!(error.contains("symlink"));
        });
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
            assert_eq!(fs::metadata(wrapper_path).unwrap().permissions().mode() & 0o111, 0o111);
        }

        let closure = crate::project::read_closure(&project, "cargo").unwrap();
        assert_eq!(closure["rust_object"]["id"], "rust-id");
        assert_eq!(closure["vendor_object"]["id"], "vendor-id");
        assert_eq!(closure["cargo_lock_sha256"], digest);
        assert_eq!(closure["plan"]["members"][0], "app");
        // Wrapper enforces the pinned compiler and refuses --config takeover.
        assert!(wrapper.contains(&format!("export RUSTC=\"{}\"", rust.join("bin/rustc").display())));
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
        assert!(result.is_err(), "symlinked bin must not carry writes outside the project");
        assert!(!outside.join("cargo").exists());
    }

    #[test]
    fn build_rejects_user_config_flag() {
        for bad in ["--config", "--config=net.offline=false"] {
            let error = build_sandboxed(
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                &[bad.to_string()],
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("--config is managed by blanket"), "{bad}: {error}");
        }
    }
}
