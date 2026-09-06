//! `status`, `ls`, `doctor`: read-only views over the project's closures and
//! the store (CLI.md 2.5–2.7). Nothing here realizes, resolves, or touches
//! the network; `doctor` is the only function that opens the store, and it
//! only reads.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::platform::Platform;
use crate::store::Store;
use crate::{dotnet, manifest, sandbox};

/// Display order; also the `ls <ecosystem>` vocabulary.
pub const ECOSYSTEMS: &[&str] = &["python", "node", "cargo", "go", "ruby", "elixir", "dotnet"];

const NODE_INPUTS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

/// The ecosystems whose inputs are present in `dir` itself (the same tests
/// `sync` uses to decide what to realize).
pub fn detected(dir: &Path) -> io::Result<Vec<&'static str>> {
    let mut found = Vec::new();
    if manifest::has_manifest(dir)? {
        found.push("python");
    }
    if NODE_INPUTS.iter().any(|name| dir.join(name).is_file()) {
        found.push("node");
    }
    if dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file() {
        found.push("cargo");
    }
    if dir.join("go.mod").is_file() {
        found.push("go");
    }
    if dir.join("Gemfile").is_file() {
        found.push("ruby");
    }
    if dir.join("mix.exs").is_file() {
        found.push("elixir");
    }
    if dir.is_dir() && dotnet::has_marker(dir)? {
        found.push("dotnet");
    }
    Ok(found)
}

/// One `.blanket/closures/<ecosystem>.json`, envelope fields lifted out.
#[derive(Debug, Clone)]
pub struct ClosureFile {
    pub ecosystem: String,
    pub platform: Option<String>,
    pub projected_at: Option<u64>,
    pub body: Value,
}

/// Every closure written here, in display order. Foreign-platform closures
/// are included (the caller decides what they mean), unlike
/// `project::read_closure`, which refuses them.
pub fn closures(dir: &Path) -> io::Result<Vec<ClosureFile>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir.join(".blanket/closures")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if stem.starts_with('.') {
            continue;
        }
        let text = fs::read_to_string(entry.path())?;
        let value: Value = serde_json::from_str(&text).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {error}; run 'blanket sync'", entry.path().display()),
            )
        })?;
        out.push(ClosureFile {
            ecosystem: value["ecosystem"]
                .as_str()
                .unwrap_or(stem)
                .to_string(),
            platform: value["platform"].as_str().map(str::to_string),
            projected_at: value["projected_at"].as_u64(),
            body: value["body"].clone(),
        });
    }
    out.sort_by_key(|closure| rank(&closure.ecosystem));
    Ok(out)
}

fn rank(ecosystem: &str) -> usize {
    ECOSYSTEMS
        .iter()
        .position(|name| *name == ecosystem)
        .unwrap_or(ECOSYSTEMS.len())
}

// ---------------------------------------------------------------------------
// ls

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRow {
    pub name: String,
    pub version: String,
    /// Artifact file, lockfile path, or content hash: shown under -v.
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Listing {
    pub ecosystem: String,
    pub platform: Option<String>,
    pub toolchain: Vec<(String, String)>,
    pub packages: Vec<PackageRow>,
}

fn string(value: &Value) -> String {
    value.as_str().unwrap_or_default().to_string()
}

pub fn listing(closure: &ClosureFile) -> Listing {
    let body = &closure.body;
    let plan = &body["plan"];
    let mut toolchain = Vec::new();
    let mut packages = Vec::new();
    let empty = Vec::new();
    match closure.ecosystem.as_str() {
        "python" => {
            let version = body["python"]["version"]
                .as_str()
                .or_else(|| plan["python_version"].as_str())
                .unwrap_or_default();
            toolchain.push(("cpython".into(), version.into()));
            for package in plan["packages"].as_array().unwrap_or(&empty) {
                packages.push(PackageRow {
                    name: string(&package["name"]),
                    version: string(&package["version"]),
                    detail: string(&package["filename"]),
                });
            }
        }
        "node" => {
            toolchain.push(("node".into(), string(&body["node_version"])));
            for package in body["packages"].as_array().unwrap_or(&empty) {
                let path = string(&package["path"]);
                let name = path
                    .rsplit_once("node_modules/")
                    .map(|(_, name)| name.to_string())
                    .unwrap_or_else(|| path.clone());
                packages.push(PackageRow {
                    name,
                    version: string(&package["version"]),
                    detail: path,
                });
            }
        }
        "cargo" => {
            toolchain.push(("rust".into(), string(&plan["rust_version"])));
            for package in plan["crates"].as_array().unwrap_or(&empty) {
                packages.push(PackageRow {
                    name: string(&package["name"]),
                    version: string(&package["version"]),
                    detail: string(&package["sha256"]),
                });
            }
        }
        "go" => {
            toolchain.push(("go".into(), string(&plan["go_version"])));
            for package in plan["modules"].as_array().unwrap_or(&empty) {
                packages.push(PackageRow {
                    name: string(&package["path"]),
                    version: string(&package["version"]),
                    detail: String::new(),
                });
            }
        }
        "ruby" => {
            toolchain.push(("ruby".into(), string(&plan["ruby_version"])));
            toolchain.push(("bundler".into(), string(&plan["bundler_version"])));
            for package in plan["gems"].as_array().unwrap_or(&empty) {
                packages.push(PackageRow {
                    name: string(&package["name"]),
                    version: string(&package["version"]),
                    detail: string(&package["full_name"]),
                });
            }
        }
        "elixir" => {
            toolchain.push(("elixir".into(), string(&plan["elixir_version"])));
            toolchain.push(("otp".into(), string(&plan["otp_version"])));
            for package in plan["deps"].as_array().unwrap_or(&empty) {
                packages.push(PackageRow {
                    name: string(&package["package"]),
                    version: string(&package["version"]),
                    detail: string(&package["app"]),
                });
            }
        }
        "dotnet" => {
            toolchain.push(("dotnet-sdk".into(), string(&plan["sdk_version"])));
            for package in plan["packages"].as_array().unwrap_or(&empty) {
                packages.push(PackageRow {
                    name: string(&package["id"]),
                    version: string(&package["version"]),
                    detail: string(&package["content_hash"]),
                });
            }
        }
        _ => {}
    }
    toolchain.retain(|(_, version)| !version.is_empty());
    packages.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));
    Listing {
        ecosystem: closure.ecosystem.clone(),
        platform: closure.platform.clone(),
        toolchain,
        packages,
    }
}

/// The `ls` output for stdout. `Err(NotFound)` when nothing is synced.
pub fn ls(dir: &Path, filter: Option<&str>, json: bool, verbose: bool) -> io::Result<String> {
    let listings: Vec<Listing> = closures(dir)?
        .iter()
        .filter(|closure| filter.map_or(true, |name| closure.ecosystem == name))
        .map(listing)
        .collect();
    if listings.is_empty() {
        let message = match filter {
            Some(name) if !closures(dir)?.is_empty() => {
                format!("no {name} closure here; 'blanket ls' lists what is synced")
            }
            _ => "nothing synced here; run 'blanket sync' first".to_string(),
        };
        return Err(io::Error::new(io::ErrorKind::NotFound, message));
    }
    if json {
        let value = json!({
            "project": dir,
            "ecosystems": listings.iter().map(|listing| json!({
                "ecosystem": listing.ecosystem,
                "platform": listing.platform,
                "toolchain": listing.toolchain.iter().map(|(name, version)| json!({
                    "name": name, "version": version
                })).collect::<Vec<_>>(),
                "packages": listing.packages.iter().map(|package| json!({
                    "name": package.name,
                    "version": package.version,
                    "detail": package.detail,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        });
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let mut out = String::new();
    for (index, listing) in listings.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let toolchain = listing
            .toolchain
            .iter()
            .map(|(name, version)| format!("{name} {version}"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "{}  ({}; {} package{})\n",
            listing.ecosystem,
            toolchain,
            listing.packages.len(),
            if listing.packages.len() == 1 { "" } else { "s" }
        ));
        let width = listing
            .packages
            .iter()
            .map(|package| package.name.len())
            .max()
            .unwrap_or(0);
        for package in &listing.packages {
            if verbose && !package.detail.is_empty() {
                out.push_str(&format!(
                    "  {:width$}  {}  {}\n",
                    package.name, package.version, package.detail
                ));
            } else {
                out.push_str(&format!("  {:width$}  {}\n", package.name, package.version));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// status

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Synced,
    NotSynced,
    /// Input files that differ from what the last sync consumed.
    Changed(Vec<String>),
    ProjectionMissing(String),
    ForeignPlatform(String),
    /// Synced, but this closure predates input recording.
    Unchecked(String),
}

#[derive(Debug, Clone)]
pub struct EcosystemStatus {
    pub ecosystem: String,
    pub state: State,
    /// Toolchain and package count, for the synced line.
    pub summary: String,
}

impl EcosystemStatus {
    pub fn is_synced(&self) -> bool {
        matches!(self.state, State::Synced | State::Unchecked(_))
    }
}

pub fn sha256_file(path: &Path) -> io::Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

/// Compare recorded `inputs` (python, node) with the files on disk.
fn changed_inputs(dir: &Path, inputs: &[Value]) -> io::Result<Vec<String>> {
    let mut changed = Vec::new();
    for input in inputs {
        let path = string(&input["path"]);
        let recorded = string(&input["sha256"]);
        if path.is_empty() {
            continue;
        }
        let file = dir.join(&path);
        if !file.is_file() {
            changed.push(format!("{path} (removed)"));
        } else if sha256_file(&file)? != recorded {
            changed.push(path);
        }
    }
    Ok(changed)
}

/// Compare a single recorded lock hash with the file on disk.
fn changed_lock(dir: &Path, lock: &str, recorded: &str) -> io::Result<Vec<String>> {
    let file = dir.join(lock);
    let current = if file.is_file() {
        sha256_file(&file)?
    } else {
        // `go.sum` may be legitimately absent; main hashes the empty string.
        hex::encode(Sha256::digest(b""))
    };
    Ok(if recorded.is_empty() {
        Vec::new()
    } else if current == recorded {
        Vec::new()
    } else if file.is_file() {
        vec![lock.to_string()]
    } else {
        vec![format!("{lock} (removed)")]
    })
}

fn symlink_target(path: &Path) -> Option<PathBuf> {
    fs::read_link(path).ok()
}

pub fn status(platform: Platform, dir: &Path) -> io::Result<Vec<EcosystemStatus>> {
    let present = detected(dir)?;
    let closures = closures(dir)?;
    let mut rows = Vec::new();
    for ecosystem in present {
        let Some(closure) = closures.iter().find(|closure| closure.ecosystem == ecosystem) else {
            rows.push(EcosystemStatus {
                ecosystem: ecosystem.into(),
                state: State::NotSynced,
                summary: String::new(),
            });
            continue;
        };
        let listing = listing(closure);
        let summary = format!(
            "{}; {} package{}",
            listing
                .toolchain
                .iter()
                .map(|(name, version)| format!("{name} {version}"))
                .collect::<Vec<_>>()
                .join(", "),
            listing.packages.len(),
            if listing.packages.len() == 1 { "" } else { "s" }
        );
        if let Some(recorded) = &closure.platform {
            if recorded != platform.triple() {
                rows.push(EcosystemStatus {
                    ecosystem: ecosystem.into(),
                    state: State::ForeignPlatform(recorded.clone()),
                    summary,
                });
                continue;
            }
        }
        let body = &closure.body;
        let state = match ecosystem {
            "python" => {
                let venv = dir.join(".venv");
                let env_object = string(&body["env_object"]);
                let target = symlink_target(&venv);
                if target.as_deref() != Some(Path::new(&env_object)) || !venv.join("bin").is_dir()
                {
                    State::ProjectionMissing(".venv".into())
                } else {
                    recorded_inputs_state(dir, body)?
                }
            }
            "node" => {
                let node_modules = dir.join("node_modules");
                if symlink_target(&node_modules).is_none() || !node_modules.is_dir() {
                    State::ProjectionMissing("node_modules".into())
                } else {
                    recorded_inputs_state(dir, body)?
                }
            }
            "cargo" => {
                if !dir.join(".blanket/cargo-home").is_dir() {
                    State::ProjectionMissing(".blanket/cargo-home".into())
                } else {
                    lock_state(dir, "Cargo.lock", &string(&body["cargo_lock_sha256"]))?
                }
            }
            "go" => lock_state(dir, "go.sum", &string(&body["go_sum_sha256"]))?,
            "ruby" => lock_state(dir, "Gemfile.lock", &string(&body["gemfile_lock_sha256"]))?,
            "elixir" => lock_state(dir, "mix.lock", &string(&body["mix_lock_sha256"]))?,
            "dotnet" => lock_state(
                dir,
                "packages.lock.json",
                &string(&body["packages_lock_sha256"]),
            )?,
            _ => State::Unchecked("unknown ecosystem".into()),
        };
        rows.push(EcosystemStatus {
            ecosystem: ecosystem.into(),
            state,
            summary,
        });
    }
    Ok(rows)
}

fn recorded_inputs_state(dir: &Path, body: &Value) -> io::Result<State> {
    match body["inputs"].as_array() {
        Some(inputs) if !inputs.is_empty() => {
            let changed = changed_inputs(dir, inputs)?;
            Ok(if changed.is_empty() {
                State::Synced
            } else {
                State::Changed(changed)
            })
        }
        _ => Ok(State::Unchecked(
            "inputs were not recorded by this sync; run 'blanket sync' once to enable checks"
                .into(),
        )),
    }
}

fn lock_state(dir: &Path, lock: &str, recorded: &str) -> io::Result<State> {
    if recorded.is_empty() {
        return Ok(State::Unchecked(format!("{lock} hash not recorded")));
    }
    let changed = changed_lock(dir, lock, recorded)?;
    Ok(if changed.is_empty() {
        State::Synced
    } else {
        State::Changed(changed)
    })
}

pub fn render_status(dir: &Path, rows: &[EcosystemStatus], json: bool) -> io::Result<String> {
    if json {
        let value = json!({
            "project": dir,
            "synced": rows.iter().all(EcosystemStatus::is_synced),
            "ecosystems": rows.iter().map(|row| {
                let (state, detail): (&str, Value) = match &row.state {
                    State::Synced => ("synced", Value::Null),
                    State::NotSynced => ("not-synced", Value::Null),
                    State::Changed(files) => ("changed", json!(files)),
                    State::ProjectionMissing(what) => ("projection-missing", json!(what)),
                    State::ForeignPlatform(platform) => ("foreign-platform", json!(platform)),
                    State::Unchecked(why) => ("synced-unchecked", json!(why)),
                };
                json!({
                    "ecosystem": row.ecosystem,
                    "state": state,
                    "detail": detail,
                    "summary": row.summary,
                })
            }).collect::<Vec<_>>(),
        });
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let width = rows
        .iter()
        .map(|row| row.ecosystem.len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for row in rows {
        let line = match &row.state {
            State::Synced => format!("synced      ({})", row.summary),
            State::NotSynced => "not synced  run 'blanket sync'".to_string(),
            State::Changed(files) => format!(
                "changed     {} since the last sync; run 'blanket sync'",
                files.join(", ")
            ),
            State::ProjectionMissing(what) => {
                format!("missing     {what} is not the synced projection; run 'blanket sync'")
            }
            State::ForeignPlatform(platform) => {
                format!("elsewhere   synced on {platform}; run 'blanket sync' on this host")
            }
            State::Unchecked(why) => format!("synced      ({}) — {why}", row.summary),
        };
        out.push_str(&format!("{:width$}  {line}\n", row.ecosystem));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// doctor

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
}

fn check(name: &'static str, level: Level, detail: impl Into<String>) -> Check {
    Check {
        name,
        level,
        detail: detail.into(),
    }
}

fn on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn free_bytes(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: statvfs writes into a zeroed struct of the right type.
    unsafe {
        let mut stats: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stats) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stats.f_bavail as u64 * stats.f_frsize as u64)
    }
}

const TOOLCHAIN_KINDS: &[&str] = &[
    "cpython",
    "uv",
    "nodejs",
    "rust",
    "go",
    "ruby",
    "beam",
    "dotnet-sdk",
    "native-libs",
];

/// Realized toolchains, from the store's metadata files only.
fn realized_toolchains(store: &Store) -> io::Result<Vec<String>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(store.root.join("meta"))? {
        let entry = entry?;
        let Ok(text) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let identity = &value["identity"];
        let kind = string(&identity["kind"]);
        if TOOLCHAIN_KINDS.contains(&kind.as_str()) {
            let name = string(&identity["name"]);
            let version = string(&identity["version"]);
            found.push(format!("{} {version}", if name.is_empty() { kind } else { name }));
        }
    }
    found.sort();
    found.dedup();
    Ok(found)
}

fn count_entries(path: &Path) -> usize {
    fs::read_dir(path).map(|entries| entries.count()).unwrap_or(0)
}

pub fn doctor(dir: &Path) -> Vec<Check> {
    let mut checks = Vec::new();
    let platform = match Platform::host() {
        Ok(platform) => {
            checks.push(check("platform", Level::Ok, platform.triple()));
            Some(platform)
        }
        Err(error) => {
            checks.push(check(
                "platform",
                Level::Fail,
                format!("{error}; blanket supports macOS arm64 and Linux x86_64"),
            ));
            None
        }
    };

    match Store::open() {
        Ok(store) => {
            let probe = store
                .root
                .join("tmp")
                .join(format!(".doctor-{}", std::process::id()));
            let writable = fs::write(&probe, b"ok").and_then(|()| fs::remove_file(&probe));
            match writable {
                Ok(()) => checks.push(check(
                    "store",
                    Level::Ok,
                    format!(
                        "{} ({} objects, {} cached artifacts)",
                        store.root.display(),
                        count_entries(&store.root.join("objects")),
                        count_entries(&store.root.join("cache/sha256"))
                    ),
                )),
                Err(error) => checks.push(check(
                    "store",
                    Level::Fail,
                    format!(
                        "{} is not writable: {error}; set BLANKET_STORE to a directory you own",
                        store.root.display()
                    ),
                )),
            }
            match free_bytes(&store.root) {
                Ok(bytes) => {
                    let gib = bytes as f64 / (1u64 << 30) as f64;
                    let level = if bytes < 5 * (1u64 << 30) {
                        Level::Warn
                    } else {
                        Level::Ok
                    };
                    let hint = if level == Level::Warn {
                        "; toolchains and native library sets need several GiB, 'blanket gc' frees space"
                    } else {
                        ""
                    };
                    checks.push(check(
                        "disk",
                        level,
                        format!("{gib:.1} GiB free under the store{hint}"),
                    ));
                }
                Err(error) => checks.push(check("disk", Level::Warn, error.to_string())),
            }
            match realized_toolchains(&store) {
                Ok(toolchains) if toolchains.is_empty() => checks.push(check(
                    "toolchains",
                    Level::Ok,
                    "none realized yet; the first 'blanket sync' downloads what the project needs",
                )),
                Ok(toolchains) => {
                    checks.push(check("toolchains", Level::Ok, toolchains.join(", ")))
                }
                Err(error) => checks.push(check("toolchains", Level::Warn, error.to_string())),
            }
        }
        Err(error) => checks.push(check(
            "store",
            Level::Fail,
            format!("cannot open the store: {error}; set BLANKET_STORE to a writable directory"),
        )),
    }

    if let Some(platform) = platform {
        match sandbox::probe(platform) {
            Ok(detail) => checks.push(check("sandbox", Level::Ok, detail)),
            Err(error) => checks.push(check(
                "sandbox",
                Level::Fail,
                format!("{error}; sdists, npm install scripts, and 'blanket build' need it"),
            )),
        }
        let required: &[&str] = match platform {
            Platform::X86_64UnknownLinuxGnu => &["cc", "c++", "make", "pkg-config", "patch"],
            Platform::Aarch64AppleDarwin => &["cc", "c++", "make"],
        };
        let missing: Vec<&str> = required
            .iter()
            .copied()
            .filter(|program| on_path(program).is_none())
            .collect();
        if missing.is_empty() {
            checks.push(check(
                "c-toolchain",
                Level::Ok,
                format!("{} on PATH", required.join(", ")),
            ));
        } else {
            let hint = match platform {
                Platform::X86_64UnknownLinuxGnu => {
                    "Fedora: sudo dnf install bubblewrap gcc gcc-c++ make binutils glibc-devel pkgconf-pkg-config patch zlib-ng-compat-devel libxcrypt-devel"
                }
                Platform::Aarch64AppleDarwin => "xcode-select --install",
            };
            checks.push(check(
                "c-toolchain",
                Level::Warn,
                format!(
                    "missing {}; pure wheels and lockfile installs work, native builds will not ({hint})",
                    missing.join(", ")
                ),
            ));
        }
    }

    let strict = std::env::var("BLANKET_STRICT").as_deref() == Ok("1");
    let policy_file = std::env::var_os("BLANKET_POLICY").map(PathBuf::from).or_else(|| {
        std::env::var_os("HOME")
            .map(|home| Path::new(&home).join(".blanket/policy.toml"))
            .filter(|path| path.is_file())
    });
    let mut policy = Vec::new();
    if strict {
        policy.push("BLANKET_STRICT=1".to_string());
    }
    if let Some(path) = policy_file {
        policy.push(path.display().to_string());
    }
    if dir.join(".blanket/policy.toml").is_file() {
        policy.push(".blanket/policy.toml".to_string());
    }
    checks.push(check(
        "policy",
        Level::Ok,
        if policy.is_empty() {
            "permissive (no policy file, BLANKET_STRICT unset)".to_string()
        } else {
            policy.join(", ")
        },
    ));

    match detected(dir) {
        Ok(found) if found.is_empty() => checks.push(check(
            "project",
            Level::Ok,
            format!("no project in {} (nothing to sync here)", dir.display()),
        )),
        Ok(found) => {
            let synced: Vec<String> = closures(dir)
                .map(|closures| closures.into_iter().map(|c| c.ecosystem).collect())
                .unwrap_or_default();
            let unsynced: Vec<&str> = found
                .iter()
                .copied()
                .filter(|name| !synced.iter().any(|s| s == name))
                .collect();
            checks.push(check(
                "project",
                Level::Ok,
                if unsynced.is_empty() {
                    format!("{} (synced; 'blanket status' checks the inputs)", found.join(", "))
                } else {
                    format!(
                        "{} found; not synced yet: {} (run 'blanket sync')",
                        found.join(", "),
                        unsynced.join(", ")
                    )
                },
            ));
        }
        Err(error) => checks.push(check("project", Level::Warn, error.to_string())),
    }
    checks
}

pub fn render_doctor(checks: &[Check], json: bool) -> io::Result<String> {
    if json {
        let value = json!({
            "ok": checks.iter().all(|check| check.level != Level::Fail),
            "checks": checks.iter().map(|check| json!({
                "name": check.name,
                "level": match check.level { Level::Ok => "ok", Level::Warn => "warn", Level::Fail => "fail" },
                "detail": check.detail,
            })).collect::<Vec<_>>(),
        });
        return Ok(serde_json::to_string_pretty(&value)? + "\n");
    }
    let width = checks
        .iter()
        .map(|check| check.name.len())
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for check in checks {
        let level = match check.level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => "FAIL",
        };
        out.push_str(&format!("{level}  {:width$}  {}\n", check.name, check.detail));
    }
    let failures = checks.iter().filter(|check| check.level == Level::Fail).count();
    if failures > 0 {
        out.push_str(&format!(
            "\n{failures} check{} failed.\n",
            if failures == 1 { "" } else { "s" }
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-inspect-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_closure(dir: &Path, ecosystem: &str, platform: &str, body: Value) {
        let closures = dir.join(".blanket/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(
            closures.join(format!("{ecosystem}.json")),
            serde_json::to_vec_pretty(&json!({
                "schema": "closure/1",
                "ecosystem": ecosystem,
                "platform": platform,
                "projected_at": 1,
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn detects_every_ecosystem_from_its_inputs() {
        let temp = TempDir::new("detect");
        assert!(detected(&temp.0).unwrap().is_empty());
        fs::write(temp.0.join("requirements.txt"), "six\n").unwrap();
        fs::write(temp.0.join("package.json"), "{}").unwrap();
        fs::write(temp.0.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::write(temp.0.join("go.mod"), "module x\n").unwrap();
        fs::write(temp.0.join("Gemfile"), "").unwrap();
        fs::write(temp.0.join("mix.exs"), "").unwrap();
        fs::write(temp.0.join("app.csproj"), "").unwrap();
        assert_eq!(detected(&temp.0).unwrap(), ECOSYSTEMS);
    }

    #[test]
    fn listing_reads_every_closure_shape() {
        let temp = TempDir::new("ls");
        let host = Platform::host().unwrap().triple();
        write_closure(
            &temp.0,
            "python",
            host,
            json!({"env_object": "/s/objects/e", "python": {"version": "3.12.14"},
                   "plan": {"python_version": "3.12.14", "packages": [
                       {"name": "six", "version": "1.17.0", "filename": "six-1.17.0-py2.py3-none-any.whl"}]}}),
        );
        write_closure(
            &temp.0,
            "node",
            host,
            json!({"node_version": "24.0.0", "packages": [
                {"path": "node_modules/a", "version": "1.0.0"},
                {"path": "node_modules/a/node_modules/@s/b", "version": "2.0.0"}]}),
        );
        write_closure(
            &temp.0,
            "cargo",
            host,
            json!({"plan": {"rust_version": "1.96.1", "crates": [{"name": "serde", "version": "1.0.0", "sha256": "ab"}]}}),
        );
        write_closure(&temp.0, "go", host, json!({"plan": {"go_version": "1.25", "modules": [{"path": "github.com/x/y", "version": "v1.2.3"}]}}));
        write_closure(&temp.0, "ruby", host, json!({"plan": {"ruby_version": "3.4.6", "bundler_version": "2.6", "gems": [{"name": "rake", "version": "13.0", "full_name": "rake-13.0"}]}}));
        write_closure(&temp.0, "elixir", host, json!({"plan": {"elixir_version": "1.18", "otp_version": "27", "deps": [{"app": "jason", "package": "jason", "version": "1.4"}]}}));
        write_closure(&temp.0, "dotnet", host, json!({"plan": {"sdk_version": "9.0", "packages": [{"id": "Newtonsoft.Json", "version": "13.0", "content_hash": "x"}]}}));

        let all = closures(&temp.0).unwrap();
        assert_eq!(
            all.iter().map(|c| c.ecosystem.as_str()).collect::<Vec<_>>(),
            ECOSYSTEMS
        );
        let node = listing(&all[1]);
        assert_eq!(node.toolchain, vec![("node".to_string(), "24.0.0".to_string())]);
        assert_eq!(node.packages[0].name, "@s/b");
        assert_eq!(node.packages[1].name, "a");
        let text = ls(&temp.0, None, false, false).unwrap();
        assert!(text.starts_with("python  (cpython 3.12.14; 1 package)\n  six  1.17.0\n"));
        assert!(text.contains("\nnode  (node 24.0.0; 2 packages)\n"));
        assert!(text.contains("  Newtonsoft.Json  13.0\n"));
        let only = ls(&temp.0, Some("go"), false, true).unwrap();
        assert_eq!(only, "go  (go 1.25; 1 package)\n  github.com/x/y  v1.2.3\n");
        let json_text = ls(&temp.0, Some("cargo"), true, false).unwrap();
        let value: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(value["ecosystems"][0]["packages"][0]["name"], "serde");
        assert_eq!(value["ecosystems"][0]["toolchain"][0]["version"], "1.96.1");

        let empty = TempDir::new("ls-empty");
        let error = ls(&empty.0, None, false, false).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("run 'blanket sync' first"));
        let error = ls(&temp.0, Some("python"), false, false);
        assert!(error.is_ok());
        let missing = {
            let solo = TempDir::new("ls-solo");
            write_closure(&solo.0, "go", host, json!({"plan": {"go_version": "1.25", "modules": []}}));
            ls(&solo.0, Some("python"), false, false).unwrap_err().to_string()
        };
        assert!(missing.contains("no python closure here"), "{missing}");
    }

    #[test]
    fn status_tracks_inputs_locks_projections_and_platforms() {
        let temp = TempDir::new("status");
        let platform = Platform::host().unwrap();
        let host = platform.triple();
        let dir = &temp.0;
        fs::write(dir.join("requirements.txt"), "six==1.17.0\n").unwrap();
        fs::write(dir.join("go.mod"), "module x\n").unwrap();
        fs::write(dir.join("go.sum"), "sum\n").unwrap();
        fs::write(dir.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
        fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

        // Nothing synced yet.
        let rows = status(platform, dir).unwrap();
        assert!(rows.iter().all(|row| row.state == State::NotSynced));
        assert_eq!(rows.len(), 3);

        // Python: projection + recorded inputs.
        let env = dir.join("env-object");
        fs::create_dir_all(env.join("bin")).unwrap();
        std::os::unix::fs::symlink(&env, dir.join(".venv")).unwrap();
        let requirements = sha256_file(&dir.join("requirements.txt")).unwrap();
        write_closure(
            dir,
            "python",
            host,
            json!({"env_object": env, "python": {"version": "3.12.14"},
                   "plan": {"packages": []},
                   "inputs": [{"path": "requirements.txt", "sha256": requirements}]}),
        );
        // Go: recorded lock hash; cargo: projection missing.
        write_closure(
            dir,
            "go",
            host,
            json!({"go_sum_sha256": sha256_file(&dir.join("go.sum")).unwrap(), "plan": {"go_version": "1.25", "modules": []}}),
        );
        write_closure(
            dir,
            "cargo",
            host,
            json!({"cargo_lock_sha256": sha256_file(&dir.join("Cargo.lock")).unwrap(), "plan": {"rust_version": "1.96.1", "crates": []}}),
        );
        let rows = status(platform, dir).unwrap();
        assert_eq!(rows[0].state, State::Synced);
        assert_eq!(rows[1].state, State::ProjectionMissing(".blanket/cargo-home".into()));
        assert_eq!(rows[2].state, State::Synced);
        let text = render_status(dir, &rows, false).unwrap();
        assert!(text.contains("python  synced      (cpython 3.12.14; 0 packages)"), "{text}");
        assert!(text.contains("cargo   missing     .blanket/cargo-home"), "{text}");

        // Edit the manifest and the lock: both reported by name.
        fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        fs::write(dir.join("go.sum"), "changed\n").unwrap();
        fs::create_dir_all(dir.join(".blanket/cargo-home")).unwrap();
        let rows = status(platform, dir).unwrap();
        assert_eq!(rows[0].state, State::Changed(vec!["requirements.txt".into()]));
        assert_eq!(rows[1].state, State::Synced);
        assert_eq!(rows[2].state, State::Changed(vec!["go.sum".into()]));
        let json_text = render_status(dir, &rows, true).unwrap();
        let value: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(value["synced"], false);
        assert_eq!(value["ecosystems"][0]["state"], "changed");
        assert_eq!(value["ecosystems"][0]["detail"][0], "requirements.txt");

        // A closure without recorded inputs is synced-but-unchecked.
        write_closure(
            dir,
            "python",
            host,
            json!({"env_object": env, "python": {"version": "3.12.14"}, "plan": {"packages": []}}),
        );
        let rows = status(platform, dir).unwrap();
        assert!(matches!(rows[0].state, State::Unchecked(_)));
        assert!(rows[0].is_synced());

        // A foreign platform is reported, not compared.
        write_closure(dir, "go", "other-platform", json!({"go_sum_sha256": "x", "plan": {}}));
        let rows = status(platform, dir).unwrap();
        assert_eq!(rows[2].state, State::ForeignPlatform("other-platform".into()));
    }

    #[test]
    fn doctor_reports_host_and_project() {
        let temp = TempDir::new("doctor");
        let store = temp.0.join("store");
        let old_store = std::env::var_os("BLANKET_STORE");
        std::env::set_var("BLANKET_STORE", &store);
        let checks = doctor(&temp.0);
        match old_store {
            Some(value) => std::env::set_var("BLANKET_STORE", value),
            None => std::env::remove_var("BLANKET_STORE"),
        }
        let names: Vec<&str> = checks.iter().map(|check| check.name).collect();
        for expected in ["platform", "store", "disk", "toolchains", "sandbox", "c-toolchain", "policy", "project"] {
            assert!(names.contains(&expected), "{names:?} lacks {expected}");
        }
        let store_check = checks.iter().find(|check| check.name == "store").unwrap();
        assert_eq!(store_check.level, Level::Ok, "{}", store_check.detail);
        assert!(store_check.detail.contains("0 objects"));
        let project = checks.iter().find(|check| check.name == "project").unwrap();
        assert!(project.detail.contains("no project in"));
        let text = render_doctor(&checks, false).unwrap();
        assert!(text.contains("  platform  "));
        let value: Value = serde_json::from_str(&render_doctor(&checks, true).unwrap()).unwrap();
        assert!(value["checks"].as_array().unwrap().len() >= 8);
    }
}
