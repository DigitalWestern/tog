//! The Go tailor: module closure via the pinned Go toolchain, blanket-owned
//! verification (dirhash h1 + raw sha256), immutable GOMODCACHE objects.
//!
//! go.sum is an authentication ledger, not a lock graph (Sol review 4): the
//! authoritative closure comes from `go mod download -json all` run by the
//! STORE Go in a disposable copy. Blanket then independently re-verifies
//! every artifact (dirhash::hash_zip / hash_gomod) before any byte enters
//! the store — delegation computes, the kernel verifies.

pub mod inputs;
pub mod objects;
pub mod tailor;

use crate::kernel::archive::Compression;
use crate::kernel::dirhash;
use crate::kernel::fetch::{cache_insert, cache_verified_held, download_verified_held, Digest};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::types::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const GO_VERSION: &str = "1.27.0";
struct GoPin {
    platform: Platform,
    version: &'static str,
    url: &'static str,
    sha256: &'static str,
}

const GO_PIN_ROWS: &[GoPin] = &[
    GoPin {
        platform: Platform::Aarch64AppleDarwin,
        version: GO_VERSION,
        url: "https://go.dev/dl/go1.27.0.darwin-arm64.tar.gz",
        sha256: "90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e",
    },
    GoPin {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: GO_VERSION,
        url: "https://go.dev/dl/go1.27.0.linux-amd64.tar.gz",
        sha256: "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685",
    },
];

fn go_pin(platform: Platform, version: &str) -> io::Result<&'static GoPin> {
    if let Some(pin) = GO_PIN_ROWS
        .iter()
        .find(|pin| pin.platform == platform && pin.version == version)
    {
        return Ok(pin);
    }
    let pins = GO_PIN_ROWS
        .iter()
        .filter(|pin| pin.platform == platform)
        .map(|pin| pin.version)
        .collect::<Vec<_>>();
    if pins.is_empty() {
        return Err(no_pin("go", platform, "stage 4"));
    }
    Err(err(format!(
        "internal: resolved Go {version} for {} but only {} is realizable; set go.mod's `go` or `toolchain` directive to one of the pinned versions, or add a matching verified Go pin",
        platform.triple(),
        pins.join(", ")
    )))
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "Go toolchain", "stage 4")?;
    go_pins(platform).map(|_| ())
}

fn go_identity(pin: &GoPin) -> Identity {
    Identity {
        kind: "go".into(),
        name: "go".into(),
        version: pin.version.into(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "go-toolchain/1".to_string()),
            ("artifact_sha256".to_string(), pin.sha256.to_string()),
            ("platform".to_string(), pin.platform.triple().to_string()),
        ]),
    }
}

fn go_pins(platform: Platform) -> io::Result<Vec<&'static str>> {
    let mut pins: Vec<_> = GO_PIN_ROWS
        .iter()
        .filter(|pin| pin.platform == platform)
        .map(|pin| pin.version)
        .collect();
    pins.sort_unstable();
    pins.dedup();
    if pins.is_empty() {
        return Err(no_pin("go", platform, "stage 4"));
    }
    Ok(pins)
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Extract a provider Go archive into its store staging directory. Go's
/// release archives have exactly one `go/` root; strip that one level while
/// retaining the complete toolchain tree below it.
#[cfg(test)]
fn extract_go_toolchain(platform: Platform, archive: &Path, staged: &Path) -> io::Result<()> {
    extract_go_toolchain_inner(platform, archive, staged, None)
}

fn extract_go_toolchain_for(
    store: &Store,
    platform: Platform,
    archive: &Path,
    staged: &Path,
) -> io::Result<()> {
    extract_go_toolchain_inner(platform, archive, staged, Some(store))
}

fn extract_go_toolchain_inner(
    platform: Platform,
    archive: &Path,
    staged: &Path,
    store: Option<&Store>,
) -> io::Result<()> {
    // List first (src/archive.rs): the layout check below and the
    // containment rules both run before tar writes anything.
    let entries = match store {
        Some(store) => crate::kernel::archive::list_for_store(
            store,
            archive_platform(platform),
            archive,
            Compression::Gzip,
        ),
        None => {
            crate::kernel::archive::list(archive_platform(platform), archive, Compression::Gzip)
        }
    }
    .map_err(|e| err(format!("could not inspect Go archive layout: {e}")))?;
    let mut saw_entry = false;
    for entry in &entries {
        let raw = entry.name.as_str();
        let entry = raw.trim_end_matches('/');
        if entry.is_empty() {
            continue;
        }
        let mut components = entry.split('/');
        if components.next() != Some("go")
            || components
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(err(format!(
                "go archive has unexpected layout entry {raw:?}; expected a single top-level go/ root"
            )));
        }
        saw_entry = true;
    }
    if !saw_entry {
        return Err(err("go archive has unexpected empty layout"));
    }

    match store {
        Some(store) => crate::kernel::archive::extract_validated_for_store(
            store,
            archive_platform(platform),
            archive,
            staged,
            1,
            Compression::Gzip,
            &entries,
        )?,
        None => crate::kernel::archive::extract_validated(
            archive_platform(platform),
            archive,
            staged,
            1,
            Compression::Gzip,
            &entries,
        )?,
    }
    if !staged.join("bin/go").is_file() {
        return Err(err("go tarball extraction failed or has unexpected layout"));
    }
    Ok(())
}

/// The tar that runs is the host's, whatever platform the pin is for; the
/// archive module needs the host so it parses the host tar's listing.
fn archive_platform(platform: Platform) -> Platform {
    Platform::host().unwrap_or(platform)
}

/// Ensure the pinned Go toolchain is realized in the store.
pub fn ensure_go(store: &Store, version: &str) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    ensure_go_for(store, Platform::host()?, version)
}

pub fn ensure_go_for(store: &Store, platform: Platform, version: &str) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Go toolchain", "stage 4")?;
    // Resolve the exact row before touching the store or downloading. A
    // future catalog may carry several versions for one platform; falling
    // back to GO_VERSION here would pair the plan with the wrong toolchain.
    let pin = go_pin(platform, version)?;
    let identity = go_identity(pin);
    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified_held(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    extract_go_toolchain_for(store, platform, &tarball, &staged)?;
    store
        .commit_with_deps(&identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(pin.sha256)?);
            deps
        })
        .map(|(path, _)| path)
}

/// The forced environment for EVERY blanket-controlled go invocation.
/// Real process env, never a GOENV file: GOTOOLCHAIN=local stops silent
/// toolchain swaps, GOROOT pins the stdlib, GOWORK/GOENV=off close the
/// config side doors (Sol review 4).
pub fn go_env(go_obj: &Path, modcache: &Path, offline: bool) -> Vec<(String, String)> {
    let mut env = vec![
        ("GOTOOLCHAIN".to_string(), "local".to_string()),
        ("GOROOT".to_string(), go_obj.display().to_string()),
        ("GOENV".to_string(), "off".to_string()),
        ("GOWORK".to_string(), "off".to_string()),
        ("GOMODCACHE".to_string(), modcache.display().to_string()),
        ("GOFLAGS".to_string(), String::new()),
        ("GOPRIVATE".to_string(), String::new()),
        ("GONOPROXY".to_string(), String::new()),
        ("GONOSUMDB".to_string(), String::new()),
        ("GOINSECURE".to_string(), String::new()),
        ("GOCACHEPROG".to_string(), String::new()),
    ];
    if offline {
        env.push(("GOPROXY".to_string(), "off".to_string()));
        env.push(("GOSUMDB".to_string(), "off".to_string()));
    } else {
        // Resolver policy is FORCED, never inherited (Sol: an inherited
        // GOPROXY=file:...+GOSUMDB=off resolves attacker code). Proxy-only,
        // checksum-db on, VCS fallback off — private modules are a later,
        // explicitly-designed feature.
        env.push((
            "GOPROXY".to_string(),
            "https://proxy.golang.org".to_string(),
        ));
        env.push(("GOSUMDB".to_string(), "sum.golang.org".to_string()));
        env.push(("GOVCS".to_string(), "*:off".to_string()));
    }
    env
}

/// Run the store Go for a delegated edit (`blanket add` and friends).
pub(crate) fn run_checked(
    store: &Store,
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<()> {
    crate::kernel::ui::trace(&format!(
        "run: go {} (in {})",
        args.join(" "),
        cwd.display()
    ));
    let out = run_go(store, go_obj, cwd, modcache, offline, args)?;
    if crate::kernel::ui::verbose() {
        eprint!("{}", String::from_utf8_lossy(&out.stdout));
    }
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "store go {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn run_go(
    store: &Store,
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<std::process::Output> {
    let mut cmd = Command::new(go_obj.join("bin/go"));
    cmd.args(args).current_dir(cwd);
    for (k, v) in go_env(go_obj, modcache, offline) {
        if v.is_empty() {
            cmd.env_remove(&k);
        } else {
            cmd.env(&k, &v);
        }
    }
    crate::kernel::supervise::output_owned(&mut cmd, store)
        .map_err(|e| io::Error::new(e.kind(), format!("run store go {args:?}: {e}")))
}

/// Toolchain selection from go.mod directives (Sol rules): `go` is a
/// minimum, `toolchain` a suggestion; pick the lowest pin satisfying both.
pub fn resolve_toolchain(platform: Platform, gomod: &str) -> io::Result<&'static str> {
    let pins = go_pins(platform)?;
    let mut min_go: Option<Vec<u64>> = None;
    let mut suggestion: Option<Vec<u64>> = None;
    for line in gomod.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("go ") {
            min_go = Some(go_version_key(v.trim(), &pins)?);
        } else if let Some(v) = line.strip_prefix("toolchain ") {
            let v = v.trim();
            if v == "default" {
                continue;
            }
            let v = v.strip_prefix("go").unwrap_or(v);
            suggestion = Some(go_version_key(v, &pins)?);
        }
    }
    let floor = |k: &Option<Vec<u64>>| k.clone().unwrap_or_default();
    let (need_a, need_b) = (floor(&min_go), floor(&suggestion));
    pins.iter()
        .copied()
        .filter_map(|p| go_version_key(p, &pins).ok().map(|k| (k, p)))
        .filter(|(k, _)| *k >= need_a && *k >= need_b)
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, p)| p)
        .ok_or_else(|| {
            err(format!(
                "no pinned Go toolchain satisfies this module's go/toolchain \
                 directives; pinned: {}",
                pins.join(", ")
            ))
        })
}

/// Resolve the Go version selected by a project's go.mod before realizing a
/// toolchain. Callers use this result as the authority for `ensure_go_for`.
pub fn resolve_project_toolchain(
    platform: Platform,
    project_dir: &Path,
) -> io::Result<&'static str> {
    let gomod = fs::read_to_string(project_dir.join("go.mod"))
        .map_err(|e| io::Error::new(e.kind(), format!("go.mod: {e}")))?;
    resolve_toolchain(platform, &gomod)
}

/// Go version ordering: numeric dot components, missing patch = 0.
/// Prerelease suffixes (rc/beta) are rejected — no pins carry them.
fn go_version_key(v: &str, pins: &[&str]) -> io::Result<Vec<u64>> {
    let mut key: Vec<u64> = Vec::new();
    for part in v.split('.') {
        key.push(part.parse::<u64>().map_err(|_| {
            err(format!(
                "unsupported Go version {v:?} (prerelease/custom toolchains \
                 are not supported; pinned: {})",
                pins.join(", ")
            ))
        })?);
    }
    while key.len() < 3 {
        key.push(0);
    }
    Ok(key)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoModule {
    pub path: String,
    pub version: String,
    pub h1: String,
    pub zip_sha256: String,
    pub modfile_h1: String,
    pub modfile_sha256: String,
    pub info_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoPlan {
    pub go_version: String,
    pub module: String,
    pub modules: Vec<GoModule>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DownloadEntry {
    path: String,
    version: String,
    #[serde(default)]
    sum: Option<String>,
    #[serde(default)]
    go_mod_sum: Option<String>,
    #[serde(default)]
    zip: Option<String>,
    #[serde(default)]
    go_mod: Option<String>,
    #[serde(default)]
    info: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    replace: Option<Box<DownloadEntry>>,
}

/// Reject go.work anywhere up the tree (v0: single-module projects only).
pub fn reject_workspaces(project_dir: &Path) -> io::Result<()> {
    if std::env::var_os("GOWORK").map_or(false, |v| !v.is_empty() && v != "off") {
        return Err(err("GOWORK is set; Go workspaces are not supported yet"));
    }
    for dir in project_dir.ancestors() {
        if dir.join("go.work").is_file() {
            return Err(err(format!(
                "{}/go.work found; Go workspaces are not supported yet — \
                 run from a single-module project",
                dir.display()
            )));
        }
    }
    Ok(())
}

/// Local-path replace directives never appear in `go mod download -json`
/// output (Go elides them), so they must be rejected from go.mod itself
/// (Sol: reproduced unverified in-project code entering a build).
pub fn reject_local_replaces(gomod: &str) -> io::Result<()> {
    let mut in_block = false;
    for raw in gomod.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        let body = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("replace") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
                continue;
            }
            rest
        } else {
            continue;
        };
        if let Some((_, target)) = body.split_once("=>") {
            let target = target.trim();
            let path = target.split_whitespace().next().unwrap_or("");
            let has_version = target.split_whitespace().count() >= 2;
            if path.starts_with("./")
                || path.starts_with("../")
                || path.starts_with('/')
                || (!has_version && !path.is_empty())
            {
                return Err(err(format!(
                    "go.mod replaces a module with local path {path:?}; \
                     local replace directives are not supported yet \
                     (no go.sum integrity for local trees)"
                )));
            }
        }
    }
    Ok(())
}

/// A plan (fresh or loaded from the .blanket cache) is untrusted input:
/// every field that becomes a cache address or identity input is validated.
fn validate_plan(plan: &GoPlan) -> io::Result<()> {
    let hex_ok = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let h1_ok = |s: &str| {
        s.len() == 47
            && s.starts_with("h1:")
            && s[3..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
    };
    let mut seen = std::collections::BTreeSet::new();
    for m in &plan.modules {
        escape_go_path(&m.path)?;
        escape_go_path(&m.version)?;
        if !seen.insert((m.path.clone(), m.version.clone())) {
            return Err(err(format!(
                "duplicate module {}@{} in plan",
                m.path, m.version
            )));
        }
        for sha in [&m.zip_sha256, &m.modfile_sha256, &m.info_sha256] {
            if !hex_ok(sha) {
                return Err(err(format!(
                    "{}@{}: invalid sha256 in plan: {sha:?}",
                    m.path, m.version
                )));
            }
        }
        for h1 in [&m.h1, &m.modfile_h1] {
            if !h1_ok(h1) {
                return Err(err(format!(
                    "{}@{}: invalid h1 in plan: {h1:?}",
                    m.path, m.version
                )));
            }
        }
    }
    Ok(())
}

/// Parse the module path from go.mod.
pub fn module_path(gomod: &str) -> io::Result<String> {
    for line in gomod.lines() {
        if let Some(m) = line.trim().strip_prefix("module ") {
            return Ok(m.trim().trim_matches('"').to_string());
        }
    }
    Err(err("go.mod has no module directive"))
}

/// Schema tag baked into the plan-cache key: a bump makes every existing
/// `.blanket/go-plan.json` miss instead of being read under new rules.
const PLANNER_SCHEMA: &str = "go-planner/2";

/// The plan-cache key. The tidy gate's inputs are exactly go.mod + go.sum +
/// the .go sources, so the key covers all three: a hit proves the last
/// successful gate's inputs are unchanged, making a re-run redundant (Sol
/// finding 7, solved by keying instead of re-running).
fn plan_cache_key(go_version: &str, gomod: &str, gosum: &str, src_digest: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{PLANNER_SCHEMA}\x00{go_version}\x00{gomod}\x00{gosum}\x00{src_digest}")
            .as_bytes(),
    ))
}

/// Read the cached plan when its key matches. The cache file is
/// attacker-editable project state, so a hit is validated before it is used;
/// anything unreadable, unparsable, or stale is simply a miss.
fn cached_plan(cache_path: &Path, input_hash: &str) -> io::Result<Option<GoPlan>> {
    if let Ok(cached) = fs::read_to_string(cache_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&cached) {
            if v["input_hash"] == input_hash {
                if let Ok(plan) = serde_json::from_value::<GoPlan>(v["plan"].clone()) {
                    validate_plan(&plan)?;
                    return Ok(Some(plan));
                }
            }
        }
    }
    Ok(None)
}

/// Consistency gate: tidy -diff is non-mutating (prints a diff, exit
/// nonzero when go.mod/go.sum need changes). Needs the source tree, so
/// it runs in the real project — but never writes. Its module cache is a
/// persistent planner scratch (resolver-trust only; never feeds objects).
/// Returns the final, possibly tidied, manifest pair.
fn tidy_gate(
    store: &Store,
    go_obj: &Path,
    project_dir: &Path,
    gate_cache: &Path,
    scratch: &Path,
    gomod: String,
    gosum: String,
) -> io::Result<(String, String)> {
    let out = run_go(
        store,
        go_obj,
        project_dir,
        gate_cache,
        false,
        &["mod", "tidy", "-diff"],
    )?;
    if out.status.success() {
        return Ok((gomod, gosum));
    }
    // Out-of-sync manifest: run the ecosystem's resolver, the same
    // delegated mutation as uv pip compile / cargo generate-lockfile.
    eprintln!("blanket: go.mod/go.sum need updating; resolving with the store go mod tidy...");
    let out = run_go(
        store,
        go_obj,
        project_dir,
        gate_cache,
        false,
        &["mod", "tidy"],
    )?;
    if !out.status.success() {
        let _ = crate::kernel::store::remove_tree(scratch);
        return Err(err(format!(
            "store go mod tidy failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok((
        fs::read_to_string(project_dir.join("go.mod"))?,
        fs::read_to_string(project_dir.join("go.sum")).unwrap_or_default(),
    ))
}

/// Run the closure download in a DISPOSABLE copy of the manifest (go mod
/// download may rewrite go.mod/go.sum). The module cache is the persistent
/// planner scratch — warm downloads; trust is irrelevant because every
/// artifact is re-verified by `closure_from_download`.
fn download_closure(
    store: &Store,
    go_obj: &Path,
    work: &Path,
    gate_cache: &Path,
    gomod: &str,
    gosum: &str,
) -> io::Result<std::process::Output> {
    fs::create_dir_all(work)?;
    fs::write(work.join("go.mod"), gomod)?;
    if !gosum.is_empty() {
        fs::write(work.join("go.sum"), gosum)?;
    }
    eprintln!("blanket: computing Go module closure with the store toolchain...");
    run_go(
        store,
        go_obj,
        work,
        gate_cache,
        false,
        &["mod", "download", "-json", "all"],
    )
}

/// Verify the JSON stream of `go mod download` into plan rows. Ledger
/// anchor: h1 values must ALSO appear in the project's go.sum — never trust
/// sums that exist only in the delegated tool's output. The stream (a
/// sequence of concatenated objects) is parsed BEFORE the exit status is
/// checked: per-module errors ride in the stream.
fn closure_from_download(
    store: &Store,
    out: &std::process::Output,
    gosum: &str,
) -> io::Result<Vec<GoModule>> {
    let ledger: std::collections::BTreeSet<String> =
        gosum.lines().map(|l| l.trim().to_string()).collect();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut modules = Vec::new();
    let mut de = serde_json::Deserializer::from_str(&stdout).into_iter::<DownloadEntry>();
    while let Some(entry) = de.next() {
        let entry = entry.map_err(|e| err(format!("go mod download JSON: {e}")))?;
        if let Some(module) = verified_module(store, entry, &ledger)? {
            modules.push(module);
        }
    }
    if !out.status.success() {
        return Err(err(format!(
            "go mod download failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(modules)
}

/// Blanket-owned verification of one download entry: recompute both
/// dirhashes, check the .info's claim, and insert the bytes into the cache.
/// `Ok(None)` means "outside the closure" — the main module (no artifacts)
/// or a build-GRAPH-only module whose zip sum the tidied go.sum omits.
fn verified_module(
    store: &Store,
    entry: DownloadEntry,
    ledger: &std::collections::BTreeSet<String>,
) -> io::Result<Option<GoModule>> {
    if let Some(msg) = &entry.error {
        return Err(err(format!(
            "{}@{}: {msg} (a selected module failed to download; the \
             closure would be incomplete)",
            entry.path, entry.version
        )));
    }
    // A version-to-version replace surfaces the replacement's
    // artifacts on the outer entry; a local-path replace has no
    // Version and no integrity — fail closed.
    if let Some(rep) = &entry.replace {
        if rep.version.is_empty() || rep.path.starts_with('.') || rep.path.starts_with('/') {
            return Err(err(format!(
                "{}: local-path replace directives are not supported \
                 yet (no go.sum integrity); vendor a released version",
                entry.path
            )));
        }
    }
    let (Some(zip), Some(gomod_file), Some(sum), Some(gomod_sum)) =
        (&entry.zip, &entry.go_mod, &entry.sum, &entry.go_mod_sum)
    else {
        return Ok(None); // main module / no artifacts
    };
    // Ledger anchor: the tidied go.sum is the authority. Modules
    // whose zip sums it omits are build-GRAPH-only (tidy records
    // zip sums for exactly the modules whose packages a build can
    // import) — exclude them from the closure rather than fail:
    // an offline build never loads their sources, and if one were
    // ever needed the readonly+GOPROXY=off build fails loudly.
    if !ledger.contains(&format!("{} {} {}", entry.path, entry.version, sum)) {
        return Ok(None);
    }
    if !ledger.contains(&format!(
        "{} {}/go.mod {}",
        entry.path, entry.version, gomod_sum
    )) {
        return Err(err(format!(
            "{}@{}: go.mod sum is not in the project's go.sum \
             ledger; refusing (run `blanket run go mod tidy`)",
            entry.path, entry.version
        )));
    }
    // Blanket-owned verification: recompute both dirhashes.
    let got_h1 = dirhash::hash_zip(Path::new(zip), &entry.path, &entry.version)?;
    if got_h1 != *sum {
        return Err(err(format!(
            "{}@{}: zip dirhash mismatch\n  expected {sum}\n  got      {got_h1}",
            entry.path, entry.version
        )));
    }
    let got_mod_h1 = dirhash::hash_gomod(Path::new(gomod_file))?;
    if got_mod_h1 != *gomod_sum {
        return Err(err(format!(
            "{}@{}: go.mod dirhash mismatch\n  expected {gomod_sum}\n  got      {got_mod_h1}",
            entry.path, entry.version
        )));
    }
    let (zip_sha256, _) = cache_insert(store, Path::new(zip))?;
    let (modfile_sha256, _) = cache_insert(store, Path::new(gomod_file))?;
    let info = entry.info.as_deref().ok_or_else(|| {
        err(format!(
            "{}@{}: download entry has no Info file",
            entry.path, entry.version
        ))
    })?;
    // .info is proxy metadata: verify it says what the plan says
    // before its bytes become an identity input.
    let info_json: serde_json::Value = serde_json::from_str(&fs::read_to_string(info)?)
        .map_err(|e| err(format!("{}@{}: bad .info: {e}", entry.path, entry.version)))?;
    if info_json["Version"].as_str() != Some(entry.version.as_str()) {
        return Err(err(format!(
            "{}@{}: .info Version {:?} does not match",
            entry.path, entry.version, info_json["Version"]
        )));
    }
    let (info_sha256, _) = cache_insert(store, Path::new(info))?;
    Ok(Some(GoModule {
        path: entry.path,
        version: entry.version,
        h1: sum.clone(),
        zip_sha256,
        modfile_h1: gomod_sum.clone(),
        modfile_sha256,
        info_sha256,
    }))
}

/// Plan the module closure. Network-permitted delegation to the store Go in
/// a DISPOSABLE copy (go mod download can rewrite go.mod/go.sum), followed
/// by blanket-owned verification of every artifact. Cached in
/// .blanket/go-plan.json keyed by go.mod+go.sum content.
pub fn plan_go(
    store: &Store,
    platform: Platform,
    project_dir: &Path,
    go_obj: &Path,
) -> io::Result<GoPlan> {
    reject_workspaces(project_dir)?;
    let gomod = fs::read_to_string(project_dir.join("go.mod"))
        .map_err(|e| io::Error::new(e.kind(), format!("go.mod: {e}")))?;
    let gosum = fs::read_to_string(project_dir.join("go.sum")).unwrap_or_default();
    reject_local_replaces(&gomod)?;
    let go_version = resolve_toolchain(platform, &gomod)?;

    let src_digest = source_digest(project_dir)?;
    let input_hash = plan_cache_key(go_version, &gomod, &gosum, &src_digest);
    let cache_path = project_dir.join(".blanket/go-plan.json");
    if let Some(plan) = cached_plan(&cache_path, &input_hash)? {
        return Ok(plan);
    }

    let scratch = store.stage()?;
    let gate_cache = store.root.join("planner-modcache");
    fs::create_dir_all(&gate_cache)?;
    let (gomod, gosum) = tidy_gate(
        store,
        go_obj,
        project_dir,
        &gate_cache,
        &scratch,
        gomod,
        gosum,
    )?;
    reject_local_replaces(&gomod)?;
    // Cache under the FINAL (possibly tidied) inputs so the next sync hits.
    let go_version = resolve_toolchain(platform, &gomod)?;
    let module = module_path(&gomod)?;
    let input_hash = plan_cache_key(go_version, &gomod, &gosum, &source_digest(project_dir)?);

    let work = scratch.join("plan");
    let out = download_closure(store, go_obj, &work, &gate_cache, &gomod, &gosum)?;
    let result = closure_from_download(store, &out, &gosum);
    let _ = crate::kernel::store::remove_tree(&scratch);
    let mut modules = result?;
    modules.sort_by(|a, b| (&a.path, &a.version).cmp(&(&b.path, &b.version)));

    let plan = GoPlan {
        go_version: go_version.to_string(),
        module,
        modules,
    };
    validate_plan(&plan)?;
    // Snapshot guard: the manifest must not have changed under us between
    // the gate and now, or the cache key would lie about the plan's inputs.
    let now_mod = fs::read_to_string(project_dir.join("go.mod")).unwrap_or_default();
    let now_sum = fs::read_to_string(project_dir.join("go.sum")).unwrap_or_default();
    if now_mod != gomod || now_sum != gosum {
        return Err(err(
            "go.mod/go.sum changed while planning; re-run blanket sync",
        ));
    }
    fs::create_dir_all(project_dir.join(".blanket"))?;
    fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "input_hash": input_hash,
            "plan": plan,
        }))?,
    )?;
    Ok(plan)
}

/// Digest of the project's .go sources (the tidy gate's third input).
/// Sorted (relpath, sha256) pairs; hidden dirs and .blanket are skipped.
fn source_digest(project_dir: &Path) -> io::Result<String> {
    let mut files: Vec<(String, String)> = Vec::new();
    fn walk(root: &Path, dir: &Path, files: &mut Vec<(String, String)>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || name.starts_with('_') {
                continue;
            }
            let md = fs::symlink_metadata(&path)?;
            if md.is_dir() {
                walk(root, &path, files)?;
            } else if md.is_file() && name.ends_with(".go") {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|e| err(format!("source walk: {e}")))?
                    .to_string_lossy()
                    .into_owned();
                let content = fs::read(&path)?;
                files.push((rel, hex::encode(Sha256::digest(&content))));
            }
        }
        Ok(())
    }
    walk(project_dir, project_dir, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for (rel, hash) in &files {
        hasher.update(format!("{hash}  {rel}\n").as_bytes());
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Go's module path/version escaping: uppercase c -> "!c" (module paths
/// never contain '!' themselves; validated below).
pub fn escape_go_path(s: &str) -> io::Result<String> {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'A'..='Z' => {
                out.push('!');
                out.push(c.to_ascii_lowercase());
            }
            '!' => return Err(err(format!("invalid Go module path/version {s:?}"))),
            _ => out.push(c),
        }
    }
    for seg in out.split('/') {
        if seg == ".." || seg == "." || seg.is_empty() {
            return Err(err(format!("unsafe Go module path/version {s:?}")));
        }
    }
    if !out
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._~!+-/".contains(&b))
    {
        return Err(err(format!(
            "invalid characters in Go module path/version {s:?}"
        )));
    }
    Ok(out)
}

/// Stage the cache/download skeleton for a plan (zips, .mod, .info,
/// blanket-verified .ziphash) from the verified artifact cache.
pub fn stage_modcache_skeleton(store: &Store, plan: &GoPlan, staged: &Path) -> io::Result<()> {
    validate_plan(plan)?;
    for m in &plan.modules {
        let dir = staged
            .join("cache/download")
            .join(escape_go_path(&m.path)?)
            .join("@v");
        fs::create_dir_all(&dir)?;
        let ver = escape_go_path(&m.version)?;
        for (hash, ext) in [
            (&m.zip_sha256, "zip"),
            (&m.modfile_sha256, "mod"),
            (&m.info_sha256, "info"),
        ] {
            // cache_verified re-hashes the entry: a cache hit is never
            // trusted (Sol: go skips extraction checks when zip+ziphash
            // already exist, so a poisoned cache byte would go straight
            // into the object).
            let src = cache_verified_held(store, hash)
                .map_err(|e| io::Error::new(e.kind(), format!("{}@{}: {e}", m.path, m.version)))?;
            // COPY, never hardlink: builds must not reach the cache.
            fs::copy(&src, dir.join(format!("{ver}.{ext}")))?;
        }
        // Belt over braces: the staged zip must still match its h1.
        let got = dirhash::hash_zip(&dir.join(format!("{ver}.zip")), &m.path, &m.version)?;
        if got != m.h1 {
            return Err(err(format!(
                "{}@{}: staged zip does not match its h1; refusing",
                m.path, m.version
            )));
        }
        fs::write(dir.join(format!("{ver}.ziphash")), &m.h1)?;
    }
    Ok(())
}

/// Identity of the immutable GOMODCACHE object. Shared by production and the
/// darwin golden test so the extractor input cannot drift unobserved.
fn modcache_identity(pin: &GoPin, plan: &GoPlan) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "go-modcache/1".to_string()),
        (
            "extractor".to_string(),
            format!("go{}:{}", pin.version, pin.sha256),
        ),
    ]);
    for m in &plan.modules {
        inputs.insert(
            format!("mod:{}@{}", m.path, m.version),
            format!("{}:{}", m.h1, m.zip_sha256),
        );
        inputs.insert(
            format!("modfile:{}@{}", m.path, m.version),
            format!("{}:{}", m.modfile_h1, m.modfile_sha256),
        );
        inputs.insert(
            format!("info:{}@{}", m.path, m.version),
            m.info_sha256.clone(),
        );
    }
    let identity = Identity {
        kind: "go-modcache".into(),
        name: "modcache".into(),
        version: plan.modules.len().to_string(),
        inputs,
    };
    identity
}

/// Realize the immutable GOMODCACHE object: verified skeleton + extraction
/// delegated to the store Go offline (full x/mod/zip validation), whose
/// recipe is part of the identity.
pub fn realize_modcache(
    store: &Store,
    platform: Platform,
    plan: &GoPlan,
    go_obj: &Path,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Go module cache", "stage 4")?;
    let pin = go_pin(platform, &plan.go_version)?;
    let identity = modcache_identity(pin, plan);

    let id = identity.object_id();
    if store.has(&id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let staged = store.stage()?;
    stage_modcache_skeleton(store, plan, &staged)?;
    // Offline extraction by the store Go: it re-verifies ziphash and runs
    // its full zip validation while materializing <module>@<version>/ dirs.
    if !plan.modules.is_empty() {
        let scratch = store.stage()?;
        let mut gomod = format!("module blanket.invalid/extract\n\ngo {}\n\nrequire (\n", {
            // go directive: major.minor only
            let mut it = plan.go_version.split('.');
            format!("{}.{}", it.next().unwrap_or("1"), it.next().unwrap_or("0"))
        });
        let mut gosum = String::new();
        for m in &plan.modules {
            gomod.push_str(&format!("\t{} {}\n", m.path, m.version));
            gosum.push_str(&format!("{} {} {}\n", m.path, m.version, m.h1));
            gosum.push_str(&format!(
                "{} {}/go.mod {}\n",
                m.path, m.version, m.modfile_h1
            ));
        }
        gomod.push_str(")\n");
        fs::write(scratch.join("go.mod"), &gomod)?;
        fs::write(scratch.join("go.sum"), &gosum)?;
        // Explicit path@version args: extract exactly the plan's modules,
        // never a graph walk (graph-only modules are deliberately absent).
        let mut args = vec!["mod".to_string(), "download".to_string()];
        args.extend(
            plan.modules
                .iter()
                .map(|m| format!("{}@{}", m.path, m.version)),
        );
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = run_go(store, go_obj, &scratch, &staged, true, &arg_refs)?;
        let _ = crate::kernel::store::remove_tree(&scratch);
        if !out.status.success() {
            return Err(err(format!(
                "offline module extraction failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    // The extraction writes lock files under cache/lock and per-module
    // .lock files; harmless immutable residue.
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(go_obj)?)?;
    for module in &plan.modules {
        deps.cache_digest(Digest::sha256(&module.zip_sha256)?);
        deps.cache_digest(Digest::sha256(&module.modfile_sha256)?);
        deps.cache_digest(Digest::sha256(&module.info_sha256)?);
    }
    store
        .commit_with_deps(&identity, &staged, &[], &deps)
        .map(|(path, _)| path)
}

/// Project provenance (closure envelope). Go needs no wrapper or config
/// projection: enforcement is process env, set by blanket run/build.
pub fn project_go_env(
    project_dir: &Path,
    go_obj: &Path,
    modcache_obj: &Path,
    plan: &GoPlan,
    gosum_sha256: &str,
) -> io::Result<()> {
    let go_obj = go_obj.canonicalize()?;
    let modcache_obj = modcache_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&go_obj)
        .ok_or_else(|| err("Go object is not in a Blanket store"))?;
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({"path": path.display().to_string(), "id": id}))
    };
    let mut refs = crate::comforter::ClosureRefs::new();
    refs.object_path(&store, &activity, &go_obj)?;
    refs.object_path(&store, &activity, &modcache_obj)?;
    crate::comforter::write_closure(
        project_dir,
        "go",
        serde_json::json!({
            "go_object": object_ref(&go_obj.canonicalize()?)?,
            "modcache_object": object_ref(&modcache_obj.canonicalize()?)?,
            "go_sum_sha256": gosum_sha256,
            "plan": plan,
        }),
        &store,
        &activity,
        refs,
    )
}

/// Sandboxed `go build`: network denied, project READ-ONLY — outputs are
/// staged in scratch and moved into the project by blanket afterwards.
pub fn build_sandboxed(
    platform: Platform,
    project_dir: &Path,
    go_obj: &Path,
    modcache_obj: &Path,
    args: &[String],
) -> io::Result<()> {
    const FORBIDDEN: &[&str] = &[
        "-mod",
        "-modfile",
        "-modcacherw",
        "-toolexec",
        "-overlay",
        "-exec",
        "-o",
    ];
    for arg in args {
        // Go flags accept one or two dashes: normalize before checking.
        let norm = arg
            .strip_prefix('-')
            .map(|s| format!("-{}", s.trim_start_matches('-')));
        let norm = norm.as_deref().unwrap_or(arg);
        if FORBIDDEN
            .iter()
            .any(|f| norm == *f || norm.starts_with(&format!("{f}=")))
        {
            return Err(err(format!(
                "{arg}: this flag is managed by blanket (module mode, output \
                 staging, and tool execution are enforced)"
            )));
        }
    }
    let project_dir = project_dir.canonicalize()?;
    let go_obj = go_obj.canonicalize()?;
    let modcache_obj = modcache_obj.canonicalize()?;
    let store = Store::open()?;
    let scratch = store.stage()?;
    let outdir = scratch.join("out");
    for sub in ["out", "gocache", "gotmp", "gopath"] {
        fs::create_dir_all(scratch.join(sub))?;
    }
    let mut argv = vec![
        go_obj.join("bin/go").display().to_string(),
        "build".to_string(),
        "-mod=readonly".to_string(),
        "-o".to_string(),
        format!("{}/", outdir.display()),
    ];
    let mut env = go_env(&go_obj, &modcache_obj, true);
    env.push((
        "GOCACHE".to_string(),
        scratch.join("gocache").display().to_string(),
    ));
    env.push((
        "GOTMPDIR".to_string(),
        scratch.join("gotmp").display().to_string(),
    ));
    env.push((
        "GOPATH".to_string(),
        scratch.join("gopath").display().to_string(),
    ));
    let env: Vec<(String, String)> = env.into_iter().filter(|(_, v)| !v.is_empty()).collect();
    argv.extend(args.iter().cloned());
    // Default package is "." (go's own default) — never "./...": recursing
    // the whole tree trips over nested non-project Go files (testdata,
    // vendored tools). Multi-package builds pass patterns explicitly.
    if !args.iter().any(|a| !a.starts_with('-')) {
        argv.push(".".to_string());
    }
    let spec = BuildSpec {
        argv,
        cwd: project_dir.clone(),
        env,
        read: vec![project_dir.clone(), go_obj.clone(), modcache_obj.clone()],
        write: vec![],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", go_obj.join("bin").display()),
    };
    let result = crate::kernel::sandbox::run_build_spec_on_for_store(platform, &spec, &store)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "go build failed: {e}; network is denied during builds (local \
             replace directives and network-dependent tooling are unsupported)"
                ),
            )
        });
    let moved: io::Result<()> = result.and_then(|_| {
        for entry in fs::read_dir(&outdir)? {
            let entry = entry?;
            let dest = project_dir.join(entry.file_name());
            fs::rename(entry.path(), &dest)
                .or_else(|_| fs::copy(entry.path(), &dest).map(|_| ()))?;
            eprintln!("blanket: built {}", dest.display());
        }
        Ok(())
    });
    let _ = crate::kernel::store::remove_tree(&scratch);
    moved
}

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let pin = go_pin(platform, GO_VERSION).expect("pinned Go toolchain for test platform");
    let go = go_identity(pin);
    let empty_plan = GoPlan {
        go_version: GO_VERSION.into(),
        module: "example.com/app".into(),
        modules: Vec::new(),
    };
    let module_plan = GoPlan {
        modules: vec![GoModule {
            path: "example.com/lib".into(),
            version: "v1.2.3".into(),
            h1: "h1:module".into(),
            zip_sha256: "a".repeat(64),
            modfile_h1: "h1:modfile".into(),
            modfile_sha256: "b".repeat(64),
            info_sha256: "c".repeat(64),
        }],
        ..empty_plan.clone()
    };
    vec![
        go,
        modcache_identity(pin, &empty_plan),
        modcache_identity(pin, &module_plan),
    ]
}

#[cfg(test)]
mod tests {

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit, or a migrated record stops matching what
    /// a re-sync publishes and every later cache hit becomes a hard error.
    #[test]
    fn legacy_adapter_recovers_the_pinned_go_artifacts() {
        for pin in GO_PIN_ROWS {
            assert_eq!(
                recovered_cache(go_identity(pin)),
                vec![format!("sha256:{}", pin.sha256)]
            );
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
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "blanket-go-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = crate::kernel::store::remove_tree(&self.0);
        }
    }

    fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, std::time::SystemTime> {
        fn visit(
            root: &Path,
            path: &Path,
            snapshot: &mut BTreeMap<PathBuf, std::time::SystemTime>,
        ) {
            let metadata = fs::metadata(path).unwrap();
            snapshot.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                metadata.modified().unwrap(),
            );
            if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), snapshot);
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    #[test]
    fn one_unique_pin_per_supported_platform() {
        assert_eq!(GO_PIN_ROWS.len(), Platform::ALL.len());
        let mut seen = std::collections::BTreeSet::new();
        for pin in GO_PIN_ROWS {
            assert!(seen.insert(pin.platform.triple()), "duplicate pin platform");
        }
        for platform in Platform::ALL {
            assert_eq!(
                GO_PIN_ROWS
                    .iter()
                    .filter(|pin| pin.platform == *platform)
                    .count(),
                1,
                "expected one Go pin for {}",
                platform.triple()
            );
        }

        let linux = go_pin(Platform::X86_64UnknownLinuxGnu, GO_VERSION).unwrap();
        assert!(go_pin(Platform::X86_64UnknownLinuxGnu, "1.27").is_err());
        assert_eq!(linux.version, "1.27.0");
        assert_eq!(linux.url, "https://go.dev/dl/go1.27.0.linux-amd64.tar.gz");
        assert_eq!(
            linux.sha256,
            "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"
        );
    }

    #[test]
    fn ensure_go_for_rejects_unpinned_version_before_store_access() {
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = TempDir::new();
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store { root: store_root };
        let platform = Platform::host().unwrap();
        let default_identity = go_identity(go_pin(platform, GO_VERSION).unwrap());
        let default_id = default_identity.object_id();
        let default_object = store.object_path(&default_id);
        fs::create_dir_all(&default_object).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&default_object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&default_object, permissions).unwrap();
        }
        fs::write(
            store.root.join("meta").join(format!("{default_id}.json")),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": default_id,
                "identity": default_identity,
                "created": 0,
                "exceptions": [],
                "refs": []
            }))
            .unwrap(),
        )
        .unwrap();
        let before = tree_snapshot(&store.root);

        let error = ensure_go_for(&store, platform, "1.26.0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("resolved Go 1.26.0"), "{error}");
        assert!(error.contains("only 1.27.0 is realizable"), "{error}");
        assert_eq!(
            tree_snapshot(&store.root),
            before,
            "unpinned lookup created or modified store files"
        );
        assert!(!store.root.join("tmp/.publish.lock").exists());
        assert!(fs::read_dir(store.root.join("tmp"))
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().starts_with("stage-")));
    }

    #[test]
    fn production_toolchain_identities_are_platform_distinct() {
        let darwin = go_identity(go_pin(Platform::Aarch64AppleDarwin, GO_VERSION).unwrap());
        let linux = go_identity(go_pin(Platform::X86_64UnknownLinuxGnu, GO_VERSION).unwrap());
        assert_ne!(darwin.object_id(), linux.object_id());
        assert_eq!(
            darwin.inputs.get("platform").map(String::as_str),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(
            linux.inputs.get("platform").map(String::as_str),
            Some("x86_64-unknown-linux-gnu")
        );
    }

    #[test]
    fn darwin_identity_unchanged() {
        let platform = Platform::Aarch64AppleDarwin;
        let pin = go_pin(platform, GO_VERSION).unwrap();
        let identity = go_identity(pin);
        assert_eq!(
            identity.object_id(),
            "d2d13392a210fa6589345911feb433fbf3bc06ae-go-1.27.0"
        );
        let empty = GoPlan {
            go_version: "1.27.0".into(),
            module: "example.com/x".into(),
            modules: vec![],
        };
        let modcache = modcache_identity(pin, &empty);
        assert_eq!(
            modcache.inputs["extractor"],
            "go1.27.0:90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e"
        );
        assert_eq!(modcache.inputs["schema"], "go-modcache/1");
        let linux = go_pin(Platform::X86_64UnknownLinuxGnu, GO_VERSION).unwrap();
        assert_ne!(
            modcache_identity(linux, &empty).object_id(),
            modcache.object_id()
        );
        assert_eq!(pin.url, "https://go.dev/dl/go1.27.0.darwin-arm64.tar.gz");
    }

    #[test]
    fn toolchain_selection_rules() {
        assert_eq!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, "module m\n\ngo 1.21\n").unwrap(),
            "1.27.0"
        );
        assert_eq!(
            resolve_toolchain(
                Platform::Aarch64AppleDarwin,
                "module m\n\ngo 1.27\n\ntoolchain go1.27.0\n"
            )
            .unwrap(),
            "1.27.0"
        );
        assert_eq!(
            resolve_toolchain(
                Platform::Aarch64AppleDarwin,
                "module m\n\ngo 1.24\n\ntoolchain default\n"
            )
            .unwrap(),
            "1.27.0"
        );
        // Requirement above every pin -> fail.
        assert!(resolve_toolchain(Platform::Aarch64AppleDarwin, "module m\n\ngo 1.99\n").is_err());
        // Prerelease -> fail with instructions.
        assert!(
            resolve_toolchain(Platform::Aarch64AppleDarwin, "module m\n\ngo 1.27rc1\n").is_err()
        );
    }

    #[test]
    fn linux_toolchain_selection_rules() {
        let platform = Platform::X86_64UnknownLinuxGnu;
        for directive in ["go 1.21", "go 1.27", "go 1.27.0"] {
            assert_eq!(
                resolve_toolchain(platform, &format!("module m\n\n{directive}\n")).unwrap(),
                "1.27.0",
                "directive {directive}"
            );
        }
        assert_eq!(
            resolve_toolchain(platform, "module m\n\ngo 1.21\n\ntoolchain go1.27.0\n").unwrap(),
            "1.27.0"
        );
        assert_eq!(
            resolve_toolchain(platform, "module m\n\ngo 1.21\n\ntoolchain default\n").unwrap(),
            "1.27.0"
        );
        assert!(resolve_toolchain(platform, "module m\n\ngo 1.28\n").is_err());
        assert!(resolve_toolchain(platform, "module m\n\ngo 1.27\n\ntoolchain go1.28\n").is_err());
        assert!(resolve_toolchain(platform, "module m\n\ngo 1.27rc1\n").is_err());
        assert!(
            resolve_toolchain(platform, "module m\n\ngo 1.27\n\ntoolchain go1.27rc1\n").is_err()
        );
    }

    #[test]
    fn go_environment_policy_is_forced_and_pinned() {
        let go_obj = Path::new("/store/objects/linux-go");
        let modcache = Path::new("/store/objects/modcache");
        fn value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
            env.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        }

        let offline = go_env(go_obj, modcache, true);
        assert_eq!(value(&offline, "GOTOOLCHAIN"), Some("local"));
        assert_eq!(value(&offline, "GOROOT"), Some("/store/objects/linux-go"));
        assert_eq!(value(&offline, "GOENV"), Some("off"));
        assert_eq!(value(&offline, "GOWORK"), Some("off"));
        assert_eq!(
            value(&offline, "GOMODCACHE"),
            Some("/store/objects/modcache")
        );
        assert_eq!(value(&offline, "GOPROXY"), Some("off"));
        assert_eq!(value(&offline, "GOSUMDB"), Some("off"));
        assert!(value(&offline, "GOVCS").is_none());

        let online = go_env(go_obj, modcache, false);
        assert_eq!(value(&online, "GOPROXY"), Some("https://proxy.golang.org"));
        assert_eq!(value(&online, "GOSUMDB"), Some("sum.golang.org"));
        assert_eq!(value(&online, "GOVCS"), Some("*:off"));
        assert_ne!(value(&online, "GOPROXY"), Some("file:///host/cache"));
    }

    #[test]
    fn go_archive_layout_strips_only_the_go_root() {
        let temp = std::env::temp_dir().join(format!(
            "blanket-go-layout-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = temp.join("source");
        std::fs::create_dir_all(source.join("go/bin")).unwrap();
        std::fs::create_dir_all(source.join("go/src")).unwrap();
        std::fs::create_dir_all(source.join("go/pkg")).unwrap();
        std::fs::write(source.join("go/bin/go"), b"go").unwrap();
        std::fs::write(source.join("go/bin/gofmt"), b"gofmt").unwrap();
        std::fs::write(source.join("go/src/README"), b"src").unwrap();
        std::fs::write(source.join("go/pkg/README"), b"pkg").unwrap();
        let archive = temp.join("go.tar.gz");
        std::fs::create_dir_all(&source).unwrap();
        assert!(Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&source)
            .arg("go")
            .status()
            .unwrap()
            .success());
        let staged = temp.join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        extract_go_toolchain(Platform::host().unwrap(), &archive, &staged).unwrap();
        assert!(staged.join("bin/go").is_file());
        assert!(staged.join("bin/gofmt").is_file());
        assert!(staged.join("src/README").is_file());
        assert!(staged.join("pkg/README").is_file());

        let nested_source = temp.join("nested-source");
        std::fs::create_dir_all(nested_source.join("outer/go/bin")).unwrap();
        std::fs::write(nested_source.join("outer/go/bin/go"), b"go").unwrap();
        let nested_archive = temp.join("nested.tar.gz");
        assert!(Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&nested_archive)
            .args(["-C"])
            .arg(&nested_source)
            .arg("outer")
            .status()
            .unwrap()
            .success());
        let nested_staged = temp.join("nested-staged");
        std::fs::create_dir_all(&nested_staged).unwrap();
        let error =
            extract_go_toolchain(Platform::host().unwrap(), &nested_archive, &nested_staged)
                .unwrap_err();
        assert!(error.to_string().contains("unexpected layout"));
        assert!(!nested_staged.join("go").exists());

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn escaping_matches_go_rules() {
        assert_eq!(escape_go_path("rsc.io/quote").unwrap(), "rsc.io/quote");
        assert_eq!(
            escape_go_path("github.com/BurntSushi/toml").unwrap(),
            "github.com/!burnt!sushi/toml"
        );
        assert!(escape_go_path("a/../b").is_err());
        assert!(escape_go_path("weird!path").is_err());
        assert!(escape_go_path("sp ace").is_err());
    }

    #[test]
    fn local_replaces_rejected_from_gomod_text() {
        // Go's download -json ELIDES local replacements entirely, so the
        // rejection must parse go.mod itself (Sol finding 3, reproduced).
        for bad in [
            "module m\n\nreplace example.com/a => ./localdep\n",
            "module m\n\nreplace example.com/a => ../up\n",
            "module m\n\nreplace example.com/a v1.0.0 => /abs/path\n",
            "module m\n\nreplace (\n\texample.com/a => ./x\n)\n",
        ] {
            assert!(reject_local_replaces(bad).is_err(), "{bad}");
        }
        // Version-to-version replaces are fine.
        for good in [
            "module m\n\nreplace example.com/a => example.com/b v1.2.3\n",
            "module m\n\nreplace (\n\texample.com/a v1.0.0 => example.com/b v1.2.3\n)\n",
            "module m\n\ngo 1.27\n",
        ] {
            assert!(reject_local_replaces(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn plan_validation_rejects_hostile_cache_fields() {
        let base = GoModule {
            path: "example.com/a".into(),
            version: "v1.0.0".into(),
            h1: format!("h1:{}=", "A".repeat(43)),
            zip_sha256: "a".repeat(64),
            modfile_h1: format!("h1:{}=", "B".repeat(43)),
            modfile_sha256: "b".repeat(64),
            info_sha256: "c".repeat(64),
        };
        let ok_plan = GoPlan {
            go_version: "1.27.0".into(),
            module: "m".into(),
            modules: vec![base.clone()],
        };
        assert!(validate_plan(&ok_plan).is_ok());
        // Path-traversal "sha256" from a tampered .blanket/go-plan.json.
        let mut evil = base.clone();
        evil.zip_sha256 = "../../objects/x".into();
        assert!(validate_plan(&GoPlan {
            go_version: "1.27.0".into(),
            module: "m".into(),
            modules: vec![evil],
        })
        .is_err());
        let mut dup = GoPlan {
            go_version: "1.27.0".into(),
            module: "m".into(),
            modules: vec![base.clone(), base.clone()],
        };
        assert!(validate_plan(&dup).is_err());
        dup.modules.pop();
        dup.modules[0].h1 = "not-an-h1".into();
        assert!(validate_plan(&dup).is_err());
    }

    #[test]
    fn build_rejects_managed_flags() {
        for bad in [
            "-mod=mod",
            "-toolexec",
            "-o",
            "-overlay=x",
            "-modcacherw",
            "--mod=vendor",
            "--o=/tmp/x",
            "--toolexec",
        ] {
            let e = build_sandboxed(
                Platform::Aarch64AppleDarwin,
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                &[bad.to_string()],
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("managed by blanket"), "{bad}: {e}");
        }
    }

    #[test]
    fn module_path_and_workspace_guard() {
        assert_eq!(module_path("module hello\n\ngo 1.27\n").unwrap(), "hello");
        assert!(module_path("go 1.27\n").is_err());
    }

    #[test]
    fn modcache_skeleton_layout() {
        let temp = std::env::temp_dir().join(format!(
            "blanket-go-skel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("BLANKET_STORE", temp.join("store"));
        let store = Store::open().unwrap();
        std::env::remove_var("BLANKET_STORE");
        // Real fixture artifacts through the verified cache.
        let fix = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-dirhash");
        let (zip_hash, _) = cache_insert(&store, &fix.join("quote-v1.5.2.zip")).unwrap();
        let (mod_hash, _) = cache_insert(&store, &fix.join("quote-v1.5.2.mod")).unwrap();
        let info = temp.join("info");
        std::fs::write(&info, r#"{"Version":"v1.5.2"}"#).unwrap();
        let (info_hash, info_cache) = cache_insert(&store, &info).unwrap();
        let module = GoModule {
            path: "rsc.io/quote".into(),
            version: "v1.5.2".into(),
            h1: "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=".into(),
            zip_sha256: zip_hash,
            modfile_h1: "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=".into(),
            modfile_sha256: mod_hash,
            info_sha256: info_hash.clone(),
        };
        let plan = GoPlan {
            go_version: "1.27.0".into(),
            module: "m".into(),
            modules: vec![module.clone()],
        };
        let staged = temp.join("staged");
        std::fs::create_dir_all(&staged).unwrap();
        stage_modcache_skeleton(&store, &plan, &staged).unwrap();
        let base = staged.join("cache/download/rsc.io/quote/@v");
        assert_eq!(
            std::fs::read_to_string(base.join("v1.5.2.ziphash")).unwrap(),
            "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y="
        );
        assert!(base.join("v1.5.2.zip").is_file());
        assert!(base.join("v1.5.2.mod").is_file());
        assert!(base.join("v1.5.2.info").is_file());

        // Poisoning regression (Sol finding 1): tamper the cached .info —
        // staging must refuse instead of copying poisoned bytes.
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&info_cache).unwrap().permissions();
            p.set_mode(0o644);
            std::fs::set_permissions(&info_cache, p).unwrap();
            std::fs::write(&info_cache, r#"{"Version":"evil"}"#).unwrap();
        }
        let staged2 = temp.join("staged2");
        std::fs::create_dir_all(&staged2).unwrap();
        let e = stage_modcache_skeleton(&store, &plan, &staged2).unwrap_err();
        assert!(e.to_string().contains(&info_hash), "{e}");
        let _ = std::fs::remove_dir_all(&temp);
    }
    /// Characterization (REFACTOR.md Stage 4 step 3): the plan cache is the
    /// only part of `plan_go` reachable without a real toolchain, and it is
    /// the part an attacker can edit. These pin the key formula, the
    /// validation of cached fields, and the fact that a hit never touches
    /// the store or the go binary.
    fn plan_fixture(project: &Path) -> (String, String, GoPlan) {
        let gomod = "module example.com/m\n\ngo 1.27.0\n";
        let gosum = "example.com/a v1.0.0 h1:AAAA=\n";
        fs::create_dir_all(project).unwrap();
        fs::write(project.join("go.mod"), gomod).unwrap();
        fs::write(project.join("go.sum"), gosum).unwrap();
        fs::write(project.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();
        let plan = GoPlan {
            go_version: "1.27.0".into(),
            module: "example.com/m".into(),
            modules: vec![GoModule {
                path: "example.com/a".into(),
                version: "v1.0.0".into(),
                h1: format!("h1:{}=", "A".repeat(43)),
                zip_sha256: "a".repeat(64),
                modfile_h1: format!("h1:{}=", "B".repeat(43)),
                modfile_sha256: "b".repeat(64),
                info_sha256: "c".repeat(64),
            }],
        };
        (gomod.into(), gosum.into(), plan)
    }

    fn write_plan_cache(project: &Path, input_hash: &str, plan: &GoPlan) {
        fs::create_dir_all(project.join(".blanket")).unwrap();
        fs::write(
            project.join(".blanket/go-plan.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "input_hash": input_hash,
                "plan": plan,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn expected_input_hash(project: &Path, gomod: &str, gosum: &str) -> String {
        hex::encode(Sha256::digest(
            format!(
                "go-planner/2\x00{}\x00{gomod}\x00{gosum}\x00{}",
                "1.27.0",
                source_digest(project).unwrap()
            )
            .as_bytes(),
        ))
    }

    #[test]
    fn plan_cache_hit_skips_the_store_and_the_toolchain() {
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, gosum, plan) = plan_fixture(&project);
        write_plan_cache(
            &project,
            &expected_input_hash(&project, &gomod, &gosum),
            &plan,
        );
        // A store root that does not exist and a go binary that does not
        // exist: a cache hit must reach neither.
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let got = plan_go(
            &store,
            Platform::host().unwrap(),
            &project,
            Path::new("/nonexistent/go"),
        )
        .unwrap();
        assert_eq!(got.go_version, "1.27.0");
        assert_eq!(got.module, "example.com/m");
        assert_eq!(got.modules, plan.modules);
        assert!(!store.root.exists(), "a cache hit touched the store");
    }

    #[test]
    fn plan_cache_hit_validates_hostile_fields_before_use() {
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, gosum, mut plan) = plan_fixture(&project);
        plan.modules[0].zip_sha256 = "../../objects/x".into();
        write_plan_cache(
            &project,
            &expected_input_hash(&project, &gomod, &gosum),
            &plan,
        );
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let e = plan_go(
            &store,
            Platform::host().unwrap(),
            &project,
            Path::new("/nonexistent/go"),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("invalid sha256 in plan"), "{e}");
        assert!(!store.root.exists(), "a rejected cache touched the store");
    }

    #[test]
    fn plan_cache_key_covers_the_go_sources() {
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, gosum, plan) = plan_fixture(&project);
        let input_hash = expected_input_hash(&project, &gomod, &gosum);
        write_plan_cache(&project, &input_hash, &plan);
        // Editing a .go source invalidates the key, so the cached plan is
        // not returned; without a toolchain the re-plan can only fail.
        fs::write(
            project.join("main.go"),
            "package main\n\nfunc main() { _ = 1 }\n",
        )
        .unwrap();
        assert_ne!(expected_input_hash(&project, &gomod, &gosum), input_hash);
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store { root: store_root };
        assert!(plan_go(
            &store,
            Platform::host().unwrap(),
            &project,
            Path::new("/nonexistent/go"),
        )
        .is_err());
    }
}
