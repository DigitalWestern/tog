//! The Go tailor: module closure via the pinned Go toolchain, blanket-owned
//! verification (dirhash h1 + raw sha256), immutable GOMODCACHE objects.
//!
//! go.sum is an authentication ledger, not a lock graph (Sol review 4): the
//! authoritative closure comes from `go mod download -json all` run by the
//! STORE Go in a disposable copy. Blanket then independently re-verifies
//! every artifact (dirhash::hash_zip / hash_gomod) before any byte enters
//! the store — delegation computes, the kernel verifies.

use crate::archive::Compression;
use crate::dirhash;
use crate::fetch::{cache_insert, cache_verified_held, download_verified_held};
use crate::platform::{no_pin, Platform};
use crate::sandbox::BuildSpec;
use crate::store::Store;
use crate::types::Identity;
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

fn go_pin(platform: Platform) -> io::Result<&'static GoPin> {
    GO_PIN_ROWS
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or_else(|| no_pin("go", platform, "stage 4"))
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::platform::require_host(platform, "Go toolchain", "stage 4")?;
    go_pin(platform).map(|_| ())
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
fn extract_go_toolchain(platform: Platform, archive: &Path, staged: &Path) -> io::Result<()> {
    // List first (src/archive.rs): the layout check below and the
    // containment rules both run before tar writes anything.
    let entries = crate::archive::list(archive_platform(platform), archive, Compression::Gzip)
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

    crate::archive::extract_validated(
        archive_platform(platform),
        archive,
        staged,
        1,
        Compression::Gzip,
        &entries,
    )?;
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
pub fn ensure_go(store: &Store) -> io::Result<PathBuf> {
    ensure_go_for(store, Platform::host()?)
}

pub fn ensure_go_for(store: &Store, platform: Platform) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "Go toolchain", "stage 4")?;
    let pin = go_pin(platform)?;
    let identity = go_identity(pin);
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified_held(store, pin.url, pin.sha256)?;
    let staged = store.stage()?;
    extract_go_toolchain(platform, &tarball, &staged)?;
    store.commit(&identity, &staged, &[]).map(|(path, _)| path)
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
    go_obj: &Path,
    cwd: &Path,
    modcache: &Path,
    offline: bool,
    args: &[&str],
) -> io::Result<()> {
    crate::ui::trace(&format!(
        "run: go {} (in {})",
        args.join(" "),
        cwd.display()
    ));
    let out = run_go(go_obj, cwd, modcache, offline, args)?;
    if crate::ui::verbose() {
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
    cmd.output()
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

    // The tidy gate's inputs are exactly go.mod + go.sum + the .go sources,
    // so the plan-cache key covers all three: a hit proves the last
    // successful gate's inputs are unchanged, making a re-run redundant
    // (Sol finding 7, solved by keying instead of re-running).
    const PLANNER_SCHEMA: &str = "go-planner/2";
    let src_digest = source_digest(project_dir)?;
    let input_hash = hex::encode(Sha256::digest(
        format!("{PLANNER_SCHEMA}\x00{go_version}\x00{gomod}\x00{gosum}\x00{src_digest}")
            .as_bytes(),
    ));
    let cache_path = project_dir.join(".blanket/go-plan.json");
    if let Ok(cached) = fs::read_to_string(&cache_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&cached) {
            if v["input_hash"] == input_hash.as_str() {
                if let Ok(plan) = serde_json::from_value::<GoPlan>(v["plan"].clone()) {
                    // The cache file is attacker-editable project state.
                    validate_plan(&plan)?;
                    return Ok(plan);
                }
            }
        }
    }

    // Consistency gate: tidy -diff is non-mutating (prints a diff, exit
    // nonzero when go.mod/go.sum need changes). Needs the source tree, so
    // it runs in the real project — but never writes. Its module cache is a
    // persistent planner scratch (resolver-trust only; never feeds objects).
    let scratch = store.stage()?;
    let gate_cache = store.root.join("planner-modcache");
    fs::create_dir_all(&gate_cache)?;
    let out = run_go(
        go_obj,
        project_dir,
        &gate_cache,
        false,
        &["mod", "tidy", "-diff"],
    )?;
    let (gomod, gosum) = if out.status.success() {
        (gomod, gosum)
    } else {
        // Out-of-sync manifest: run the ecosystem's resolver, the same
        // delegated mutation as uv pip compile / cargo generate-lockfile.
        eprintln!("blanket: go.mod/go.sum need updating; resolving with the store go mod tidy...");
        let out = run_go(go_obj, project_dir, &gate_cache, false, &["mod", "tidy"])?;
        if !out.status.success() {
            let _ = crate::store::remove_tree(&scratch);
            return Err(err(format!(
                "store go mod tidy failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        (
            fs::read_to_string(project_dir.join("go.mod"))?,
            fs::read_to_string(project_dir.join("go.sum")).unwrap_or_default(),
        )
    };
    reject_local_replaces(&gomod)?;
    // Cache under the FINAL (possibly tidied) inputs so the next sync hits.
    let go_version = resolve_toolchain(platform, &gomod)?;
    let module = module_path(&gomod)?;
    let input_hash = hex::encode(Sha256::digest(
        format!(
            "{PLANNER_SCHEMA}\x00{go_version}\x00{gomod}\x00{gosum}\x00{}",
            source_digest(project_dir)?
        )
        .as_bytes(),
    ));

    // Disposable copy for download (it may rewrite go.mod/go.sum). The
    // module cache is the persistent planner scratch — warm downloads;
    // trust is irrelevant because every artifact is re-verified below.
    let work = scratch.join("plan");
    fs::create_dir_all(&work)?;
    fs::write(work.join("go.mod"), &gomod)?;
    if !gosum.is_empty() {
        fs::write(work.join("go.sum"), &gosum)?;
    }
    eprintln!("blanket: computing Go module closure with the store toolchain...");
    let out = run_go(
        go_obj,
        &work,
        &gate_cache,
        false,
        &["mod", "download", "-json", "all"],
    )?;
    // Ledger anchor: h1 values must ALSO appear in the project's go.sum —
    // never trust sums that exist only in the delegated tool's output.
    let ledger: std::collections::BTreeSet<String> =
        gosum.lines().map(|l| l.trim().to_string()).collect();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    // Parse the JSON stream (concatenated objects) BEFORE checking status:
    // per-module errors ride in the stream.
    let mut modules = Vec::new();
    let mut de = serde_json::Deserializer::from_str(&stdout).into_iter::<DownloadEntry>();
    let result: io::Result<()> = (|| {
        while let Some(entry) = de.next() {
            let entry = entry.map_err(|e| err(format!("go mod download JSON: {e}")))?;
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
                if rep.version.is_empty() || rep.path.starts_with('.') || rep.path.starts_with('/')
                {
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
                continue; // main module / no artifacts
            };
            // Ledger anchor: the tidied go.sum is the authority. Modules
            // whose zip sums it omits are build-GRAPH-only (tidy records
            // zip sums for exactly the modules whose packages a build can
            // import) — exclude them from the closure rather than fail:
            // an offline build never loads their sources, and if one were
            // ever needed the readonly+GOPROXY=off build fails loudly.
            if !ledger.contains(&format!("{} {} {}", entry.path, entry.version, sum)) {
                continue;
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
            modules.push(GoModule {
                path: entry.path,
                version: entry.version,
                h1: sum.clone(),
                zip_sha256,
                modfile_h1: gomod_sum.clone(),
                modfile_sha256,
                info_sha256,
            });
        }
        if !out.status.success() {
            return Err(err(format!(
                "go mod download failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    })();
    let _ = crate::store::remove_tree(&scratch);
    result?;
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
    crate::platform::require_host(platform, "Go module cache", "stage 4")?;
    let pin = go_pin(platform)?;
    let identity = modcache_identity(pin, plan);

    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
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
            let mut it = GO_VERSION.split('.');
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
        let out = run_go(go_obj, &scratch, &staged, true, &arg_refs)?;
        let _ = crate::store::remove_tree(&scratch);
        if !out.status.success() {
            return Err(err(format!(
                "offline module extraction failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    // The extraction writes lock files under cache/lock and per-module
    // .lock files; harmless immutable residue.
    store.commit(&identity, &staged, &[]).map(|(path, _)| path)
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
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({"path": path.display().to_string(), "id": id}))
    };
    crate::project::write_closure(
        project_dir,
        "go",
        serde_json::json!({
            "go_object": object_ref(&go_obj.canonicalize()?)?,
            "modcache_object": object_ref(&modcache_obj.canonicalize()?)?,
            "go_sum_sha256": gosum_sha256,
            "plan": plan,
        }),
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
    let result = crate::sandbox::run_build_spec_on(platform, &spec).map_err(|e| {
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
    let _ = crate::store::remove_tree(&scratch);
    moved
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let linux = go_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(linux.version, "1.27.0");
        assert_eq!(linux.url, "https://go.dev/dl/go1.27.0.linux-amd64.tar.gz");
        assert_eq!(
            linux.sha256,
            "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"
        );
    }

    #[test]
    fn production_toolchain_identities_are_platform_distinct() {
        let darwin = go_identity(go_pin(Platform::Aarch64AppleDarwin).unwrap());
        let linux = go_identity(go_pin(Platform::X86_64UnknownLinuxGnu).unwrap());
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
        let pin = go_pin(platform).unwrap();
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
        let linux = go_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
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
        let _lock = crate::store::STORE_ENV_LOCK
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
}
