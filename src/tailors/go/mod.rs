//! The Go tailor: module closure via the pinned Go toolchain, tog-owned
//! verification (dirhash h1 + raw sha256), immutable GOMODCACHE objects.
//!
//! go.sum is an authentication ledger, not a lock graph: the authoritative
//! closure comes from `go mod download -json all` run by the
//! STORE Go in a disposable copy. Tog then independently re-verifies
//! every artifact (dirhash::hash_zip / hash_gomod) before any byte enters
//! the store — delegation computes, the kernel verifies.
//!
//! The finished plan is cached in `.tog/go-plan.json`, which is project
//! state anyone who ships the repo can write. A hit is therefore held to
//! the same go.sum ledger a fresh plan is: every cached module's zip and
//! go.mod lines must be in the current go.sum, or the cache is refused.

pub mod edit;
pub mod inputs;
pub mod objects;
pub mod registry;
mod resolve;
pub(crate) use resolve::{attest_project, gate_cache, go_tool, tidy_project};
use resolve::{download_closure, is_tidy};
pub mod tailor;
mod tool;

use crate::kernel::activity::StoreActivity;
use crate::kernel::archive::Compression;
use crate::kernel::dirhash;
use crate::kernel::fetch::{
    cache_insert, cache_verified_held, download_toolchain_artifact_held, Digest,
};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::resolve::ledger::LedgerObjects;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::sandbox::BuildSpec;
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::{
    ArtifactRow, ArtifactSpec, Catalog, LegacyEvidence, Selected, Source,
};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tool::run_go_offline;
pub(crate) use tool::{run_go_checked, GoPublish, GoRun};

/// The shipped Go catalog: every go.dev release of the supported Go lines,
/// with its default, generated and verified by `tools/catalog.py go`.
static CATALOG: Shipped = Shipped::new(include_str!("catalog.toml"));

/// The extraction/layout recipe this binary knows for a Go toolchain: the
/// catalog emits it, the object identity commits to it, and a locked row
/// naming anything else is refused rather than guessed at.
const GO_RECIPE: &str = "go-toolchain/1";

/// One platform's go.dev archive for one Go release, as the shipped
/// catalog lists it.
#[derive(Clone, Copy, Debug)]
struct GoPin {
    platform: Platform,
    version: &'static str,
    #[cfg_attr(not(test), expect(dead_code, reason = "only the tests read the row"))]
    row: &'static ArtifactRow,
}

#[cfg(test)]
impl GoPin {
    fn url(&self) -> &'static str {
        &self.row.url
    }

    fn sha256(&self) -> &'static str {
        self.row.digest.hex()
    }
}

/// Every shipped Go archive: one row per release and supported platform.
fn go_pin_rows() -> io::Result<Vec<GoPin>> {
    let mut rows = Vec::new();
    for bundle in &CATALOG.document()?.bundles {
        let version = bundle.component("go").ok_or_else(|| {
            err(format!(
                "go catalog: {} has no go component",
                bundle.release
            ))
        })?;
        for row in bundle.artifacts.iter().filter(|row| row.component == "go") {
            rows.push(GoPin {
                platform: row.platform,
                version: version.version.as_str(),
                row,
            });
        }
    }
    Ok(rows)
}

fn go_pin(platform: Platform, version: &str) -> io::Result<GoPin> {
    let rows = go_pin_rows()?;
    if let Some(pin) = rows
        .iter()
        .find(|pin| pin.platform == platform && pin.version == version)
    {
        return Ok(*pin);
    }
    let pins = go_pins(platform)?;
    Err(err(format!(
        "internal: resolved Go {version} for {} but this tog realizes only Go {}; set go.mod's `go` or `toolchain` directive to one of the pinned versions, or add a matching verified Go pin",
        platform.triple(),
        pins.join(", ")
    )))
}

/// The shipped Go catalog: one release bundle per go.dev release, and the
/// release a project with no Go pin gets.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

/// A pre-lock Go closure records the toolchain under `plan.go_version` and
/// the Go object under `go_object`: the archive and recipe that object's
/// identity names are the proof.
pub fn legacy_toolchain_evidence(
    platform: Option<Platform>,
    body: &serde_json::Value,
    store: Option<&crate::kernel::store::Store>,
) -> LegacyEvidence {
    use crate::comforter::toolchain::{self as project_toolchain, LegacyRuntime};
    let mut evidence =
        crate::comforter::legacy_toolchain_evidence(platform, body, &[("go", "/plan/go_version")]);
    project_toolchain::prove_legacy_runtime(
        &mut evidence,
        store,
        body,
        LegacyRuntime {
            pointer: "/go_object",
            via: &[],
            kind: "go",
        },
        |identity, evidence| {
            project_toolchain::expect_legacy_version(identity, evidence, "go", &identity.version)?;
            Ok(vec![project_toolchain::proved_from_identity(
                identity,
                "go",
                "artifact_sha256",
                "sha256",
                project_toolchain::schema_recipe(identity)?,
            )?])
        },
    );
    evidence
}

/// The Go object a pre-lock sync from `selected` left for legacy seeding to
/// read, and the body field that names it.
#[cfg(test)]
pub(crate) fn legacy_runtime_for_test(
    platform: Platform,
    selected: &Selected,
    store: &Store,
) -> (serde_json::Value, Vec<Identity>) {
    let row = runtime_row(platform, selected).unwrap();
    let go = runtime_identity(platform, &row.version, row.digest.hex());
    let body = serde_json::json!({
        "go_object": crate::comforter::toolchain::object_ref_for_test(store, &go.object_id()),
    });
    (body, vec![go])
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "Go toolchain")?;
    go_pins(platform).map(|_| ())
}

/// The identity the compiled pin row produces. Realization builds its
/// identity from the selected bundle row instead; this is how the tests hold
/// the two spellings to the same object id.
#[cfg(test)]
fn go_identity(pin: GoPin) -> Identity {
    runtime_identity(pin.platform, pin.version, pin.sha256())
}

/// The Go object's identity, from the archive that went into it. The pin
/// table and a locked bundle row reach this with the same bytes, so a
/// toolchain realized from a lock lands on the object the pin already built.
fn runtime_identity(platform: Platform, version: &str, artifact_sha256: &str) -> Identity {
    Identity {
        kind: "go".into(),
        name: "go".into(),
        version: version.into(),
        inputs: BTreeMap::from([
            ("schema".to_string(), GO_RECIPE.to_string()),
            ("artifact_sha256".to_string(), artifact_sha256.to_string()),
            ("platform".to_string(), platform.triple().to_string()),
        ]),
    }
}

/// The row of `selected` this tailor realizes from, checked before it is
/// fetched: the selection must be a Go one, the platform must have a row,
/// and the recipe must be one this binary knows how to lay out.
fn runtime_row(platform: Platform, selected: &Selected) -> io::Result<ArtifactSpec> {
    if selected.runtime() != "go" {
        return Err(err(format!(
            "internal: a {} selection (runtime {}) reached the Go tailor",
            selected.ecosystem,
            selected.runtime()
        )));
    }
    let row = selected.artifact(platform, "go")?;
    if row.recipe != GO_RECIPE {
        return Err(err(format!(
            "go: recipe {} in tog-toolchain.toml is not known to this tog; upgrade tog",
            row.recipe
        )));
    }
    if row.digest.algo() != "sha256" {
        return Err(err(format!(
            "go: artifact is a {} digest; this tog realizes Go from sha256 artifacts",
            row.digest.algo()
        )));
    }
    Ok(row)
}

fn go_pins(platform: Platform) -> io::Result<Vec<&'static str>> {
    let mut pins: Vec<_> = go_pin_rows()?
        .into_iter()
        .filter(|pin| pin.platform == platform)
        .map(|pin| pin.version)
        .collect();
    // Numeric order: 1.26.10 follows 1.26.9.
    pins.sort_by_key(|version| crate::kernel::toolchain::Version::parse(version).ok());
    pins.dedup();
    if pins.is_empty() {
        return Err(no_pin("go", platform));
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
fn extract_go_toolchain(archive: &Path, staged: &Path) -> io::Result<()> {
    extract_go_toolchain_inner(archive, staged, None)
}

fn extract_go_toolchain_for(
    activity: &StoreActivity,
    archive: &Path,
    staged: &Path,
) -> io::Result<()> {
    extract_go_toolchain_inner(archive, staged, Some(activity))
}

fn extract_go_toolchain_inner(
    archive: &Path,
    staged: &Path,
    activity: Option<&StoreActivity>,
) -> io::Result<()> {
    // List first: the layout check below and the containment rules both
    // run before tar writes anything.
    let entries = match activity {
        Some(activity) => {
            crate::kernel::archive::list_with_activity(activity, archive, Compression::Gzip)
        }
        None => crate::kernel::archive::list(archive, Compression::Gzip),
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

    match activity {
        Some(activity) => crate::kernel::archive::extract_validated_with_activity_and_options(
            activity,
            archive,
            staged,
            &crate::kernel::archive::ExtractOptions::platform_build(1),
            Compression::Gzip,
            &entries,
        )?,
        None => crate::kernel::archive::extract_validated_with_options(
            archive,
            staged,
            &crate::kernel::archive::ExtractOptions::platform_build(1),
            Compression::Gzip,
            &entries,
        )?,
    }
    if !staged.join("bin/go").is_file() {
        return Err(err("go tarball extraction failed or has unexpected layout"));
    }
    Ok(())
}

/// Realize the Go toolchain `selected` names: its bytes, its layout recipe
/// and its version all come from the selection's row, so a catalog refresh
/// cannot move a project's compiler under it. Inside a project this is the
/// only way a Go object is built.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Go toolchain")?;
    // Resolve the exact row before touching the store or downloading: what
    // is realized must be what the selection names, never a default.
    let row = runtime_row(platform, selected)?;
    let identity = runtime_identity(platform, &row.version, row.digest.hex());
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let tarball =
        download_toolchain_artifact_held(store, activity, &row.provider, &row.url, &row.digest)?;
    let staged = store.stage_with_activity(activity)?;
    extract_go_toolchain_for(activity, &tarball, &staged)?;
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(row.digest.clone());
            deps
        })
        .map(|(path, _)| path)
}

/// The shipped catalog's release for one exact Go version, as a selection.
/// This is what a caller outside any project gets: there is no lock to
/// honor, so the compiled pin table is both the catalog and the answer. The
/// refusal for a version this binary cannot realize is raised here, before
/// the store is touched.
fn shipped_selection(platform: Platform, version: &str) -> io::Result<Selected> {
    let _ = go_pin(platform, version)?;
    let catalog = toolchain_catalog()?;
    let bundle = catalog
        .bundles()
        .iter()
        .find(|bundle| {
            bundle
                .component("go")
                .is_some_and(|component| component.version == version)
        })
        .ok_or_else(|| err(format!("internal: no shipped Go release for {version}")))?
        .clone();
    Ok(Selected {
        helpers: Default::default(),
        ecosystem: catalog.ecosystem().to_string(),
        bundle,
        lock_sha256: None,
        source: Source::Shipped,
    })
}

/// Ensure the shipped Go toolchain is realized in the store, for callers
/// with no project selection to honor (`tog deps`, tests). A run inside a
/// project realizes through [`realize_runtime`] with the toolchain its lock
/// selected.
pub fn ensure_go(store: &Store, activity: &StoreActivity, version: &str) -> io::Result<PathBuf> {
    ensure_go_for(store, activity, Platform::host()?, version)
}

pub fn ensure_go_for(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    version: &str,
) -> io::Result<PathBuf> {
    realize_runtime(
        store,
        activity,
        platform,
        &shipped_selection(platform, version)?,
    )
}

/// The forced environment for EVERY tog-controlled go invocation.
/// Real process env, never a GOENV file: GOTOOLCHAIN=local stops silent
/// toolchain swaps, GOROOT pins the stdlib, GOWORK/GOENV=off close the
/// config side doors.
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
        // Resolver policy is FORCED, never inherited: an inherited
        // GOPROXY=file:...+GOSUMDB=off resolves attacker code. Proxy-only,
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

/// The Go version this project uses, answered the way sync answers it:
/// the `[toolchain.go]` section of `tog-toolchain.toml` when there is a
/// lock, otherwise the release a Go closure written before the lock existed
/// proves (the seed the next sync would lock), otherwise the newest complete
/// catalog release satisfying go.mod's `go` and `toolchain` directives. It
/// writes nothing, and a lock sync would refuse (no Go section, or stale
/// against go.mod) is refused here in the same words.
///
/// `tog doctor` and the Go `tog status` row ask this. Sync, plan and build
/// take the version from the [`Selected`] they are given, and `tog deps`
/// from the same read-only resolution, so no command names a Go sync does
/// not use. go's own rule (`go` as a minimum, the lowest toolchain that
/// satisfies it) is deliberately not applied anywhere: with more than one
/// pin it would answer with an older release than selection does.
///
/// The project is read through the caller's held descriptor.
pub fn project_go_version(platform: Platform, project: &ProjectRoot) -> io::Result<String> {
    project_go_version_from(toolchain_catalog()?, platform, project)
}

fn project_go_version_from(
    catalog: Catalog,
    platform: Platform,
    project: &ProjectRoot,
) -> io::Result<String> {
    use crate::comforter::toolchain::{self as project_toolchain, EcosystemInput, Mode};
    let resolved = project_toolchain::resolve(
        project,
        platform,
        vec![EcosystemInput {
            lock_ecosystem: "go".into(),
            catalog,
            legacy: project_toolchain::legacy_evidence_in(project, &tailor::Go)?,
            external: None,
            helper_pins: Default::default(),
            legacy_helper_pins: Default::default(),
            declared_helpers: Default::default(),
        }],
        Mode::ReadOnly,
        false,
    )?;
    Ok(resolved.get("go")?.version("go")?.to_string())
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
/// The project's own go.work is read through the held descriptor; the
/// directories above it are outside the project and checked by path.
pub fn reject_workspaces(project: &ProjectRoot) -> io::Result<()> {
    reject_workspaces_with(project, std::env::var_os("GOWORK"))
}

/// `reject_workspaces` with the `GOWORK` value passed in, so tests can cover
/// it without mutating the process environment under parallel tests.
fn reject_workspaces_with(
    project: &ProjectRoot,
    gowork: Option<std::ffi::OsString>,
) -> io::Result<()> {
    if gowork.is_some_and(|v| !v.is_empty() && v != "off") {
        return Err(err("GOWORK is set; Go workspaces are not supported yet"));
    }
    let project_dir = project.path();
    for dir in project_dir.ancestors() {
        let found = if dir == project_dir {
            project.is_input_file(Path::new("go.work"))
        } else {
            dir.join("go.work").is_file()
        };
        if found {
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
/// output (Go elides them), so they must be rejected from go.mod itself:
/// otherwise unverified in-project code enters a build.
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

/// A plan (fresh or loaded from the .tog cache) is untrusted input:
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
/// `.tog/go-plan.json` miss instead of being read under new rules.
const PLANNER_SCHEMA: &str = "go-planner/2";

/// The plan-cache key. The tidy gate's inputs are exactly go.mod + go.sum +
/// the .go sources, so the key covers all three: a hit proves the last
/// successful gate's inputs are unchanged, making a re-run redundant.
fn plan_cache_key(go_version: &str, gomod: &str, gosum: &str, src_digest: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{PLANNER_SCHEMA}\x00{go_version}\x00{gomod}\x00{gosum}\x00{src_digest}")
            .as_bytes(),
    ))
}

const PLAN_CACHE: &str = ".tog/go-plan.json";

/// Read the cached plan when its key matches. The cache file is
/// attacker-editable project state, so a hit is validated before it is used;
/// anything unreadable, unparsable, or stale is simply a miss, while a
/// symlinked or non-regular cache is refused.
///
/// The key alone proves nothing: a repo author computes it from the repo's
/// own go.mod and go.sum, and a planted plan may name any module already in
/// this machine's artifact cache. So a hit is held to the ledger check a
/// fresh plan applies in `verified_module`: every cached module must have
/// both its zip line and its go.mod line in `gosum`, the current go.sum. A
/// fresh plan only keeps modules whose zip line is present, so a module
/// missing either line is a tampered cache and is refused, not missed.
fn cached_plan(project: &ProjectRoot, input_hash: &str, gosum: &str) -> io::Result<Option<GoPlan>> {
    let cached = match project.read_file(Path::new(PLAN_CACHE)) {
        Ok(Some(cached)) => cached,
        Ok(None) => return Ok(None),
        // A symlinked or non-regular cache is a refusal; an unreadable
        // regular file is a miss that the next write replaces.
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return Err(error),
        Err(_) => return Ok(None),
    };
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&cached) {
        if v["input_hash"] == input_hash {
            if let Ok(plan) = serde_json::from_value::<GoPlan>(v["plan"].clone()) {
                validate_plan(&plan)?;
                let ledger = ledger_lines(gosum);
                for m in &plan.modules {
                    let gap = ledger_has_module(&ledger, &m.path, &m.version, &m.h1, &m.modfile_h1);
                    if let Err(missing) = gap {
                        return Err(err(format!(
                            "{}@{}: {PLAN_CACHE} lists a module whose {missing} is not in \
                             the project's go.sum; refusing the cached plan (delete \
                             {PLAN_CACHE} and run tog again)",
                            m.path, m.version
                        )));
                    }
                }
                return Ok(Some(plan));
            }
        }
    }
    Ok(None)
}

/// The refusal for a go.mod/go.sum pair the tidy gate rejects at planning
/// time: `prepare` would have tidied it, and the command layer skips
/// `prepare` under `--frozen`.
fn untidy(project: &ProjectRoot) -> io::Error {
    err(format!(
        "go.mod and go.sum in {} are not tidy and --frozen never updates them; run \
         `tog` once without --frozen and commit the result",
        project.path().display()
    ))
}

/// go.mod through the held descriptor. Absent is the NotFound a path read
/// reported.
fn read_gomod(project: &ProjectRoot) -> io::Result<String> {
    project
        .read_input_string(Path::new("go.mod"))?
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}

/// go.sum through the held descriptor. `None` only when it is absent; an
/// unreadable or non-UTF-8 go.sum is an error, because reading it as empty
/// would drop every module from the ledger and let the sync succeed on a
/// closure the build cannot use.
pub(crate) fn read_gosum(project: &ProjectRoot) -> io::Result<Option<String>> {
    project.read_input_string(Path::new("go.sum"))
}

/// Verify the JSON stream of `go mod download` into plan rows. Ledger
/// anchor: h1 values must ALSO appear in the project's go.sum — never trust
/// sums that exist only in the delegated tool's output. The stream (a
/// sequence of concatenated objects) is parsed BEFORE the exit status is
/// checked: per-module errors ride in the stream.
fn closure_from_download(
    store: &Store,
    activity: &StoreActivity,
    out: &std::process::Output,
    gosum: &str,
) -> io::Result<Vec<GoModule>> {
    let ledger = ledger_lines(gosum);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut modules = Vec::new();
    let de = serde_json::Deserializer::from_str(&stdout).into_iter::<DownloadEntry>();
    for entry in de {
        let entry = entry.map_err(|e| err(format!("go mod download JSON: {e}")))?;
        if let Some(module) = verified_module(store, activity, entry, &ledger)? {
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

/// go.sum as a set of trimmed lines, the form the ledger checks look up.
fn ledger_lines(gosum: &str) -> BTreeSet<String> {
    gosum.lines().map(|l| l.trim().to_string()).collect()
}

/// Which of a module's two ledger lines go.sum lacks, if either: the zip
/// line `<path> <version> <h1>` first, then the go.mod line
/// `<path> <version>/go.mod <modfile_h1>`. Fresh and cached plans both
/// answer to this one test, so a cache hit can never admit a module a
/// fresh plan would not.
fn ledger_has_module(
    ledger: &BTreeSet<String>,
    path: &str,
    version: &str,
    h1: &str,
    modfile_h1: &str,
) -> Result<(), LedgerGap> {
    if !ledger.contains(&format!("{path} {version} {h1}")) {
        return Err(LedgerGap::Zip);
    }
    if !ledger.contains(&format!("{path} {version}/go.mod {modfile_h1}")) {
        return Err(LedgerGap::GoMod);
    }
    Ok(())
}

/// The ledger line `ledger_has_module` found missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerGap {
    Zip,
    GoMod,
}

impl std::fmt::Display for LedgerGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LedgerGap::Zip => "zip sum",
            LedgerGap::GoMod => "go.mod sum",
        })
    }
}

/// Tog-owned verification of one download entry: recompute both
/// dirhashes, check the .info's claim, and insert the bytes into the cache.
/// `Ok(None)` means "outside the closure" — the main module (no artifacts)
/// or a build-GRAPH-only module whose zip sum the tidied go.sum omits.
fn verified_module(
    store: &Store,
    activity: &StoreActivity,
    entry: DownloadEntry,
    ledger: &BTreeSet<String>,
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
    match ledger_has_module(ledger, &entry.path, &entry.version, sum, gomod_sum) {
        Ok(()) => {}
        Err(LedgerGap::Zip) => return Ok(None),
        Err(LedgerGap::GoMod) => {
            return Err(err(format!(
                "{}@{}: go.mod sum is not in the project's go.sum \
                 ledger; refusing (run `tog run go mod tidy`)",
                entry.path, entry.version
            )))
        }
    }
    // Tog-owned verification: recompute both dirhashes.
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
    let (zip_sha256, _) = cache_insert(store, activity, Path::new(zip))?;
    let (modfile_sha256, _) = cache_insert(store, activity, Path::new(gomod_file))?;
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
    let (info_sha256, _) = cache_insert(store, activity, Path::new(info))?;
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
/// by tog-owned verification of every artifact. Cached in
/// .tog/go-plan.json keyed by go.mod+go.sum content.
///
/// `go_version` is the selected toolchain, which is also the Go that
/// realized `go_obj`. The plan never re-reads go.mod's `go` or `toolchain`
/// directive for it: the lock decides the toolchain, and the tidy gate below
/// is free to rewrite those directives without moving the plan to a
/// different compiler than the one it is being planned with.
///
/// The project is read through the held descriptor `project`. With
/// `use_cache` false the plan cache is skipped and the closure downloaded
/// again, which puts every artifact it names in this store's cache.
pub fn plan_go(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    go_obj: &Path,
    go_version: &str,
    use_cache: bool,
    ledgers: &mut Vec<LedgerObjects>,
) -> io::Result<GoPlan> {
    reject_workspaces(project)?;
    let gomod =
        read_gomod(project).map_err(|e| io::Error::new(e.kind(), format!("go.mod: {e}")))?;
    let gosum = read_gosum(project)?.unwrap_or_default();
    reject_local_replaces(&gomod)?;

    let src_digest = source_digest(project)?;
    let input_hash = plan_cache_key(go_version, &gomod, &gosum, &src_digest);
    if use_cache {
        if let Some(plan) = cached_plan(project, &input_hash, &gosum)? {
            return Ok(plan);
        }
    }

    let (store, activity) = (door.store(), door.lease());
    let gate_cache = gate_cache(store)?;
    if !is_tidy(door, go_obj, project, &gate_cache, ledgers)? {
        return Err(untidy(project));
    }
    let module = module_path(&gomod)?;

    let scratch = store.stage_with_activity(activity)?;
    let work = scratch.join("plan");
    let out = download_closure(
        door,
        project,
        go_obj,
        &work,
        &gate_cache,
        &gomod,
        &gosum,
        ledgers,
    );
    let out = match out {
        Ok(out) => out,
        Err(error) => {
            let _ = crate::kernel::store::remove_tree(&scratch);
            return Err(error);
        }
    };
    let result = closure_from_download(store, activity, &out, &gosum);
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
    let now_mod =
        read_gomod(project).map_err(|e| io::Error::new(e.kind(), format!("go.mod: {e}")))?;
    let now_sum = read_gosum(project)?.unwrap_or_default();
    if now_mod != gomod || now_sum != gosum {
        return Err(err("go.mod/go.sum changed while planning; re-run 'tog'"));
    }
    project.write_file(
        Path::new(PLAN_CACHE),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "input_hash": input_hash,
            "plan": plan,
        }))?,
    )?;
    Ok(plan)
}

/// Digest of the project's .go sources (the tidy gate's third input).
/// Sorted (relpath, sha256) pairs; names starting with `.` or `_` (so
/// `.tog` too) are skipped. The walk runs through the held descriptor, each
/// subdirectory held as its own root and opened with the strict no-follow
/// walk; a symlink is neither followed nor hashed, and one swapped in after
/// the entry was classified is refused rather than walked into.
fn source_digest(project: &ProjectRoot) -> io::Result<String> {
    let mut files: Vec<(String, String)> = Vec::new();
    fn walk(dir: &ProjectRoot, rel: &Path, files: &mut Vec<(String, String)>) -> io::Result<()> {
        let names = dir
            .read_input_dir(Path::new("."))?
            .ok_or_else(|| err(format!("source walk: {} vanished", dir.path().display())))?;
        for name in names {
            let lossy = name.to_string_lossy();
            if lossy.starts_with('.') || lossy.starts_with('_') {
                continue;
            }
            let child = Path::new(&name);
            match dir.entry(child)? {
                Entry::Directory => {
                    let sub = dir.subdir(child)?.ok_or_else(|| {
                        err(format!(
                            "source walk: {} vanished",
                            dir.path().join(child).display()
                        ))
                    })?;
                    walk(&sub, &rel.join(child), files)?;
                }
                Entry::Regular if lossy.ends_with(".go") => {
                    let content = dir.read_file(child)?.ok_or_else(|| {
                        err(format!(
                            "source walk: {} vanished",
                            dir.path().join(child).display()
                        ))
                    })?;
                    let rel = rel.join(child).to_string_lossy().into_owned();
                    files.push((rel, hex::encode(Sha256::digest(&content))));
                }
                _ => {}
            }
        }
        Ok(())
    }
    walk(project, Path::new(""), &mut files)?;
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
/// tog-verified .ziphash) from the verified artifact cache.
pub fn stage_modcache_skeleton(
    store: &Store,
    activity: &StoreActivity,
    plan: &GoPlan,
    staged: &Path,
) -> io::Result<()> {
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
            // trusted, because go skips extraction checks when zip+ziphash
            // already exist, so a poisoned cache byte would go straight
            // into the object.
            let src = cache_verified_held(store, activity, hash)
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
fn modcache_identity(extractor_version: &str, extractor_sha256: &str, plan: &GoPlan) -> Identity {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "go-modcache/1".to_string()),
        (
            "extractor".to_string(),
            format!("go{extractor_version}:{extractor_sha256}"),
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

    Identity {
        kind: "go-modcache".into(),
        name: "modcache".into(),
        version: plan.modules.len().to_string(),
        inputs,
    }
}

/// Realize the immutable GOMODCACHE object: verified skeleton + extraction
/// delegated to the store Go offline (full x/mod/zip validation), whose
/// recipe is part of the identity.
pub fn realize_modcache(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
    plan: &GoPlan,
    go_obj: &Path,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Go module cache")?;
    // The extractor is the toolchain this plan was made with, and it is part
    // of the cache object's identity: take it from the same row the runtime
    // was realized from, never from the pin table.
    let row = runtime_row(platform, selected)?;
    if row.version != plan.go_version {
        return Err(err(format!(
            "internal: plan names Go {} but the selection realizes {}",
            plan.go_version, row.version
        )));
    }
    let identity = modcache_identity(&row.version, row.digest.hex(), plan);

    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    let staged = store.stage_with_activity(activity)?;
    stage_modcache_skeleton(store, activity, plan, &staged)?;
    // Offline extraction by the store Go: it re-verifies ziphash and runs
    // its full zip validation while materializing <module>@<version>/ dirs.
    if !plan.modules.is_empty() {
        let scratch = store.stage_with_activity(activity)?;
        let mut gomod = format!("module tog.invalid/extract\n\ngo {}\n\nrequire (\n", {
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
        let out = run_go_offline(activity, go_obj, &scratch, &staged, &arg_refs)?;
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
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &deps)
        .map(|(path, _)| path)
}

/// Project provenance (closure envelope). Go needs no wrapper or config
/// projection: enforcement is process env, set by tog run/build. `toolchain`
/// is the selection the run honored: the closure records it so the release
/// this Go object came from is readable without re-deriving it from go.mod.
pub fn project_go_env(
    activity: &StoreActivity,
    project: &ProjectRoot,
    go_obj: &Path,
    modcache_obj: &Path,
    plan: &GoPlan,
    gosum_sha256: &str,
    toolchain: &Selected,
    ledgers: &[LedgerObjects],
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let go_obj = go_obj.canonicalize()?;
    let modcache_obj = modcache_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&go_obj)
        .ok_or_else(|| err("Go object is not in a Tog store"))?;
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({"path": path.display().to_string(), "id": id}))
    };
    let mut refs = crate::comforter::ClosureRefs::new();
    // The runtime object and `go_object` are the same object; the direct
    // reference is what keeps it alive across a GC.
    refs.object_path(&store, activity, &go_obj)?;
    refs.object_path(&store, activity, &modcache_obj)?;
    // The planner doors' ledgers: evidence of what planning fetched, kept
    // as long as this closure is.
    for objects in ledgers {
        refs.object_id(&store, activity, &objects.ledger)?;
        refs.object_id(&store, activity, &objects.diagnostics)?;
    }
    let mut body = serde_json::json!({
        "go_object": object_ref(&go_obj.canonicalize()?)?,
        "modcache_object": object_ref(&modcache_obj.canonicalize()?)?,
        "go_sum_sha256": gosum_sha256,
        "plan": plan,
    });
    // The Go object is this ecosystem's runtime: the record names the bundle
    // it came from and refers to it directly, so a later catalog refresh
    // cannot re-pair these modules with another toolchain.
    if let (Some(body), Some(record)) = (
        body.as_object_mut(),
        crate::comforter::toolchain::closure_record(toolchain, &go_obj).as_object(),
    ) {
        for (key, value) in record {
            body.insert(key.clone(), value.clone());
        }
    }
    crate::comforter::write_closure(project, "go", body, &store, activity, refs, attribution)
}

/// Sandboxed `go build`: network denied, project READ-ONLY — outputs are
/// staged in scratch and moved into the project by tog afterwards.
pub fn build_sandboxed(
    platform: Platform,
    activity: &StoreActivity,
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
                "{arg}: this flag is managed by tog (module mode, output \
                 staging, and tool execution are enforced)"
            )));
        }
    }
    let project_dir = project_dir.canonicalize()?;
    let go_obj = go_obj.canonicalize()?;
    let modcache_obj = modcache_obj.canonicalize()?;
    let store = Store::open()?;
    store.require_activity(activity, "go build")?;
    let scratch = store.stage_with_activity(activity)?;
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
        host_view: crate::kernel::sandbox::HostView::Full,
    };
    let result = crate::kernel::sandbox::run_build_spec_on_with_activity(platform, &spec, activity)
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
            ui::note(&format!("built {}", dest.display()));
        }
        Ok(())
    });
    let _ = crate::kernel::store::remove_tree(&scratch);
    moved
}

/// The shipped default Go, the object-id golden the identity tests hold:
/// adding a newer release to the catalog must not move it.
#[cfg(test)]
const GO_VERSION: &str = "1.27.0";

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
        modcache_identity(pin.version, pin.sha256(), &empty_plan),
        modcache_identity(pin.version, pin.sha256(), &module_plan),
    ]
}

#[cfg(test)]
mod tests {

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit, or a migrated record stops matching what
    /// a re-sync publishes and every later cache hit becomes a hard error.
    #[test]
    fn legacy_adapter_recovers_the_pinned_go_artifacts() {
        for pin in go_pin_rows().unwrap() {
            assert_eq!(
                recovered_cache(go_identity(pin)),
                vec![format!("sha256:{}", pin.sha256())]
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
    use crate::kernel::testutil::TempDir;

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
    fn every_release_has_one_pin_per_platform_and_the_default_is_unchanged() {
        let rows = go_pin_rows().unwrap();
        let catalog = toolchain_catalog().unwrap();
        assert_eq!(rows.len(), catalog.bundles().len() * Platform::ALL.len());
        let mut seen = std::collections::BTreeSet::new();
        for pin in &rows {
            assert!(
                seen.insert((pin.version, pin.platform.triple())),
                "duplicate Go pin {} {}",
                pin.version,
                pin.platform.triple()
            );
            assert!(
                pin.url().starts_with("https://go.dev/dl/go"),
                "{}",
                pin.url()
            );
        }
        // The catalog holds releases newer than the default; the default
        // is still the one every Go object id golden was minted from.
        assert!(catalog
            .bundles()
            .iter()
            .any(|bundle| bundle.component("go").unwrap().version != GO_VERSION));
        assert_eq!(selection().version("go").unwrap(), GO_VERSION);

        let linux = go_pin(Platform::X86_64UnknownLinuxGnu, GO_VERSION).unwrap();
        assert!(go_pin(Platform::X86_64UnknownLinuxGnu, "1.27").is_err());
        assert_eq!(linux.version, "1.27.0");
        assert_eq!(linux.url(), "https://go.dev/dl/go1.27.0.linux-amd64.tar.gz");
        assert_eq!(
            linux.sha256(),
            "675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"
        );
    }

    /// The shipped selection: what a run with no lock to honor is handed.
    fn selection() -> Selected {
        crate::kernel::toolchain::shipped(&toolchain_catalog().unwrap()).unwrap()
    }

    /// A selection built from another ecosystem's bundle, or one whose row
    /// names a layout this binary has never heard of, is refused before
    /// anything is fetched. A lock is an input like any other: it can name a
    /// recipe a newer tog invented, and the honest answer is to say so.
    #[test]
    fn realization_refuses_a_foreign_selection_and_an_unknown_recipe() {
        use crate::kernel::toolchain::fixtures;
        let temp = TempDir::new();
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        let platform = Platform::host().unwrap();

        let foreign = Selected {
            helpers: Default::default(),
            ecosystem: "node".into(),
            bundle: fixtures::bundle("node-24.20.0", "node", "24.20.0", Platform::ALL),
            lock_sha256: None,
            source: Source::Lock,
        };
        let error = realize_runtime(&store, activity, platform, &foreign)
            .unwrap_err()
            .to_string();
        assert!(error.contains("node selection"), "{error}");
        assert!(error.contains("Go tailor"), "{error}");

        let unknown = Selected {
            helpers: Default::default(),
            ecosystem: "go".into(),
            bundle: fixtures::bundle("go-9.9.9", "go", "9.9.9", Platform::ALL),
            lock_sha256: None,
            source: Source::Lock,
        };
        let error = realize_runtime(&store, activity, platform, &unknown)
            .unwrap_err()
            .to_string();
        assert!(error.contains("recipe example/1"), "{error}");
        assert!(error.contains("upgrade tog"), "{error}");

        // A bundle with no row for this platform is refused by name.
        let elsewhere = Selected {
            helpers: Default::default(),
            ecosystem: "go".into(),
            bundle: fixtures::bundle("go-1.27.0", "go", "1.27.0", &[]),
            lock_sha256: None,
            source: Source::Lock,
        };
        let error = realize_runtime(&store, activity, platform, &elsewhere)
            .unwrap_err()
            .to_string();
        assert!(error.contains("go artifact"), "{error}");
        assert!(error.contains(platform.triple()), "{error}");

        assert!(
            !store.root.exists(),
            "a refused selection touched the store"
        );
    }

    /// Realization from a locked bundle row and realization from the
    /// compiled pin are two spellings of one object. If they ever disagree,
    /// a project that adopts a lock silently rebuilds its toolchain under a
    /// new id and every record naming the old one goes stale. The module
    /// cache hangs off the same row, so its extractor input is held here too.
    #[test]
    fn a_selected_row_and_the_pin_build_the_same_object_id() {
        let selected = selection();
        let plan = GoPlan {
            go_version: GO_VERSION.into(),
            module: "example.com/m".into(),
            modules: Vec::new(),
        };
        for platform in Platform::ALL {
            let pin = go_pin(*platform, GO_VERSION).unwrap();
            let row = runtime_row(*platform, &selected).unwrap();
            assert_eq!(
                runtime_identity(*platform, &row.version, row.digest.hex()).object_id(),
                go_identity(pin).object_id(),
                "{}",
                platform.triple()
            );
            assert_eq!(
                modcache_identity(&row.version, row.digest.hex(), &plan).object_id(),
                modcache_identity(pin.version, pin.sha256(), &plan).object_id(),
                "{}",
                platform.triple()
            );
        }
    }

    /// The closure states which bundle the toolchain came from and refers to
    /// the runtime object directly, so a GC keeps it alive by that reference
    /// and a later resolve needs nothing from the plan.
    #[test]
    fn the_go_closure_records_the_selection_and_the_runtime_object() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("go").unwrap();
        let temp = TempDir::new();
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store { root: store_root };
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let selected = selection();
        let go_id = {
            let row = runtime_row(Platform::host().unwrap(), &selected).unwrap();
            runtime_identity(Platform::host().unwrap(), &row.version, row.digest.hex()).object_id()
        };
        let modcache_id = "0000000000000000000000000000000000000000-modcache-0".to_string();
        for id in [&go_id, &modcache_id] {
            let object = store.object_path(id);
            fs::create_dir_all(&object).unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "id": id,
                    "identity": {"kind": "go", "name": "go", "version": "0", "inputs": {}},
                    "created": 0,
                    "exceptions": [],
                    "refs": []
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let plan = GoPlan {
            go_version: GO_VERSION.into(),
            module: "example.com/m".into(),
            modules: Vec::new(),
        };
        project_go_env(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &store.object_path(&go_id),
            &store.object_path(&modcache_id),
            &plan,
            "sum",
            &selected,
            &[],
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let closure = crate::comforter::read_closure(&project, "go").unwrap();
        assert_eq!(closure["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(closure["toolchain"]["release"], selected.bundle.release);
        assert_eq!(closure["toolchain"]["versions"]["go"], GO_VERSION);
        assert_eq!(closure["runtime_object"]["id"], go_id);
        assert_eq!(closure["runtime_object"]["id"], closure["go_object"]["id"]);
        // Every key the readers already depend on is still there.
        assert_eq!(closure["go_sum_sha256"], "sum");
        assert_eq!(closure["plan"]["go_version"], GO_VERSION);
    }

    /// The durable root/2 record `project_go_env` publishes names exactly
    /// the Go runtime object and the module-cache object it was handed:
    /// nothing inferred from the closure JSON, nothing missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("go").unwrap();
        let temp = TempDir::new();
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store {
            root: store_root.canonicalize().unwrap(),
        };
        let lease = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let activity = &lease;
        let selected = selection();
        let go_id = {
            let row = runtime_row(Platform::host().unwrap(), &selected).unwrap();
            runtime_identity(Platform::host().unwrap(), &row.version, row.digest.hex()).object_id()
        };
        let modcache_id = "0000000000000000000000000000000000000000-modcache-0".to_string();
        for id in [&go_id, &modcache_id] {
            let object = store.object_path(id);
            fs::create_dir_all(&object).unwrap();
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "id": id,
                    "identity": {"kind": "go", "name": "go", "version": "0", "inputs": {}},
                    "created": 0,
                    "exceptions": [],
                    "refs": []
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let project = temp.0.join("project");
        fs::create_dir_all(&project).unwrap();
        let plan = GoPlan {
            go_version: GO_VERSION.into(),
            module: "example.com/m".into(),
            modules: Vec::new(),
        };
        project_go_env(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &store.object_path(&go_id),
            &store.object_path(&modcache_id),
            &plan,
            "sum",
            &selected,
            &[],
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([go_id, modcache_id])
        );
        assert!(record.projections.is_empty(), "{:?}", record.projections);

        // `gc --register` rebuilds the same record from this closure alone.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
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
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
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

        let error = ensure_go_for(&store, activity, platform, "1.25.0")
            .unwrap_err()
            .to_string();
        assert!(error.contains("resolved Go 1.25.0"), "{error}");
        assert!(
            error.contains("realizes only Go 1.26.0, 1.26.1, "),
            "{error}"
        );
        assert!(error.contains(" 1.27.0"), "{error}");
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
        let modcache = modcache_identity(pin.version, pin.sha256(), &empty);
        assert_eq!(
            modcache.inputs["extractor"],
            "go1.27.0:90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e"
        );
        assert_eq!(modcache.inputs["schema"], "go-modcache/1");
        let linux = go_pin(Platform::X86_64UnknownLinuxGnu, GO_VERSION).unwrap();
        assert_ne!(
            modcache_identity(linux.version, linux.sha256(), &empty).object_id(),
            modcache.object_id()
        );
        assert_eq!(pin.url(), "https://go.dev/dl/go1.27.0.darwin-arm64.tar.gz");
    }

    /// A project directory holding just this go.mod.
    fn gomod_project(temp: &TempDir, gomod: &str) -> PathBuf {
        let dir = temp.0.join("proj");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("go.mod"), gomod).unwrap();
        dir
    }

    #[test]
    fn toolchain_selection_rules() {
        for platform in [
            Platform::Aarch64AppleDarwin,
            Platform::X86_64UnknownLinuxGnu,
        ] {
            for gomod in [
                "module m\n\ngo 1.21\n",
                "module m\n\ngo 1.27\n",
                "module m\n\ngo 1.27.0\n",
                "module m\n\ngo 1.21\n\ntoolchain go1.27.0\n",
                "module m\n\ngo 1.24\n\ntoolchain default\n",
            ] {
                let temp = TempDir::new();
                let dir = gomod_project(&temp, gomod);
                assert_eq!(
                    project_go_version(platform, &ProjectRoot::open(&dir).unwrap()).unwrap(),
                    "1.27.0",
                    "{gomod:?}"
                );
            }
            // A requirement above every pin, and a prerelease, are refused.
            for gomod in [
                "module m\n\ngo 1.99\n",
                "module m\n\ngo 1.27\n\ntoolchain go1.28\n",
                "module m\n\ngo 1.27rc1\n",
                "module m\n\ngo 1.27\n\ntoolchain go1.27rc1\n",
            ] {
                let temp = TempDir::new();
                let dir = gomod_project(&temp, gomod);
                assert!(
                    project_go_version(platform, &ProjectRoot::open(&dir).unwrap()).is_err(),
                    "{gomod:?}"
                );
            }
        }
    }

    /// Two Go releases that both satisfy `go 1.26`.
    fn two_pin_catalog() -> Catalog {
        use crate::kernel::toolchain::fixtures::bundle;
        Catalog::new(
            "go",
            vec![
                bundle("go-1.26.0", "go", "1.26.0", Platform::ALL),
                bundle("go-1.27.0", "go", "1.27.0", Platform::ALL),
            ],
        )
        .unwrap()
    }

    /// With no lock, doctor and status name what selection would lock: the
    /// newest satisfying release, not go's lowest-satisfying one.
    #[test]
    fn the_lockless_answer_is_the_newest_satisfying_release() {
        use crate::kernel::toolchain::{input, select_for};
        let temp = TempDir::new();
        let dir = gomod_project(&temp, "module m\n\ngo 1.26\n");
        let catalog = two_pin_catalog();
        let rows = input::discover(&ProjectRoot::open(&dir).unwrap(), "go").unwrap();
        let selected = select_for(&catalog, "go", &rows).unwrap();
        assert_eq!(selected.component("go").unwrap().version, "1.27.0");
        let answer = project_go_version_from(
            catalog.clone(),
            Platform::X86_64UnknownLinuxGnu,
            &ProjectRoot::open(&dir).unwrap(),
        )
        .unwrap();
        assert_eq!(answer, "1.27.0");
        assert!(
            !dir.join(crate::kernel::toolchain::lock::LOCK_PATH).exists(),
            "answering wrote a lock"
        );
    }

    /// With no lock but a closure written before the lock existed, the
    /// answer is the release that closure proves, because the next sync
    /// seeds the lock from it rather than selecting the newest.
    #[test]
    fn a_pre_lock_closure_seeds_the_lockless_answer() {
        let temp = TempDir::new();
        let dir = gomod_project(&temp, "module m\n\ngo 1.26\n");
        fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        fs::write(
            dir.join(".tog/closures/go.json"),
            serde_json::json!({
                "schema": "closure/1",
                "ecosystem": "go",
                "platform": Platform::X86_64UnknownLinuxGnu.triple(),
                "body": {"plan": {"go_version": "1.26.0", "modules": []}},
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            project_go_version_from(
                two_pin_catalog(),
                Platform::X86_64UnknownLinuxGnu,
                &ProjectRoot::open(&dir).unwrap()
            )
            .unwrap(),
            "1.26.0"
        );
    }

    /// A committed lock that pins the older release wins over selection.
    #[test]
    fn a_lock_that_pins_the_older_release_wins() {
        use crate::kernel::toolchain::input;
        use crate::kernel::toolchain::lock::{ToolchainLock, LOCK_PATH};
        let temp = TempDir::new();
        let dir = gomod_project(&temp, "module m\n\ngo 1.26\n");
        let catalog = two_pin_catalog();
        let rows = input::discover(&ProjectRoot::open(&dir).unwrap(), "go").unwrap();
        let older = catalog.release("go-1.26.0").unwrap().clone();
        let mut lock = ToolchainLock::new(env!("CARGO_PKG_VERSION"));
        lock.set_ecosystem("go", &older, &rows).unwrap();
        fs::write(dir.join(LOCK_PATH), lock.canonical_bytes()).unwrap();
        assert_eq!(
            project_go_version_from(
                catalog,
                Platform::X86_64UnknownLinuxGnu,
                &ProjectRoot::open(&dir).unwrap()
            )
            .unwrap(),
            "1.26.0"
        );
    }

    /// The module extraction's real command passes the host-local
    /// tripwire, and loosening any variable the offline form pins is
    /// refused.
    #[test]
    fn the_offline_extraction_passes_the_tripwire_only_as_built() {
        use crate::kernel::resolve::tripwire::refusal;
        let store = TempDir::named("go-tripwire");
        crate::kernel::testutil::store_program(&store.0, "objects/go/bin/go");
        let go_obj = store.0.join("objects/go");
        let cwd = store.0.join("tmp/stage-cwd");
        fs::create_dir_all(&cwd).unwrap();
        let build = || {
            tool::offline_command(
                &go_obj,
                &cwd,
                &store.0.join("tmp/stage-modcache"),
                &["mod", "download", "example.com/m@v1.0.0"],
            )
        };
        let command = build();
        let refused = |command: &std::process::Command| refusal(command, &store.0);
        assert!(refused(&command).is_none(), "{:?}", refused(&command));
        for (key, value) in [("GONOPROXY", "*"), ("GOVCS", "*:all"), ("GOFLAGS", "-x")] {
            let mut command = build();
            command.env(key, value);
            assert!(refused(&command).is_some(), "{key}");
        }
        let loosened = crate::kernel::testutil::loosened(build);
        let keys: Vec<&str> = loosened.iter().map(|(key, _)| key.as_str()).collect();
        for key in [
            "GOROOT",
            "GOMODCACHE",
            "GOPROXY",
            "GOCACHEPROG",
            "HOME",
            "XDG_CONFIG_HOME",
        ] {
            assert!(keys.contains(&key), "{key} is not forced: {keys:?}");
        }
        for (key, command) in &loosened {
            assert!(refused(command).is_some(), "loosened {key}");
        }
        let host = TempDir::named("go-tripwire-host");
        crate::kernel::testutil::store_program(&host.0, "go/bin/go");
        let shim = tool::offline_command(
            &host.0.join("go"),
            &cwd,
            &store.0.join("tmp/stage-modcache"),
            &["mod", "download", "example.com/m@v1.0.0"],
        );
        assert!(refused(&shim).is_some(), "a go outside the store");
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
        let scratch = TempDir::named("go-layout");
        let temp = scratch.0.clone();
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
        assert!(crate::kernel::testutil::tar_create()
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
        extract_go_toolchain(&archive, &staged).unwrap();
        assert!(staged.join("bin/go").is_file());
        assert!(staged.join("bin/gofmt").is_file());
        assert!(staged.join("src/README").is_file());
        assert!(staged.join("pkg/README").is_file());

        let nested_source = temp.join("nested-source");
        std::fs::create_dir_all(nested_source.join("outer/go/bin")).unwrap();
        std::fs::write(nested_source.join("outer/go/bin/go"), b"go").unwrap();
        let nested_archive = temp.join("nested.tar.gz");
        assert!(crate::kernel::testutil::tar_create()
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
        let error = extract_go_toolchain(&nested_archive, &nested_staged).unwrap_err();
        assert!(error.to_string().contains("unexpected layout"));
        assert!(!nested_staged.join("go").exists());
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
        // rejection must parse go.mod itself.
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
        // Path-traversal "sha256" from a tampered .tog/go-plan.json.
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
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
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
                &activity,
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                &[bad.to_string()],
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("managed by tog"), "{bad}: {e}");
        }
    }

    #[test]
    fn module_path_reads_the_module_directive_and_requires_one() {
        assert_eq!(module_path("module hello\n\ngo 1.27\n").unwrap(), "hello");
        assert!(module_path("go 1.27\n").is_err());
    }

    /// v0 builds single-module projects only: a `go.work` in the project or
    /// in any directory above it is refused, and so is a `GOWORK` naming a
    /// workspace file. `GOWORK=off` or empty is the single-module default.
    #[test]
    fn go_workspaces_are_refused_in_the_project_above_it_and_through_gowork() {
        let scratch = TempDir::named("go-workspace-guard");
        let project = scratch.0.join("outer/project");
        fs::create_dir_all(&project).unwrap();
        let root = || ProjectRoot::open(&project).unwrap();
        for gowork in [None, Some(""), Some("off")] {
            reject_workspaces_with(&root(), gowork.map(Into::into))
                .unwrap_or_else(|error| panic!("{gowork:?}: {error}"));
        }

        let error = reject_workspaces_with(&root(), Some("/elsewhere/go.work".into()))
            .unwrap_err()
            .to_string();
        assert_eq!(error, "GOWORK is set; Go workspaces are not supported yet");

        let above = scratch.0.join("outer/go.work");
        fs::write(&above, "go 1.27\n").unwrap();
        let error = reject_workspaces_with(&root(), None)
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with(&format!(
                "{}/go.work found; ",
                root().path().parent().unwrap().display()
            )),
            "{error}"
        );
        fs::remove_file(&above).unwrap();

        fs::write(project.join("go.work"), "go 1.27\n").unwrap();
        let error = reject_workspaces_with(&root(), None)
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with(&format!("{}/go.work found; ", root().path().display())),
            "{error}"
        );
    }

    /// A plan the store can realize: its object is there, or every artifact
    /// is. A missing artifact without the object sends the sync to plan
    /// again, which is how a plan cached against another store recovers.
    #[test]
    fn modcache_realizable_needs_the_object_or_every_artifact() {
        let scratch = TempDir::named("go-realizable");
        let temp = scratch.0.clone();
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TOG_STORE", temp.join("store"));
        let store = Store::open().unwrap();
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        std::env::remove_var("TOG_STORE");
        let fix = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-dirhash");
        let (zip_hash, zip_cache) =
            cache_insert(&store, activity, &fix.join("quote-v1.5.2.zip")).unwrap();
        let (mod_hash, _) = cache_insert(&store, activity, &fix.join("quote-v1.5.2.mod")).unwrap();
        let info = temp.join("info");
        std::fs::write(&info, r#"{"Version":"v1.5.2"}"#).unwrap();
        let (info_hash, _) = cache_insert(&store, activity, &info).unwrap();
        let plan = GoPlan {
            go_version: GO_VERSION.into(),
            module: "m".into(),
            modules: vec![GoModule {
                path: "rsc.io/quote".into(),
                version: "v1.5.2".into(),
                h1: "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=".into(),
                zip_sha256: zip_hash,
                modfile_h1: "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=".into(),
                modfile_sha256: mod_hash,
                info_sha256: info_hash,
            }],
        };
        let selected = selection();
        let platform = Platform::host().unwrap();
        let realizable =
            || super::inputs::modcache_realizable(&store, activity, platform, &selected, &plan);
        assert!(realizable().unwrap());

        std::fs::remove_file(&zip_cache).unwrap();
        assert!(!realizable().unwrap());

        let row = runtime_row(platform, &selected).unwrap();
        let identity = modcache_identity(&row.version, row.digest.hex(), &plan);
        let staged = store.stage().unwrap();
        store
            .commit_with_deps(
                &identity,
                &staged,
                &[],
                &crate::kernel::store::ObjectDeps::new(),
            )
            .unwrap();
        assert!(realizable().unwrap());
    }

    #[test]
    fn modcache_skeleton_layout() {
        let scratch = TempDir::named("go-skel");
        let temp = scratch.0.clone();
        let _lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TOG_STORE", temp.join("store"));
        let store = Store::open().unwrap();
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        std::env::remove_var("TOG_STORE");
        // Real fixture artifacts through the verified cache.
        let fix = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-dirhash");
        let (zip_hash, _) = cache_insert(&store, activity, &fix.join("quote-v1.5.2.zip")).unwrap();
        let (mod_hash, _) = cache_insert(&store, activity, &fix.join("quote-v1.5.2.mod")).unwrap();
        let info = temp.join("info");
        std::fs::write(&info, r#"{"Version":"v1.5.2"}"#).unwrap();
        let (info_hash, info_cache) = cache_insert(&store, activity, &info).unwrap();
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
        stage_modcache_skeleton(&store, activity, &plan, &staged).unwrap();
        let base = staged.join("cache/download/rsc.io/quote/@v");
        assert_eq!(
            std::fs::read_to_string(base.join("v1.5.2.ziphash")).unwrap(),
            "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y="
        );
        assert!(base.join("v1.5.2.zip").is_file());
        assert!(base.join("v1.5.2.mod").is_file());
        assert!(base.join("v1.5.2.info").is_file());

        // Poisoning regression: tamper the cached .info — staging must
        // refuse instead of copying poisoned bytes.
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = std::fs::metadata(&info_cache).unwrap().permissions();
            p.set_mode(0o644);
            std::fs::set_permissions(&info_cache, p).unwrap();
            std::fs::write(&info_cache, r#"{"Version":"evil"}"#).unwrap();
        }
        let staged2 = temp.join("staged2");
        std::fs::create_dir_all(&staged2).unwrap();
        let e = stage_modcache_skeleton(&store, activity, &plan, &staged2).unwrap_err();
        assert!(e.to_string().contains(&info_hash), "{e}");
    }
    /// Characterization: the plan cache is the
    /// only part of `plan_go` reachable without a real toolchain, and it is
    /// the part an attacker can edit. These pin the key formula, the
    /// validation of cached fields, and the fact that a hit never touches
    /// the store or the go binary.
    fn plan_fixture(project: &Path) -> (String, String, GoPlan) {
        let gomod = "module example.com/m\n\ngo 1.27.0\n";
        // The ledger lines a fresh plan requires for the fixture's module,
        // so the cached plan below passes the same ledger check on a hit.
        let gosum = format!(
            "example.com/a v1.0.0 h1:{a}=\nexample.com/a v1.0.0/go.mod h1:{b}=\n",
            a = "A".repeat(43),
            b = "B".repeat(43),
        );
        fs::create_dir_all(project).unwrap();
        fs::write(project.join("go.mod"), gomod).unwrap();
        fs::write(project.join("go.sum"), &gosum).unwrap();
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
        (gomod.into(), gosum, plan)
    }

    fn write_plan_cache(project: &Path, input_hash: &str, plan: &GoPlan) {
        fs::create_dir_all(project.join(".tog")).unwrap();
        fs::write(
            project.join(".tog/go-plan.json"),
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
                source_digest(&ProjectRoot::open(project).unwrap()).unwrap()
            )
            .as_bytes(),
        ))
    }

    #[test]
    fn plan_cache_hit_skips_the_store_and_the_toolchain() {
        // The plan borrows the caller's lease; these cases never reach the
        // store, so a lease on a scratch store stands in for it.
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
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
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &ProjectRoot::open(&project).unwrap(),
            Path::new("/nonexistent/go"),
            "1.27.0",
            true,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(got.go_version, "1.27.0");
        assert_eq!(got.module, "example.com/m");
        assert_eq!(got.modules, plan.modules);
        assert!(!store.root.exists(), "a cache hit touched the store");
    }

    /// The plan is made with the toolchain the selection handed in, never
    /// with the one go.mod's `go`/`toolchain` directives would have picked.
    /// go.mod here asks for a Go this project is not being planned with, and
    /// the cache written for the selected version is still the one served;
    /// change the selection and that cache stops applying, because the
    /// selected version is part of the plan's input hash.
    #[test]
    fn the_plan_follows_the_selection_not_the_go_directive() {
        // The plan borrows the caller's lease; these cases never reach the
        // store, so a lease on a scratch store stands in for it.
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
        // The changed selection below reaches the re-plan path, which runs
        // the store go through the supervisor: one supervised child at a
        // time (see `plan_cache_key_covers_the_go_sources`).
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (_, gosum, plan) = plan_fixture(&project);
        fs::write(
            project.join("go.mod"),
            "module example.com/m\n\ngo 1.21\n\ntoolchain go1.22.0\n",
        )
        .unwrap();
        let gomod = fs::read_to_string(project.join("go.mod")).unwrap();
        write_plan_cache(
            &project,
            &plan_cache_key(
                "1.27.0",
                &gomod,
                &gosum,
                &source_digest(&ProjectRoot::open(&project).unwrap()).unwrap(),
            ),
            &plan,
        );
        // A store root that does not exist and a go binary that does not
        // exist: the selected toolchain hits the cache and reaches neither.
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let got = plan_go(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &ProjectRoot::open(&project).unwrap(),
            Path::new("/nonexistent/go"),
            "1.27.0",
            true,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(got.go_version, "1.27.0");
        assert!(!store.root.exists(), "a cache hit touched the store");

        // A different selection is a different plan: the cache keyed to the
        // old one is not served for it. The miss goes on to the tidy gate,
        // which creates its module cache in the store before running the
        // (absent) go; that directory is the proof the cache was skipped.
        plan_go(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &ProjectRoot::open(&project).unwrap(),
            Path::new("/nonexistent/go"),
            "1.28.0",
            true,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            store.root.join("planner-modcache").is_dir(),
            "a changed selection was served the cached plan"
        );
    }

    #[test]
    fn unreadable_plan_cache_is_a_miss_not_an_error() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, gosum, plan) = plan_fixture(&project);
        let input_hash = expected_input_hash(&project, &gomod, &gosum);
        write_plan_cache(&project, &input_hash, &plan);
        use std::os::unix::fs::PermissionsExt;
        let cache = project.join(".tog/go-plan.json");
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o200)).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        assert!(cached_plan(&root, &input_hash, &gosum).unwrap().is_none());
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            cached_plan(&root, &input_hash, &gosum)
                .unwrap()
                .unwrap()
                .modules,
            plan.modules
        );
    }

    /// A cache hit whose go.sum is rewritten to `gosum` (with the key
    /// recomputed, as a repo author can) and the error `plan_go` returns.
    fn cached_plan_error(gosum: &str) -> String {
        // The plan borrows the caller's lease; these cases never reach the
        // store, so a lease on a scratch store stands in for it.
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, _, plan) = plan_fixture(&project);
        fs::write(project.join("go.sum"), gosum).unwrap();
        write_plan_cache(
            &project,
            &expected_input_hash(&project, &gomod, gosum),
            &plan,
        );
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let e = plan_go(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &ProjectRoot::open(&project).unwrap(),
            Path::new("/nonexistent/go"),
            "1.27.0",
            true,
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(!store.root.exists(), "a refused cache touched the store");
        e
    }

    #[test]
    fn cached_module_without_its_zip_line_in_go_sum_is_refused() {
        let gosum = format!("example.com/a v1.0.0/go.mod h1:{}=\n", "B".repeat(43));
        let e = cached_plan_error(&gosum);
        assert!(e.contains("example.com/a@v1.0.0"), "{e}");
        assert!(e.contains(".tog/go-plan.json"), "{e}");
        assert!(
            e.contains("delete .tog/go-plan.json and run tog again"),
            "{e}"
        );
    }

    #[test]
    fn cached_module_without_its_go_mod_line_in_go_sum_is_refused() {
        let gosum = format!("example.com/a v1.0.0 h1:{}=\n", "A".repeat(43));
        let e = cached_plan_error(&gosum);
        assert!(e.contains("example.com/a@v1.0.0"), "{e}");
        assert!(e.contains(".tog/go-plan.json"), "{e}");
        assert!(
            e.contains("delete .tog/go-plan.json and run tog again"),
            "{e}"
        );
    }

    #[test]
    fn read_gosum_is_none_when_go_sum_is_absent() {
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        plan_fixture(&project);
        fs::remove_file(project.join("go.sum")).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        assert!(read_gosum(&root).unwrap().is_none());
    }

    #[test]
    fn read_gosum_propagates_a_permission_error() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        plan_fixture(&project);
        fs::set_permissions(project.join("go.sum"), fs::Permissions::from_mode(0o000)).unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let e = read_gosum(&root).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains("go.sum"), "{e}");
    }

    #[test]
    fn read_gosum_propagates_invalid_utf8() {
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        plan_fixture(&project);
        fs::write(project.join("go.sum"), b"example.com/a v1.0.0 h1:\xff\n").unwrap();
        let root = ProjectRoot::open(&project).unwrap();
        let e = read_gosum(&root).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        assert!(e.to_string().contains("go.sum"), "{e}");
    }

    /// An unreadable go.sum is an error, not an empty ledger: a cache keyed
    /// to an empty go.sum is never served for one tog cannot read.
    #[test]
    fn unreadable_go_sum_fails_the_plan() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, _, mut plan) = plan_fixture(&project);
        plan.modules.clear();
        write_plan_cache(&project, &expected_input_hash(&project, &gomod, ""), &plan);
        fs::set_permissions(project.join("go.sum"), fs::Permissions::from_mode(0o000)).unwrap();
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let e = plan_go(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &ProjectRoot::open(&project).unwrap(),
            Path::new("/nonexistent/go"),
            "1.27.0",
            true,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains("go.sum"), "{e}");
        assert!(
            !store.root.exists(),
            "an unreadable go.sum reached the store"
        );
    }

    #[test]
    fn plan_cache_behind_a_symlinked_tog_is_refused() {
        // The plan borrows the caller's lease; these cases never reach the
        // store, so a lease on a scratch store stands in for it.
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, gosum, plan) = plan_fixture(&project);
        let outside = temp.0.join("outside");
        write_plan_cache(
            &outside,
            &expected_input_hash(&project, &gomod, &gosum),
            &plan,
        );
        std::os::unix::fs::symlink(outside.join(".tog"), project.join(".tog")).unwrap();
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let e = plan_go(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &ProjectRoot::open(&project).unwrap(),
            Path::new("/nonexistent/go"),
            "1.27.0",
            true,
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("not a real directory"), "{e}");
        assert!(!store.root.exists(), "a refused cache touched the store");
    }

    #[test]
    fn plan_cache_hit_validates_hostile_fields_before_use() {
        // The plan borrows the caller's lease; these cases never reach the
        // store, so a lease on a scratch store stands in for it.
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
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
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &ProjectRoot::open(&project).unwrap(),
            Path::new("/nonexistent/go"),
            "1.27.0",
            true,
            &mut Vec::new(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("invalid sha256 in plan"), "{e}");
        assert!(!store.root.exists(), "a rejected cache touched the store");
    }

    #[test]
    fn plan_cache_key_covers_the_go_sources() {
        // The plan borrows the caller's lease; these cases never reach the
        // store, so a lease on a scratch store stands in for it.
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
        // plan_go's re-plan path runs the store go through the supervisor,
        // which owns process-wide signal dispositions: one supervised child
        // at a time, so every test that can reach a supervised child holds
        // this (same convention as kernel::gitsrc's realization tests).
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, gosum, plan) = plan_fixture(&project);
        let input_hash = expected_input_hash(&project, &gomod, &gosum);
        write_plan_cache(&project, &input_hash, &plan);
        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp", "roots"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store { root: store_root };
        // A miss goes on to the tidy gate, which creates its module cache in
        // the store before running the (absent) go: that directory is how
        // the test tells a miss from a hit through `plan_go` itself.
        let gate_cache = store.root.join("planner-modcache");
        let plan_now = || {
            plan_go(
                &mut crate::kernel::testutil::DoorScope::new().door(
                    &store,
                    &activity,
                    crate::kernel::platform::Platform::host().unwrap(),
                    crate::kernel::resolve::DoorKind::Planner,
                ),
                &ProjectRoot::open(&project).unwrap(),
                Path::new("/nonexistent/go"),
                "1.27.0",
                true,
                &mut Vec::new(),
            )
        };
        // Unchanged sources: the cached plan is served.
        assert_eq!(plan_now().unwrap().modules, plan.modules);
        assert!(!gate_cache.exists(), "unchanged sources missed the cache");
        // Editing a .go source invalidates the key, so the cached plan is
        // not returned; without a toolchain the re-plan can only fail.
        fs::write(
            project.join("main.go"),
            "package main\n\nfunc main() { _ = 1 }\n",
        )
        .unwrap();
        plan_now().unwrap_err();
        assert!(gate_cache.is_dir(), "an edited source was served the cache");
    }

    /// A project renamed away mid-sync and replaced by another at the same
    /// path is still read through the descriptor held for the original:
    /// detection, go.mod, the source digest, and the plan cache all come
    /// from the original directory, never the replacement.
    #[test]
    fn a_held_root_keeps_reading_the_original_project_after_a_swap() {
        use crate::tailors::Tailor;
        // The plan borrows the caller's lease; a cache hit never reaches the
        // store, so a lease on a scratch store stands in for it.
        let (_lease_store, activity) = crate::kernel::testutil::detached_lease();
        let temp = TempDir::new();
        let project = temp.0.join("proj");
        let (gomod, gosum, plan) = plan_fixture(&project);
        write_plan_cache(
            &project,
            &expected_input_hash(&project, &gomod, &gosum),
            &plan,
        );
        let root = ProjectRoot::open(&project).unwrap();
        let digest = source_digest(&root).unwrap();

        fs::rename(&project, temp.0.join("moved")).unwrap();
        fs::create_dir_all(&project).unwrap();
        fs::write(
            project.join("go.mod"),
            "module example.com/evil\n\ngo 1.27.0\n",
        )
        .unwrap();
        fs::write(project.join("evil.go"), "package main\n").unwrap();

        assert!(tailor::Go.detect(&root).unwrap());
        assert_eq!(read_gomod(&root).unwrap(), gomod);
        assert_eq!(read_gosum(&root).unwrap().unwrap(), gosum);
        assert_eq!(source_digest(&root).unwrap(), digest);
        // The original's cache is served; the replacement has none, so a
        // read of the replacement would have missed and reached the store.
        let store = Store {
            root: temp.0.join("absent-store"),
        };
        let got = plan_go(
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                crate::kernel::platform::Platform::host().unwrap(),
                crate::kernel::resolve::DoorKind::Planner,
            ),
            &root,
            Path::new("/nonexistent/go"),
            "1.27.0",
            true,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(got.module, "example.com/m");
        assert!(
            !store.root.exists(),
            "the swap made the plan miss its cache"
        );
    }

    const QUOTE_H1: &str = "h1:w5fcysjrx7yqtD/aO+QwRjYZOKnaM9Uh2b40tElTs3Y=";
    const QUOTE_MOD_H1: &str = "h1:LzX7hefJvL54yjefDEDHNONDjII0t9xZLPXsUe+TKr0=";
    /// Well-formed but wrong: the shape of an h1 sum, not the fixture's.
    const WRONG_H1: &str = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// A scratch store plus the real rsc.io/quote v1.5.2 artifacts, for
    /// driving `closure_from_download` with a hand-written download stream.
    struct DownloadCase {
        scratch: TempDir,
        store: Store,
        activity: StoreActivity,
        fix: PathBuf,
    }

    impl DownloadCase {
        fn new() -> Self {
            let scratch = TempDir::named("go-download");
            let root = scratch.0.join("store");
            for sub in ["objects", "meta", "cache/sha256", "tmp"] {
                fs::create_dir_all(root.join(sub)).unwrap();
            }
            let store = Store { root };
            let activity = store
                .activity(crate::kernel::activity::ActivityMode::Shared)
                .unwrap();
            let info = scratch.0.join("quote.info");
            fs::write(&info, r#"{"Version":"v1.5.2"}"#).unwrap();
            let fix = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-dirhash");
            DownloadCase {
                scratch,
                store,
                activity,
                fix,
            }
        }

        /// The download entry `go mod download -json` prints for the fixture.
        fn entry(&self) -> serde_json::Value {
            serde_json::json!({
                "Path": "rsc.io/quote",
                "Version": "v1.5.2",
                "Sum": QUOTE_H1,
                "GoModSum": QUOTE_MOD_H1,
                "Zip": self.fix.join("quote-v1.5.2.zip"),
                "GoMod": self.fix.join("quote-v1.5.2.mod"),
                "Info": self.scratch.0.join("quote.info"),
            })
        }

        fn run(
            &self,
            entries: &[serde_json::Value],
            gosum: &str,
            exit: i32,
        ) -> io::Result<Vec<GoModule>> {
            use std::os::unix::process::ExitStatusExt;
            let stdout: String = entries.iter().map(|e| format!("{e}\n")).collect();
            let out = std::process::Output {
                status: std::process::ExitStatus::from_raw(exit << 8),
                stdout: stdout.into_bytes(),
                stderr: b"go: something broke\n".to_vec(),
            };
            closure_from_download(&self.store, &self.activity, &out, gosum)
        }

        fn refusal(&self, entry: serde_json::Value, gosum: &str) -> String {
            match self.run(&[entry], gosum, 0) {
                Ok(modules) => panic!("the entry was accepted: {modules:?}"),
                Err(e) => e.to_string(),
            }
        }
    }

    /// The go.sum lines a tidied project holds for the fixture module.
    fn quote_gosum(h1: &str, mod_h1: &str) -> String {
        format!("rsc.io/quote v1.5.2 {h1}\nrsc.io/quote v1.5.2/go.mod {mod_h1}\n")
    }

    #[test]
    fn a_verified_download_becomes_a_plan_row() {
        let case = DownloadCase::new();
        let main = serde_json::json!({"Path": "example.com/app", "Version": ""});
        let modules = case
            .run(
                &[main, case.entry()],
                &quote_gosum(QUOTE_H1, QUOTE_MOD_H1),
                0,
            )
            .unwrap();
        assert_eq!(modules.len(), 1, "{modules:?}");
        let row = &modules[0];
        assert_eq!(
            (row.path.as_str(), row.version.as_str()),
            ("rsc.io/quote", "v1.5.2")
        );
        assert_eq!(
            (row.h1.as_str(), row.modfile_h1.as_str()),
            (QUOTE_H1, QUOTE_MOD_H1)
        );
        let sha =
            |p: &Path| crate::kernel::fetch::hash_file(p, crate::kernel::digest::Algo::Sha256);
        for (hex, source) in [
            (&row.zip_sha256, case.fix.join("quote-v1.5.2.zip")),
            (&row.modfile_sha256, case.fix.join("quote-v1.5.2.mod")),
            (&row.info_sha256, case.scratch.0.join("quote.info")),
        ] {
            assert_eq!(*hex, sha(&source).unwrap(), "{}", source.display());
            assert!(
                case.store.cache_path("sha256", hex).is_file(),
                "{} not cached",
                source.display()
            );
        }
    }

    #[test]
    fn a_module_without_its_zip_line_in_go_sum_is_left_out_of_the_closure() {
        let case = DownloadCase::new();
        let gosum = format!("rsc.io/quote v1.5.2/go.mod {QUOTE_MOD_H1}\n");
        let modules = case.run(&[case.entry()], &gosum, 0).unwrap();
        assert!(modules.is_empty(), "{modules:?}");
        // A zip line with another sum is no line for these bytes either.
        let gosum = quote_gosum(WRONG_H1, QUOTE_MOD_H1);
        let modules = case.run(&[case.entry()], &gosum, 0).unwrap();
        assert!(modules.is_empty(), "{modules:?}");
    }

    #[test]
    fn a_module_without_its_go_mod_line_in_go_sum_is_refused() {
        let case = DownloadCase::new();
        for gosum in [
            format!("rsc.io/quote v1.5.2 {QUOTE_H1}\n"),
            quote_gosum(QUOTE_H1, WRONG_H1),
        ] {
            let e = case.refusal(case.entry(), &gosum);
            assert!(
                e.starts_with(
                    "rsc.io/quote@v1.5.2: go.mod sum is not in the project's go.sum ledger"
                ),
                "{gosum}: {e}"
            );
        }
    }

    /// go.sum and the download agree on a sum the bytes do not hash to:
    /// only Tog's own dirhash catches it.
    #[test]
    fn a_zip_that_does_not_hash_to_its_sum_is_refused() {
        let case = DownloadCase::new();
        let mut entry = case.entry();
        entry["Sum"] = WRONG_H1.into();
        let e = case.refusal(entry, &quote_gosum(WRONG_H1, QUOTE_MOD_H1));
        assert!(
            e.starts_with("rsc.io/quote@v1.5.2: zip dirhash mismatch"),
            "{e}"
        );
        assert!(e.contains(&format!("expected {WRONG_H1}")), "{e}");
        assert!(e.contains(&format!("got      {QUOTE_H1}")), "{e}");
    }

    #[test]
    fn a_go_mod_that_does_not_hash_to_its_sum_is_refused() {
        let case = DownloadCase::new();
        let mut entry = case.entry();
        entry["GoModSum"] = WRONG_H1.into();
        let e = case.refusal(entry, &quote_gosum(QUOTE_H1, WRONG_H1));
        assert!(
            e.starts_with("rsc.io/quote@v1.5.2: go.mod dirhash mismatch"),
            "{e}"
        );
        assert!(e.contains(&format!("expected {WRONG_H1}")), "{e}");
        assert!(e.contains(&format!("got      {QUOTE_MOD_H1}")), "{e}");
    }

    #[test]
    fn info_file_refusals() {
        let case = DownloadCase::new();
        let gosum = quote_gosum(QUOTE_H1, QUOTE_MOD_H1);
        let info = |name: &str, body: &str| {
            let path = case.scratch.0.join(name);
            fs::write(&path, body).unwrap();
            serde_json::Value::from(path.to_str().unwrap())
        };
        let cases = [
            (
                serde_json::Value::Null,
                "rsc.io/quote@v1.5.2: download entry has no Info file",
            ),
            (
                info("junk.info", "not json"),
                "rsc.io/quote@v1.5.2: bad .info: ",
            ),
            (
                info("other.info", r#"{"Version":"v1.5.3"}"#),
                "rsc.io/quote@v1.5.2: .info Version String(\"v1.5.3\") does not match",
            ),
            (
                info("none.info", "{}"),
                "rsc.io/quote@v1.5.2: .info Version Null does not match",
            ),
        ];
        for (info, needle) in cases {
            let mut entry = case.entry();
            entry["Info"] = info.clone();
            let e = case.refusal(entry, &gosum);
            assert!(e.starts_with(needle), "{info}: {e}");
        }
    }

    #[test]
    fn a_module_that_failed_to_download_is_refused() {
        let case = DownloadCase::new();
        let failed = serde_json::json!({
            "Path": "rsc.io/quote",
            "Version": "v1.5.2",
            "Error": "unrecognized import path",
        });
        let e = case.refusal(failed, "");
        assert_eq!(
            e,
            "rsc.io/quote@v1.5.2: unrecognized import path (a selected module \
             failed to download; the closure would be incomplete)"
        );
    }

    #[test]
    fn a_local_path_replace_is_refused() {
        let case = DownloadCase::new();
        let gosum = quote_gosum(QUOTE_H1, QUOTE_MOD_H1);
        for replace in [
            serde_json::json!({"Path": "../quote", "Version": ""}),
            serde_json::json!({"Path": "quote", "Version": ""}),
            serde_json::json!({"Path": "./quote", "Version": "v1.5.2"}),
            serde_json::json!({"Path": "/src/quote", "Version": "v1.5.2"}),
        ] {
            let mut entry = case.entry();
            entry["Replace"] = replace.clone();
            let e = case.refusal(entry, &gosum);
            assert!(
                e.starts_with("rsc.io/quote: local-path replace directives are not supported"),
                "{replace}: {e}"
            );
        }
        let mut entry = case.entry();
        entry["Replace"] = serde_json::json!({"Path": "example.com/fork", "Version": "v1.5.2"});
        assert_eq!(case.run(&[entry], &gosum, 0).unwrap().len(), 1);
    }

    /// Per-module errors ride in the stream, so the stream is read before
    /// the exit status: the module's own message wins over the generic one.
    #[test]
    fn a_failed_download_names_the_module_before_the_exit_status() {
        let case = DownloadCase::new();
        let gosum = quote_gosum(QUOTE_H1, QUOTE_MOD_H1);
        let failed = serde_json::json!({
            "Path": "rsc.io/sampler",
            "Version": "v1.3.0",
            "Error": "checksum mismatch",
        });
        let e = case
            .run(&[case.entry(), failed], &gosum, 1)
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("rsc.io/sampler@v1.3.0: checksum mismatch"),
            "{e}"
        );

        let e = case
            .run(&[case.entry()], &gosum, 1)
            .unwrap_err()
            .to_string();
        assert_eq!(e, "go mod download failed: go: something broke");
    }

    #[test]
    fn a_malformed_download_stream_is_refused() {
        let case = DownloadCase::new();
        let out = std::process::Output {
            status: std::os::unix::process::ExitStatusExt::from_raw(0),
            stdout: br#"{"Path": "rsc.io/quote", "Version": 7}"#.to_vec(),
            stderr: Vec::new(),
        };
        let e = closure_from_download(&case.store, &case.activity, &out, "")
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("go mod download JSON: "), "{e}");
    }
}
