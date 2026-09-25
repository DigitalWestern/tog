//! The .NET tailor: NuGet packages.lock.json (v1, tog-mandatory),
//! materialization delegated to the pinned NuGet, per-build fresh offline
//! restore, sandboxed builds only.
//!
//! Signed nupkgs' contentHash is a SEMANTIC hash over transformed bytes, so
//! tog never compares lock hashes to raw
//! downloads — the pinned NuGet verifies contentHash while installing into
//! the global-packages layout (locked mode), the same delegated-extractor
//! pattern as Go, with the full SDK object id in the object identity. The
//! lock (not project obj/) is the only durable authority: every sandboxed
//! build re-restores offline into scratch and builds --no-restore.

pub mod objects;
pub mod tailor;

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{cache_insert, download_verified_digest_held, Digest};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::Platform;
use crate::kernel::sandbox::{force_env, BuildSpec};
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::{ArtifactRow, Catalog, LegacyEvidence, Selected};
use crate::kernel::types::Identity;
use crate::kernel::ui;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The shipped .NET catalog: every SDK of the .NET channels Microsoft still
/// supports, with its default, generated and verified by
/// `tools/catalog.py dotnet` from Microsoft's release metadata (sha512,
/// published over HTTPS, not signed).
static CATALOG: Shipped = Shipped::new(include_str!("catalog.toml"));

/// The default SDK's archive for a platform: what a project with no
/// `global.json` pin realizes there.
fn sdk_pin(platform: Platform) -> io::Result<&'static ArtifactRow> {
    CATALOG.default_row(platform, "dotnet-sdk")
}

/// The shipped .NET catalog: one release bundle per SDK, keeping the sha512
/// Microsoft publishes, and the default.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

/// A pre-lock .NET closure records the SDK under `plan.sdk_version` and the
/// SDK object under `sdk_object`: the archive and recipe that object's
/// identity names are the proof.
pub fn legacy_toolchain_evidence(
    platform: Option<Platform>,
    body: &serde_json::Value,
    store: Option<&crate::kernel::store::Store>,
) -> LegacyEvidence {
    use crate::comforter::toolchain::{self as project_toolchain, LegacyRuntime};
    let mut evidence = crate::comforter::legacy_toolchain_evidence(
        platform,
        body,
        &[("dotnet-sdk", "/plan/sdk_version")],
    );
    project_toolchain::prove_legacy_runtime(
        &mut evidence,
        store,
        body,
        LegacyRuntime {
            pointer: "/sdk_object",
            via: &[],
            kind: "dotnet-sdk",
        },
        |identity, evidence| {
            project_toolchain::expect_legacy_version(
                identity,
                evidence,
                "dotnet-sdk",
                &identity.version,
            )?;
            Ok(vec![project_toolchain::proved_from_identity(
                identity,
                "dotnet-sdk",
                "artifact_sha512",
                "sha512",
                project_toolchain::schema_recipe(identity)?,
            )?])
        },
    );
    evidence
}

/// The SDK object a pre-lock sync from `selected` left for legacy seeding
/// to read, and the body field that names it.
#[cfg(test)]
pub(crate) fn legacy_runtime_for_test(
    platform: Platform,
    selected: &Selected,
    store: &Store,
) -> (serde_json::Value, Vec<Identity>) {
    let sdk = sdk_identity(&sdk_spec(platform, selected).unwrap());
    let body = serde_json::json!({
        "sdk_object": crate::comforter::toolchain::object_ref_for_test(store, &sdk.object_id()),
    });
    (body, vec![sdk])
}

pub fn preflight_platform(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, ".NET SDK")?;
    sdk_pin(platform).map(|_| ())
}

/// The recipe this tailor knows how to build an SDK object from. A lock
/// naming any other recipe was written by a tog that installs the SDK some
/// other way, and this one must not guess.
const SDK_RECIPE: &str = "dotnet-sdk/1";

/// One SDK realization's bytes, read from the selected toolchain rather
/// than from the compiled pin table: the same fields a pin carries, owned,
/// so a project's lock can supply them.
#[derive(Debug)]
struct SdkSpec {
    platform: Platform,
    version: String,
    url: String,
    sha512: String,
}

/// The selected SDK's row for `platform`, refused unless this tog knows the
/// recipe that produced it. Microsoft publishes sha512, so the row must
/// carry one: a sha256 row is a different provenance channel.
fn sdk_spec(platform: Platform, selected: &Selected) -> io::Result<SdkSpec> {
    if selected.ecosystem != "dotnet" || selected.runtime() != "dotnet-sdk" {
        return Err(err(format!(
            "dotnet: selected toolchain is {} ({}), not dotnet",
            selected.ecosystem,
            selected.runtime()
        )));
    }
    let row = selected.artifact(platform, "dotnet-sdk")?;
    if row.recipe != SDK_RECIPE {
        return Err(err(format!(
            "dotnet: recipe {} in tog-toolchain.toml is not known to this tog; upgrade tog",
            row.recipe
        )));
    }
    if row.digest.algo() != "sha512" {
        return Err(err(format!(
            "dotnet: artifact digest must be sha512, got {}",
            row.digest.algo()
        )));
    }
    Ok(SdkSpec {
        platform,
        version: row.version,
        url: row.url,
        sha512: row.digest.hex().to_string(),
    })
}

/// The shipped catalog's SDK, for callers with no project selection to
/// honor. Inside a project every caller realizes from the lock instead.
fn shipped_selection() -> io::Result<Selected> {
    crate::kernel::toolchain::shipped(&toolchain_catalog()?)
}

fn sdk_identity(spec: &SdkSpec) -> Identity {
    Identity {
        kind: "dotnet-sdk".into(),
        name: "dotnet-sdk".into(),
        version: spec.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "dotnet-sdk/1".to_string()),
            ("artifact_sha512".to_string(), spec.sha512.clone()),
            ("platform".to_string(), spec.platform.triple().to_string()),
        ]),
    }
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A short fingerprint of the SDK an output tree was built with: published
/// build directories must not be shared across SDK upgrades.
fn sdk_fingerprint_of(spec: &SdkSpec) -> String {
    hex::encode(&Sha256::digest(spec.sha512.as_bytes())[..8])
}

fn nuget_identity(
    plan: &DotnetPlan,
    sdk_id: &str,
    raw_hashes: &BTreeMap<String, String>,
) -> io::Result<Identity> {
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "nuget-packages/1".to_string()),
        ("extractor".to_string(), sdk_id.to_string()),
    ]);
    for p in &plan.packages {
        let key = format!("{}@{}", p.id.to_ascii_lowercase(), p.version);
        inputs.insert(format!("pkg:{key}"), p.content_hash.clone());
        inputs.insert(
            format!("raw:{key}"),
            raw_hashes
                .get(&key)
                .cloned()
                .ok_or_else(|| err(format!("missing raw hash for {key}")))?,
        );
    }
    Ok(Identity {
        kind: "nuget-packages".into(),
        name: "packages".into(),
        version: plan.packages.len().to_string(),
        inputs,
    })
}

/// A spec straight from the compiled pin table: the catalog's own rows, and
/// the fixture the identity goldens are written against.
#[cfg(test)]
fn pin_spec(platform: Platform) -> SdkSpec {
    let pin = sdk_pin(platform).expect("pinned SDK for test platform");
    SdkSpec {
        platform: pin.platform,
        version: SDK_VERSION.to_string(),
        url: pin.url.to_string(),
        sha512: pin.digest.hex().to_string(),
    }
}

/// The shipped default SDK, the object-id golden the identity tests hold:
/// adding a newer SDK to the catalog must not move it.
#[cfg(test)]
const SDK_VERSION: &str = "9.0.317";

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    let sdk = sdk_identity(&pin_spec(platform));
    let empty_plan = DotnetPlan {
        sdk_version: SDK_VERSION.into(),
        project: "app.csproj".into(),
        targets: vec!["net9.0".into()],
        packages: Vec::new(),
    };
    let package = NugetPackage {
        id: "Newtonsoft.Json".into(),
        version: "13.0.3".into(),
        content_hash: "content-hash".into(),
    };
    let package_plan = DotnetPlan {
        packages: vec![package],
        ..empty_plan.clone()
    };
    let raw_hashes = BTreeMap::from([(String::from("newtonsoft.json@13.0.3"), "a".repeat(64))]);
    let nuget_empty = nuget_identity(&empty_plan, &sdk.object_id(), &BTreeMap::new())
        .expect("empty NuGet identity");
    let nuget_package = nuget_identity(&package_plan, &sdk.object_id(), &raw_hashes)
        .expect("NuGet package identity");
    vec![sdk, nuget_empty, nuget_package]
}

/// Ensure the pinned .NET SDK is realized (muxer at <obj>/dotnet).
pub fn ensure_sdk(store: &Store, activity: &StoreActivity) -> io::Result<PathBuf> {
    ensure_sdk_for(store, activity, Platform::host()?)
}

/// The shipped SDK, for callers with no project selection: tests and the
/// host-side work that precedes a project's first sync.
pub fn ensure_sdk_for(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
) -> io::Result<PathBuf> {
    realize_runtime(store, activity, platform, &shipped_selection()?)
}

/// Realize the SDK the selection names: its bytes, its version, its digest.
/// A catalog refresh cannot move a project's SDK, because nothing here
/// reads the pin table.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, ".NET SDK")?;
    let spec = sdk_spec(platform, selected)?;
    let identity = sdk_identity(&spec);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }
    let digest = Digest::sha512(&spec.sha512)?;
    let tarball = download_verified_digest_held(store, activity, &spec.url, &digest)?;
    let staged = store.stage_with_activity(activity)?;
    extract_sdk_archive_for(activity, &tarball, &staged)?;
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(digest);
            deps
        })
        .map(|(path, _)| path)
}

#[cfg(test)]
fn extract_sdk_archive(tarball: &Path, staged: &Path) -> io::Result<()> {
    let st = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .status()?;
    if !st.success() || !staged.join("dotnet").is_file() {
        return Err(err("dotnet SDK extraction failed or has unexpected layout"));
    }
    Ok(())
}

fn extract_sdk_archive_for(
    activity: &StoreActivity,
    tarball: &Path,
    staged: &Path,
) -> io::Result<()> {
    let mut command = Command::new("/usr/bin/tar");
    command.args(["-xzf"]).arg(tarball).args(["-C"]).arg(staged);
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    if !status.success() || !staged.join("dotnet").is_file() {
        return Err(err("dotnet SDK extraction failed or has unexpected layout"));
    }
    Ok(())
}

/// global.json gate: it must name the SELECTED SDK exactly, with
/// rollForward disabled and no redirection. Comparing against the shipped
/// constant would let a catalog refresh start failing locked projects.
/// The project is read through the held descriptor.
pub fn check_global_json(project: &ProjectRoot, sdk_version: &str) -> io::Result<()> {
    let rel = Path::new("global.json");
    if !regular_file_if_present(project, rel, "global.json")? {
        return Ok(());
    }
    let text = read_input_text(project, rel)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| err(format!("global.json: {e}")))?;
    reject_global_redirects(&v, "global.json")?;
    let sdk = v
        .get("sdk")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| err("global.json must contain an sdk object"))?;
    let want = sdk
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| err("global.json sdk.version is required"))?;
    if want != sdk_version {
        return Err(err(format!(
            "global.json requires SDK {want}; pinned: {sdk_version}"
        )));
    }
    if sdk.get("rollForward").and_then(serde_json::Value::as_str) != Some("disable") {
        return Err(err(
            "global.json must set \"rollForward\": \"disable\" (tog pins the SDK exactly)",
        ));
    }
    Ok(())
}

fn reject_global_redirects(value: &serde_json::Value, path: &str) -> io::Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if key == "paths" || key == "msbuild-sdks" {
                    return Err(err(format!(
                        "{path}: {key} is not supported (SDK redirection)"
                    )));
                }
                reject_global_redirects(value, path)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reject_global_redirects(value, path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A project-relative name inspected from the held descriptor without
/// following a symlink (what `symlink_metadata` on its path did).
fn regular_file_if_present(project: &ProjectRoot, rel: &Path, label: &str) -> io::Result<bool> {
    let path = project.path().join(rel);
    match project.entry(rel)? {
        Entry::Symlink => Err(err(format!(
            "{label} must be a regular file, not a symlink: {}",
            path.display()
        ))),
        Entry::Directory | Entry::Other => Err(err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ))),
        Entry::Regular => Ok(true),
        Entry::Absent => Ok(false),
    }
}

/// A project input's text, read through the held descriptor. A file that
/// vanished after its entry was checked reads as NotFound, as
/// `fs::read_to_string` reported it.
fn read_input_text(project: &ProjectRoot, rel: &Path) -> io::Result<String> {
    project.read_input_string(rel)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", project.path().join(rel).display()),
        )
    })
}

const ENV_REMOVE_PREFIXES: &[&str] = &["DOTNET_", "NUGET_", "MSBUILD", "MSBuild", "Msbuild"];
const ENV_REMOVE: &[&str] = &[
    "MSBuildSDKsPath",
    "MSBuildExtensionsPath",
    "RestoreSources",
    "RestoreConfigFile",
    "RestorePackagesPath",
];

fn forced_env(sdk_obj: &Path, packages: &Path, scratch: &Path) -> Vec<(String, String)> {
    vec![
        ("DOTNET_ROOT".to_string(), sdk_obj.display().to_string()),
        ("NUGET_PACKAGES".to_string(), packages.display().to_string()),
        ("DOTNET_CLI_TELEMETRY_OPTOUT".to_string(), "1".to_string()),
        ("DOTNET_NOLOGO".to_string(), "1".to_string()),
        ("DOTNET_CLI_HOME".to_string(), scratch.display().to_string()),
        (
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE".to_string(),
            "1".to_string(),
        ),
        (
            "HOME".to_string(),
            scratch.join("home").display().to_string(),
        ),
        (
            "XDG_CONFIG_HOME".to_string(),
            scratch.join("xdg").display().to_string(),
        ),
        (
            "XDG_CACHE_HOME".to_string(),
            scratch.join("xdg-cache").display().to_string(),
        ),
        (
            "XDG_DATA_HOME".to_string(),
            xdg_data_home(scratch).display().to_string(),
        ),
    ]
}

fn xdg_data_home(scratch: &Path) -> PathBuf {
    scratch.join("xdg-data")
}

/// Create the scratch layout every store-SDK invocation runs against.
///
/// The NuGet migration sentinel is the load-bearing part. NuGet guards its
/// first-run migration with a machine-global named mutex ("NuGet-Migrations"),
/// and tog hands every invocation a fresh home, so without the sentinel
/// every invocation re-runs that migration and contends for that single
/// mutex; concurrent syncs then die inside `Mutex.ReleaseMutex`. A home
/// already marked migrated never takes the mutex, and a directory tog
/// just created has nothing to migrate.
pub(crate) fn prepare_scratch(scratch: &Path) -> io::Result<()> {
    fs::create_dir_all(scratch.join("home"))?;
    let migrations = xdg_data_home(scratch).join("NuGet").join("Migrations");
    fs::create_dir_all(&migrations)?;
    fs::write(migrations.join("1"), "")
}

/// Env for `tog run`. Build-capable verbs are REJECTED at run: they
/// execute arbitrary MSBuild code and are sandbox-only. This env is for
/// `dotnet <app.dll>`, --version/--info, and compiled-app execution.
pub fn run_env(
    sdk_obj: &Path,
    packages: &Path,
    scratch: &Path,
) -> (Vec<&'static str>, Vec<&'static str>, Vec<(String, String)>) {
    (
        ENV_REMOVE_PREFIXES.to_vec(),
        ENV_REMOVE.to_vec(),
        forced_env(sdk_obj, packages, scratch),
    )
}

pub const BUILD_VERBS: &[&str] = &[
    "build", "run", "test", "publish", "pack", "msbuild", "restore", "clean", "watch",
];

/// `tog run`'s guard is advisory: wrappers can bypass it. During
/// realization and build, tog never evaluates project code outside the
/// build sandbox. Missing-lock lock generation is the explicit host-side
/// exception: config and environment are pinned, but project MSBuild code
/// runs on the host.
pub fn refused_run_command(cmd: &[String]) -> Option<String> {
    if cmd.first().map(String::as_str) != Some("dotnet") {
        return None;
    }
    let (verb_index, verb) = cmd[1..]
        .iter()
        .enumerate()
        .find(|(_, arg)| !arg.starts_with('-'))
        .map(|(i, arg)| (i + 1, arg.as_str()))?;
    if BUILD_VERBS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(verb))
    {
        return Some(format!(
            "`dotnet {verb}` compiles/executes MSBuild code and must run sandboxed: use `tog build dotnet ...`"
        ));
    }
    if verb.eq_ignore_ascii_case("exec")
        && cmd[verb_index + 1..].iter().any(|arg| {
            Path::new(arg)
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.eq_ignore_ascii_case("MSBuild.dll"))
                .unwrap_or(false)
        })
    {
        return Some(
            "`dotnet exec .../MSBuild.dll` executes MSBuild code and must run sandboxed: use `tog build dotnet ...`"
                .to_string(),
        );
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NugetPackage {
    pub id: String,
    pub version: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotnetPlan {
    pub sdk_version: String,
    pub project: String,
    /// Full lock target matrix retained for provenance (TFM and TFM/RID).
    pub targets: Vec<String>,
    pub packages: Vec<NugetPackage>,
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        && !s.starts_with('.')
        && !s.contains("..")
}

fn target_framework(target: &str) -> io::Result<&str> {
    let tfm = target.split('/').next().unwrap_or("");
    if tfm.is_empty()
        || !tfm
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return Err(err(format!("invalid lock target framework: {target}")));
    }
    Ok(tfm)
}

fn validate_plan(plan: &DotnetPlan, sdk_version: &str) -> io::Result<()> {
    if plan.sdk_version != sdk_version {
        return Err(err(format!(
            "plan requires SDK {}; pinned: {sdk_version}",
            plan.sdk_version
        )));
    }
    if plan.targets.is_empty() {
        return Err(err("packages.lock.json has no target frameworks"));
    }
    let mut base_tfms = std::collections::BTreeSet::new();
    for target in &plan.targets {
        base_tfms.insert(target_framework(target)?);
    }
    if base_tfms.len() > 1 {
        return Err(err(
            "multi-targeted locks are unsupported in v0; use a single TargetFramework",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for p in &plan.packages {
        if !valid_id(&p.id) || !valid_id(&p.version) {
            return Err(err(format!("invalid package coordinates: {p:?}")));
        }
        // contentHash: base64 sha512 (88 chars with padding).
        if p.content_hash.len() > 100
            || !p
                .content_hash
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return Err(err(format!("{}: invalid contentHash", p.id)));
        }
        if !seen.insert((p.id.to_ascii_lowercase(), p.version.clone())) {
            return Err(err(format!("duplicate package {}@{}", p.id, p.version)));
        }
    }
    Ok(())
}

/// The names in the project root, listed through the held descriptor. A
/// root that went away reads as NotFound, as `fs::read_dir` reported it.
fn root_names(project: &ProjectRoot) -> io::Result<Vec<std::ffi::OsString>> {
    project.read_input_dir(Path::new("."))?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", project.path().display()),
        )
    })
}

/// Locate the single .csproj (v0 boundary: one SDK-style project, no sln).
/// Returns its project-relative name; the root is listed through the held
/// descriptor.
pub fn find_project(project: &ProjectRoot) -> io::Result<PathBuf> {
    let mut found = Vec::new();
    for name in root_names(project)? {
        let path = PathBuf::from(name);
        let name = path.to_str().unwrap_or("");
        if name.ends_with(".sln") || name.ends_with(".slnx") {
            return Err(err(
                "solution files are not supported yet; sync a single project",
            ));
        }
        if name.ends_with(".csproj") {
            found.push(path);
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(err("no .csproj found")),
        _ => Err(err(
            "multiple .csproj files; tog supports one project per directory in v0",
        )),
    }
}

/// Directory-read failures propagate: guessing "no dotnet here" would hide
/// them, and guessing "dotnet present" would trigger SDK realization first.
/// The project is read through the held descriptor.
pub fn has_marker(project: &ProjectRoot) -> io::Result<bool> {
    for name in root_names(project)? {
        let name = name.to_string_lossy();
        if name.ends_with(".csproj") || name.ends_with(".sln") || name.ends_with(".slnx") {
            return Ok(true);
        }
    }
    let present = |rel: &str| {
        matches!(
            project.entry(Path::new(rel)),
            Ok(Entry::Regular | Entry::Directory | Entry::Symlink | Entry::Other)
        )
    };
    Ok(present(LOCK_FILE) || present(".tog/closures/dotnet.json"))
}

/// MSBuild elements a csproj may not contain, each because it breaks what
/// the tailor relies on: the lock is the only package authority, the
/// project is this one file, and every write lands in scratch.
const BLOCKED_ELEMENTS: &[(&str, &str)] = &[
    (
        "Import",
        "pulls in targets and props outside the validated project file",
    ),
    ("Sdk", "adds an MSBuild SDK other than Microsoft.NET.Sdk"),
    ("UsingTask", "loads task assemblies outside the SDK"),
    (
        "PackageDownload",
        "downloads packages the lock does not name",
    ),
    (
        "ProjectReference",
        "builds another project tog has not validated",
    ),
    (
        "RestoreSources",
        "points restore at feeds other than the projected packages",
    ),
    (
        "RestorePackagesPath",
        "moves the package folder away from the projected packages",
    ),
    (
        "MSBuildProjectExtensionsPath",
        "moves restore output away from scratch obj",
    ),
    ("BaseIntermediateOutputPath", "moves obj away from scratch"),
    ("IntermediateOutputPath", "moves obj away from scratch"),
    ("BaseOutputPath", "moves build output away from scratch"),
    ("OutputPath", "moves build output away from scratch"),
];

/// The csproj text with every comment and CDATA section replaced by a
/// space. Both hold character data, never markup, so what remains is what
/// MSBuild reads as elements and attributes. An unterminated section is a
/// refusal: MSBuild would reject the file, and the rest cannot be scanned.
fn strip_comments_and_cdata(text: &str, path: &Path) -> io::Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let comment = rest.find("<!--");
        let cdata = rest.find("<![CDATA[");
        let (at, open, close, what) = match (comment, cdata) {
            (Some(c), Some(d)) if d < c => (d, "<![CDATA[".len(), "]]>", "CDATA section"),
            (Some(c), _) => (c, "<!--".len(), "-->", "XML comment"),
            (None, Some(d)) => (d, "<![CDATA[".len(), "]]>", "CDATA section"),
            (None, None) => break,
        };
        out.push_str(&rest[..at]);
        out.push(' ');
        let body = &rest[at + open..];
        let end = body
            .find(close)
            .ok_or_else(|| err(format!("{}: unterminated {what}", path.display())))?;
        rest = &body[end + close.len()..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Does `markup` (lowercase, comments stripped) open an element named
/// `name` (lowercase)? The name must end at whitespace, `>` or `/`, so
/// `<OutputPath` matches `<OutputPath>`, `<OutputPath Condition=...>` and
/// `<OutputPath/>` but not `<AppendTargetFrameworkToOutputPath>`.
fn opens_element(markup: &str, name: &str) -> bool {
    let tag = format!("<{name}");
    markup.match_indices(&tag).any(|(at, _)| {
        markup
            .as_bytes()
            .get(at + tag.len())
            .map(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
            .unwrap_or(false)
    })
}

/// The quoted values of every `attribute=` in `markup` (lowercase, comments
/// stripped), where `attribute` is a whole name. An unquoted value is an
/// error: well-formed XML always quotes, and the scan must not guess.
fn attribute_values<'a>(markup: &'a str, attribute: &str, path: &Path) -> io::Result<Vec<&'a str>> {
    let bytes = markup.as_bytes();
    let mut values = Vec::new();
    let mut at = 0;
    while let Some(found) = markup[at..].find(attribute) {
        let start = at + found;
        let before_ok = start == 0 || !is_name_byte(bytes[start - 1]);
        let mut i = start + attribute.len();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if !before_ok || i >= bytes.len() || bytes[i] != b'=' {
            at = start + attribute.len();
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || !matches!(bytes[i], b'"' | b'\'') {
            return Err(err(format!(
                "{}: {attribute} attribute must be quoted",
                path.display()
            )));
        }
        let quote = bytes[i];
        let value_start = i + 1;
        let end = bytes[value_start..]
            .iter()
            .position(|b| *b == quote)
            .map(|offset| value_start + offset)
            .ok_or_else(|| {
                err(format!(
                    "{}: unterminated {attribute} attribute",
                    path.display()
                ))
            })?;
        values.push(&markup[value_start..end]);
        at = end + 1;
    }
    Ok(values)
}

/// Does `b` join the name before an attribute? The boundary keeps `sdk=`
/// from matching inside `MySdk=`; punctuation such as `-`, `.` and `:`
/// counts as a boundary so that anything resembling the name is checked.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Validate a project-relative csproj, read through the held descriptor.
///
/// Matching is on whole element and attribute names, case-insensitively,
/// with comments and CDATA removed first; entity references cannot encode
/// names, so a well-formed file cannot hide one. The scan is an early,
/// named refusal: the sandbox (network denied, writes confined to scratch)
/// is what holds the boundary when a build step does something the scan
/// does not model.
fn validate_csproj(project: &ProjectRoot, rel: &Path) -> io::Result<()> {
    let text = read_input_text(project, rel)?;
    let path = project.path().join(rel);
    let path = path.as_path();
    let markup = strip_comments_and_cdata(&text, path)?.to_ascii_lowercase();
    let mut document = markup
        .strip_prefix('\u{feff}')
        .unwrap_or(&markup)
        .trim_start();
    if document.starts_with("<?xml")
        && document
            .as_bytes()
            .get(5)
            .map(|b| b.is_ascii_whitespace())
            .unwrap_or(false)
    {
        let end = document
            .find("?>")
            .ok_or_else(|| err(format!("{}: unterminated XML declaration", path.display())))?;
        document = document[end + 2..].trim_start();
    }
    // The root must be exactly <Project (word-bounded: <Projector/> is not).
    let root_ok = document.starts_with("<project")
        && document
            .as_bytes()
            .get(8)
            .map(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
            .unwrap_or(false);
    if !root_ok {
        return Err(err(format!(
            "{}: not a supported project file (expected <Project root)",
            path.display()
        )));
    }
    for (name, why) in BLOCKED_ELEMENTS {
        if opens_element(&markup, &name.to_ascii_lowercase()) {
            return Err(err(format!(
                "{}: unsupported MSBuild/project feature <{name}>: it {why}",
                path.display()
            )));
        }
    }
    // tog overrides the output and intermediate paths as global properties
    // on the command line, which a project cannot reassign unless it names
    // them in TreatAsLocalProperty.
    if !attribute_values(&markup, "treataslocalproperty", path)?.is_empty() {
        return Err(err(format!(
            "{}: unsupported MSBuild/project feature TreatAsLocalProperty: it lets the \
             project override the paths tog sets on the command line",
            path.display()
        )));
    }
    // A task's <Output> creates items and properties by name, the same as
    // the blocked elements would.
    for attribute in ["itemname", "propertyname"] {
        for value in attribute_values(&markup, attribute, path)? {
            let value = value.trim();
            if let Some((name, why)) = BLOCKED_ELEMENTS
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(value))
            {
                return Err(err(format!(
                    "{}: unsupported MSBuild/project feature {name} created by a task: it {why}",
                    path.display()
                )));
            }
        }
    }
    for value in attribute_values(&markup, "sdk", path)? {
        if value != "microsoft.net.sdk" {
            return Err(err(format!(
                "{}: only Microsoft.NET.Sdk is supported",
                path.display()
            )));
        }
    }
    Ok(())
}

/// What a v1 packages.lock.json pins: its targets in lock order and one
/// package per case-insensitive id and version, sorted by that key.
struct ParsedLock {
    targets: Vec<String>,
    packages: Vec<NugetPackage>,
}

/// The one reader of packages.lock.json: preflight and planning both call
/// it, so every refusal of a lock has one text and a lock preflight accepts
/// is one planning can use.
fn parse_lock(text: &str) -> io::Result<ParsedLock> {
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| err(format!("packages.lock.json: {e}")))?;
    if v["version"] != 1 {
        return Err(err(format!(
            "packages.lock.json version {} unsupported (v1 only in v0; \
             Central Package Management locks are v2+)",
            v["version"]
        )));
    }
    let deps = v["dependencies"]
        .as_object()
        .ok_or_else(|| err("packages.lock.json has no dependencies"))?;
    let mut targets = Vec::new();
    let mut packages: BTreeMap<(String, String), NugetPackage> = BTreeMap::new();
    for (target, entries) in deps {
        targets.push(target.clone());
        let entries = entries
            .as_object()
            .ok_or_else(|| err(format!("bad lock target {target}")))?;
        for (id, e) in entries {
            match e["type"].as_str() {
                Some("Direct") | Some("Transitive") => {}
                Some("Project") => {
                    return Err(err(format!(
                    "{id}: Project lock entries are not supported; use package dependencies only"
                )))
                }
                Some(kind) => {
                    return Err(err(format!(
                    "{id}: unsupported lock dependency type {kind}; expected Direct or Transitive"
                )))
                }
                None => {
                    return Err(err(format!(
                        "{id}: unsupported lock dependency type {}; expected Direct or Transitive",
                        e["type"]
                    )))
                }
            }
            let version = e["resolved"]
                .as_str()
                .ok_or_else(|| err(format!("{id}: no resolved version")))?;
            let hash = e["contentHash"]
                .as_str()
                .ok_or_else(|| err(format!("{id}: no contentHash")))?;
            let key = (id.to_ascii_lowercase(), version.to_string());
            let pkg = NugetPackage {
                id: id.clone(),
                version: version.to_string(),
                content_hash: hash.to_string(),
            };
            if let Some(prev) = packages.get(&key) {
                if prev.content_hash != pkg.content_hash {
                    return Err(err(format!(
                        "{id}@{version}: conflicting contentHash across lock targets"
                    )));
                }
            } else {
                packages.insert(key, pkg);
            }
        }
    }
    Ok(ParsedLock {
        targets,
        packages: packages.into_values().collect(),
    })
}

/// Central v0 trust-boundary validation. The tuple is the canonical project
/// file and its lock path (the latter may not exist until delegated planning).
///
/// Project files are read through the held descriptor (a held root is a
/// directory by construction); the returned paths are for messages and
/// child-process arguments. Ancestors lie outside the project and are
/// still inspected by path.
pub fn preflight(project: &ProjectRoot, sdk_version: &str) -> io::Result<(PathBuf, PathBuf)> {
    let project_dir = project.path();
    let csproj_rel = find_project(project)?;
    let csproj = project_dir.join(&csproj_rel);
    if !regular_file_if_present(project, &csproj_rel, "csproj")? {
        return Err(err(format!("csproj is missing: {}", csproj.display())));
    }
    validate_csproj(project, &csproj_rel)?;

    let lock_rel = Path::new(LOCK_FILE);
    let lock_path = project_dir.join(lock_rel);
    regular_file_if_present(project, lock_rel, "packages.lock.json")?;
    regular_file_if_present(project, Path::new("global.json"), "global.json")?;
    check_global_json(project, sdk_version)?;

    for (depth, ancestor) in project_dir.ancestors().enumerate() {
        for name in [
            "Directory.Packages.props",
            "Directory.Build.rsp",
            "packages.config",
        ] {
            // The project itself through the descriptor, its ancestors
            // (outside the project) by path.
            let present = if depth == 0 {
                project
                    .entry(Path::new(name))
                    .map(|entry| entry != Entry::Absent)
            } else {
                path_present(&ancestor.join(name))
            };
            match present {
                Ok(true) => {
                    return Err(err(format!(
                        "{name} is not supported in the project or an SDK ancestor: {}",
                        ancestor.join(name).display()
                    )))
                }
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }
        if depth > 0 {
            match path_present(&ancestor.join("global.json")) {
                Ok(true) => {
                    return Err(err(format!(
                        "ancestor global.json is not supported; SDK discovery would see {}",
                        ancestor.join("global.json").display()
                    )))
                }
                Ok(false) => {}
                Err(e) => return Err(e),
            }
        }
    }
    if project.is_input_file(lock_rel) {
        parse_lock(&read_input_text(project, lock_rel)?)?;
    }
    Ok((csproj, lock_path))
}

const LOCK_FILE: &str = "packages.lock.json";

/// Does a path outside the project name anything (`symlink_metadata`)?
fn path_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// The lock every plan reads, or the refusal that names it: `prepare`
/// generates it, and the command layer skips `prepare` under `--frozen`.
/// Checked before any toolchain is realized, so a frozen sync of an
/// unlocked project fails without a download.
pub fn require_lock(project: &ProjectRoot) -> io::Result<()> {
    if project.is_input_file(Path::new(LOCK_FILE)) {
        Ok(())
    } else {
        Err(crate::tailors::missing_lock(project, LOCK_FILE))
    }
}

/// `prepare`: packages.lock.json, written by a store-SDK `restore
/// --use-lock-file` (named resolver mutation, isolated caches) when there
/// is none. The one place the .NET tailor writes project inputs. The
/// restore child runs in the project's path.
pub fn generate_lock(
    store: &Store,
    activity: &StoreActivity,
    project: &ProjectRoot,
    sdk_obj: &Path,
    selected: &Selected,
) -> io::Result<()> {
    let sdk_version = selected.version("dotnet-sdk")?.to_string();
    preflight(project, &sdk_version)?;
    ui::note("no packages.lock.json; resolving with the store SDK...");
    let scratch = store.stage_with_activity(activity)?;
    let config = scratch.join("nuget.config");
    fs::write(
        &config,
        "<configuration><packageSources><clear /><add key=\"nuget.org\" \
         value=\"https://api.nuget.org/v3/index.json\" protocolVersion=\"3\" />\
         </packageSources></configuration>",
    )?;
    let config = config.canonicalize()?;
    let config_arg = config.to_string_lossy().into_owned();
    let out = run_dotnet(
        activity,
        sdk_obj,
        project.path(),
        &scratch.join("pkgs"),
        &scratch,
        &["restore", "--use-lock-file", "--configfile", &config_arg],
    )?;
    let ok = out.status.success();
    let _ = crate::kernel::store::remove_tree(&scratch);
    if !ok {
        return Err(err(format!(
            "store dotnet restore --use-lock-file failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Plan from packages.lock.json (v1 only; tog makes the opt-in lock
/// mandatory). The project is read through the held descriptor.
pub fn plan_dotnet(project: &ProjectRoot, selected: &Selected) -> io::Result<(DotnetPlan, String)> {
    let lock_rel = Path::new(LOCK_FILE);
    let sdk_version = selected.version("dotnet-sdk")?.to_string();
    let (csproj, _) = preflight(project, &sdk_version)?;
    require_lock(project)?;
    let lock = read_input_text(project, lock_rel)?;
    let ParsedLock { targets, packages } = parse_lock(&lock)?;
    let plan = DotnetPlan {
        // The SDK this plan was restored under is the selected one.
        sdk_version: sdk_version.clone(),
        project: csproj
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("project")
            .to_string(),
        targets,
        packages,
    };
    validate_plan(&plan, &sdk_version)?;
    let now = read_input_text(project, lock_rel)?;
    if now != lock {
        return Err(err(
            "packages.lock.json changed while planning; re-run 'tog'",
        ));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes()))))
}

fn run_dotnet(
    activity: &StoreActivity,
    sdk_obj: &Path,
    cwd: &Path,
    packages: &Path,
    scratch: &Path,
    args: &[&str],
) -> io::Result<std::process::Output> {
    // Host-only resolver path: currently used for missing-lock delegation;
    // SDK probing does not use this helper. Realization uses run_build_spec.
    fs::create_dir_all(packages)?;
    fs::create_dir_all(scratch)?;
    let home = scratch.join("home");
    prepare_scratch(scratch)?;
    let mut cmd = Command::new(sdk_obj.join("dotnet"));
    cmd.args(args).current_dir(cwd).env_clear();
    cmd.env("PATH", format!("{}:/usr/bin:/bin", sdk_obj.display()));
    cmd.env("TMPDIR", scratch).env("HOME", &home);
    force_env(
        &mut cmd,
        ENV_REMOVE_PREFIXES,
        ENV_REMOVE,
        &forced_env(sdk_obj, packages, scratch),
    );
    cmd.stdin(std::process::Stdio::null());
    crate::kernel::supervise::output(&mut cmd, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run store dotnet {args:?}: {e}")))
}

fn synthetic_csproj(plan: &DotnetPlan, tfm: &str) -> String {
    let refs = plan
        .packages
        .iter()
        .map(|p| {
            format!(
                "    <PackageReference Include=\"{}\" Version=\"[{}]\" />\n",
                p.id, p.version
            )
        })
        .collect::<String>();
    format!(
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
         <TargetFramework>{tfm}</TargetFramework>\n    \
         <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n    \
         <NoAutoResponse>true</NoAutoResponse>\n  </PropertyGroup>\n  \
         <ItemGroup>\n{refs}  </ItemGroup>\n</Project>\n"
    )
}

fn synthetic_lock(plan: &DotnetPlan, tfm: &str) -> serde_json::Value {
    let entries = plan
        .packages
        .iter()
        .map(|p| {
            (
                p.id.clone(),
                serde_json::json!({
                    "type": "Direct",
                    "requested": format!("[{}]", p.version),
                    "resolved": p.version,
                    "contentHash": p.content_hash,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    serde_json::json!({
        "version": 1,
        "dependencies": { tfm: entries },
    })
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn rewrite_metadata_source(path: &Path) -> io::Result<()> {
    let text = fs::read_to_string(path)?;
    let mut value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        err(format!(
            "{}: invalid .nupkg.metadata JSON: {e}",
            path.display()
        ))
    })?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            err(format!(
                "{}: .nupkg.metadata is not an object",
                path.display()
            ))
        })?
        .insert(
            "source".to_string(),
            serde_json::Value::String("tog-feed".to_string()),
        );
    fs::write(path, serde_json::to_vec(&value)?)
}

/// Realize the global-packages object: tog fetches every nupkg into a
/// local folder feed (raw bytes cached by sha256), then the PINNED NuGet
/// installs from that feed in LOCKED mode — it verifies each package's
/// semantic contentHash against the lock and writes the exact
/// global-packages layout (.nupkg.sha512/.nupkg.metadata/nuspec). The SDK
/// is the extractor, so its full store object id is an identity input (Go
/// precedent). Network denied at install: the feed is local.
pub fn realize_packages(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    plan: &DotnetPlan,
    sdk_obj: &Path,
    project: &ProjectRoot,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, ".NET packages")?;
    let spec = sdk_spec(platform, selected)?;
    let _ = preflight(project, &spec.version)?;
    validate_plan(plan, &spec.version)?;
    let sdk_obj = sdk_obj.canonicalize()?;
    // Fetch every nupkg (nuget.org flatcontainer only in v0). No upfront
    // per-file hash exists (contentHash is semantic): download to tmp,
    // record raw sha256 via cache_insert, verify semantically below.
    let scratch = store.stage_with_activity(activity)?;
    let feed = scratch.join("feed");
    fs::create_dir_all(&feed)?;
    let mut raw_hashes = BTreeMap::new();
    for p in &plan.packages {
        let idl = p.id.to_ascii_lowercase();
        let verl = p.version.to_ascii_lowercase();
        let url = format!("https://api.nuget.org/v3-flatcontainer/{idl}/{verl}/{idl}.{verl}.nupkg");
        let tmp = scratch.join(format!("{idl}.{verl}.nupkg"));
        let agent = ureq::AgentBuilder::new().https_only(true).build();
        let resp = agent
            .get(&url)
            .call()
            .map_err(|e| err(format!("{}: GET {url}: {e}", p.id)))?;
        let mut file = fs::File::create(&tmp)?;
        use std::io::Read;
        let mut reader = resp.into_reader().take(1 << 30);
        io::copy(&mut reader, &mut file)?;
        let (raw_sha256, _) = cache_insert(store, activity, &tmp)?;
        raw_hashes.insert(format!("{}@{}", idl, p.version), raw_sha256);
        fs::rename(&tmp, feed.join(format!("{idl}.{verl}.nupkg")))?;
    }

    let sdk_id = sdk_obj
        .canonicalize()?
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| err("pinned SDK object has no UTF-8 store id"))?
        .to_string();
    let identity = nuget_identity(plan, &sdk_id, &raw_hashes)?;
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        let _ = crate::kernel::store::remove_tree(&scratch);
        return Ok(store.object_path(&id));
    }

    // Locked-mode restore from a synthetic project into the staged folder:
    // the user's project and global.json are never evaluated in realization.
    let staged = store.stage_with_activity(activity)?;
    let verifier = scratch.join("verifier");
    fs::create_dir_all(&verifier)?;
    prepare_scratch(&scratch)?;
    let tfm = target_framework(
        plan.targets
            .first()
            .ok_or_else(|| err("plan has no target framework"))?,
    )?;
    if plan.targets.len() > 1 {
        ui::note(&format!(
            "synthetic NuGet verifier uses the first TFM/RID lock target: {tfm}"
        ));
    }
    fs::write(
        verifier.join("tog-verifier.csproj"),
        synthetic_csproj(plan, tfm),
    )?;
    fs::write(
        verifier.join("packages.lock.json"),
        serde_json::to_vec_pretty(&synthetic_lock(plan, tfm))?,
    )?;
    fs::write(
        verifier.join("nuget.config"),
        format!(
            "<configuration><packageSources><clear /><add key=\"tog-feed\" \
             value=\"{}\" /></packageSources><config><add key=\"updatePackageLastAccessTime\" \
             value=\"false\" /></config></configuration>",
            xml_escape(&feed.display().to_string())
        ),
    )?;
    let config = verifier.join("nuget.config").canonicalize()?;
    let result = crate::kernel::sandbox::run_build_spec_on_with_activity(
        platform,
        &BuildSpec {
            argv: vec![
                sdk_obj.join("dotnet").display().to_string(),
                "restore".to_string(),
                "--locked-mode".to_string(),
                "--no-cache".to_string(),
                "--disable-build-servers".to_string(),
                "--configfile".to_string(),
                config.display().to_string(),
                "-noAutoResponse".to_string(),
            ],
            cwd: verifier.clone(),
            env: forced_env(&sdk_obj, &staged, &scratch),
            read: vec![sdk_obj.to_path_buf(), feed.clone(), verifier.clone()],
            write: dotnet_write_roots(platform, vec![staged.clone()])?,
            scratch: scratch.clone(),
            path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
        },
        activity,
    );
    if let Err(e) = result {
        let _ = crate::kernel::store::remove_tree(&scratch);
        let _ = crate::kernel::store::remove_tree(&staged);
        return Err(io::Error::new(
            e.kind(),
            format!("locked-mode package verification failed: {e}"),
        ));
    }
    // Every locked package must have materialized with its completion
    // marker; anything missing means the lock and feed disagree.
    for p in &plan.packages {
        let dir = staged
            .join(p.id.to_ascii_lowercase())
            .join(p.version.to_ascii_lowercase());
        if !dir.join(".nupkg.metadata").is_file() {
            let _ = crate::kernel::store::remove_tree(&scratch);
            let _ = crate::kernel::store::remove_tree(&staged);
            return Err(err(format!(
                "{}@{}: not materialized by locked restore",
                p.id, p.version
            )));
        }
        if let Err(e) = rewrite_metadata_source(&dir.join(".nupkg.metadata")) {
            let _ = crate::kernel::store::remove_tree(&scratch);
            let _ = crate::kernel::store::remove_tree(&staged);
            return Err(e);
        }
    }
    let _ = crate::kernel::store::remove_tree(&scratch);
    let mut deps = crate::kernel::store::ObjectDeps::new();
    deps.object_id(&crate::kernel::store::object_id_from_path(&sdk_obj)?)?;
    for raw_sha256 in raw_hashes.values() {
        deps.cache_digest(Digest::sha256(raw_sha256)?);
    }
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &deps)
        .map(|(path, _)| path)
}

pub fn project_dotnet_env(
    activity: &StoreActivity,
    project: &ProjectRoot,
    sdk_obj: &Path,
    packages_obj: &Path,
    plan: &DotnetPlan,
    lock_sha256: &str,
    selected: &Selected,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    let sdk_obj = sdk_obj.canonicalize()?;
    let packages_obj = packages_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&sdk_obj)
        .ok_or_else(|| err(".NET SDK object is not in a Tog store"))?;
    let mut refs = crate::comforter::ClosureRefs::new();
    refs.object_path(&store, activity, &sdk_obj)?;
    refs.object_path(&store, activity, &packages_obj)?;
    crate::comforter::write_closure(
        project,
        "dotnet",
        closure_body(&sdk_obj, &packages_obj, plan, lock_sha256, selected)?,
        &store,
        activity,
        refs,
        attribution,
    )
}

/// The .NET closure body: the projection's objects and plan, plus the
/// toolchain record that says which selection realized them. The SDK object
/// is this ecosystem's runtime, and `project_dotnet_env` already holds it as
/// a direct ref, so GC keeps it alive by the recorded id.
fn closure_body(
    sdk_obj: &Path,
    packages_obj: &Path,
    plan: &DotnetPlan,
    lock_sha256: &str,
    selected: &Selected,
) -> io::Result<serde_json::Value> {
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err(format!("object path has no UTF-8 id: {}", path.display())))?;
        Ok(serde_json::json!({"path": path.display().to_string(), "id": id}))
    };
    let mut body = serde_json::json!({
        "sdk_object": object_ref(sdk_obj)?,
        "packages_object": object_ref(packages_obj)?,
        "packages_lock_sha256": lock_sha256,
        "plan": plan,
    });
    let record = crate::comforter::toolchain::closure_record(selected, sdk_obj);
    if let (Some(body), Some(record)) = (body.as_object_mut(), record.as_object()) {
        for (key, value) in record {
            body.insert(key.clone(), value.clone());
        }
    }
    Ok(body)
}

fn dotnet_tmp_path(platform: Platform) -> PathBuf {
    if platform.is_macos() {
        PathBuf::from("/private/tmp/.dotnet")
    } else {
        PathBuf::from("/tmp/.dotnet")
    }
}

// Reviewed site (tests/architecture.rs): host probe (`id -u`); no store.
#[allow(clippy::disallowed_methods)]
fn invoking_uid() -> io::Result<u32> {
    let uid = Command::new("/usr/bin/id").arg("-u").output()?.stdout;
    String::from_utf8(uid)
        .map_err(|_| err("could not determine current uid"))?
        .trim()
        .parse::<u32>()
        .map_err(|_| err("could not determine current uid"))
}

fn ensure_dotnet_tmp_at(
    path: &Path,
    expected_uid: u32,
    precreate_shm: bool,
) -> io::Result<PathBuf> {
    let created = match fs::symlink_metadata(&path) {
        Ok(md) => {
            if md.file_type().is_symlink() || !md.is_dir() {
                return Err(err(format!(
                    "{} must be a real directory, not a symlink or non-directory",
                    path.display()
                )));
            }
            false
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Two tog processes may race here (concurrent syncs share
            // this directory by design); losing the race is fine, the
            // validation below still applies to whatever now exists.
            match fs::create_dir(&path) {
                Ok(()) => true,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => false,
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };
    if created {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    let md = fs::symlink_metadata(&path)?;
    if md.file_type().is_symlink() || !md.is_dir() {
        return Err(err(format!(
            "{} must be a real directory, not a symlink or non-directory",
            path.display()
        )));
    }
    if md.uid() != expected_uid {
        return Err(err(format!(
            "{} is owned by uid {}, current uid is {expected_uid}",
            path.display(),
            md.uid(),
        )));
    }
    if path.canonicalize()? != path {
        return Err(err(format!(
            "{} does not canonicalize to the required path",
            path.display()
        )));
    }
    if precreate_shm {
        // Both platforms and both sandbox backends: CoreCLR creates `shm` by
        // mkdtemp()-ing `/tmp/.coreclr.XXXXXX`
        // and rename()-ing it into place. Inside the bwrap sandbox /tmp is
        // a private tmpfs and this directory a separate bind mount, so the
        // rename fails with EXDEV; under Seatbelt only this directory is
        // writable, not /tmp itself, so the mkdtemp fails with EPERM. Either
        // way every NuGet/MSBuild named mutex ("NuGet-Migrations") errors
        // out. macOS periodically purges /private/tmp, so `shm` cannot be
        // assumed to survive from an earlier run. Creating it here, owned by
        // us with the runtime's expected 0700, lets CoreCLR skip that path.
        let shm = path.join("shm");
        match fs::symlink_metadata(&shm) {
            Ok(md) if md.file_type().is_symlink() || !md.is_dir() => {
                return Err(err(format!(
                    "{} must be a real directory, not a symlink or non-directory",
                    shm.display()
                )));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => match fs::create_dir(&shm) {
                Ok(()) => fs::set_permissions(&shm, fs::Permissions::from_mode(0o700))?,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
    Ok(path.to_path_buf())
}

fn ensure_dotnet_tmp(platform: Platform) -> io::Result<PathBuf> {
    let path = dotnet_tmp_path(platform);
    ensure_dotnet_tmp_at(&path, invoking_uid()?, true)
}

fn add_dotnet_tmp_write_root(mut roots: Vec<PathBuf>, dotnet_tmp: PathBuf) -> Vec<PathBuf> {
    roots.push(dotnet_tmp);
    roots
}

fn dotnet_write_roots(platform: Platform, roots: Vec<PathBuf>) -> io::Result<Vec<PathBuf>> {
    Ok(add_dotnet_tmp_write_root(
        roots,
        ensure_dotnet_tmp(platform)?,
    ))
}

fn validate_build_args(args: &[String]) -> io::Result<()> {
    let mut i = 0;
    while i < args.len() {
        let lower = args[i].to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "-c" | "--configuration" | "-v" | "--verbosity" | "-f" | "--framework"
        ) {
            if i + 1 == args.len() || args[i + 1].starts_with('-') || args[i + 1].starts_with('@') {
                return Err(err(format!("{}: missing option value", args[i])));
            }
            i += 2;
            continue;
        }
        if matches!(lower.as_str(), "--no-incremental" | "-warnaserror")
            || lower.starts_with("-p:configuration=")
            || lower.starts_with("-p:treatwarningsaserrors=")
        {
            i += 1;
            continue;
        }
        return Err(err(format!(
            "{}: not allowed for sandboxed dotnet build",
            args[i]
        )));
    }
    Ok(())
}

fn checked_output_dir(project_dir: &Path, fingerprint: &str) -> io::Result<PathBuf> {
    let project_dir = project_dir.canonicalize()?;
    let bin = project_dir.join("bin");
    if let Ok(md) = fs::symlink_metadata(&bin) {
        if md.file_type().is_symlink() {
            return Err(err(format!("{} must not be a symlink", bin.display())));
        }
        if !md.is_dir() {
            return Err(err(format!("{} must be a directory", bin.display())));
        }
    }
    let output = bin.join(format!("tog-{fingerprint}"));
    if let Ok(md) = fs::symlink_metadata(&output) {
        if md.file_type().is_symlink() {
            return Err(err(format!("{} must not be a symlink", output.display())));
        }
        if !md.is_dir() {
            return Err(err(format!("{} must be a directory", output.display())));
        }
    }
    fs::create_dir_all(&bin)?;
    let canonical_bin = bin.canonicalize()?;
    if !canonical_bin.starts_with(&project_dir) {
        return Err(err(format!("{} escapes the project", bin.display())));
    }
    if output.exists() && !output.canonicalize()?.starts_with(&project_dir) {
        return Err(err(format!("{} escapes the project", output.display())));
    }
    Ok(output)
}

fn publish_output(
    staged: &Path,
    project_dir: &Path,
    platform: Platform,
    fingerprint: &str,
    activity: Option<&StoreActivity>,
) -> io::Result<PathBuf> {
    let output = checked_output_dir(project_dir, fingerprint)?;
    let bin = output
        .parent()
        .ok_or_else(|| err("output directory has no bin parent"))?;
    let new = bin.join(format!(".tog-{fingerprint}.new.{}", std::process::id()));
    let old = bin.join(format!(".tog-{fingerprint}.old.{}", std::process::id()));
    for path in [&new, &old] {
        if fs::symlink_metadata(path).is_ok() {
            return Err(err(format!(
                "temporary output already exists: {}",
                path.display()
            )));
        }
    }
    match fs::rename(staged, &new) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(18) => {
            let cloned = match activity {
                Some(activity) => {
                    crate::kernel::store::clone_tree_with_activity(activity, staged, &new, platform)
                }
                None => crate::comforter::clone_tree_for(staged, &new, platform),
            };
            if let Err(clone_error) = cloned {
                let _ = crate::kernel::store::remove_tree(&new);
                return Err(io::Error::new(
                    clone_error.kind(),
                    format!("publish {}: {clone_error}", output.display()),
                ));
            }
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("publish {}: {e}", output.display()),
            ))
        }
    }

    let had_old = output.exists();
    if had_old {
        if let Err(e) = fs::rename(&output, &old) {
            let _ = crate::kernel::store::remove_tree(&new);
            return Err(io::Error::new(
                e.kind(),
                format!("publish {}: {e}", output.display()),
            ));
        }
    }
    if let Err(e) = fs::rename(&new, &output) {
        let _ = crate::kernel::store::remove_tree(&new);
        let restore = if had_old {
            fs::rename(&old, &output)
        } else {
            Ok(())
        };
        return Err(match restore {
            Ok(()) => io::Error::new(e.kind(), format!("publish {}: {e}", output.display())),
            Err(restore_error) => io::Error::new(
                e.kind(),
                format!(
                    "publish {}: {e}; restoring previous output failed: {restore_error}",
                    output.display()
                ),
            ),
        });
    }
    if had_old {
        if let Err(e) = crate::kernel::store::remove_tree(&old) {
            // The publish itself succeeded; rolling back here could lose
            // BOTH versions (the old tree may be partially deleted). Keep
            // the new output and report the leftover.
            ui::warning(
                &format!("previous output left at {} ({e})", old.display()),
                &ui::shell_line(&["rm", "-rf", &old.display().to_string()]),
            );
        }
    }
    Ok(output)
}

/// Sandboxed build: fresh offline locked restore into scratch obj, attest
/// assets, then build --no-restore. Project obj/ is never authority.
pub fn build_sandboxed(
    platform: Platform,
    activity: &StoreActivity,
    project: &ProjectRoot,
    sdk_obj: &Path,
    packages_obj: &Path,
    args: &[String],
    selected: &Selected,
) -> io::Result<()> {
    validate_build_args(args)?;
    let sdk_spec = sdk_spec(platform, selected)?;
    let (csproj, _) = preflight(project, &sdk_spec.version)?;
    let project_dir = project.path().to_path_buf();
    let sdk_obj = sdk_obj.canonicalize()?;
    let packages_obj = packages_obj.canonicalize()?;
    let store = Store::open()?;
    store.require_activity(activity, "dotnet build")?;
    let scratch = store.stage_with_activity(activity)?;
    let objdir = scratch.join("obj");
    let output_scratch = scratch.join("output");
    fs::create_dir_all(&objdir)?;
    fs::create_dir_all(&output_scratch)?;
    prepare_scratch(&scratch)?;
    // Empty source list: everything must come from the projected packages.
    fs::write(
        scratch.join("nuget.config"),
        "<configuration><packageSources><clear /></packageSources><config>\
         <add key=\"updatePackageLastAccessTime\" value=\"false\" /></config></configuration>",
    )?;
    let common = |verb: &str| -> Vec<String> {
        vec![
            sdk_obj.join("dotnet").display().to_string(),
            verb.to_string(),
            csproj.display().to_string(),
        ]
    };
    // CoreCLR named mutexes use the platform-selected local write root.
    let env: Vec<(String, String)> = forced_env(&sdk_obj, &packages_obj, &scratch);
    let mut restore = common("restore");
    restore.extend([
        "--locked-mode".to_string(),
        "--no-cache".to_string(),
        "--configfile".to_string(),
        scratch.join("nuget.config").display().to_string(),
        "-noAutoResponse".to_string(),
        format!("-p:MSBuildProjectExtensionsPath={}/", objdir.display()),
        format!("-p:BaseIntermediateOutputPath={}/", objdir.display()),
        "-p:UseSharedCompilation=false".to_string(),
        "-nodeReuse:false".to_string(),
        "--disable-build-servers".to_string(),
    ]);
    let spec = BuildSpec {
        argv: restore,
        cwd: project_dir.clone(),
        env: env.clone(),
        read: vec![project_dir.clone(), sdk_obj.clone(), packages_obj.clone()],
        write: dotnet_write_roots(platform, vec![objdir.clone()])?,
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
    };
    crate::kernel::sandbox::run_build_spec_on_with_activity(platform, &spec, activity).map_err(
        |e| {
            io::Error::new(
                e.kind(),
                format!(
                    "offline locked restore failed: {e}; network is denied — \
                     packages outside the lock, framework packs, or workloads \
                     are unsupported in v0"
                ),
            )
        },
    )?;
    if !objdir.join("project.assets.json").is_file() {
        let _ = crate::kernel::store::remove_tree(&scratch);
        return Err(err("restore produced no project.assets.json"));
    }
    let assets = fs::read(objdir.join("project.assets.json"))?;
    let assets_sha256 = hex::encode(Sha256::digest(&assets));
    let mut build = common("build");
    build.extend(args.iter().cloned());
    build.extend([
        "--no-restore".to_string(),
        format!("-p:OutputPath={}/", output_scratch.display()),
        "-noAutoResponse".to_string(),
        format!("-p:MSBuildProjectExtensionsPath={}/", objdir.display()),
        format!("-p:BaseIntermediateOutputPath={}/", objdir.display()),
        "-p:UseSharedCompilation=false".to_string(),
        "-nodeReuse:false".to_string(),
        "--disable-build-servers".to_string(),
    ]);
    let spec = BuildSpec {
        argv: build,
        cwd: project_dir.clone(),
        env,
        read: vec![project_dir.clone(), sdk_obj.clone(), packages_obj.clone()],
        write: dotnet_write_roots(platform, vec![output_scratch.clone(), objdir.clone()])?,
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
    };
    if let Err(e) =
        crate::kernel::sandbox::run_build_spec_on_with_activity(platform, &spec, activity)
    {
        let _ = crate::kernel::store::remove_tree(&scratch);
        return Err(io::Error::new(
            e.kind(),
            format!("dotnet build failed: {e}\n(network is denied during builds)"),
        ));
    }
    let after = fs::read(objdir.join("project.assets.json"))?;
    if hex::encode(Sha256::digest(&after)) != assets_sha256 {
        let _ = crate::kernel::store::remove_tree(&scratch);
        return Err(err(
            "project.assets.json changed during build; refusing to publish output",
        ));
    }
    let output = match publish_output(
        &output_scratch,
        &project_dir,
        platform,
        &sdk_fingerprint_of(&sdk_spec),
        Some(activity),
    ) {
        Ok(output) => output,
        Err(e) => {
            let _ = crate::kernel::store::remove_tree(&scratch);
            return Err(e);
        }
    };
    let _ = crate::kernel::store::remove_tree(&scratch);
    ui::note(&format!("built into {}", output.display()));
    Ok(())
}

#[cfg(test)]
mod tests {

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit, or a migrated record stops matching what
    /// a re-sync publishes and every later cache hit becomes a hard error.
    #[test]
    fn legacy_adapter_recovers_the_pinned_sdk_artifact() {
        for platform in Platform::ALL {
            let spec = pin_spec(*platform);
            assert_eq!(
                recovered_cache(sdk_identity(&spec)),
                vec![format!("sha512:{}", spec.sha512)]
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
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn sdk_pins_cover_each_supported_platform() {
        let catalog = toolchain_catalog().unwrap();
        assert!(
            catalog.bundles().len() > 1,
            "the catalog holds more than the default"
        );
        for bundle in catalog.bundles() {
            for &platform in Platform::ALL {
                let row = bundle.artifact(platform, "dotnet-sdk").unwrap();
                assert_eq!(row.digest.algo(), "sha512");
                assert!(row
                    .url
                    .starts_with("https://builds.dotnet.microsoft.com/dotnet/Sdk/"));
            }
        }
        assert_eq!(
            shipped_selection().unwrap().version("dotnet-sdk").unwrap(),
            SDK_VERSION
        );

        let linux = sdk_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(
            linux.url,
            "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.317/dotnet-sdk-9.0.317-linux-x64.tar.gz"
        );
        assert_eq!(linux.digest.hex().len(), 128);
        assert!(linux
            .digest
            .hex()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn sdk_identities_and_fingerprints_are_platform_specific() {
        let darwin = pin_spec(Platform::Aarch64AppleDarwin);
        let linux = pin_spec(Platform::X86_64UnknownLinuxGnu);
        assert_ne!(
            sdk_identity(&darwin).object_id(),
            sdk_identity(&linux).object_id()
        );
        assert_ne!(sdk_fingerprint_of(&darwin), sdk_fingerprint_of(&linux));
    }

    #[test]
    fn darwin_identity_unchanged() {
        let platform = Platform::Aarch64AppleDarwin;
        let pin = sdk_pin(platform).unwrap();
        assert_eq!(
            pin.url,
            "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.317/dotnet-sdk-9.0.317-osx-arm64.tar.gz"
        );
        assert_eq!(
            pin.digest.hex(),
            "f707a1c73e84c6d009baab2a274270bd11bbb58cd8244cf59594fe1662f50225d1665878d3af4e4b9649b6feccd95b693cf9cf28e127742b7a4e6287caa3eb2a"
        );
        let spec = pin_spec(platform);
        let identity = sdk_identity(&spec);
        assert_eq!(
            identity.object_id(),
            "aebf0bc6741c81b414dfe7825ed9115ccc60f085-dotnet-sdk-9.0.317"
        );
        assert_eq!(sdk_fingerprint_of(&spec), "3a532efac27c3140");
    }

    /// The selection is the only authority on the sync path, so the object
    /// it realizes must have the id the pin table realized before selection
    /// existed, on both platforms: that is the id every cached SDK already
    /// has. If this drifts, every cached SDK is orphaned.
    #[test]
    fn a_selected_row_and_the_pin_build_the_same_identity() {
        let selected = shipped_selection().unwrap();
        for platform in Platform::ALL {
            let from_lock = sdk_spec(*platform, &selected).unwrap();
            let from_pin = pin_spec(*platform);
            assert_eq!(from_lock.version, from_pin.version);
            assert_eq!(from_lock.url, from_pin.url);
            assert_eq!(from_lock.sha512, from_pin.sha512);
            assert_eq!(
                sdk_identity(&from_lock).object_id(),
                sdk_identity(&from_pin).object_id(),
                "{}",
                platform.triple()
            );
            assert_eq!(
                sdk_fingerprint_of(&from_lock),
                sdk_fingerprint_of(&from_pin)
            );
        }
    }

    #[test]
    fn an_unknown_recipe_and_a_foreign_selection_are_both_refused() {
        let mut selected = shipped_selection().unwrap();
        for row in &mut selected.bundle.artifacts {
            row.recipe = "dotnet-sdk/99".into();
        }
        let error = sdk_spec(Platform::X86_64UnknownLinuxGnu, &selected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("dotnet-sdk/99"), "{error}");
        assert!(error.contains("upgrade tog"), "{error}");

        let mut foreign = shipped_selection().unwrap();
        foreign.ecosystem = "go".into();
        let error = sdk_spec(Platform::X86_64UnknownLinuxGnu, &foreign)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not dotnet"), "{error}");

        // Microsoft publishes sha512; a sha256 row is another provenance
        // channel and this tailor does not accept one.
        let mut wrong_algo = shipped_selection().unwrap();
        for row in &mut wrong_algo.bundle.artifacts {
            row.digest = Digest::sha256(&"a".repeat(64)).unwrap();
        }
        let error = sdk_spec(Platform::X86_64UnknownLinuxGnu, &wrong_algo)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must be sha512"), "{error}");
    }

    /// The global.json gate answers to the selection, so a project locked to
    /// an older SDK keeps passing after the shipped catalog moves on.
    #[test]
    fn the_global_json_gate_compares_against_the_selected_sdk() {
        let scratch = TempDir::named("dotnet-globaljson");
        let temp = scratch.0.clone();
        fs::write(
            temp.join("global.json"),
            "{\"sdk\":{\"version\":\"9.0.100\",\"rollForward\":\"disable\"}}",
        )
        .unwrap();
        check_global_json(&ProjectRoot::open(&temp).unwrap(), "9.0.100").unwrap();
        let error = check_global_json(&ProjectRoot::open(&temp).unwrap(), SDK_VERSION)
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires SDK 9.0.100"), "{error}");
        assert!(error.contains(SDK_VERSION), "{error}");
    }

    /// Every closure this tailor writes carries which bundle realized it and
    /// which store object that bundle became: `tog status` compares the one,
    /// `tog run` resolves the other.
    #[test]
    fn the_closure_body_records_the_bundle_and_the_runtime_object() {
        let selected = shipped_selection().unwrap();
        let sdk_obj = Path::new("/store/objects/abc-dotnet-sdk-9.0.317");
        let plan = DotnetPlan {
            sdk_version: SDK_VERSION.into(),
            project: "app.csproj".into(),
            targets: vec!["net9.0".into()],
            packages: Vec::new(),
        };
        let body = closure_body(
            sdk_obj,
            Path::new("/store/objects/def-packages-0"),
            &plan,
            &"c".repeat(64),
            &selected,
        )
        .unwrap();
        assert_eq!(body["toolchain"]["ecosystem"], "dotnet");
        assert_eq!(body["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(body["toolchain"]["versions"]["dotnet-sdk"], SDK_VERSION);
        assert_eq!(body["runtime_object"]["id"], "abc-dotnet-sdk-9.0.317");
        assert_eq!(
            body["runtime_object"]["path"],
            sdk_obj.display().to_string()
        );
        // The runtime object is the SDK the projection already records, and
        // every pre-existing key survives beside the record.
        assert_eq!(body["sdk_object"]["id"], body["runtime_object"]["id"]);
        assert_eq!(body["packages_object"]["id"], "def-packages-0");
        assert_eq!(body["packages_lock_sha256"], "c".repeat(64));
        assert_eq!(body["plan"]["project"], "app.csproj");
    }

    /// The durable root/2 record `project_dotnet_env` publishes names
    /// exactly the SDK object and the packages object it was handed:
    /// nothing inferred from the closure JSON, nothing missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("dotnet").unwrap();
        let scratch = TempDir::named("dotnet-closure-refs");
        let temp = scratch.0.clone();
        let store_root = temp.join("store");
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
        let sdk_id = format!("{}-dotnet-sdk-{SDK_VERSION}", "1".repeat(40));
        let packages_id = format!("{}-packages-0", "2".repeat(40));
        for id in [&sdk_id, &packages_id] {
            let object = store.object_path(id);
            fs::create_dir_all(&object).unwrap();
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::to_vec_pretty(&serde_json::json!({ "id": id })).unwrap(),
            )
            .unwrap();
        }
        let project = temp.join("project");
        fs::create_dir_all(&project).unwrap();
        let plan = DotnetPlan {
            sdk_version: SDK_VERSION.into(),
            project: "app.csproj".into(),
            targets: vec!["net9.0".into()],
            packages: Vec::new(),
        };
        project_dotnet_env(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &store.object_path(&sdk_id),
            &store.object_path(&packages_id),
            &plan,
            &"c".repeat(64),
            &shipped_selection().unwrap(),
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([sdk_id, packages_id])
        );
        assert!(record.projections.is_empty(), "{:?}", record.projections);

        // `gc --register` rebuilds the same record from this closure alone.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        assert_eq!(reimported.projections, record.projections);
    }

    #[test]
    fn dotnet_tmp_paths_are_platform_specific() {
        assert_eq!(
            dotnet_tmp_path(Platform::Aarch64AppleDarwin),
            PathBuf::from("/private/tmp/.dotnet")
        );
        assert_eq!(
            dotnet_tmp_path(Platform::X86_64UnknownLinuxGnu),
            PathBuf::from("/tmp/.dotnet")
        );
    }

    #[test]
    fn dotnet_tmp_validation_is_path_specific_and_testable() {
        // The validator requires canonical paths, and a TempDir path is one.
        let scratch = TempDir::named("dn-tmp");
        let base = scratch.0.clone();
        let uid = invoking_uid().unwrap();

        let safe = base.join("safe");
        fs::create_dir(&safe).unwrap();
        assert_eq!(ensure_dotnet_tmp_at(&safe, uid, false).unwrap(), safe);

        let created = base.join("created");
        assert_eq!(ensure_dotnet_tmp_at(&created, uid, false).unwrap(), created);
        assert_eq!(
            fs::metadata(&created).unwrap().permissions().mode() & 0o7777,
            0o700
        );

        let file = base.join("file");
        fs::write(&file, b"not a directory").unwrap();
        assert!(ensure_dotnet_tmp_at(&file, uid, false).is_err());

        let link = base.join("link");
        symlink(&safe, &link).unwrap();
        assert!(ensure_dotnet_tmp_at(&link, uid, false).is_err());

        let mismatch = base.join("mismatch");
        fs::create_dir(&mismatch).unwrap();
        let error = ensure_dotnet_tmp_at(&mismatch, uid ^ 1, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("is owned by uid"), "{error}");
    }

    #[test]
    fn precreates_shm_under_the_dotnet_tmp_dir_on_every_platform() {
        let scratch = TempDir::named("dotnet-shm");
        let temp = scratch.0.join("tmp");
        let uid = invoking_uid().unwrap();
        let dir = ensure_dotnet_tmp_at(&temp, uid, true).unwrap();
        let shm = dir.join("shm");
        assert!(shm.is_dir());
        assert_eq!(
            fs::metadata(&shm).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // idempotent, and a symlinked shm is refused
        ensure_dotnet_tmp_at(&temp, uid, true).unwrap();
        fs::remove_dir(&shm).unwrap();
        std::os::unix::fs::symlink(&temp, &shm).unwrap();
        assert!(ensure_dotnet_tmp_at(&temp, uid, true).is_err());
    }

    #[test]
    fn every_prepared_scratch_is_already_marked_nuget_migrated() {
        let scratch = TempDir::named("dn-mig");
        let base = scratch.0.clone();
        prepare_scratch(&base).unwrap();
        assert!(base.join("home").is_dir());
        let data_home = forced_env(&base, &base, &base)
            .into_iter()
            .find(|(k, _)| k == "XDG_DATA_HOME")
            .map(|(_, v)| PathBuf::from(v))
            .expect("dotnet forces XDG_DATA_HOME");
        assert!(
            data_home
                .join("NuGet")
                .join("Migrations")
                .join("1")
                .is_file(),
            "NuGet reads migrations under XDG_DATA_HOME; the sentinel must land there"
        );
        prepare_scratch(&base).unwrap();
    }

    #[test]
    fn all_dotnet_sandbox_phases_add_only_the_selected_tmp_write_root() {
        let scratch = TempDir::named("dn-spec");
        let base = scratch.0.clone();
        let project = base.join("project");
        let packages = base.join("packages");
        let selected_tmp = base.join(".dotnet");
        let phases = [
            vec![base.join("staged-packages")],
            vec![base.join("obj")],
            vec![base.join("output"), base.join("obj")],
        ];
        for phase in phases {
            let writes = add_dotnet_tmp_write_root(phase, selected_tmp.clone());
            assert!(writes.iter().any(|path| path == &selected_tmp));
            assert!(!writes.iter().any(|path| path == &project));
            assert!(!writes.iter().any(|path| path == &packages));
        }
    }

    fn minimal_csproj() -> &'static str {
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup></Project>"
    }

    #[test]
    fn lock_parsing_and_validation() {
        let base = NugetPackage {
            id: "Newtonsoft.Json".into(),
            version: "13.0.4".into(),
            content_hash: "A".repeat(88),
        };
        let ok = DotnetPlan {
            sdk_version: SDK_VERSION.into(),
            project: "p.csproj".into(),
            targets: vec!["net9.0".into()],
            packages: vec![base.clone()],
        };
        assert!(validate_plan(&ok, SDK_VERSION).is_ok());
        let error = validate_plan(
            &DotnetPlan {
                targets: vec!["net9.0".into(), "net8.0".into()],
                ..ok.clone()
            },
            SDK_VERSION,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("multi-targeted locks are unsupported in v0"),
            "{error}"
        );
        let same_tfm_rids = DotnetPlan {
            targets: vec![
                "net9.0".into(),
                "net9.0/osx-arm64".into(),
                "net9.0/linux-x64".into(),
            ],
            ..ok.clone()
        };
        assert!(validate_plan(&same_tfm_rids, SDK_VERSION).is_ok());
        let mut evil = base.clone();
        evil.id = "../escape".into();
        assert!(validate_plan(
            &DotnetPlan {
                packages: vec![evil],
                ..ok.clone()
            },
            SDK_VERSION
        )
        .is_err());
        let mut bad = base.clone();
        bad.content_hash = "not/base64\n".into();
        assert!(validate_plan(
            &DotnetPlan {
                packages: vec![bad],
                ..ok.clone()
            },
            SDK_VERSION
        )
        .is_err());
    }

    #[test]
    fn global_json_gate() {
        let scratch = TempDir::named("dn-gj");
        let temp = scratch.0.clone();
        assert!(check_global_json(&ProjectRoot::open(&temp).unwrap(), SDK_VERSION).is_ok()); // absent
        std::fs::write(
            temp.join("global.json"),
            format!("{{\"sdk\":{{\"version\":\"{SDK_VERSION}\",\"rollForward\":\"disable\"}}}}"),
        )
        .unwrap();
        assert!(check_global_json(&ProjectRoot::open(&temp).unwrap(), SDK_VERSION).is_ok());
        std::fs::write(
            temp.join("global.json"),
            "{\"sdk\":{\"version\":\"8.0.100\",\"rollForward\":\"disable\"}}",
        )
        .unwrap();
        assert!(check_global_json(&ProjectRoot::open(&temp).unwrap(), SDK_VERSION).is_err());
        std::fs::write(
            temp.join("global.json"),
            format!("{{\"sdk\":{{\"version\":\"{SDK_VERSION}\"}}}}"),
        )
        .unwrap();
        assert!(check_global_json(&ProjectRoot::open(&temp).unwrap(), SDK_VERSION).is_err()); // rollForward missing
        std::fs::write(
            temp.join("global.json"),
            "{\"msbuild-sdks\":{\"X\":\"1.0\"}}",
        )
        .unwrap();
        assert!(check_global_json(&ProjectRoot::open(&temp).unwrap(), SDK_VERSION).is_err());
    }

    #[test]
    fn build_argument_allowlist() {
        for bad in [
            "-p:RestoreSources=https://evil",
            "--output",
            "project.csproj",
            "@resp.rsp",
            "-r",
        ] {
            assert!(validate_build_args(&[bad.to_string()]).is_err(), "{bad}");
        }
        for good in [
            vec!["-c", "Release"],
            vec!["--verbosity", "minimal"],
            vec!["-f", "net9.0"],
            vec!["--no-incremental"],
            vec!["-warnaserror"],
            vec!["-p:Configuration=Release"],
            vec!["-p:treatwarningsaserrors=true"],
        ] {
            assert!(
                validate_build_args(&good.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
                    .is_ok(),
                "{good:?}"
            );
        }
        for v in ["build", "test", "publish", "msbuild", "restore"] {
            assert!(BUILD_VERBS.contains(&v));
        }
    }

    #[test]
    fn preflight_rejects_unsafe_project_shapes() {
        let scratch = TempDir::named("dn-preflight");
        let base = scratch.0.clone();

        let minimal = base.join("minimal.csproj");
        fs::write(&minimal, minimal_csproj()).unwrap();
        assert!(validate_csproj(
            &ProjectRoot::open(&base).unwrap(),
            Path::new("minimal.csproj")
        )
        .is_ok());
        let sdk_element = base.join("sdk-element.csproj");
        fs::write(
            &sdk_element,
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Sdk Name=\"X\" /></Project>",
        )
        .unwrap();
        assert!(validate_csproj(
            &ProjectRoot::open(&base).unwrap(),
            Path::new("sdk-element.csproj")
        )
        .is_err());
        let garbage = base.join("garbage.csproj");
        fs::write(&garbage, "not XML").unwrap();
        assert!(validate_csproj(
            &ProjectRoot::open(&base).unwrap(),
            Path::new("garbage.csproj")
        )
        .is_err());

        let symlinked = base.join("symlinked");
        fs::create_dir(&symlinked).unwrap();
        fs::write(symlinked.join("project.xml"), minimal_csproj()).unwrap();
        symlink(
            symlinked.join("project.xml"),
            symlinked.join("project.csproj"),
        )
        .unwrap();
        assert!(preflight(&ProjectRoot::open(&symlinked).unwrap(), SDK_VERSION).is_err());

        let project_lock = base.join("project-lock");
        fs::create_dir(&project_lock).unwrap();
        fs::write(project_lock.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(
            project_lock.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{"type":"Project","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();
        let error = preflight(&ProjectRoot::open(&project_lock).unwrap(), SDK_VERSION)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Project lock entries"), "{error}");

        let central_transitive = base.join("central-transitive");
        fs::create_dir(&central_transitive).unwrap();
        fs::write(central_transitive.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(
            central_transitive.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{"type":"CentralTransitive","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();
        let error = preflight(
            &ProjectRoot::open(&central_transitive).unwrap(),
            SDK_VERSION,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("Other"), "{error}");
        assert!(error.contains("CentralTransitive"), "{error}");

        let import = base.join("import");
        fs::create_dir(&import).unwrap();
        fs::write(
            import.join("project.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Import Project=\"evil.targets\" /></Project>",
        )
        .unwrap();
        assert!(preflight(&ProjectRoot::open(&import).unwrap(), SDK_VERSION).is_err());

        let bad_global = base.join("bad-global");
        fs::create_dir(&bad_global).unwrap();
        fs::write(bad_global.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(bad_global.join("global.json"), "{}").unwrap();
        assert!(preflight(&ProjectRoot::open(&bad_global).unwrap(), SDK_VERSION).is_err());

        let ancestor = base.join("ancestor");
        fs::create_dir(&ancestor).unwrap();
        fs::write(ancestor.join("global.json"), "{}").unwrap();
        let child = ancestor.join("child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("project.csproj"), minimal_csproj()).unwrap();
        let error = preflight(&ProjectRoot::open(&child).unwrap(), SDK_VERSION)
            .unwrap_err()
            .to_string();
        assert!(error.contains("ancestor global.json"), "{error}");

        let solution_only = base.join("solution-only");
        fs::create_dir(&solution_only).unwrap();
        fs::write(solution_only.join("x.sln"), "solution").unwrap();
        assert!(has_marker(&ProjectRoot::open(&solution_only).unwrap()).unwrap());
        // An unreadable/missing dir propagates instead of guessing.
        assert!(ProjectRoot::open(&base.join("missing")).is_err());

        let bypass = base.join("bypass");
        fs::create_dir(&bypass).unwrap();
        let cr_sdk = bypass.join("cr.csproj");
        fs::write(
            &cr_sdk,
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Sdk\rName=\"X\"/></Project>",
        )
        .unwrap();
        assert!(
            validate_csproj(&ProjectRoot::open(&bypass).unwrap(), Path::new("cr.csproj")).is_err()
        );
        let projector = bypass.join("projector.csproj");
        fs::write(&projector, "<Projector/>").unwrap();
        assert!(validate_csproj(
            &ProjectRoot::open(&bypass).unwrap(),
            Path::new("projector.csproj")
        )
        .is_err());
    }

    /// Preflight and planning read the lock through one parser, so a lock
    /// preflight accepts is one planning can use, and each refusal has one
    /// text.
    #[test]
    fn preflight_and_planning_share_one_lock_parser() {
        let scratch = TempDir::named("dn-lock");
        let refusal = |name: &str, lock: &str| -> String {
            let dir = scratch.0.join(name);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("p.csproj"), minimal_csproj()).unwrap();
            fs::write(dir.join("packages.lock.json"), lock).unwrap();
            preflight(&ProjectRoot::open(&dir).unwrap(), SDK_VERSION)
                .map(|_| String::new())
                .unwrap_err()
                .to_string()
        };
        let entry = |fields: &str| {
            format!(
                r#"{{"version":1,"dependencies":{{"net9.0":{{"Newtonsoft.Json":{{{fields}}}}}}}}}"#
            )
        };
        let error = refusal("v2", r#"{"version":2,"dependencies":{}}"#);
        assert!(
            error.contains("packages.lock.json version 2 unsupported (v1 only in v0; Central Package Management locks are v2+)"),
            "{error}"
        );
        let error = refusal(
            "kind",
            &entry(r#""type":"Weird","resolved":"1.0.0","contentHash":"A""#),
        );
        assert!(
            error.contains("Newtonsoft.Json: unsupported lock dependency type Weird; expected Direct or Transitive"),
            "{error}"
        );
        let error = refusal("untyped", &entry(r#""resolved":"1.0.0","contentHash":"A""#));
        assert!(
            error.contains("Newtonsoft.Json: unsupported lock dependency type null; expected Direct or Transitive"),
            "{error}"
        );
        let error = refusal("unresolved", &entry(r#""type":"Direct","contentHash":"A""#));
        assert!(
            error.contains("Newtonsoft.Json: no resolved version"),
            "{error}"
        );
        let error = refusal("unhashed", &entry(r#""type":"Direct","resolved":"1.0.0""#));
        assert!(error.contains("Newtonsoft.Json: no contentHash"), "{error}");
        let error = refusal(
            "conflict",
            r#"{"version":1,"dependencies":{
                "net9.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"1.0.0","contentHash":"A"}},
                "net9.0/linux-x64":{"newtonsoft.json":{"type":"Transitive","resolved":"1.0.0","contentHash":"B"}}}}"#,
        );
        assert!(
            error.contains("newtonsoft.json@1.0.0: conflicting contentHash across lock targets"),
            "{error}"
        );

        let lock = parse_lock(
            r#"{"version":1,"dependencies":{
                "net9.0":{
                    "Zeta":{"type":"Direct","resolved":"2.0.0","contentHash":"Z"},
                    "Alpha":{"type":"Transitive","resolved":"1.0.0","contentHash":"A"}},
                "net9.0/linux-x64":{
                    "alpha":{"type":"Transitive","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();
        assert_eq!(lock.targets, ["net9.0", "net9.0/linux-x64"]);
        let packages: Vec<_> = lock
            .packages
            .iter()
            .map(|p| (p.id.as_str(), p.version.as_str(), p.content_hash.as_str()))
            .collect();
        assert_eq!(packages, [("Alpha", "1.0.0", "A"), ("Zeta", "2.0.0", "Z")]);
    }

    /// Validate one csproj body in a fresh project directory.
    fn csproj_verdict(body: &str) -> io::Result<()> {
        let scratch = TempDir::named("dn-csproj");
        fs::write(scratch.0.join("p.csproj"), body).unwrap();
        validate_csproj(
            &ProjectRoot::open(&scratch.0).unwrap(),
            Path::new("p.csproj"),
        )
    }

    fn in_project(inner: &str) -> String {
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>{inner}</PropertyGroup></Project>"
        )
    }

    /// Blocked names match whole element names outside comments, so a
    /// longer property that merely contains one is a valid project.
    #[test]
    fn csproj_markers_match_whole_element_names() {
        for accepted in [
            in_project(
                "<AppendTargetFrameworkToOutputPath>false</AppendTargetFrameworkToOutputPath>",
            ),
            in_project(
                "<AppendRuntimeIdentifierToOutputPath>false</AppendRuntimeIdentifierToOutputPath>",
            ),
            in_project("<!-- <OutputPath>bin/elsewhere</OutputPath> -->"),
            in_project("<!-- an Import, a ProjectReference and a UsingTask -->"),
            in_project("<Description>$(OutputPath) is where it lands</Description>"),
            "<!-- lead --><Project Sdk=\"Microsoft.NET.Sdk\"><!-- Sdk=\"Other\" --></Project>"
                .into(),
            in_project("<![CDATA[<OutputPath>]]>"),
        ] {
            assert!(csproj_verdict(&accepted).is_ok(), "{accepted}");
        }
        for refused in [
            in_project("<OutputPath>bin/elsewhere</OutputPath>"),
            in_project("<OutputPath Condition=\"'$(Configuration)' == 'Release'\">x</OutputPath>"),
            in_project("<OutputPath\n>x</OutputPath>"),
            in_project("<OutputPath/>"),
            in_project("<outputpath>x</outputpath>"),
            in_project("<OUTPUTPATH>x</OUTPUTPATH>"),
            in_project("<BaseOutputPath>x</BaseOutputPath>"),
            in_project("<IntermediateOutputPath>x</IntermediateOutputPath>"),
            in_project("<BaseIntermediateOutputPath>x</BaseIntermediateOutputPath>"),
            in_project("<MSBuildProjectExtensionsPath>x</MSBuildProjectExtensionsPath>"),
            in_project("<RestoreSources>https://evil</RestoreSources>"),
            in_project("<RestorePackagesPath>x</RestorePackagesPath>"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><PackageDownload Include=\"X\" Version=\"[1.0.0]\" /></ItemGroup></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"../o/o.csproj\" /></ItemGroup></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><UsingTask TaskName=\"T\" AssemblyFile=\"t.dll\" /></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><import Project=\"evil.targets\" /></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\" TreatAsLocalProperty=\"OutputPath\"></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Target Name=\"T\"><CreateItem Include=\"X\"><Output TaskParameter=\"Include\" ItemName=\"PackageDownload\" /></CreateItem></Target></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Target Name=\"T\"><CreateProperty Value=\"x\"><Output TaskParameter=\"Value\" PropertyName=\"RestoreSources\" /></CreateProperty></Target></Project>".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><!-- open".into(),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><![CDATA[ open</Project>".into(),
            "<Project Sdk=\"Other.Sdk\"></Project>".into(),
        ] {
            assert!(csproj_verdict(&refused).is_err(), "{refused}");
        }
    }

    /// A project read through a held root keeps reading the original
    /// directory after it is renamed and another project takes its path.
    #[test]
    fn preflight_reads_the_held_project_after_a_rename() {
        let scratch = TempDir::named("dn-held");
        let base = scratch.0.clone();
        let project = base.join("project");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("original.csproj"), minimal_csproj()).unwrap();
        fs::write(
            project.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{}}}"#,
        )
        .unwrap();
        let root = ProjectRoot::open(&project).unwrap();

        fs::rename(&project, base.join("moved")).unwrap();
        fs::create_dir(&project).unwrap();
        fs::write(
            project.join("replacement.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Import Project=\"evil.targets\" /></Project>",
        )
        .unwrap();
        fs::write(
            project.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{"type":"Project","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();

        assert_eq!(
            find_project(&root).unwrap(),
            PathBuf::from("original.csproj")
        );
        let (csproj, _) = preflight(&root, SDK_VERSION).unwrap();
        assert_eq!(csproj, root.path().join("original.csproj"));
        // The replacement at the old path is what a path read would see.
        assert!(preflight(&ProjectRoot::open(&project).unwrap(), SDK_VERSION).is_err());
    }

    #[test]
    fn sdk_extraction_requires_muxer_at_object_root() {
        let scratch = TempDir::named("dn-extract");
        let base = scratch.0.clone();

        let root = base.join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("dotnet"), b"muxer").unwrap();
        let archive = base.join("root.tar.gz");
        assert!(Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&archive)
            .args(["-C"])
            .arg(&root)
            .arg("dotnet")
            .status()
            .unwrap()
            .success());
        let stage = base.join("stage");
        fs::create_dir(&stage).unwrap();
        extract_sdk_archive(&archive, &stage).unwrap();
        assert!(stage.join("dotnet").is_file());

        let nested_root = base.join("nested-root");
        fs::create_dir_all(nested_root.join("nested")).unwrap();
        fs::write(nested_root.join("nested/dotnet"), b"muxer").unwrap();
        let nested_archive = base.join("nested.tar.gz");
        assert!(Command::new("/usr/bin/tar")
            .args(["-czf"])
            .arg(&nested_archive)
            .args(["-C"])
            .arg(&nested_root)
            .arg("nested")
            .status()
            .unwrap()
            .success());
        let nested_stage = base.join("nested-stage");
        fs::create_dir(&nested_stage).unwrap();
        let error = extract_sdk_archive(&nested_archive, &nested_stage)
            .unwrap_err()
            .to_string();
        assert!(error.contains("unexpected layout"), "{error}");
    }

    #[test]
    fn output_roots_reject_symlinks_and_metadata_source_is_fixed() {
        let scratch = TempDir::named("dn-output");
        let base = scratch.0.clone();
        let outside = base.join("outside");
        fs::create_dir(&outside).unwrap();
        let project = base.join("project");
        fs::create_dir(&project).unwrap();
        symlink(&outside, project.join("bin")).unwrap();
        assert!(checked_output_dir(&project, "fp").is_err());

        let project = base.join("project2");
        fs::create_dir_all(project.join("bin")).unwrap();
        symlink(&outside, project.join("bin/tog-fp")).unwrap();
        assert!(checked_output_dir(&project, "fp").is_err());

        let metadata = base.join(".nupkg.metadata");
        fs::write(&metadata, r#"{"source":"/tmp/feed","version":2}"#).unwrap();
        rewrite_metadata_source(&metadata).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(metadata).unwrap()).unwrap();
        assert_eq!(value["source"], "tog-feed");

        let publish_project = base.join("publish-project");
        fs::create_dir_all(publish_project.join("bin")).unwrap();
        let staged_old = base.join("staged-old");
        fs::create_dir(&staged_old).unwrap();
        fs::write(staged_old.join("artifact"), "old").unwrap();
        let output = publish_output(
            &staged_old,
            &publish_project,
            Platform::Aarch64AppleDarwin,
            "fp",
            None,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(output.join("artifact")).unwrap(), "old");

        let staged_new = base.join("staged-new");
        fs::create_dir(&staged_new).unwrap();
        fs::write(staged_new.join("artifact"), "new").unwrap();
        publish_output(
            &staged_new,
            &publish_project,
            Platform::Aarch64AppleDarwin,
            "fp",
            None,
        )
        .unwrap();
        assert_eq!(fs::read_to_string(output.join("artifact")).unwrap(), "new");
        assert!(!publish_project
            .join(format!(".tog-fp.new.{}", std::process::id()))
            .exists());
        assert!(!publish_project
            .join(format!(".tog-fp.old.{}", std::process::id()))
            .exists());
    }

    /// A project with its manifest but no lock is refused by name and
    /// nothing is written: the lock is `prepare`'s to generate, and a
    /// frozen run skips `prepare`.
    #[test]
    fn a_missing_lock_is_refused_by_name_and_nothing_is_written() {
        let temp = crate::kernel::testutil::TempDir::named("dotnet-frozen");
        std::fs::write(
            temp.0.join("hello.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n",
        )
        .unwrap();
        let project = crate::kernel::fsroot::ProjectRoot::open(&temp.0).unwrap();
        let error = super::require_lock(&project).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let message = error.to_string();
        assert!(
            message.contains("packages.lock.json is missing and --frozen never creates it"),
            "{message}"
        );
        assert!(
            message.contains("run `tog` once without --frozen"),
            "{message}"
        );
        assert!(!temp.0.join("packages.lock.json").exists());
        std::fs::write(temp.0.join("packages.lock.json"), "").unwrap();
        super::require_lock(&project).unwrap();
    }
}
