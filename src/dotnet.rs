//! The .NET tailor: NuGet packages.lock.json (v1, blanket-mandatory),
//! materialization delegated to the pinned NuGet, per-build fresh offline
//! restore, sandboxed builds only.
//!
//! Sol review 7 shaped this: signed nupkgs' contentHash is a SEMANTIC hash
//! over transformed bytes, so blanket never compares lock hashes to raw
//! downloads — the pinned NuGet verifies contentHash while installing into
//! the global-packages layout (locked mode), the same delegated-extractor
//! pattern as Go, with the full SDK object id in the object identity. The
//! lock (not project obj/) is the only durable authority: every sandboxed
//! build re-restores offline into scratch and builds --no-restore.

use crate::fetch::{cache_insert, download_verified_digest, Digest};
use crate::sandbox::{force_env, run_build_spec, BuildSpec};
use crate::store::Store;
use crate::types::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const SDK_VERSION: &str = "9.0.317";
// Official Microsoft release-metadata checksum channel (HTTPS; hashes
// published, not cryptographically signed — honest wording per Sol).
const SDK_URL: &str =
    "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.317/dotnet-sdk-9.0.317-osx-arm64.tar.gz";
const SDK_SHA512: &str = "f707a1c73e84c6d009baab2a274270bd11bbb58cd8244cf59594fe1662f50225d1665878d3af4e4b9649b6feccd95b693cf9cf28e127742b7a4e6287caa3eb2a";

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

pub fn sdk_fingerprint() -> String {
    hex::encode(&Sha256::digest(SDK_SHA512.as_bytes())[..8])
}

/// Ensure the pinned .NET SDK is realized (muxer at <obj>/dotnet).
pub fn ensure_sdk(store: &Store) -> io::Result<PathBuf> {
    let identity = Identity {
        kind: "dotnet-sdk".into(),
        name: "dotnet-sdk".into(),
        version: SDK_VERSION.into(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "dotnet-sdk/1".to_string()),
            ("artifact_sha512".to_string(), SDK_SHA512.to_string()),
            ("platform".to_string(), "aarch64-apple-darwin".to_string()),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified_digest(store, SDK_URL, &Digest::sha512(SDK_SHA512)?)?;
    let staged = store.stage()?;
    let st = Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(&staged)
        .status()?;
    if !st.success() || !staged.join("dotnet").is_file() {
        return Err(err("dotnet SDK extraction failed or has unexpected layout"));
    }
    store.commit(&identity, &staged)
}

/// global.json gate (Sol): exact pin, rollForward disable, no redirection.
pub fn check_global_json(project_dir: &Path) -> io::Result<()> {
    let path = project_dir.join("global.json");
    if !regular_file_if_present(&path, "global.json")? {
        return Ok(());
    }
    let text = fs::read_to_string(&path)?;
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
    if want != SDK_VERSION {
        return Err(err(format!(
            "global.json requires SDK {want}; pinned: {SDK_VERSION}"
        )));
    }
    if sdk.get("rollForward").and_then(serde_json::Value::as_str) != Some("disable") {
        return Err(err(
            "global.json must set \"rollForward\": \"disable\" (blanket pins the SDK exactly)",
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

fn regular_file_if_present(path: &Path, label: &str) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => Err(err(format!(
            "{label} must be a regular file, not a symlink: {}",
            path.display()
        ))),
        Ok(md) if !md.is_file() => Err(err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ))),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
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
    ]
}

/// Env for `blanket run`. Build-capable verbs are REJECTED at run (they
/// execute arbitrary MSBuild code — sandbox-only, per Sol); this env is
/// for `dotnet <app.dll>`, --version/--info, and compiled-app execution.
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

/// `blanket run`'s guard is advisory: wrappers can bypass it. The enforced
/// boundary is that blanket itself never evaluates project code outside the
/// build sandbox.
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
            "`dotnet {verb}` compiles/executes MSBuild code and must run sandboxed: use `blanket build dotnet ...`"
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
            "`dotnet exec .../MSBuild.dll` executes MSBuild code and must run sandboxed: use `blanket build dotnet ...`"
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

fn validate_plan(plan: &DotnetPlan) -> io::Result<()> {
    if plan.sdk_version != SDK_VERSION {
        return Err(err(format!(
            "plan requires SDK {}; pinned: {SDK_VERSION}",
            plan.sdk_version
        )));
    }
    if plan.targets.is_empty() {
        return Err(err("packages.lock.json has no target frameworks"));
    }
    for target in &plan.targets {
        target_framework(target)?;
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

/// Locate the single .csproj (v0 boundary: one SDK-style project, no sln).
pub fn find_project(dir: &Path) -> io::Result<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
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
            "multiple .csproj files; blanket supports one project per directory in v0",
        )),
    }
}

pub fn has_marker(dir: &Path) -> bool {
    let has_csproj = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".csproj"))
        })
        .unwrap_or(false);
    has_csproj
        || fs::symlink_metadata(dir.join("packages.lock.json")).is_ok()
        || fs::symlink_metadata(dir.join(".blanket/closures/dotnet.json")).is_ok()
}

fn validate_csproj(path: &Path) -> io::Result<()> {
    let text = fs::read_to_string(path)?;
    let lower = text.to_ascii_lowercase();
    for marker in [
        "<import",
        "packagedownload",
        "projectreference",
        "usingtask",
        "restoresources",
        "restorepackagespath",
        "msbuildprojectextensionspath",
        "baseintermediateoutputpath",
        "outputpath",
    ] {
        if lower.contains(marker) {
            return Err(err(format!(
                "{}: unsupported MSBuild/project feature {marker}",
                path.display()
            )));
        }
    }
    let bytes = lower.as_bytes();
    let mut at = 0;
    while let Some(found) = lower[at..].find("sdk") {
        let start = at + found;
        let before_ok =
            start == 0 || !bytes[start - 1].is_ascii_alphanumeric() && bytes[start - 1] != b'_';
        let mut i = start + 3;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if before_ok && i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i >= bytes.len() || !matches!(bytes[i], b'"' | b'\'') {
                return Err(err(format!(
                    "{}: SDK attribute must be quoted",
                    path.display()
                )));
            }
            let quote = bytes[i];
            let value_start = i + 1;
            let end = bytes[value_start..]
                .iter()
                .position(|b| *b == quote)
                .map(|offset| value_start + offset)
                .ok_or_else(|| err(format!("{}: unterminated SDK attribute", path.display())))?;
            if &lower[value_start..end] != "microsoft.net.sdk" {
                return Err(err(format!(
                    "{}: only Microsoft.NET.Sdk is supported",
                    path.display()
                )));
            }
            at = end + 1;
        } else {
            at = start + 3;
        }
    }
    // XML entity references cannot encode element or attribute names, so this
    // fail-closed name scan cannot be bypassed by a well-formed MSBuild XML file.
    Ok(())
}

fn validate_lock_shape(path: &Path) -> io::Result<()> {
    let text = fs::read_to_string(path)?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| err(format!("packages.lock.json: {e}")))?;
    if v["version"] != 1 {
        return Err(err(format!(
            "packages.lock.json version {} unsupported (v1 only in v0; Central Package Management locks are v2+)",
            v["version"]
        )));
    }
    let targets = v["dependencies"]
        .as_object()
        .ok_or_else(|| err("packages.lock.json has no dependencies"))?;
    for (target, entries) in targets {
        for (id, entry) in entries
            .as_object()
            .ok_or_else(|| err(format!("bad lock target {target}")))?
        {
            if entry["type"].as_str() == Some("Project") {
                return Err(err(format!(
                    "{id}: Project lock entries are not supported; use package dependencies only"
                )));
            }
        }
    }
    Ok(())
}

/// Central v0 trust-boundary validation. The tuple is the canonical project
/// file and its lock path (the latter may not exist until delegated planning).
pub fn preflight(project_dir: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let project_dir = project_dir.canonicalize()?;
    if !project_dir.is_dir() {
        return Err(err(format!(
            "dotnet project root is not a directory: {}",
            project_dir.display()
        )));
    }
    let csproj = find_project(&project_dir)?;
    if !regular_file_if_present(&csproj, "csproj")? {
        return Err(err(format!("csproj is missing: {}", csproj.display())));
    }
    validate_csproj(&csproj)?;

    let lock_path = project_dir.join("packages.lock.json");
    regular_file_if_present(&lock_path, "packages.lock.json")?;
    let global_path = project_dir.join("global.json");
    regular_file_if_present(&global_path, "global.json")?;
    check_global_json(&project_dir)?;

    for (depth, ancestor) in project_dir.ancestors().enumerate() {
        for name in [
            "Directory.Packages.props",
            "Directory.Build.rsp",
            "packages.config",
        ] {
            match fs::symlink_metadata(ancestor.join(name)) {
                Ok(_) => {
                    return Err(err(format!(
                        "{name} is not supported in the project or an SDK ancestor: {}",
                        ancestor.join(name).display()
                    )))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if depth > 0 {
            match fs::symlink_metadata(ancestor.join("global.json")) {
                Ok(_) => {
                    return Err(err(format!(
                        "ancestor global.json is not supported; SDK discovery would see {}",
                        ancestor.join("global.json").display()
                    )))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    if lock_path.is_file() {
        validate_lock_shape(&lock_path)?;
    }
    Ok((csproj, lock_path))
}

/// Plan from packages.lock.json (v1 only; blanket makes the opt-in lock
/// mandatory). Missing lock delegates a store-SDK restore --use-lock-file
/// (named resolver mutation, isolated caches).
pub fn plan_dotnet(
    store: &Store,
    project_dir: &Path,
    sdk_obj: &Path,
) -> io::Result<(DotnetPlan, String)> {
    let (mut csproj, mut lock_path) = preflight(project_dir)?;
    if !lock_path.is_file() {
        eprintln!("blanket: no packages.lock.json; resolving with the store SDK...");
        let scratch = store.stage()?;
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
            sdk_obj,
            project_dir,
            &scratch.join("pkgs"),
            &scratch,
            &["restore", "--use-lock-file", "--configfile", &config_arg],
        )?;
        let ok = out.status.success();
        let _ = crate::store::remove_tree(&scratch);
        if !ok {
            return Err(err(format!(
                "store dotnet restore --use-lock-file failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        (csproj, lock_path) = preflight(project_dir)?;
    }
    let lock = fs::read_to_string(&lock_path)?;
    let v: serde_json::Value =
        serde_json::from_str(&lock).map_err(|e| err(format!("packages.lock.json: {e}")))?;
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
                Some("Project") => return Err(err(format!(
                    "{id}: Project lock entries are not supported; use package dependencies only"
                ))),
                other => {
                    return Err(err(format!(
                        "{id}: unsupported lock dependency type {other:?} (v0)"
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
    let plan = DotnetPlan {
        sdk_version: SDK_VERSION.to_string(),
        project: csproj
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("project")
            .to_string(),
        targets,
        packages: packages.into_values().collect(),
    };
    validate_plan(&plan)?;
    let now = fs::read_to_string(&lock_path)?;
    if now != lock {
        return Err(err(
            "packages.lock.json changed while planning; re-run blanket sync",
        ));
    }
    Ok((plan, hex::encode(Sha256::digest(lock.as_bytes()))))
}

fn run_dotnet(
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
    fs::create_dir_all(&home)?;
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
    cmd.output()
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
            serde_json::Value::String("blanket-feed".to_string()),
        );
    fs::write(path, serde_json::to_vec(&value)?)
}

/// Realize the global-packages object: blanket fetches every nupkg into a
/// local folder feed (raw bytes cached by sha256), then the PINNED NuGet
/// installs from that feed in LOCKED mode — it verifies each package's
/// semantic contentHash against the lock and writes the exact
/// global-packages layout (.nupkg.sha512/.nupkg.metadata/nuspec). The SDK
/// is the extractor, so its full store object id is an identity input (Go
/// precedent). Network denied at install: the feed is local.
pub fn realize_packages(
    store: &Store,
    plan: &DotnetPlan,
    sdk_obj: &Path,
    project_dir: &Path,
) -> io::Result<PathBuf> {
    let _ = preflight(project_dir)?;
    validate_plan(plan)?;
    let sdk_obj = sdk_obj.canonicalize()?;
    // Fetch every nupkg (nuget.org flatcontainer only in v0). No upfront
    // per-file hash exists (contentHash is semantic): download to tmp,
    // record raw sha256 via cache_insert, verify semantically below.
    let scratch = store.stage()?;
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
        let (raw_sha256, _) = cache_insert(store, &tmp)?;
        raw_hashes.insert(format!("{}@{}", idl, p.version), raw_sha256);
        fs::rename(&tmp, feed.join(format!("{idl}.{verl}.nupkg")))?;
    }

    let sdk_id = sdk_obj
        .canonicalize()?
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| err("pinned SDK object has no UTF-8 store id"))?
        .to_string();
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "nuget-packages/1".to_string()),
        ("extractor".to_string(), sdk_id),
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
    let identity = Identity {
        kind: "nuget-packages".into(),
        name: "packages".into(),
        version: plan.packages.len().to_string(),
        inputs,
    };
    let id = identity.object_id();
    if store.has(&id) {
        let _ = crate::store::remove_tree(&scratch);
        return Ok(store.object_path(&id));
    }

    // Locked-mode restore from a synthetic project into the staged folder:
    // the user's project and global.json are never evaluated in realization.
    let staged = store.stage()?;
    let verifier = scratch.join("verifier");
    fs::create_dir_all(&verifier)?;
    fs::create_dir_all(scratch.join("home"))?;
    let tfm = target_framework(
        plan.targets
            .first()
            .ok_or_else(|| err("plan has no target framework"))?,
    )?;
    if plan.targets.len() > 1 {
        eprintln!("blanket: synthetic NuGet verifier uses the first lock target framework: {tfm}");
    }
    fs::write(
        verifier.join("blanket-verifier.csproj"),
        synthetic_csproj(plan, tfm),
    )?;
    fs::write(
        verifier.join("packages.lock.json"),
        serde_json::to_vec_pretty(&synthetic_lock(plan, tfm))?,
    )?;
    fs::write(
        verifier.join("nuget.config"),
        format!(
            "<configuration><packageSources><clear /><add key=\"blanket-feed\" \
             value=\"{}\" /></packageSources><config><add key=\"updatePackageLastAccessTime\" \
             value=\"false\" /></config></configuration>",
            xml_escape(&feed.display().to_string())
        ),
    )?;
    let config = verifier.join("nuget.config").canonicalize()?;
    let result = run_build_spec(&BuildSpec {
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
        write: vec![staged.clone(), ensure_dotnet_tmp()?],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
    });
    if let Err(e) = result {
        let _ = crate::store::remove_tree(&scratch);
        let _ = crate::store::remove_tree(&staged);
        return Err(err(format!(
            "locked-mode package verification failed: {e}"
        )));
    }
    // Every locked package must have materialized with its completion
    // marker; anything missing means the lock and feed disagree.
    for p in &plan.packages {
        let dir = staged
            .join(p.id.to_ascii_lowercase())
            .join(p.version.to_ascii_lowercase());
        if !dir.join(".nupkg.metadata").is_file() {
            let _ = crate::store::remove_tree(&scratch);
            let _ = crate::store::remove_tree(&staged);
            return Err(err(format!(
                "{}@{}: not materialized by locked restore",
                p.id, p.version
            )));
        }
        if let Err(e) = rewrite_metadata_source(&dir.join(".nupkg.metadata")) {
            let _ = crate::store::remove_tree(&scratch);
            let _ = crate::store::remove_tree(&staged);
            return Err(e);
        }
    }
    let _ = crate::store::remove_tree(&scratch);
    store.commit(&identity, &staged)
}

pub fn project_dotnet_env(
    project_dir: &Path,
    sdk_obj: &Path,
    packages_obj: &Path,
    plan: &DotnetPlan,
    lock_sha256: &str,
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
        "dotnet",
        serde_json::json!({
            "sdk_object": object_ref(&sdk_obj.canonicalize()?)?,
            "packages_object": object_ref(&packages_obj.canonicalize()?)?,
            "packages_lock_sha256": lock_sha256,
            "plan": plan,
        }),
    )
}

fn ensure_dotnet_tmp() -> io::Result<PathBuf> {
    let path = PathBuf::from("/private/tmp/.dotnet");
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
            fs::create_dir(&path)?;
            true
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
    let uid = Command::new("/usr/bin/id").arg("-u").output()?.stdout;
    let uid = String::from_utf8(uid)
        .map_err(|_| err("could not determine current uid"))?
        .trim()
        .parse::<u32>()
        .map_err(|_| err("could not determine current uid"))?;
    if md.uid() != uid {
        return Err(err(format!(
            "{} is owned by uid {}, current uid is {uid}",
            path.display(),
            md.uid()
        )));
    }
    if path.canonicalize()? != path {
        return Err(err(format!(
            "{} does not canonicalize to the required path",
            path.display()
        )));
    }
    Ok(path)
}

fn validate_build_args(args: &[String]) -> io::Result<()> {
    let mut i = 0;
    while i < args.len() {
        let lower = args[i].to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "-c" | "--configuration" | "-v" | "--verbosity" | "-f" | "--framework"
        ) {
            if i + 1 == args.len()
                || args[i + 1].starts_with('-')
                || args[i + 1].starts_with('@')
            {
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
    let output = bin.join(format!("blanket-{fingerprint}"));
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

fn publish_output(staged: &Path, project_dir: &Path, fingerprint: &str) -> io::Result<PathBuf> {
    let output = checked_output_dir(project_dir, fingerprint)?;
    if output.exists() {
        crate::store::remove_tree(&output)?;
    }
    match fs::rename(staged, &output) {
        Ok(()) => Ok(output),
        Err(e) if e.raw_os_error() == Some(18) => {
            let bin = output
                .parent()
                .ok_or_else(|| err("output directory has no bin parent"))?;
            let temp = bin.join(format!(
                ".blanket-{}-tmp-{}",
                fingerprint,
                std::process::id()
            ));
            if fs::symlink_metadata(&temp).is_ok() {
                return Err(err(format!(
                    "temporary output already exists: {}",
                    temp.display()
                )));
            }
            crate::project::clone_tree(staged, &temp)?;
            if output.exists() {
                crate::store::remove_tree(&output)?;
            }
            fs::rename(&temp, &output)?;
            Ok(output)
        }
        Err(e) => Err(io::Error::new(
            e.kind(),
            format!("publish {}: {e}", output.display()),
        )),
    }
}

/// Sandboxed build: fresh offline locked restore into scratch obj, attest
/// assets, then build --no-restore. Project obj/ is never authority (Sol).
pub fn build_sandboxed(
    project_dir: &Path,
    sdk_obj: &Path,
    packages_obj: &Path,
    args: &[String],
) -> io::Result<()> {
    validate_build_args(args)?;
    let (csproj, _) = preflight(project_dir)?;
    let project_dir = project_dir.canonicalize()?;
    let sdk_obj = sdk_obj.canonicalize()?;
    let packages_obj = packages_obj.canonicalize()?;
    let store = Store::open()?;
    let scratch = store.stage()?;
    let objdir = scratch.join("obj");
    let output_scratch = scratch.join("output");
    fs::create_dir_all(&objdir)?;
    fs::create_dir_all(&output_scratch)?;
    fs::create_dir_all(scratch.join("home"))?;
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
    // CoreCLR named mutexes live hardcoded at /tmp/.dotnet — a bounded,
    // local-only write root (no data flows out through it).
    let shm = ensure_dotnet_tmp()?;
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
        write: vec![objdir.clone(), shm.clone()],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
    };
    run_build_spec(&spec).map_err(|e| {
        err(format!(
            "offline locked restore failed: {e}; network is denied — \
                     packages outside the lock, framework packs, or workloads \
                     are unsupported in v0"
        ))
    })?;
    if !objdir.join("project.assets.json").is_file() {
        let _ = crate::store::remove_tree(&scratch);
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
        write: vec![output_scratch.clone(), objdir.clone(), shm.clone()],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
    };
    if let Err(e) = run_build_spec(&spec) {
        let _ = crate::store::remove_tree(&scratch);
        return Err(err(format!(
            "dotnet build failed: {e}\n(network is denied during builds)"
        )));
    }
    let after = fs::read(objdir.join("project.assets.json"))?;
    if hex::encode(Sha256::digest(&after)) != assets_sha256 {
        let _ = crate::store::remove_tree(&scratch);
        return Err(err(
            "project.assets.json changed during build; refusing to publish output",
        ));
    }
    let output = match publish_output(&output_scratch, &project_dir, &sdk_fingerprint()) {
        Ok(output) => output,
        Err(e) => {
            let _ = crate::store::remove_tree(&scratch);
            return Err(e);
        }
    };
    let _ = crate::store::remove_tree(&scratch);
    eprintln!("blanket: built into {}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

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
        assert!(validate_plan(&ok).is_ok());
        let mut evil = base.clone();
        evil.id = "../escape".into();
        assert!(validate_plan(&DotnetPlan {
            packages: vec![evil],
            ..ok.clone()
        })
        .is_err());
        let mut bad = base.clone();
        bad.content_hash = "not/base64\n".into();
        assert!(validate_plan(&DotnetPlan {
            packages: vec![bad],
            ..ok.clone()
        })
        .is_err());
    }

    #[test]
    fn global_json_gate() {
        let temp = std::env::temp_dir().join(format!(
            "blanket-dn-gj-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        assert!(check_global_json(&temp).is_ok()); // absent
        std::fs::write(
            temp.join("global.json"),
            format!("{{\"sdk\":{{\"version\":\"{SDK_VERSION}\",\"rollForward\":\"disable\"}}}}"),
        )
        .unwrap();
        assert!(check_global_json(&temp).is_ok());
        std::fs::write(
            temp.join("global.json"),
            "{\"sdk\":{\"version\":\"8.0.100\",\"rollForward\":\"disable\"}}",
        )
        .unwrap();
        assert!(check_global_json(&temp).is_err());
        std::fs::write(
            temp.join("global.json"),
            format!("{{\"sdk\":{{\"version\":\"{SDK_VERSION}\"}}}}"),
        )
        .unwrap();
        assert!(check_global_json(&temp).is_err()); // rollForward missing
        std::fs::write(
            temp.join("global.json"),
            "{\"msbuild-sdks\":{\"X\":\"1.0\"}}",
        )
        .unwrap();
        assert!(check_global_json(&temp).is_err());
        let _ = std::fs::remove_dir_all(&temp);
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
        let base = std::env::temp_dir().join(format!(
            "blanket-dn-preflight-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();

        let symlinked = base.join("symlinked");
        fs::create_dir(&symlinked).unwrap();
        fs::write(symlinked.join("project.xml"), minimal_csproj()).unwrap();
        symlink(
            symlinked.join("project.xml"),
            symlinked.join("project.csproj"),
        )
        .unwrap();
        assert!(preflight(&symlinked).is_err());

        let project_lock = base.join("project-lock");
        fs::create_dir(&project_lock).unwrap();
        fs::write(project_lock.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(
            project_lock.join("packages.lock.json"),
            r#"{"version":1,"dependencies":{"net9.0":{"Other":{"type":"Project","resolved":"1.0.0","contentHash":"A"}}}}"#,
        )
        .unwrap();
        let error = preflight(&project_lock).unwrap_err().to_string();
        assert!(error.contains("Project lock entries"), "{error}");

        let import = base.join("import");
        fs::create_dir(&import).unwrap();
        fs::write(
            import.join("project.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk\"><Import Project=\"evil.targets\" /></Project>",
        )
        .unwrap();
        assert!(preflight(&import).is_err());

        let bad_global = base.join("bad-global");
        fs::create_dir(&bad_global).unwrap();
        fs::write(bad_global.join("project.csproj"), minimal_csproj()).unwrap();
        fs::write(bad_global.join("global.json"), "{}").unwrap();
        assert!(preflight(&bad_global).is_err());

        let ancestor = base.join("ancestor");
        fs::create_dir(&ancestor).unwrap();
        fs::write(ancestor.join("global.json"), "{}").unwrap();
        let child = ancestor.join("child");
        fs::create_dir(&child).unwrap();
        fs::write(child.join("project.csproj"), minimal_csproj()).unwrap();
        let error = preflight(&child).unwrap_err().to_string();
        assert!(error.contains("ancestor global.json"), "{error}");

        let _ = crate::store::remove_tree(&base);
    }

    #[test]
    fn output_roots_reject_symlinks_and_metadata_source_is_fixed() {
        let base = std::env::temp_dir().join(format!(
            "blanket-dn-output-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let outside = base.join("outside");
        fs::create_dir(&outside).unwrap();
        let project = base.join("project");
        fs::create_dir(&project).unwrap();
        symlink(&outside, project.join("bin")).unwrap();
        assert!(checked_output_dir(&project, "fp").is_err());

        let project = base.join("project2");
        fs::create_dir_all(project.join("bin")).unwrap();
        symlink(&outside, project.join("bin/blanket-fp")).unwrap();
        assert!(checked_output_dir(&project, "fp").is_err());

        let metadata = base.join(".nupkg.metadata");
        fs::write(&metadata, r#"{"source":"/tmp/feed","version":2}"#).unwrap();
        rewrite_metadata_source(&metadata).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(metadata).unwrap()).unwrap();
        assert_eq!(value["source"], "blanket-feed");

        let _ = crate::store::remove_tree(&base);
    }
}
