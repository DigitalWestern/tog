//! The .NET tailor: NuGet packages.lock.json (v1, blanket-mandatory),
//! materialization delegated to the pinned NuGet, per-build fresh offline
//! restore, sandboxed builds only.
//!
//! Sol review 7 shaped this: signed nupkgs' contentHash is a SEMANTIC hash
//! over transformed bytes, so blanket never compares lock hashes to raw
//! downloads — the pinned NuGet verifies contentHash while installing into
//! the global-packages layout (locked mode), the same delegated-extractor
//! pattern as Go, with the SDK fingerprint in the object identity. The
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
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    let v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| err(format!("global.json: {e}")))?;
    if v.get("msbuild-sdks").is_some() {
        return Err(err("global.json msbuild-sdks is not supported yet (fail closed)"));
    }
    let sdk = &v["sdk"];
    if sdk.get("paths").is_some() {
        return Err(err("global.json sdk.paths is not supported (it redirects SDK discovery)"));
    }
    if let Some(want) = sdk["version"].as_str() {
        if want != SDK_VERSION {
            return Err(err(format!(
                "global.json requires SDK {want}; pinned: {SDK_VERSION}"
            )));
        }
        if sdk["rollForward"].as_str() != Some("disable") {
            return Err(err(
                "global.json must set \"rollForward\": \"disable\" (blanket pins the SDK exactly)",
            ));
        }
    }
    Ok(())
}

const ENV_REMOVE_PREFIXES: &[&str] = &["DOTNET_", "NUGET_", "MSBUILD"];
const ENV_REMOVE: &[&str] = &["MSBuildSDKsPath", "MSBuildExtensionsPath"];

fn forced_env(sdk_obj: &Path, packages: &Path, scratch: &Path) -> Vec<(String, String)> {
    vec![
        ("DOTNET_ROOT".to_string(), sdk_obj.display().to_string()),
        ("NUGET_PACKAGES".to_string(), packages.display().to_string()),
        ("DOTNET_CLI_TELEMETRY_OPTOUT".to_string(), "1".to_string()),
        ("DOTNET_NOLOGO".to_string(), "1".to_string()),
        ("DOTNET_CLI_HOME".to_string(), scratch.display().to_string()),
        ("DOTNET_SKIP_FIRST_TIME_EXPERIENCE".to_string(), "1".to_string()),
        ("HOME".to_string(), scratch.display().to_string()),
        ("XDG_CONFIG_HOME".to_string(), scratch.join("xdg").display().to_string()),
        ("XDG_CACHE_HOME".to_string(), scratch.join("xdg-cache").display().to_string()),
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
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        && !s.starts_with('.')
        && !s.contains("..")
}

fn validate_plan(plan: &DotnetPlan) -> io::Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for p in &plan.packages {
        if !valid_id(&p.id) || !valid_id(&p.version) {
            return Err(err(format!("invalid package coordinates: {p:?}")));
        }
        // contentHash: base64 sha512 (88 chars with padding).
        if p.content_hash.len() > 100
            || !p.content_hash.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
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
            return Err(err("solution files are not supported yet; sync a single project"));
        }
        if name.ends_with(".csproj") {
            found.push(path);
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(err("no .csproj found")),
        _ => Err(err("multiple .csproj files; blanket supports one project per directory in v0")),
    }
}

/// Plan from packages.lock.json (v1 only; blanket makes the opt-in lock
/// mandatory). Missing lock delegates a store-SDK restore --use-lock-file
/// (named resolver mutation, isolated caches).
pub fn plan_dotnet(
    store: &Store,
    project_dir: &Path,
    sdk_obj: &Path,
) -> io::Result<(DotnetPlan, String)> {
    check_global_json(project_dir)?;
    let csproj = find_project(project_dir)?;
    let lock_path = project_dir.join("packages.lock.json");
    if !lock_path.is_file() {
        eprintln!("blanket: no packages.lock.json; resolving with the store SDK...");
        let scratch = store.stage()?;
        let out = run_dotnet(
            sdk_obj,
            project_dir,
            &scratch.join("pkgs"),
            &scratch,
            &["restore", "--use-lock-file"],
        )?;
        let ok = out.status.success();
        let _ = crate::store::remove_tree(&scratch);
        if !ok {
            return Err(err(format!(
                "store dotnet restore --use-lock-file failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
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
                Some("Project") => continue,
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
        return Err(err("packages.lock.json changed while planning; re-run blanket sync"));
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
    fs::create_dir_all(packages)?;
    fs::create_dir_all(scratch)?;
    let mut cmd = Command::new(sdk_obj.join("dotnet"));
    cmd.args(args).current_dir(cwd);
    cmd.env("PATH", format!("{}:/usr/bin:/bin", sdk_obj.display()));
    cmd.env("TMPDIR", scratch);
    force_env(&mut cmd, ENV_REMOVE_PREFIXES, ENV_REMOVE, &forced_env(sdk_obj, packages, scratch));
    cmd.stdin(std::process::Stdio::null());
    cmd.output()
        .map_err(|e| io::Error::new(e.kind(), format!("run store dotnet {args:?}: {e}")))
}

/// Realize the global-packages object: blanket fetches every nupkg into a
/// local folder feed (raw bytes cached by sha256), then the PINNED NuGet
/// installs from that feed in LOCKED mode — it verifies each package's
/// semantic contentHash against the lock and writes the exact
/// global-packages layout (.nupkg.sha512/.nupkg.metadata/nuspec). The SDK
/// is the extractor, so its fingerprint is an identity input (Go
/// precedent). Network denied at install: the feed is local.
pub fn realize_packages(
    store: &Store,
    plan: &DotnetPlan,
    sdk_obj: &Path,
    project_dir: &Path,
) -> io::Result<PathBuf> {
    validate_plan(plan)?;
    let mut inputs = BTreeMap::from([
        ("schema".to_string(), "nuget-packages/1".to_string()),
        ("extractor".to_string(), format!("sdk{SDK_VERSION}:{}", sdk_fingerprint())),
    ]);
    for p in &plan.packages {
        inputs.insert(
            format!("pkg:{}@{}", p.id.to_ascii_lowercase(), p.version),
            p.content_hash.clone(),
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
        return Ok(store.object_path(&id));
    }

    // Fetch every nupkg (nuget.org flatcontainer only in v0). No upfront
    // per-file hash exists (contentHash is semantic): download to tmp,
    // record raw sha256 via cache_insert, verify semantically below.
    let scratch = store.stage()?;
    let feed = scratch.join("feed");
    fs::create_dir_all(&feed)?;
    for p in &plan.packages {
        let idl = p.id.to_ascii_lowercase();
        let verl = p.version.to_ascii_lowercase();
        let url = format!(
            "https://api.nuget.org/v3-flatcontainer/{idl}/{verl}/{idl}.{verl}.nupkg"
        );
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
        let (_, _) = cache_insert(store, &tmp)?;
        fs::rename(&tmp, feed.join(format!("{idl}.{verl}.nupkg")))?;
    }

    // Locked-mode restore from the local feed into the staged folder: the
    // pinned NuGet verifies every contentHash and builds the layout.
    let staged = store.stage()?;
    let work = scratch.join("verify");
    fs::create_dir_all(&work)?;
    for f in ["packages.lock.json"] {
        fs::copy(project_dir.join(f), work.join(f))?;
    }
    let csproj = find_project(project_dir)?;
    fs::copy(&csproj, work.join(csproj.file_name().unwrap()))?;
    if project_dir.join("global.json").is_file() {
        fs::copy(project_dir.join("global.json"), work.join("global.json"))?;
    }
    fs::write(
        work.join("nuget.config"),
        format!(
            "<configuration><packageSources><clear /><add key=\"blanket-feed\" \
             value=\"{}\" /></packageSources><config><add key=\"updatePackageLastAccessTime\" \
             value=\"false\" /></config></configuration>",
            feed.display()
        ),
    )?;
    let out = run_dotnet(
        sdk_obj,
        &work,
        &staged,
        &scratch,
        &[
            "restore",
            "--locked-mode",
            "--no-cache",
            "--disable-build-servers",
            "--configfile",
            "nuget.config",
        ],
    )?;
    if !out.status.success() {
        let _ = crate::store::remove_tree(&scratch);
        return Err(err(format!(
            "locked-mode package verification failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
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
            return Err(err(format!(
                "{}@{}: not materialized by locked restore",
                p.id, p.version
            )));
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

/// Sandboxed build: fresh offline locked restore into scratch obj, attest
/// assets, then build --no-restore. Project obj/ is never authority (Sol).
pub fn build_sandboxed(
    project_dir: &Path,
    sdk_obj: &Path,
    packages_obj: &Path,
    args: &[String],
) -> io::Result<()> {
    for arg in args {
        let norm = arg.trim_start_matches('-').to_ascii_lowercase();
        for banned in ["p:restoresources", "p:restorepackagespath", "p:baseintermediateoutputpath",
                       "p:msbuildprojectextensionspath", "source", "packages", "configfile", "@"] {
            if norm.starts_with(banned) || arg.starts_with('@') {
                return Err(err(format!("{arg}: this argument is managed by blanket")));
            }
        }
    }
    let project_dir = project_dir.canonicalize()?;
    let sdk_obj = sdk_obj.canonicalize()?;
    let packages_obj = packages_obj.canonicalize()?;
    let store = Store::open()?;
    let scratch = store.stage()?;
    let objdir = scratch.join("obj");
    let bin = project_dir.join(format!("bin/blanket-{}", sdk_fingerprint()));
    fs::create_dir_all(&objdir)?;
    fs::create_dir_all(&bin)?;
    let bin = bin.canonicalize()?;
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
            format!("-p:MSBuildProjectExtensionsPath={}/", objdir.display()),
            format!("-p:BaseIntermediateOutputPath={}/", objdir.display()),
            "-p:UseSharedCompilation=false".to_string(),
            "-nodeReuse:false".to_string(),
            "--disable-build-servers".to_string(),
        ]
    };
    // CoreCLR named mutexes live hardcoded at /tmp/.dotnet — a bounded,
    // local-only write root (no data flows out through it).
    let shm = PathBuf::from("/private/tmp/.dotnet");
    fs::create_dir_all(&shm)?;
    let env: Vec<(String, String)> = forced_env(&sdk_obj, &packages_obj, &scratch);
    let mut restore = common("restore");
    restore.extend([
        "--locked-mode".to_string(),
        "--no-cache".to_string(),
        "--configfile".to_string(),
        scratch.join("nuget.config").display().to_string(),
    ]);
    let spec = BuildSpec {
        argv: restore,
        cwd: project_dir.clone(),
        env: env.clone(),
        read: vec![project_dir.clone(), sdk_obj.clone(), packages_obj.clone()],
        write: vec![bin.clone(), shm.clone()],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
    };
    run_build_spec(&spec).map_err(|e| {
        err(format!("offline locked restore failed: {e}; network is denied — \
                     packages outside the lock, framework packs, or workloads \
                     are unsupported in v0"))
    })?;
    if !objdir.join("project.assets.json").is_file() {
        return Err(err("restore produced no project.assets.json"));
    }
    let mut build = common("build");
    build.push("--no-restore".to_string());
    build.push(format!("-p:OutputPath={}/", bin.display()));
    build.extend(args.iter().cloned());
    let spec = BuildSpec {
        argv: build,
        cwd: project_dir.clone(),
        env,
        read: vec![project_dir.clone(), sdk_obj.clone(), packages_obj.clone()],
        write: vec![bin.clone(), shm.clone()],
        scratch: scratch.clone(),
        path: format!("{}:/usr/bin:/bin", sdk_obj.display()),
    };
    let result = run_build_spec(&spec).map_err(|e| {
        err(format!("dotnet build failed: {e}\n(network is denied during builds)"))
    });
    let _ = crate::store::remove_tree(&scratch);
    result?;
    eprintln!("blanket: built into {}", bin.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(validate_plan(&DotnetPlan { packages: vec![evil], ..ok.clone() }).is_err());
        let mut bad = base.clone();
        bad.content_hash = "not/base64\n".into();
        assert!(validate_plan(&DotnetPlan { packages: vec![bad], ..ok.clone() }).is_err());
    }

    #[test]
    fn global_json_gate() {
        let temp = std::env::temp_dir().join(format!(
            "blanket-dn-gj-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        assert!(check_global_json(&temp).is_ok()); // absent
        std::fs::write(temp.join("global.json"),
            format!("{{\"sdk\":{{\"version\":\"{SDK_VERSION}\",\"rollForward\":\"disable\"}}}}")).unwrap();
        assert!(check_global_json(&temp).is_ok());
        std::fs::write(temp.join("global.json"),
            "{\"sdk\":{\"version\":\"8.0.100\",\"rollForward\":\"disable\"}}").unwrap();
        assert!(check_global_json(&temp).is_err());
        std::fs::write(temp.join("global.json"),
            format!("{{\"sdk\":{{\"version\":\"{SDK_VERSION}\"}}}}")).unwrap();
        assert!(check_global_json(&temp).is_err()); // rollForward missing
        std::fs::write(temp.join("global.json"),
            "{\"msbuild-sdks\":{\"X\":\"1.0\"}}").unwrap();
        assert!(check_global_json(&temp).is_err());
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn build_rejects_managed_args_and_run_verbs_enumerated() {
        for bad in ["-p:RestoreSources=https://evil", "--source", "@resp.rsp", "--configfile"] {
            let e = build_sandboxed(
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                Path::new("/nonexistent"),
                &[bad.to_string()],
            )
            .unwrap_err()
            .to_string();
            assert!(e.contains("managed by blanket"), "{bad}: {e}");
        }
        for v in ["build", "test", "publish", "msbuild", "restore"] {
            assert!(BUILD_VERBS.contains(&v));
        }
    }
}
