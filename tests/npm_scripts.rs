//! Acceptance: npm install scripts run in the sandbox; strict mode rejects a
//! network attempt while permissive mode retains it as a cached exception.
//!
//! The cases that need a real Node (or a real network to deny) realize the
//! pinned release on first run, so they are #[ignore]d and run in the heavy
//! workflow:
//!     cargo test --test npm_scripts -- --ignored
//! The rest run offline on every PR: Node and node-gyp's CPython are stubs
//! (tests/common/node_stub.rs), so their install scripts are plain `sh`.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use sha2::{Digest as Sha2Digest, Sha512};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tog::comforter;
use tog::kernel::fetch::{self, Digest};
use tog::kernel::platform::Platform;
use tog::kernel::policy;
use tog::kernel::store::Store;
use tog::tailors::node::{self, NpmPackage, NpmPlan};

mod common;

use common::node_stub::{sandbox_or_skip, seed_gyp_python, seed_shipped_node, stub_node_selection};
use common::{tar_create, tog, TempDir};

/// Build a one-package tarball whose postinstall runs `script`.
fn make_pkg_tarball(dir: &std::path::Path, script: &str) -> (PathBuf, String) {
    let pkg = dir.join("package");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(
            r#"{{"name":"fixture-pkg","version":"1.0.0","scripts":{{"postinstall":{}}}}}"#,
            serde_json::to_string(script).unwrap()
        ),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), "module.exports = 1;\n").unwrap();
    let tarball = dir.join("fixture-pkg-1.0.0.tgz");
    let status = tar_create()
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(dir)
        .arg("package")
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = std::fs::read(&tarball).unwrap();
    let sri = format!("sha512-{}", b64(&Sha512::digest(&bytes)));
    (tarball, sri)
}

/// Minimal standard base64 encoder (test-only; the crate has no base64 dep).
fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn plan_for(tarball: &std::path::Path, sri: &str) -> NpmPlan {
    NpmPlan {
        node_version: "24.20.0".into(),
        lock_source: "package-lock.json".into(),
        packages: vec![NpmPackage {
            path: "node_modules/fixture-pkg".into(),
            name: "fixture-pkg".into(),
            version: "1.0.0".into(),
            url: format!("file://{}", tarball.display()),
            integrity: sri.into(),
            bin: vec![],
            patch: None,
            git: None,
            optional: false,
            foreign_platform: false,
            needs_workspace: false,
        }],
        links: vec![],
        workspaces: vec![],
    }
}

/// Same as `make_pkg_tarball`, but the package can be named: the
/// skip-download table is keyed by package name.
fn make_named_pkg_tarball(dir: &std::path::Path, name: &str, script: &str) -> (PathBuf, String) {
    let pkg = dir.join("package");
    let _ = std::fs::remove_dir_all(&pkg);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(
            r#"{{"name":{},"version":"1.0.0","scripts":{{"postinstall":{}}}}}"#,
            serde_json::to_string(name).unwrap(),
            serde_json::to_string(script).unwrap()
        ),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), "module.exports = 1;\n").unwrap();
    let tarball = dir.join(format!("{name}-1.0.0.tgz"));
    let status = tar_create()
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(dir)
        .arg("package")
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = std::fs::read(&tarball).unwrap();
    let sri = format!("sha512-{}", b64(&Sha512::digest(&bytes)));
    (tarball, sri)
}

fn plan_named(tarball: &std::path::Path, sri: &str, name: &str) -> NpmPlan {
    let mut plan = plan_for(tarball, sri);
    plan.packages[0].name = name.to_string();
    plan.packages[0].path = format!("node_modules/{name}");
    plan
}

/// Realize `plan` against a stub Node and node-gyp CPython, so the case
/// needs no network: the plan's Node version is the stub selection's. A
/// script that fails is only an exception in permissive mode, so the env is
/// checked to carry none, and a broken script reads as itself rather than
/// as a missing output file.
fn realize_offline(dir: &Path, platform: Platform, mut plan: NpmPlan) -> PathBuf {
    let store = store_at(dir);
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let selected = stub_node_selection(dir, &store, activity, platform);
    seed_gyp_python(&store, platform);
    plan.node_version = selected.version("node").unwrap().to_string();
    let env = node::realize_node_env_for(
        &store,
        activity,
        platform,
        &plan,
        &[],
        &selected,
        &node::shipped_gyp_python().unwrap(),
    )
    .expect("realize");
    let exceptions = store
        .exceptions(env.file_name().unwrap().to_str().unwrap())
        .unwrap();
    assert!(
        exceptions
            .iter()
            .all(|exception| exception.kind != policy::INSTALL_SCRIPT_FAILED),
        "the install script failed: {exceptions:?}"
    );
    env
}

/// `policy`'s pending-exception list is process-global, so tests that record
/// exceptions must not overlap: one test's exception would otherwise land in
/// another's closure. Every test here that realizes an env holds this.
fn policy_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
}

fn store_at(dir: &std::path::Path) -> Store {
    let root = dir.join("store");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    Store {
        root: root.canonicalize().unwrap(),
    }
}

fn make_fixture_tarball(
    dir: &Path,
    package_name: &str,
    package_json: &str,
    files: &[(&str, &[u8])],
) -> (PathBuf, String) {
    let source = dir.join(format!("{package_name}-source"));
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("package.json"), package_json).unwrap();
    for (relative, contents) in files {
        let path = source.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }
    let tarball = dir.join(format!("{package_name}-1.0.0.tgz"));
    let status = tar_create()
        .args(["-czf"])
        .arg(&tarball)
        .args(["-C"])
        .arg(dir)
        .arg(source.file_name().unwrap())
        .status()
        .unwrap();
    assert!(status.success());
    let bytes = std::fs::read(&tarball).unwrap();
    (tarball, format!("sha512-{}", b64(&Sha512::digest(&bytes))))
}

fn seed_verified_fixture(store: &Store, tarball: &Path, sri: &str) {
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let digest = Digest::from_sri(sri).unwrap();
    fetch::download_verified_digest(
        store,
        activity,
        &format!("file://{}", tarball.display()),
        &digest,
    )
    .unwrap();
}

fn add_fixture_dependency(project: &Path, package_name: &str, sri: &str) {
    let package_path = project.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&package_path).unwrap()).unwrap();
    package["dependencies"][package_name] = serde_json::json!("1.0.0");
    std::fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();

    let lock_path = project.join("package-lock.json");
    let mut lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    lock["packages"][""]["dependencies"][package_name] = serde_json::json!("1.0.0");
    lock["packages"].as_object_mut().unwrap().insert(
        format!("node_modules/{package_name}"),
        serde_json::json!({
            "name": package_name,
            "version": "1.0.0",
            "resolved": format!("https://fixture.invalid/{package_name}-1.0.0.tgz"),
            "integrity": sri,
        }),
    );
    assert_eq!(
        package["dependencies"], lock["packages"][""]["dependencies"],
        "package.json and package-lock.json root dependencies diverged"
    );
    std::fs::write(&lock_path, serde_json::to_vec_pretty(&lock).unwrap()).unwrap();
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Publish the `tog-toolchain.toml` section a writable sync of `project`
/// would write for `ecosystem` (a tailor id), through the same selection and
/// writer the binary uses.
fn commit_toolchain_lock(project: &Path, ecosystem: &str) {
    use tog::kernel::toolchain::lock::{ToolchainLock, LOCK_PATH};
    let tailor = tog::tailors::by_id(ecosystem).unwrap();
    let lock_ecosystem = tailor.lock_ecosystem();
    let root = tog::kernel::fsroot::ProjectRoot::open(project).unwrap();
    let rows = tog::kernel::toolchain::input::discover(&root, lock_ecosystem).unwrap();
    let catalog = tailor.toolchain_catalog().unwrap();
    let bundle = tog::kernel::toolchain::select_for(&catalog, lock_ecosystem, &rows).unwrap();
    let mut lock = ToolchainLock::read_via(&root)
        .unwrap()
        .unwrap_or_else(|| ToolchainLock::new(env!("CARGO_PKG_VERSION")));
    lock.set_ecosystem(lock_ecosystem, bundle, &rows).unwrap();
    std::fs::write(project.join(LOCK_PATH), lock.canonical_bytes()).unwrap();
}

#[test]
#[ignore]
fn network_access_during_install_script_fails() {
    let _policy_guard = policy_guard();
    let platform = Platform::host().expect("host platform");
    if let Ok(dir) = std::env::var("TOG_NPM_STRICT_CHILD") {
        let _attribution = policy::Attribution::open("node").expect("test attribution");
        policy::init(std::path::Path::new(&dir)).unwrap();
        let tarball = PathBuf::from(std::env::var("TOG_NPM_TARBALL").unwrap());
        let sri = std::env::var("TOG_NPM_SRI").unwrap();
        let store = Store::open().expect("store");
        let activity = &store
            .activity(tog::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let result =
            node::realize_node_env(&store, activity, platform, &plan_for(&tarball, &sri), &[]);
        let err = result.expect_err("install script reaching the network must fail");
        assert!(
            err.to_string().contains("network-denied"),
            "unexpected error shape: {err}"
        );
        return;
    }
    let temp = TempDir::new("evil-npm");
    let dir = temp.path();
    // Network probe: connects to an IP literal, so no resolver is involved,
    // and says how the connect ended on its stderr, which the sandbox
    // relays to the strict child's stderr. Exits 0 when connected, 1 not.
    let (tarball, sri) = make_pkg_tarball(
        dir,
        "node -e \"require('net').connect(443, '1.1.1.1')\
         .on('connect', () => { console.error('TOG-PROBE connected'); process.exit(0) })\
         .on('error', (e) => { console.error('TOG-PROBE connect failed: ' + e.code); process.exit(1) })\"",
    );
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "network_access_during_install_script_fails",
            "--ignored",
            "--nocapture",
        ])
        .env("TOG_STORE", dir.join("store"))
        .env("TOG_NPM_STRICT_CHILD", dir)
        .env("TOG_NPM_TARBALL", &tarball)
        .env("TOG_NPM_SRI", &sri)
        .env("TOG_STRICT", "1")
        .env_remove("TOG_POLICY")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(child.status.success(), "strict child failed: {stderr}");
    // "network-denied" is in every strict script failure's message; the
    // probe's own words say the failure was the connect, refused by a
    // namespace with no route out (not a DNS error, not a timeout).
    assert!(!stderr.contains("TOG-PROBE connected"), "{stderr}");
    assert!(
        stderr.contains("TOG-PROBE connect failed: ENETUNREACH"),
        "the install script did not fail on a refused connection:\n{stderr}"
    );
}

#[test]
#[ignore]
fn permissive_install_script_is_cached_but_rejected_strict() {
    let _policy_guard = policy_guard();
    let platform = Platform::host().expect("host platform");
    if let Ok(dir) = std::env::var("TOG_NPM_CACHED_CHILD") {
        policy::init(std::path::Path::new(&dir)).unwrap();
        let tarball = PathBuf::from(std::env::var("TOG_NPM_TARBALL").unwrap());
        let sri = std::env::var("TOG_NPM_SRI").unwrap();
        let store = Store::open().expect("store");
        let activity = &store
            .activity(tog::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let err =
            node::realize_node_env(&store, activity, platform, &plan_for(&tarball, &sri), &[])
                .expect_err("strict sync must reject the cached exception");
        assert!(err.to_string().contains("install-script-failed"));
        assert!(err.to_string().contains("'tog --fresh' will not help"));
        return;
    }
    let temp = TempDir::new("permissive-npm");
    let dir = temp.path();
    let (tarball, sri) = make_pkg_tarball(
        dir,
        "node -e \"require('fs').writeFileSync('partial.txt','partial'); require('https').get('https://registry.npmjs.org/', \
         () => process.exit(0)).on('error', () => process.exit(1))\"",
    );
    let store = store_at(dir);
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    policy::init(dir).unwrap();
    let plan = plan_for(&tarball, &sri);
    let mut attribution = policy::Attribution::open("node").expect("test attribution");
    let env =
        node::realize_node_env(&store, activity, platform, &plan, &[]).expect("permissive realize");
    let package_dir = env.join("node_modules/fixture-pkg");
    assert!(package_dir.is_dir());
    assert!(package_dir.join("package.json").is_file());
    assert!(!package_dir.join("partial.txt").exists());
    let project = tog::kernel::fsroot::ProjectRoot::open(dir).unwrap();
    node::project_node_env(
        activity,
        &project,
        &env,
        platform,
        &plan,
        &[],
        false,
        &mut attribution,
    )
    .expect("project");
    attribution.finish(true).expect("test closure attribution");
    let closure = comforter::read_closure(dir, "node").unwrap();
    let exceptions = closure["exceptions"].as_array().unwrap();
    assert_eq!(exceptions.len(), 1);
    assert_eq!(exceptions[0]["kind"], "install-script-failed");

    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "permissive_install_script_is_cached_but_rejected_strict",
            "--ignored",
            "--nocapture",
        ])
        .env("TOG_STORE", dir.join("store"))
        .env("TOG_NPM_CACHED_CHILD", dir)
        .env("TOG_NPM_TARBALL", &tarball)
        .env("TOG_NPM_SRI", &sri)
        .env("TOG_STRICT", "1")
        .env_remove("TOG_POLICY")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "strict cached child failed: {}",
        String::from_utf8_lossy(&child.stderr)
    );
}

#[test]
fn benign_install_script_runs_and_output_is_captured() {
    let platform = Platform::host().expect("host platform");
    if !sandbox_or_skip(
        "benign_install_script_runs_and_output_is_captured",
        platform,
    ) {
        return;
    }
    let _policy_guard = policy_guard();
    let _attribution = policy::Attribution::open("node").expect("test attribution");
    let temp = TempDir::new("good-npm");
    let dir = temp.path();
    let (tarball, sri) = make_pkg_tarball(dir, "printf ok > built.txt");
    let env = realize_offline(dir, platform, plan_for(&tarball, &sri));
    let built = env.join("node_modules/fixture-pkg/built.txt");
    assert_eq!(std::fs::read_to_string(built).unwrap(), "ok");
}

#[test]
#[ignore]
fn linux_npm_roundtrip() {
    let _policy_guard = policy_guard();
    let _attribution = policy::Attribution::open("node").expect("test attribution");
    if !cfg!(target_os = "linux") {
        eprintln!("linux_npm_roundtrip skipped: supported Linux only");
        return;
    }

    let platform = Platform::host().expect("Linux glibc host platform");
    assert_eq!(platform, Platform::X86_64UnknownLinuxGnu);
    let temp = TempDir::new("npm-scripts");
    let project = &temp.0;
    let store = store_at(project);
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let store_root = store.root.clone();
    let node = node::ensure_node_for(&store, activity, platform).expect("pinned Linux Node");
    let node_bin = node.join("bin");
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"linux-npm-roundtrip","version":"1.0.0","private":true,"dependencies":{"esbuild":"0.25.9"}}"#,
    )
    .unwrap();

    // The lock is generated by the pinned npm bundled with the pinned Node,
    // never by a host npm. Both optional platform packages must be present in
    // the generated lock before tog applies its platform selector.
    let npm_lock = Command::new(node.join("bin/npm"))
        .current_dir(project)
        .env("TOG_STORE", &store_root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                node_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .args([
            "install",
            "--package-lock-only",
            "--ignore-scripts",
            "--include=optional",
            "--save-exact",
            "--no-audit",
            "--no-fund",
        ])
        .output()
        .unwrap();
    assert_success(&npm_lock, "pinned npm package-lock generation");
    let generated_lock = std::fs::read_to_string(project.join("package-lock.json")).unwrap();
    assert!(generated_lock.contains("node_modules/@esbuild/linux-x64"));
    assert!(generated_lock.contains("node_modules/@esbuild/darwin-arm64"));

    let addon_package = serde_json::json!({
        "name": "fixture-addon",
        "version": "1.0.0",
        "main": "index.js"
    })
    .to_string();
    let (addon_tarball, addon_sri) = make_fixture_tarball(
        project,
        "fixture-addon",
        &addon_package,
        &[
            (
                "binding.gyp",
                br#"{
  "targets": [{"target_name": "addon", "sources": ["addon.c"]}]
}"#,
            ),
            (
                "addon.c",
                br#"#include <node_api.h>

static napi_value answer(napi_env env, napi_callback_info info) {
  napi_value value;
  napi_create_int32(env, 42, &value);
  return value;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value function;
  napi_create_function(env, "answer", NAPI_AUTO_LENGTH, answer, NULL, &function);
  napi_set_named_property(env, exports, "answer", function);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
"#,
            ),
            (
                "index.js",
                b"module.exports = require('./build/Release/addon.node');\n",
            ),
        ],
    );
    let containment_script = "node -e \"const fs=require('fs');fs.writeFileSync('generated.txt','captured');let denied=false;try{fs.writeFileSync('../escape.txt','escaped')}catch(_){denied=true}if(!denied)process.exit(23)\"";
    let script_package = serde_json::json!({
        "name": "fixture-script",
        "version": "1.0.0",
        "scripts": {"postinstall": containment_script},
        "main": "index.js"
    })
    .to_string();
    let (script_tarball, script_sri) = make_fixture_tarball(
        project,
        "fixture-script",
        &script_package,
        &[("index.js", b"module.exports = 'script';\n")],
    );

    // Lock entries use synthetic HTTPS URLs, while their verified cache
    // entries are seeded through tog's normal digest-checked API. This
    // exercises cache reuse without weakening production HTTPS validation.
    seed_verified_fixture(&store, &addon_tarball, &addon_sri);
    seed_verified_fixture(&store, &script_tarball, &script_sri);
    add_fixture_dependency(project, "fixture-addon", &addon_sri);
    add_fixture_dependency(project, "fixture-script", &script_sri);

    // Strict policy never creates the toolchain lock, so the project commits
    // one first, exactly as a user runs `tog` once before CI goes strict.
    commit_toolchain_lock(project, "node");
    let synced = tog(project, &temp.0, &["sync", "--strict"]);
    assert_success(&synced, "tog --strict");

    let closure = comforter::read_closure(project, "node").unwrap();
    let package_paths: Vec<&str> = closure["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|package| package["path"].as_str())
        .collect();
    assert!(package_paths.contains(&"node_modules/@esbuild/linux-x64"));
    assert!(!package_paths.contains(&"node_modules/@esbuild/darwin-arm64"));
    let exceptions = closure["exceptions"].as_array().unwrap();
    assert!(exceptions
        .iter()
        .all(|exception| { exception["kind"].as_str() != Some("install-script-failed") }));

    let env_object = PathBuf::from(closure["env_object"].as_str().unwrap());
    assert_eq!(
        std::fs::read_to_string(env_object.join("node_modules/fixture-script/generated.txt"))
            .unwrap(),
        "captured"
    );
    assert!(!env_object.join("node_modules/escape.txt").exists());
    assert!(env_object
        .join("node_modules/fixture-addon/build/Release/addon.node")
        .is_file());

    let node_check = r#"
const esbuild = require('esbuild');
const addon = require('fixture-addon');
if (process.version !== 'v24.20.0' || process.platform !== 'linux' || process.arch !== 'x64') process.exit(10);
// The platform packages ship only bin/ + package.json (no main), so resolve
// the manifest rather than the package itself.
if (!require.resolve('@esbuild/linux-x64/package.json').includes('@esbuild/linux-x64')) process.exit(11);
try { require.resolve('@esbuild/darwin-arm64/package.json'); process.exit(12); } catch (_) {}
if (addon.answer() !== 42) process.exit(13);
esbuild.transformSync('const answer = 42', {loader: 'js'});
console.log('linux-npm-roundtrip-ok');
"#;
    let run = tog(project, &temp.0, &["run", "node", "-e", node_check]);
    assert_success(&run, "tog run Node/esbuild/addon check");
    assert!(String::from_utf8_lossy(&run.stdout).contains("linux-npm-roundtrip-ok"));

    // Re-project with identical inputs after clearing every downloaded npm
    // archive. Archive classification is persisted separately, so the Linux
    // warm lookup must find the environment before it attempts any fetch.
    for entry in std::fs::read_dir(store_root.join("cache/sha512")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            std::fs::remove_file(path).unwrap();
        }
    }
    assert_eq!(
        std::fs::read_dir(store_root.join("cache/sha512"))
            .unwrap()
            .count(),
        0
    );
    let repeated = tog(project, &temp.0, &["sync", "--strict"]);
    assert_success(&repeated, "offline warm sync --strict");
    let repeated_closure = comforter::read_closure(project, "node").unwrap();
    assert_eq!(
        repeated_closure["env_object"], closure["env_object"],
        "identical inputs produced a different node environment object"
    );
    let repeated_run = tog(project, &temp.0, &["run", "node", "-e", node_check]);
    assert_success(&repeated_run, "repeat tog run Node/esbuild/addon check");
}

#[test]
fn skip_download_switch_is_injected_and_recorded() {
    if !sandbox_or_skip(
        "skip_download_switch_is_injected_and_recorded",
        Platform::host().expect("host platform"),
    ) {
        return;
    }
    let _policy_guard = policy_guard();
    let attribution = policy::Attribution::open("node").expect("test attribution");
    // puppeteer's installer reads PUPPETEER_SKIP_DOWNLOAD (verified against the
    // package's own getConfiguration.js). The script here asserts the switch is
    // visible to the lifecycle process, which is what makes the real installer
    // return without touching the denied network.
    let platform = Platform::host().expect("host platform");
    let temp = TempDir::new("skip-npm");
    let dir = temp.path();
    let (tarball, sri) = make_named_pkg_tarball(
        dir,
        "puppeteer",
        "[ \"$PUPPETEER_SKIP_DOWNLOAD\" = true ] || exit 3; printf ok > skipped.txt",
    );
    let env = realize_offline(dir, platform, plan_named(&tarball, &sri, "puppeteer"));
    assert_eq!(
        std::fs::read_to_string(env.join("node_modules/puppeteer/skipped.txt")).unwrap(),
        "ok"
    );
    // The skip is recorded: the user learns the browser was not
    // downloaded and the one command that downloads it.
    let skipped: Vec<_> = attribution
        .recorded()
        .into_iter()
        .filter(|exception| exception.kind == policy::ARTIFACT_NOT_PROVISIONED)
        .collect();
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert_eq!(skipped[0].subject, "puppeteer@1.0.0");
    assert_eq!(
        skipped[0].detail,
        "install-time download skipped; run: npx puppeteer browsers install chrome"
    );
    attribution.discard();
}

#[test]
fn prebuilt_downloader_is_told_to_build_from_source() {
    if !sandbox_or_skip(
        "prebuilt_downloader_is_told_to_build_from_source",
        Platform::host().expect("host platform"),
    ) {
        return;
    }
    let _policy_guard = policy_guard();
    let _attribution = policy::Attribution::open("test").expect("test attribution");
    // A prebuild-install style script: with the network denied the download can
    // never succeed, so tog asks for the source build up front.
    let platform = Platform::host().expect("host platform");
    let temp = TempDir::new("src-npm");
    let dir = temp.path();
    let (tarball, sri) = make_named_pkg_tarball(
        dir,
        "fake-prebuilt",
        "[ \"$npm_config_build_from_source\" = true ] || exit 3; printf ok > compiled.txt # prebuild-install",
    );
    let env = realize_offline(dir, platform, plan_named(&tarball, &sri, "fake-prebuilt"));
    assert_eq!(
        std::fs::read_to_string(env.join("node_modules/fake-prebuilt/compiled.txt")).unwrap(),
        "ok"
    );
}

/// A project that locks Python builds its native addons on that Python.
/// node-gyp's interpreter is the project's CPython 3.13, not the shipped
/// 3.12 a Node-only project gets, and the `node-env/5` identity names it,
/// so the two projects never share an environment object.
#[test]
#[ignore]
fn node_gyp_builds_on_the_projects_locked_python() {
    let _policy_guard = policy_guard();
    if !cfg!(target_os = "linux") {
        eprintln!("node_gyp_builds_on_the_projects_locked_python skipped: supported Linux only");
        return;
    }
    let temp = TempDir::new("npm-scripts");
    let store = store_at(&temp.0);
    let store_root = store.root.clone();
    let record_python = "\"$PYTHON\" -c \"import sys; open('python-version.txt', 'w').write('%d.%d.%d' % sys.version_info[:3])\"";
    let addon_package = serde_json::json!({
        "name": "fixture-addon",
        "version": "1.0.0",
        "main": "index.js",
        "scripts": {"postinstall": record_python}
    })
    .to_string();
    let (addon_tarball, addon_sri) = make_fixture_tarball(
        &temp.0,
        "fixture-addon",
        &addon_package,
        &[
            (
                "binding.gyp",
                br#"{"targets": [{"target_name": "addon", "sources": ["addon.c"]}]}"#,
            ),
            (
                "addon.c",
                br#"#include <node_api.h>
static napi_value init(napi_env env, napi_value exports) { return exports; }
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
"#,
            ),
            (
                "index.js",
                b"module.exports = require('./build/Release/addon.node');\n",
            ),
        ],
    );
    seed_verified_fixture(&store, &addon_tarball, &addon_sri);

    let mut envs = Vec::new();
    for (name, locked_python, expected) in [
        ("locks-python", Some("3.13"), "3.13.15"),
        ("node-only", None, "3.12.14"),
    ] {
        let project = temp.0.join(name);
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("package.json"),
            format!(r#"{{"name":"{name}","version":"1.0.0","private":true}}"#),
        )
        .unwrap();
        std::fs::write(
            project.join("package-lock.json"),
            format!(
                r#"{{"name":"{name}","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{{"":{{"name":"{name}","version":"1.0.0"}}}}}}"#
            ),
        )
        .unwrap();
        add_fixture_dependency(&project, "fixture-addon", &addon_sri);
        if let Some(line) = locked_python {
            std::fs::write(project.join(".python-version"), format!("{line}\n")).unwrap();
            std::fs::write(
                project.join("pyproject.toml"),
                format!(
                    "[project]\nname = \"{name}\"\nversion = \"0.1.0\"\nrequires-python = \">={line}\"\ndependencies = []\n"
                ),
            )
            .unwrap();
        }

        let synced = tog(&project, &temp.0, &["sync"]);
        assert_success(&synced, &format!("tog sync ({name})"));
        let lock = std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap();
        assert_eq!(lock.contains("cpython"), locked_python.is_some(), "{lock}");

        let closure = comforter::read_closure(&project, "node").unwrap();
        let env_object = PathBuf::from(closure["env_object"].as_str().unwrap());
        let addon = env_object.join("node_modules/fixture-addon");
        assert!(addon.join("build/Release/addon.node").is_file(), "{name}");
        assert_eq!(
            std::fs::read_to_string(addon.join("python-version.txt")).unwrap(),
            expected,
            "{name}: node-gyp ran on the wrong Python"
        );
        let id = env_object
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let meta: serde_json::Value = serde_json::from_slice(
            &std::fs::read(store_root.join("meta").join(format!("{id}.json"))).unwrap(),
        )
        .unwrap();
        let inputs = &meta["identity"]["inputs"];
        assert_eq!(inputs["schema"], "node-env/5");
        assert!(
            inputs["gyp_python"]
                .as_str()
                .unwrap()
                .ends_with(&format!("-cpython-{expected}")),
            "{name}: {inputs}"
        );
        // The closure records which Python that was, for `status`.
        assert!(
            closure["toolchain"]["helpers"]["python"].is_string(),
            "{name}: {closure}"
        );
        envs.push(env_object);
    }
    assert_ne!(envs[0], envs[1]);

    // Without its Python manifest the project's next sync would give
    // node-gyp the shipped default, so Node is no longer synced even though
    // nothing Node reads changed.
    let project = temp.0.join("locks-python");
    std::fs::remove_file(project.join("pyproject.toml")).unwrap();
    std::fs::remove_file(project.join(".python-version")).unwrap();
    let status = tog(&project, &temp.0, &["status"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        text.contains("the python toolchain node builds with"),
        "{text}"
    );
}

/// Ctrl-C while a lifecycle script runs stops the sync. A terminal delivers
/// the interrupt to its foreground process group, which holds tog and the
/// outer bwrap but not the sandboxed script (bwrap starts it in a new
/// session), so the case sends SIGINT to tog's own group the same way.
#[test]
fn interrupt_during_install_script_stops_the_sync() {
    let _policy_guard = policy_guard();
    if !cfg!(target_os = "linux") {
        eprintln!("interrupt_during_install_script_stops_the_sync skipped: Linux only");
        return;
    }
    assert_signal_mid_script_stops_the_sync(libc::SIGINT, true);
}

/// A TERM sent to tog alone, as `kill <pid>` or a service manager sends it,
/// is forwarded to bwrap and stops the sync the same way.
#[test]
fn terminate_during_install_script_stops_the_sync() {
    let _policy_guard = policy_guard();
    if !cfg!(target_os = "linux") {
        eprintln!("terminate_during_install_script_stops_the_sync skipped: Linux only");
        return;
    }
    assert_signal_mid_script_stops_the_sync(libc::SIGTERM, false);
}

/// Live `sleep <arg>` processes, by pid, read from `/proc/*/cmdline`. A
/// zombie has an empty cmdline, so only a process still running counts.
fn sleepers(arg: &str) -> Vec<i32> {
    let wanted = format!("sleep\0{arg}\0");
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            let cmdline = std::fs::read(entry.path().join("cmdline")).ok()?;
            let base = cmdline.rsplit(|&byte| byte == b'/').next()?;
            (cmdline.ends_with(wanted.as_bytes()) && base.starts_with(b"sleep\0")).then_some(pid)
        })
        .collect()
}

/// Sync a project whose one dependency's postinstall sleeps, send `signal`
/// to tog (or to its whole process group) once the script is running, and
/// require that tog exits non-zero, says it was interrupted, and does not
/// write the interrupted script into the closure as an
/// `install-script-failed` exception.
fn assert_signal_mid_script_stops_the_sync(signal: libc::c_int, whole_group: bool) {
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    let platform = Platform::host().expect("host platform");
    if !sandbox_or_skip("a signal mid-script", platform) {
        return;
    }
    let temp = TempDir::new("npm-interrupt");
    let store_root = temp.0.join("store");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        std::fs::create_dir_all(store_root.join(sub)).unwrap();
    }
    let store = Store {
        root: store_root.canonicalize().unwrap(),
    };
    let project = temp.0.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"npm-interrupt","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    std::fs::write(
        project.join("package-lock.json"),
        r#"{"name":"npm-interrupt","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"npm-interrupt","version":"1.0.0"}}}"#,
    )
    .unwrap();
    // The marker is how the case knows the script is running inside the
    // sandbox; the sleep outlives every deadline below, so only the
    // interrupt can end it. Its duration is unique to this run, so the
    // sleep can be found in /proc afterwards: the sandbox gives it its own
    // pid namespace and session, so neither a pid it prints nor tog's
    // process group names it from out here.
    let sleep_arg = format!("600.{}", std::process::id());
    let sleeper_package = serde_json::json!({
        "name": "fixture-sleeper",
        "version": "1.0.0",
        "scripts": {"postinstall": format!("printf 'TOG_SCRIPT_RUNNING\\n'; sleep {sleep_arg}")},
        "main": "index.js"
    })
    .to_string();
    let (tarball, sri) = make_fixture_tarball(
        &temp.0,
        "fixture-sleeper",
        &sleeper_package,
        &[("index.js", b"module.exports = 1;\n")],
    );
    seed_verified_fixture(&store, &tarball, &sri);
    // The binary realizes the shipped Node and node-gyp's CPython; stubs
    // published under their ids keep the sync offline.
    seed_shipped_node(&store, platform);
    seed_gyp_python(&store, platform);
    add_fixture_dependency(&project, "fixture-sleeper", &sri);

    let mut command = common::command(&project, &temp.0, &store.root);
    command
        .arg("sync")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0);
    let mut child = command.spawn().expect("spawn tog");
    let pid = child.id() as i32;
    // Whatever happens below, nothing this case started outlives it.
    struct GroupGuard(i32);
    impl Drop for GroupGuard {
        fn drop(&mut self) {
            // SAFETY: tog leads its own process group (process_group(0)).
            unsafe { libc::kill(-self.0, libc::SIGKILL) };
        }
    }
    let _guard = GroupGuard(pid);

    let stdout = child.stdout.take().unwrap();
    let (lines, received) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let stderr_reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    // It is the marker, never a sleep, that decides when to signal.
    let mut stdout_text = String::new();
    let start_deadline = Instant::now() + Duration::from_secs(900);
    loop {
        let remaining = start_deadline.saturating_duration_since(Instant::now());
        match received.recv_timeout(remaining.min(Duration::from_secs(1))) {
            Ok(line) => {
                stdout_text.push_str(&line);
                stdout_text.push('\n');
                if line.contains("TOG_SCRIPT_RUNNING") {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!(
                        "tog exited ({status}) before the script ran\nstdout:\n{stdout_text}\nstderr:\n{}",
                        stderr_reader.join().unwrap()
                    );
                }
                assert!(
                    Instant::now() < start_deadline,
                    "the install script never started\nstdout:\n{stdout_text}"
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!(
                    "tog closed stdout before the script ran\nstdout:\n{stdout_text}\nstderr:\n{}",
                    stderr_reader.join().unwrap()
                );
            }
        }
    }

    let target = if whole_group { -pid } else { pid };
    // SAFETY: a plain kill(2) on the process or group this case created.
    assert_eq!(unsafe { libc::kill(target, signal) }, 0);
    let exit_deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < exit_deadline,
            "tog kept running after the interrupt\nstdout:\n{stdout_text}"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let stderr_text = stderr_reader.join().unwrap();
    for line in received.try_iter() {
        stdout_text.push_str(&line);
        stdout_text.push('\n');
    }
    let _ = reader.join();
    let report = format!("status: {status:?}\nstdout:\n{stdout_text}\nstderr:\n{stderr_text}");
    println!("{report}");

    assert!(
        !status.success(),
        "an interrupted sync reported success\n{report}"
    );
    assert!(
        stderr_text.contains("interrupted"),
        "the failure does not say the sync was interrupted\n{report}"
    );
    // The sandboxed script went with the sync: no `sleep` survives it as
    // an orphan. A process that was killed may take a moment to be reaped,
    // so this waits a bounded time for the list to empty.
    let survivors = || sleepers(&sleep_arg);
    let orphan_deadline = Instant::now() + Duration::from_secs(10);
    while !survivors().is_empty() && Instant::now() < orphan_deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let left = survivors();
    for pid in &left {
        // SAFETY: a plain kill(2) of a process this case started.
        unsafe { libc::kill(*pid, libc::SIGKILL) };
    }
    assert!(
        left.is_empty(),
        "the sandboxed script outlived the interrupted sync: pids {left:?}\n{report}"
    );
    // No closure at all is the expected outcome; a closure that does exist
    // must not carry the interrupted script as a failure.
    if let Ok(closure) = comforter::read_closure(&project, "node") {
        let exceptions = closure["exceptions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            exceptions
                .iter()
                .all(|exception| exception["kind"].as_str() != Some("install-script-failed")),
            "the interrupted script was recorded as an exception: {exceptions:?}\n{report}"
        );
    }
}
