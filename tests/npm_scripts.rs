//! Acceptance: npm install scripts run in the sandbox; strict mode rejects a
//! network attempt while permissive mode retains it as a cached exception.
//!
//! Heavy (realizes Node on first run), so #[ignore]d; tests/acceptance.sh
//! runs it with a shared BLANKET_STORE:
//!     cargo test --test npm_scripts -- --ignored

use blanket::fetch::{self, Digest};
use blanket::npm::{self, NpmPackage, NpmPlan};
use blanket::store::Store;
use blanket::{platform::Platform, policy, project};
use sha2::{Digest as Sha2Digest, Sha512};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-npm-scripts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
    let status = Command::new("/usr/bin/tar")
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
            optional: false,
        }],
        links: vec![],
        workspaces: vec![],
    }
}

/// Same as `make_pkg_tarball`, but the package can be named: the item-5 policy
/// table is keyed by package name.
fn make_named_pkg_tarball(
    dir: &std::path::Path,
    name: &str,
    script: &str,
) -> (PathBuf, String) {
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
    let status = Command::new("/usr/bin/tar")
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
    let status = Command::new("/usr/bin/tar")
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
    let digest = Digest::from_sri(sri).unwrap();
    fetch::download_verified_digest(
        store,
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
    lock["packages"]
        .as_object_mut()
        .unwrap()
        .insert(
            format!("node_modules/{package_name}"),
            serde_json::json!({
                "name": package_name,
                "version": "1.0.0",
                "resolved": format!("https://fixture.invalid/{package_name}-1.0.0.tgz"),
                "integrity": sri,
            }),
        );
    assert_eq!(
        package["dependencies"],
        lock["packages"][""]["dependencies"],
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

fn blanket(bin: &Path, project: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(project)
        .env("BLANKET_STORE", store)
        .args(args)
        .output()
        .unwrap()
}

#[test]
#[ignore]
fn network_access_during_install_script_fails() {
    let platform = Platform::host().expect("host platform");
    if let Ok(dir) = std::env::var("BLANKET_NPM_STRICT_CHILD") {
        policy::init(std::path::Path::new(&dir), false).unwrap();
        let tarball = PathBuf::from(std::env::var("BLANKET_NPM_TARBALL").unwrap());
        let sri = std::env::var("BLANKET_NPM_SRI").unwrap();
        let store = Store::open().expect("store");
        let result = npm::realize_node_env(
            &store,
            platform,
            &plan_for(&tarball, &sri),
            &[],
        );
        let err = result.expect_err("install script reaching the network must fail");
        assert!(
            err.to_string().contains("network-denied"),
            "unexpected error shape: {err}"
        );
        return;
    }
    let dir = std::env::temp_dir().join(format!("blanket-evil-npm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Network probe: succeeds (exit 0) with network, exits 1 without.
    let (tarball, sri) = make_pkg_tarball(
        &dir,
        "node -e \"require('https').get('https://registry.npmjs.org/', \
         () => process.exit(0)).on('error', () => process.exit(1))\"",
    );
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "network_access_during_install_script_fails",
            "--ignored",
            "--nocapture",
        ])
        .env("BLANKET_STORE", dir.join("store"))
        .env("BLANKET_NPM_STRICT_CHILD", &dir)
        .env("BLANKET_NPM_TARBALL", &tarball)
        .env("BLANKET_NPM_SRI", &sri)
        .env("BLANKET_STRICT", "1")
        .env_remove("BLANKET_POLICY")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "strict child failed: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn permissive_install_script_is_cached_but_rejected_strict() {
    let platform = Platform::host().expect("host platform");
    if let Ok(dir) = std::env::var("BLANKET_NPM_CACHED_CHILD") {
        policy::init(std::path::Path::new(&dir), false).unwrap();
        let tarball = PathBuf::from(std::env::var("BLANKET_NPM_TARBALL").unwrap());
        let sri = std::env::var("BLANKET_NPM_SRI").unwrap();
        let store = Store::open().expect("store");
        let err = npm::realize_node_env(
            &store,
            platform,
            &plan_for(&tarball, &sri),
            &[],
        )
            .expect_err("strict sync must reject the cached exception");
        assert!(err.to_string().contains("install-script-failed"));
        assert!(err
            .to_string()
            .contains("blanket sync --fresh will not help"));
        return;
    }
    let dir = std::env::temp_dir().join(format!("blanket-permissive-npm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (tarball, sri) = make_pkg_tarball(
        &dir,
        "node -e \"require('fs').writeFileSync('partial.txt','partial'); require('https').get('https://registry.npmjs.org/', \
         () => process.exit(0)).on('error', () => process.exit(1))\"",
    );
    let store = store_at(&dir);
    policy::init(&dir, false).unwrap();
    let plan = plan_for(&tarball, &sri);
    let env = npm::realize_node_env(
        &store,
        platform,
        &plan,
        &[],
    )
    .expect("permissive realize");
    let package_dir = env.join("node_modules/fixture-pkg");
    assert!(package_dir.is_dir());
    assert!(package_dir.join("package.json").is_file());
    assert!(!package_dir.join("partial.txt").exists());
    npm::project_node_env(
        &dir,
        &env,
        platform,
        &plan,
        &[],
        false,
    )
    .expect("project");
    let closure = project::read_closure(&dir, "node").unwrap();
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
        .env("BLANKET_STORE", dir.join("store"))
        .env("BLANKET_NPM_CACHED_CHILD", &dir)
        .env("BLANKET_NPM_TARBALL", &tarball)
        .env("BLANKET_NPM_SRI", &sri)
        .env("BLANKET_STRICT", "1")
        .env_remove("BLANKET_POLICY")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "strict cached child failed: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn benign_install_script_runs_and_output_is_captured() {
    let platform = Platform::host().expect("host platform");
    let dir = std::env::temp_dir().join(format!("blanket-good-npm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (tarball, sri) = make_pkg_tarball(
        &dir,
        "node -e \"require('fs').writeFileSync('built.txt','ok')\"",
    );
    let store = store_at(&dir);
    let env = npm::realize_node_env(
        &store,
        platform,
        &plan_for(&tarball, &sri),
        &[],
    )
    .expect("realize");
    let built = env.join("node_modules/fixture-pkg/built.txt");
    assert_eq!(std::fs::read_to_string(built).unwrap(), "ok");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn linux_npm_roundtrip() {
    if !cfg!(target_os = "linux") {
        eprintln!("linux_npm_roundtrip skipped: supported Linux only");
        return;
    }

    let platform = Platform::host().expect("Linux glibc host platform");
    assert_eq!(platform, Platform::X86_64UnknownLinuxGnu);
    let temp = TempDir::new();
    let project = &temp.0;
    let store = store_at(project);
    let store_root = store.root.clone();
    let node = npm::ensure_node_for(&store, platform).expect("pinned Linux Node");
    let node_bin = node.join("bin");
    std::fs::write(
        project.join("package.json"),
        r#"{"name":"linux-npm-roundtrip","version":"1.0.0","private":true,"dependencies":{"esbuild":"0.25.9"}}"#,
    )
    .unwrap();

    // The lock is generated by the pinned npm bundled with the pinned Node,
    // never by a host npm. Both optional platform packages must be present in
    // the generated lock before blanket applies its platform selector.
    let npm_lock = Command::new(node.join("bin/npm"))
        .current_dir(project)
        .env("BLANKET_STORE", &store_root)
        .env("PATH", format!("{}:{}", node_bin.display(), std::env::var("PATH").unwrap_or_default()))
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
            ("index.js", b"module.exports = require('./build/Release/addon.node');\n"),
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
    // entries are seeded through blanket's normal digest-checked API. This
    // exercises cache reuse without weakening production HTTPS validation.
    seed_verified_fixture(&store, &addon_tarball, &addon_sri);
    seed_verified_fixture(&store, &script_tarball, &script_sri);
    add_fixture_dependency(project, "fixture-addon", &addon_sri);
    add_fixture_dependency(project, "fixture-script", &script_sri);

    let binary = Path::new(env!("CARGO_BIN_EXE_blanket"));
    let synced = blanket(binary, project, &store_root, &["sync", "--strict"]);
    assert_success(&synced, "blanket sync --strict");

    let closure = project::read_closure(project, "node").unwrap();
    let package_paths: Vec<&str> = closure["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|package| package["path"].as_str())
        .collect();
    assert!(package_paths.contains(&"node_modules/@esbuild/linux-x64"));
    assert!(!package_paths.contains(&"node_modules/@esbuild/darwin-arm64"));
    let exceptions = closure["exceptions"].as_array().unwrap();
    assert!(exceptions.iter().all(|exception| {
        exception["kind"].as_str() != Some("install-script-failed")
    }));

    let env_object = PathBuf::from(closure["env_object"].as_str().unwrap());
    assert_eq!(
        std::fs::read_to_string(
            env_object.join("node_modules/fixture-script/generated.txt")
        )
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
    let run = blanket(binary, project, &store_root, &["run", "node", "-e", node_check]);
    assert_success(&run, "blanket run Node/esbuild/addon check");
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
    assert_eq!(std::fs::read_dir(store_root.join("cache/sha512")).unwrap().count(), 0);
    let repeated = blanket(binary, project, &store_root, &["sync", "--strict"]);
    assert_success(&repeated, "offline warm sync --strict");
    let repeated_closure = project::read_closure(project, "node").unwrap();
    assert_eq!(
        repeated_closure["env_object"],
        closure["env_object"],
        "identical inputs produced a different node environment object"
    );
    let repeated_run = blanket(binary, project, &store_root, &["run", "node", "-e", node_check]);
    assert_success(&repeated_run, "repeat blanket run Node/esbuild/addon check");
}

#[test]
#[ignore]
fn skip_download_switch_is_injected_and_recorded() {
    // puppeteer's installer reads PUPPETEER_SKIP_DOWNLOAD (verified against the
    // package's own getConfiguration.js). The script here asserts the switch is
    // visible to the lifecycle process, which is what makes the real installer
    // return without touching the denied network.
    let platform = Platform::host().expect("host platform");
    let dir = std::env::temp_dir().join(format!("blanket-skip-npm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (tarball, sri) = make_named_pkg_tarball(
        &dir,
        "puppeteer",
        "node -e \"if(process.env.PUPPETEER_SKIP_DOWNLOAD!=='true'){process.exit(3)};require('fs').writeFileSync('skipped.txt','ok')\"",
    );
    let store = store_at(&dir);
    let env = npm::realize_node_env(&store, platform, &plan_named(&tarball, &sri, "puppeteer"), &[])
        .expect("realize");
    assert_eq!(
        std::fs::read_to_string(env.join("node_modules/puppeteer/skipped.txt")).unwrap(),
        "ok"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn prebuilt_downloader_is_told_to_build_from_source() {
    // A prebuild-install style script: with the network denied the download can
    // never succeed, so blanket asks for the source build up front.
    let platform = Platform::host().expect("host platform");
    let dir = std::env::temp_dir().join(format!("blanket-src-npm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (tarball, sri) = make_named_pkg_tarball(
        &dir,
        "fake-prebuilt",
        "node -e \"if(process.env.npm_config_build_from_source!=='true'){process.exit(3)};require('fs').writeFileSync('compiled.txt','ok')\" # prebuild-install",
    );
    let store = store_at(&dir);
    let env = npm::realize_node_env(
        &store,
        platform,
        &plan_named(&tarball, &sri, "fake-prebuilt"),
        &[],
    )
    .expect("realize");
    assert_eq!(
        std::fs::read_to_string(env.join("node_modules/fake-prebuilt/compiled.txt")).unwrap(),
        "ok"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
