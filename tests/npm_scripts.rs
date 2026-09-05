//! Acceptance: npm install scripts run in the sandbox; strict mode rejects a
//! network attempt while permissive mode retains it as a cached exception.
//!
//! Heavy (realizes Node on first run), so #[ignore]d; tests/acceptance.sh
//! runs it with a shared BLANKET_STORE:
//!     cargo test --test npm_scripts -- --ignored

use blanket::npm::{self, NpmPackage, NpmPlan};
use blanket::store::Store;
use blanket::{platform::Platform, policy, project};
use sha2::{Digest, Sha512};
use std::path::PathBuf;
use std::process::Command;

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
        packages: vec![NpmPackage {
            path: "node_modules/fixture-pkg".into(),
            name: "fixture-pkg".into(),
            version: "1.0.0".into(),
            url: format!("file://{}", tarball.display()),
            integrity: sri.into(),
            bin: vec![],
            optional: false,
        }],
        links: vec![],
    }
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
