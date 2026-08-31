//! Acceptance: npm install scripts run in the sandbox, and a script that
//! attempts network access MUST fail the realization (fail closed).
//!
//! Heavy (realizes Node on first run), so #[ignore]d; tests/acceptance.sh
//! runs it with a shared BLANKET_STORE:
//!     cargo test --test npm_scripts -- --ignored

use blanket::npm::{self, NpmPackage, NpmPlan};
use blanket::store::Store;
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
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
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

#[test]
#[ignore]
fn network_access_during_install_script_fails() {
    let dir = std::env::temp_dir().join(format!("blanket-evil-npm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Network probe: succeeds (exit 0) with network, exits 1 without.
    let (tarball, sri) = make_pkg_tarball(
        &dir,
        "node -e \"require('https').get('https://registry.npmjs.org/', \
         () => process.exit(0)).on('error', () => process.exit(1))\"",
    );
    let store = Store::open().expect("store");
    let result = npm::realize_node_env(&store, &plan_for(&tarball, &sri), &[]);
    let err = result.expect_err("install script reaching the network must fail");
    assert!(
        err.to_string().contains("network-denied"),
        "unexpected error shape: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore]
fn benign_install_script_runs_and_output_is_captured() {
    let dir = std::env::temp_dir().join(format!("blanket-good-npm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (tarball, sri) = make_pkg_tarball(&dir, "node -e \"require('fs').writeFileSync('built.txt','ok')\"");
    let store = Store::open().expect("store");
    let env = npm::realize_node_env(&store, &plan_for(&tarball, &sri), &[]).expect("realize");
    let built = env.join("node_modules/fixture-pkg/built.txt");
    assert_eq!(std::fs::read_to_string(built).unwrap(), "ok");
    let _ = std::fs::remove_dir_all(&dir);
}
