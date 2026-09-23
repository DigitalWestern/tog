//! A node environment's dependency evidence names only the cache entries its
//! realization actually read.
//!
//! Regression for microsoft/playwright (#51): electron 42 ships no install
//! script, so tog never provisions its release zip, yet the zip's sha256 is
//! still an identity input. The commit used to claim that digest as a cache
//! dependency and then refuse its own publication because the file was
//! absent. Offline: Node is a stub tree realized from a local tarball through
//! a selection row that names it, and no package here has lifecycle work, so
//! the stub never runs.

use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use std::path::{Path, PathBuf};
use std::process::Command;
use tog::kernel::fetch::Digest;
use tog::kernel::platform::Platform;
use tog::kernel::policy;
use tog::kernel::store::Store;
use tog::tailors::node::{self, DeclaredArtifact, NpmPackage, NpmPlan};

struct Temp(PathBuf);

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = tog::kernel::store::remove_tree(&self.0);
    }
}

fn temp() -> Temp {
    let path = std::env::temp_dir().join(format!(
        "tog-node-env-evidence-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    Temp(path)
}

fn store_at(dir: &Path) -> Store {
    let root = dir.join("store");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    Store {
        root: root.canonicalize().unwrap(),
    }
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

/// Tar `dir/<top>` into `dir/<top>.tgz`.
fn tar(dir: &Path, top: &str) -> PathBuf {
    let tarball = dir.join(format!("{top}.tgz"));
    let status = Command::new("/usr/bin/tar")
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(dir)
        .arg(top)
        .status()
        .unwrap();
    assert!(status.success());
    tarball
}

/// A Node release stub with exactly the layout `realize_runtime` checks, and
/// a selection whose host row points at it by file URL and digest.
fn stub_node_selection(dir: &Path, platform: Platform) -> tog::kernel::toolchain::Selected {
    let root = dir.join("node-stub");
    for (relative, contents) in [
        ("bin/node", "#!/bin/sh\nexit 1\n"),
        ("include/node/node.h", ""),
        ("lib/node_modules/npm/bin/npm-cli.js", ""),
        (
            "lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js",
            "",
        ),
    ] {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let tarball = tar(dir, "node-stub");
    let sha256 = hex::encode(Sha256::digest(std::fs::read(&tarball).unwrap()));
    let mut selected = node::shipped_selection().unwrap();
    let row = selected
        .bundle
        .artifacts
        .iter_mut()
        .find(|row| row.platform == platform && row.component == "node")
        .expect("the shipped Node release has a host row");
    row.url = format!("file://{}", tarball.display());
    row.digest = Digest::sha256(&sha256).unwrap();
    selected
}

/// An `electron` package with no lifecycle scripts, as electron 42 ships.
fn scriptless_electron(dir: &Path, version: &str) -> NpmPackage {
    let package = dir.join("package");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(
        package.join("package.json"),
        format!(r#"{{"name":"electron","version":"{version}","main":"index.js"}}"#),
    )
    .unwrap();
    std::fs::write(package.join("index.js"), "module.exports = 'electron';\n").unwrap();
    let tarball = tar(dir, "package");
    let sri = format!(
        "sha512-{}",
        b64(&Sha512::digest(std::fs::read(&tarball).unwrap()))
    );
    NpmPackage {
        path: "node_modules/electron".into(),
        name: "electron".into(),
        version: version.into(),
        url: format!("file://{}", tarball.display()),
        integrity: sri,
        bin: Vec::new(),
        patch: None,
        git: None,
        optional: false,
    }
}

/// Seed the release checksum manifest the `provisioned:` identity input reads,
/// so computing the identity needs no network. Returns the zip's sha256.
fn seed_electron_shasums(store: &Store, platform: Platform, version: &str) -> String {
    let (os, arch) = match platform {
        Platform::Aarch64AppleDarwin => ("darwin", "arm64"),
        Platform::X86_64UnknownLinuxGnu => ("linux", "x64"),
    };
    let release_url = format!("https://github.com/electron/electron/releases/download/v{version}");
    let dir = store.root.join("cache/electron-shasums").join(
        tog::tailors::python::artifacts::electron_cache_directory(&release_url),
    );
    std::fs::create_dir_all(&dir).unwrap();
    let zip_sha256 = "6705a9d0cc5c8f225d705d6e1c2607b2b5be8667d2befb18cdafe8b7b29b8008";
    std::fs::write(
        dir.join("SHASUMS256.txt"),
        format!("{zip_sha256} *electron-v{version}-{os}-{arch}.zip\n"),
    )
    .unwrap();
    zip_sha256.to_string()
}

fn recorded_cache_digests(store: &Store, env: &Path) -> Vec<String> {
    let id = env.file_name().unwrap().to_str().unwrap();
    let meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read(store.root.join("meta").join(format!("{id}.json"))).unwrap(),
    )
    .unwrap();
    meta["cache_digests"]
        .as_array()
        .expect("object-meta/2 records explicit cache digests")
        .iter()
        .map(|digest| digest["hex"].as_str().unwrap().to_string())
        .collect()
}

/// Realize one scriptless electron with the given declared artifacts and
/// return the env's recorded cache digests, the electron zip's sha256, and
/// the package tarball's digest.
fn realize_scriptless_electron(artifacts: &[DeclaredArtifact]) -> (Vec<String>, String, String) {
    // Policy attribution is process-global: one realization at a time.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let _attribution = policy::Attribution::open("node").expect("test attribution");
    let platform = Platform::host().expect("host platform");
    let dir = temp();
    let store = store_at(&dir.0);
    let version = "42.5.0";
    let selected = stub_node_selection(&dir.0, platform);
    let electron = scriptless_electron(&dir.0, version);
    let zip_sha256 = seed_electron_shasums(&store, platform, version);
    let plan = NpmPlan {
        node_version: selected.version("node").unwrap().to_string(),
        packages: vec![electron.clone()],
        links: Vec::new(),
        workspaces: Vec::new(),
        lock_source: "package-lock.json".into(),
    };

    let env = node::realize_node_env_for(&store, platform, &plan, artifacts, &selected)
        .expect("a scriptless electron realizes without its release zip");

    assert!(env.join("node_modules/electron/index.js").is_file());
    assert!(
        !store.cache_path("sha256", &zip_sha256).exists(),
        "nothing downloaded the zip"
    );
    let tarball = Digest::from_sri(&electron.integrity).unwrap();
    (
        recorded_cache_digests(&store, &env),
        zip_sha256,
        tarball.hex().to_string(),
    )
}

#[test]
fn an_unprovisioned_electron_zip_is_not_claimed_as_a_cache_dependency() {
    let (recorded, zip_sha256, tarball) = realize_scriptless_electron(&[]);
    assert!(
        !recorded.contains(&zip_sha256),
        "the never-provisioned electron zip is not evidence: {recorded:?}"
    );
    assert!(
        recorded.contains(&tarball),
        "the package tarball the tree was extracted from is evidence: {recorded:?}"
    );
}

#[test]
fn an_unplanted_declared_artifact_is_not_claimed_as_a_cache_dependency() {
    // With no lifecycle work the artifact is never planted, so its
    // unreachable URL is never fetched either.
    let unused_sha256 = "1".repeat(64);
    let (recorded, _, tarball) = realize_scriptless_electron(&[DeclaredArtifact {
        url: "https://127.0.0.1:9/never-requested.bin".into(),
        sha256: unused_sha256.clone(),
        path: ".cache/never-requested.bin".into(),
    }]);
    assert!(
        !recorded.contains(&unused_sha256),
        "the never-planted declared artifact is not evidence: {recorded:?}"
    );
    assert!(recorded.contains(&tarball));
}
