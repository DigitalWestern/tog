//! A node environment's dependency evidence names exactly the cache entries
//! its realization read.
//!
//! Regression for microsoft/playwright (#51): electron 42 ships no install
//! script, so tog never provisions its release zip, yet the zip's sha256 is
//! still an identity input. The commit used to claim that digest as a cache
//! dependency and then refuse its own publication because the file was
//! absent. The consumed side is covered too: a provisioned zip and a planted
//! declared artifact are recorded and survive a GC sweep, and a failed
//! provisioning publishes nothing.
//!
//! Offline: Node is a stub tree realized from a local tarball through a
//! selection row that names it, node-gyp's CPython is a stub published under
//! its real id, and every artifact is seeded into the verified cache.

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

/// An `electron` package; `postinstall` is its lifecycle script, if any.
/// Electron 42 ships none.
fn electron_package(dir: &Path, version: &str, postinstall: Option<&str>) -> NpmPackage {
    let package = dir.join("package");
    std::fs::create_dir_all(&package).unwrap();
    let mut manifest = serde_json::json!({
        "name": "electron",
        "version": version,
        "main": "index.js",
    });
    if let Some(script) = postinstall {
        manifest["scripts"] = serde_json::json!({ "postinstall": script });
    }
    std::fs::write(package.join("package.json"), manifest.to_string()).unwrap();
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

/// Seed the release checksum manifest the `provisioned:` identity input
/// reads, listing `zip_sha256` for this platform's zip, so computing the
/// identity needs no network.
fn seed_electron_shasums(store: &Store, platform: Platform, version: &str, zip_sha256: &str) {
    let (os, arch) = match platform {
        Platform::Aarch64AppleDarwin => ("darwin", "arm64"),
        Platform::X86_64UnknownLinuxGnu => ("linux", "x64"),
    };
    let release_url = format!("https://github.com/electron/electron/releases/download/v{version}");
    let dir = store.root.join("cache/electron-shasums").join(
        tog::tailors::python::artifacts::electron_cache_directory(&release_url),
    );
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SHASUMS256.txt"),
        format!("{zip_sha256} *electron-v{version}-{os}-{arch}.zip\n"),
    )
    .unwrap();
}

/// Publish a stub of the CPython node-gyp would use under the exact id
/// `ensure_gyp_python` looks up, so lifecycle setup finds it cached instead
/// of downloading the real interpreter. No script here calls it.
fn seed_gyp_python(store: &Store, platform: Platform) {
    tog::tailors::install_kinds();
    let selected = tog::tailors::python::shipped_selection("3.12").unwrap();
    let spec = selected.artifact(platform, "cpython").unwrap();
    let identity = tog::kernel::types::Identity {
        kind: "cpython".into(),
        name: "cpython".into(),
        version: spec.version.clone(),
        inputs: std::collections::BTreeMap::from([
            ("artifact_sha256".to_string(), spec.digest.hex().to_string()),
            ("platform".to_string(), platform.triple().to_string()),
        ]),
    };
    assert_eq!(
        identity.object_id(),
        tog::tailors::python::runtime_object_id(platform, &selected).unwrap(),
        "the stub is published under the id the producer looks up"
    );
    let staged = store.stage().unwrap();
    std::fs::create_dir_all(staged.join("bin")).unwrap();
    store
        .commit_with_deps(
            &identity,
            &staged,
            &[],
            &tog::kernel::store::ObjectDeps::new(),
        )
        .unwrap();
}

fn plan_of(selected: &tog::kernel::toolchain::Selected, package: NpmPackage) -> NpmPlan {
    NpmPlan {
        node_version: selected.version("node").unwrap().to_string(),
        packages: vec![package],
        links: Vec::new(),
        workspaces: Vec::new(),
        lock_source: "package-lock.json".into(),
    }
}

/// Policy attribution is process-global: one realization at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Backdate a cache file past the GC keep window.
fn age(path: &Path) {
    let old = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(2 * 24 * 60 * 60))
        .unwrap();
    std::fs::File::open(path)
        .unwrap()
        .set_modified(old)
        .unwrap();
}

/// Realize one scriptless electron with the given declared artifacts and
/// return the env's recorded cache digests, the electron zip's sha256, and
/// the package tarball's digest.
fn realize_scriptless_electron(artifacts: &[DeclaredArtifact]) -> (Vec<String>, String, String) {
    let _serial = serial();
    let _attribution = policy::Attribution::open("node").expect("test attribution");
    let platform = Platform::host().expect("host platform");
    let dir = temp();
    let store = store_at(&dir.0);
    let version = "42.5.0";
    let selected = stub_node_selection(&dir.0, platform);
    let electron = electron_package(&dir.0, version, None);
    let zip_sha256 = "6705a9d0cc5c8f225d705d6e1c2607b2b5be8667d2befb18cdafe8b7b29b8008";
    seed_electron_shasums(&store, platform, version, zip_sha256);

    let env = node::realize_node_env_for(
        &store,
        platform,
        &plan_of(&selected, electron.clone()),
        artifacts,
        &selected,
    )
    .expect("a scriptless electron realizes without its release zip");

    assert!(env.join("node_modules/electron/index.js").is_file());
    assert!(
        !store.cache_path("sha256", zip_sha256).exists(),
        "nothing downloaded the zip"
    );
    let tarball = Digest::from_sri(&electron.integrity).unwrap();
    (
        recorded_cache_digests(&store, &env),
        zip_sha256.to_string(),
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

/// `TOG_SANDBOX_TESTS=required` (any non-empty value) turns a missing
/// sandbox from a skip into a failure, as in tests/sandbox_deny.rs.
fn sandbox_or_skip(test_name: &str, platform: Platform) -> bool {
    match tog::kernel::sandbox::probe(platform) {
        Ok(_) => true,
        Err(error) => {
            if matches!(std::env::var_os("TOG_SANDBOX_TESTS"), Some(value) if !value.is_empty()) {
                panic!("required sandbox test {test_name} unavailable: {error}");
            }
            eprintln!("skip {test_name}: sandbox unavailable: {error}");
            false
        }
    }
}

/// The consumed side: electron with an install script gets its zip
/// provisioned from the verified cache, and a declared artifact is planted
/// for it. Both are recorded, and a GC sweep keeps both because the live
/// env names them, while an unreferenced cache entry of the same age goes.
#[test]
fn consumed_artifacts_are_recorded_and_survive_a_sweep() {
    let platform = Platform::host().expect("host platform");
    if !sandbox_or_skip(
        "consumed_artifacts_are_recorded_and_survive_a_sweep",
        platform,
    ) {
        return;
    }
    let _serial = serial();
    let _attribution = policy::Attribution::open("node").expect("test attribution");
    let dir = temp();
    let store = store_at(&dir.0);
    let version = "42.5.0";
    let selected = stub_node_selection(&dir.0, platform);
    seed_gyp_python(&store, platform);
    // The zip is seeded into the verified cache under its own sha256, so
    // provisioning is a cache hit and never reaches GitHub.
    let zip = dir.0.join("electron.zip");
    std::fs::write(&zip, b"not really a zip").unwrap();
    let (zip_sha256, _) = tog::kernel::fetch::cache_insert(&store, &zip).unwrap();
    seed_electron_shasums(&store, platform, version, &zip_sha256);
    let declared = dir.0.join("declared.bin");
    std::fs::write(&declared, b"declared artifact bytes").unwrap();
    let declared_sha256 = hex::encode(Sha256::digest(std::fs::read(&declared).unwrap()));
    let artifacts = [DeclaredArtifact {
        url: format!("file://{}", declared.display()),
        sha256: declared_sha256.clone(),
        path: ".cache/declared.bin".into(),
    }];
    let unreferenced = dir.0.join("unreferenced.bin");
    std::fs::write(&unreferenced, b"nobody names this").unwrap();
    let (unreferenced_sha256, _) = tog::kernel::fetch::cache_insert(&store, &unreferenced).unwrap();
    // The script proves both inputs were really handed to it.
    let script = "test -f \"$electron_config_cache\"/*/electron-v*.zip && test -f \"$HOME/.cache/declared.bin\"";
    let electron = electron_package(&dir.0, version, Some(script));

    let env = node::realize_node_env_for(
        &store,
        platform,
        &plan_of(&selected, electron),
        &artifacts,
        &selected,
    )
    .expect("realize with consumed artifacts");

    let exceptions = store
        .exceptions(env.file_name().unwrap().to_str().unwrap())
        .unwrap();
    assert!(
        exceptions
            .iter()
            .all(|exception| exception.kind != policy::INSTALL_SCRIPT_FAILED),
        "the script found both inputs: {exceptions:?}"
    );
    let recorded = recorded_cache_digests(&store, &env);
    assert!(
        recorded.contains(&zip_sha256),
        "the provisioned zip is evidence: {recorded:?}"
    );
    assert!(
        recorded.contains(&declared_sha256),
        "the planted declared artifact is evidence: {recorded:?}"
    );

    for hex in [&zip_sha256, &declared_sha256, &unreferenced_sha256] {
        age(&store.cache_path("sha256", hex));
    }
    let project = dir.0.join("project");
    std::fs::create_dir_all(&project).unwrap();
    let project = project.canonicalize().unwrap();
    store
        .register_root_record(tog::kernel::store::RootRecord {
            key: Store::root_key(&project).unwrap(),
            project_path: project,
            objects: [env.file_name().unwrap().to_str().unwrap().to_string()].into(),
            projections: Default::default(),
            updated: 1,
        })
        .unwrap();
    let mut out = Vec::new();
    tog::kernel::gc::collect(
        &store,
        tog::kernel::gc::Options {
            keep_days: 0,
            ..Default::default()
        },
        &mut out,
    )
    .unwrap_or_else(|error| panic!("sweep: {error}\n{}", String::from_utf8_lossy(&out)));
    let text = String::from_utf8_lossy(&out);
    assert!(
        !store.cache_path("sha256", &unreferenced_sha256).exists(),
        "the sweep ran and collected what nothing names: {text}"
    );
    assert!(
        store.cache_path("sha256", &zip_sha256).is_file(),
        "the provisioned zip survived: {text}"
    );
    assert!(
        store.cache_path("sha256", &declared_sha256).is_file(),
        "the declared artifact survived: {text}"
    );
}

/// A failed provisioning publishes nothing. The failure is forced offline:
/// `cache/sha256` is a file, so the zip cannot be stored and provisioning
/// fails before any network request. Node is realized first, while the
/// cache still works.
#[test]
fn a_failed_provisioning_publishes_no_environment() {
    let _serial = serial();
    let _attribution = policy::Attribution::open("node").expect("test attribution");
    let platform = Platform::host().expect("host platform");
    let dir = temp();
    let store = store_at(&dir.0);
    let version = "42.5.0";
    let selected = stub_node_selection(&dir.0, platform);
    node::realize_runtime(&store, platform, &selected).unwrap();
    seed_gyp_python(&store, platform);
    seed_electron_shasums(&store, platform, version, &"0".repeat(64));
    let cache = store.root.join("cache/sha256");
    tog::kernel::store::remove_tree(&cache).unwrap();
    std::fs::write(&cache, b"").unwrap();
    let electron = electron_package(&dir.0, version, Some("true"));
    let objects_before: Vec<_> = std::fs::read_dir(store.root.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();

    let error = node::realize_node_env_for(
        &store,
        platform,
        &plan_of(&selected, electron),
        &[],
        &selected,
    )
    .expect_err("a provisioning failure fails the realization");

    assert!(
        error.to_string().contains("electron@42.5.0: provisioning"),
        "{error}"
    );
    let objects_after: Vec<_> = std::fs::read_dir(store.root.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        objects_after, objects_before,
        "no environment was published"
    );
}
