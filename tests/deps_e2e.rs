//! Real dependency-edit delegation round trips.
//!
//! These tests deliberately exercise the pinned ecosystem tools. They are
//! ignored because each test may download a toolchain and resolve a package
//! from its registry.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest as _, Sha224, Sha256, Sha512};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-deps-e2e-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::create_dir_all(path.join("home")).unwrap();
        std::fs::create_dir_all(path.join("tmp")).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = tog::kernel::store::remove_tree(&self.0);
    }
}

fn run(binary: &Path, project: &Path, store: &Path, args: &[&str], tmp: &Path) -> Output {
    Command::new(binary)
        .current_dir(project)
        .env("TOG_STORE", store)
        .env("TMPDIR", tmp.join("tmp"))
        .env("HOME", tmp.join("home"))
        .env("TOG_SANDBOX_TESTS", "required")
        .env_remove("PNPM_HOME")
        .env_remove("TOG_POLICY")
        .env_remove("TOG_STRICT")
        .args(args)
        .output()
        .unwrap()
}

fn assert_ok(output: Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tog"))
}

fn copy_fixture(temp: &TempDir, fixture: &str) {
    fn copy_dir(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source = entry.path();
            let destination = destination.join(entry.file_name());
            if source.is_dir() {
                copy_dir(&source, &destination);
            } else {
                std::fs::copy(source, destination).unwrap();
            }
        }
    }

    copy_dir(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture),
        &temp.0,
    );
}

fn set_package_manager(project: &Path, value: &str) {
    let path = project.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    package["packageManager"] = serde_json::Value::String(value.to_string());
    std::fs::write(path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
}

fn assert_status_synced(binary: &Path, project: &Path, store: &Path, temp: &TempDir) {
    let status = run(binary, project, store, &["status"], &temp.0);
    assert_ok(status, "status");
    let status = run(binary, project, store, &["status"], &temp.0);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("synced"),
        "status was not synced:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
}

fn node_env_object_count(store: &Path) -> usize {
    std::fs::read_dir(store.join("meta"))
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(entry.path()).ok()?)
                .ok()
        })
        .filter(|metadata| metadata["identity"]["kind"] == "node-env")
        .count()
}

fn find_files(root: &Path, name: &str, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().and_then(|value| value.to_str()) == Some(name) {
            found.push(path.clone());
        }
        if std::fs::symlink_metadata(&path)
            .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            find_files(&path, name, found);
        }
    }
}

fn closure_exceptions(path: &Path) -> Vec<serde_json::Value> {
    serde_json::from_slice::<serde_json::Value>(&std::fs::read(path).unwrap()).unwrap()["body"]
        ["exceptions"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[test]
#[ignore]
fn python_requirements_add_update_remove_roundtrip() {
    let temp = TempDir::new("python-requirements");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(project.join("requirements.txt"), "idna==3.10\n").unwrap();
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--no-sync", "charset-normalizer==3.4.3"],
            &temp.0,
        ),
        "python requirements add",
    );
    assert!(std::fs::read_to_string(project.join("requirements.txt"))
        .unwrap()
        .contains("charset-normalizer==3.4.3"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["update", "--no-sync", "charset-normalizer"],
            &temp.0,
        ),
        "python requirements update",
    );
    assert!(std::fs::read_to_string(project.join("requirements.txt"))
        .unwrap()
        .contains("charset-normalizer==3.4.3"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--no-sync", "charset-normalizer"],
            &temp.0,
        ),
        "python requirements remove",
    );
    let requirements = std::fs::read_to_string(project.join("requirements.txt")).unwrap();
    assert_eq!(requirements, "idna==3.10\n");
}

#[test]
#[ignore]
fn python_uv_add_update_remove_roundtrip() {
    let temp = TempDir::new("python-uv");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"deps-e2e\"\nversion = \"0.1.0\"\ndependencies = []\n",
    )
    .unwrap();
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--dev", "--no-sync", "idna==3.10"],
            &temp.0,
        ),
        "uv add",
    );
    assert!(std::fs::read_to_string(project.join("pyproject.toml"))
        .unwrap()
        .contains("idna"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["update", "--no-sync", "idna"],
            &temp.0,
        ),
        "uv update",
    );
    assert!(std::fs::read_to_string(project.join("pyproject.toml"))
        .unwrap()
        .contains("idna"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--dev", "--no-sync", "idna"],
            &temp.0,
        ),
        "uv remove",
    );
    let pyproject = std::fs::read_to_string(project.join("pyproject.toml")).unwrap();
    assert!(!pyproject.contains("idna"), "{pyproject}");
}

#[test]
#[ignore]
fn npm_add_update_remove_roundtrip() {
    let temp = TempDir::new("npm");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(
        project.join("package.json"),
        "{\"name\":\"deps-e2e\",\"version\":\"1.0.0\"}\n",
    )
    .unwrap();
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--no-sync", "is-number@7.0.0"],
            &temp.0,
        ),
        "npm add",
    );
    let package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(package["dependencies"]["is-number"], "^7.0.0");
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["update", "--no-sync", "is-number"],
            &temp.0,
        ),
        "npm update",
    );
    let package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(package["dependencies"]["is-number"], "^7.0.0");
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--no-sync", "is-number"],
            &temp.0,
        ),
        "npm remove",
    );
    let package = std::fs::read_to_string(project.join("package.json")).unwrap();
    assert!(!package.contains("is-number"), "{package}");
}

#[test]
#[ignore]
fn pnpm_add_update_remove_roundtrip() {
    let temp = TempDir::new("pnpm");
    copy_fixture(&temp, "proj-pnpm");
    let project = &temp.0;
    let store = project.join("store");
    set_package_manager(project, "pnpm@9.12.3");
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--dev", "is-number@7.0.0"],
            &temp.0,
        ),
        "pnpm add",
    );
    let package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(package["devDependencies"]["is-number"], "7.0.0");
    let first_env_count = node_env_object_count(&store);
    assert!(first_env_count >= 1);
    assert_status_synced(&bin, project, &store, &temp);

    let x_root = temp.0.join("home/.tog/x");
    let x_root = std::fs::read_dir(&x_root)
        .unwrap()
        .find_map(|entry| {
            let path = entry.ok()?.path();
            path.join("package-lock.json").is_file().then_some(path)
        })
        .expect("pnpm x project");
    let x_lock = x_root.join("package-lock.json");
    let x_lock_mtime = std::fs::metadata(&x_lock).unwrap().modified().unwrap();
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(x_root.join(".tog/closures/node.json")).unwrap(),
    )
    .unwrap();
    let pnpm = closure["body"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["path"] == "node_modules/pnpm")
        .unwrap();
    let digest = tog::kernel::fetch::Digest::from_sri(pnpm["integrity"].as_str().unwrap()).unwrap();
    let tarball =
        std::fs::read(store.join("cache").join(digest.algo()).join(digest.hex())).unwrap();
    let corepack_sha224 = hex::encode(Sha224::digest(&tarball));
    let corepack_sha512 = hex::encode(Sha512::digest(&tarball));
    set_package_manager(project, &format!("pnpm@9.12.3+sha224.{corepack_sha224}"));

    let update = run(
        &bin,
        project,
        &store,
        &["update", "--no-sync", "is-number"],
        &temp.0,
    );
    assert_ok(update, "pnpm update");
    assert_eq!(
        std::fs::metadata(&x_lock).unwrap().modified().unwrap(),
        x_lock_mtime,
        "warm pnpm invocation re-resolved the tool"
    );
    assert_eq!(node_env_object_count(&store), first_env_count);
    assert!(temp.0.join("home/.tog/x").is_dir());

    let wrong_digest = {
        let mut value = corepack_sha224.clone().into_bytes();
        value[0] = if value[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(value).unwrap()
    };
    set_package_manager(project, &format!("pnpm@9.12.3+sha224.{wrong_digest}"));
    let package_before_wrong = std::fs::read_to_string(project.join("package.json")).unwrap();
    let lock_before_wrong = std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap();
    let wrong = run(
        &bin,
        project,
        &store,
        &["update", "--no-sync", "is-number"],
        &temp.0,
    );
    assert_eq!(
        wrong.status.code(),
        Some(1),
        "wrong digest unexpectedly passed"
    );
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("sha224 mismatch"),
        "wrong digest error:\n{}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(project.join("package.json")).unwrap(),
        package_before_wrong
    );
    assert_eq!(
        std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap(),
        lock_before_wrong
    );

    // Current Corepack writes `+sha512.`; a wrong one must fail the same way
    // (no extra network — the tool root and the tarball are already cached).
    let wrong_sha512 = {
        let mut value = corepack_sha512.clone().into_bytes();
        value[0] = if value[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(value).unwrap()
    };
    set_package_manager(project, &format!("pnpm@9.12.3+sha512.{wrong_sha512}"));
    // `set_package_manager` rewrote package.json, so the snapshot to compare
    // against is taken after it: the delegate must leave the file untouched.
    let package_before_sha512 = std::fs::read_to_string(project.join("package.json")).unwrap();
    let wrong = run(
        &bin,
        project,
        &store,
        &["update", "--no-sync", "is-number"],
        &temp.0,
    );
    assert_eq!(
        wrong.status.code(),
        Some(1),
        "wrong sha512 digest unexpectedly passed"
    );
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("sha512 mismatch"),
        "wrong sha512 error:\n{}",
        String::from_utf8_lossy(&wrong.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(project.join("package.json")).unwrap(),
        package_before_sha512
    );
    assert_eq!(
        std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap(),
        lock_before_wrong
    );

    // An algorithm tog cannot verify names itself, never the version.
    set_package_manager(
        project,
        &format!("pnpm@9.12.3+sha1.{}", &corepack_sha224[..40]),
    );
    let package_before_unknown = std::fs::read_to_string(project.join("package.json")).unwrap();
    let unknown = run(
        &bin,
        project,
        &store,
        &["update", "--no-sync", "is-number"],
        &temp.0,
    );
    assert_eq!(
        unknown.status.code(),
        Some(1),
        "unknown hash algorithm unexpectedly passed"
    );
    let unknown = String::from_utf8_lossy(&unknown.stderr).into_owned();
    assert!(unknown.contains("\"sha1\""), "{unknown}");
    assert!(unknown.contains("sha224, sha256, sha512"), "{unknown}");
    assert!(!unknown.contains("exact release"), "{unknown}");
    assert_eq!(
        std::fs::read_to_string(project.join("package.json")).unwrap(),
        package_before_unknown
    );
    assert_eq!(
        std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap(),
        lock_before_wrong
    );

    // The correct sha512 is accepted and the delegate runs for real.
    set_package_manager(project, &format!("pnpm@9.12.3+sha512.{corepack_sha512}"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--dev", "--no-sync", "is-number"],
            &temp.0,
        ),
        "pnpm remove",
    );
    let package = std::fs::read_to_string(project.join("package.json")).unwrap();
    assert!(!package.contains("is-number"), "{package}");
    assert_ok(run(&bin, project, &store, &["sync"], &temp.0), "pnpm sync");
    assert_status_synced(&bin, project, &store, &temp);
}

#[test]
#[ignore]
fn mixed_cargo_pnpm_edit_keeps_toolchain_exception_with_cargo() {
    let temp = TempDir::new("mixed-cargo-pnpm");
    let project = &temp.0;
    let store = project.join("store");
    copy_fixture(&temp, "proj-pnpm");
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"mixed-cargo-pnpm\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(
        project.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"mixed-cargo-pnpm\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(
        project.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"clippy\"]\n",
    )
    .unwrap();
    set_package_manager(project, "pnpm@9.12.3");
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "npm:is-number@7.0.0"],
            &temp.0,
        ),
        "mixed pnpm add",
    );

    let cargo_exceptions = closure_exceptions(&project.join(".tog/closures/cargo.json"));
    assert_eq!(
        cargo_exceptions.len(),
        1,
        "cargo exceptions: {cargo_exceptions:?}"
    );
    assert_eq!(
        cargo_exceptions[0]["kind"],
        "toolchain-component-unavailable"
    );
    assert!(
        cargo_exceptions[0]["subject"]
            .as_str()
            .is_some_and(|subject| subject.ends_with("rust-toolchain.toml")),
        "unexpected Cargo exception: {:?}",
        cargo_exceptions[0]
    );

    let pnpm_exceptions = closure_exceptions(&project.join(".tog/closures/node.json"));
    assert!(
        pnpm_exceptions
            .iter()
            .all(|exception| exception["kind"] != "toolchain-component-unavailable"),
        "pnpm closure inherited Cargo's exception: {pnpm_exceptions:?}"
    );

    let mut x_closures = Vec::new();
    find_files(&temp.0.join("home/.tog/x"), "node.json", &mut x_closures);
    assert_eq!(x_closures.len(), 1, "Node x closures: {x_closures:?}");
    let x_exceptions = closure_exceptions(&x_closures[0]);
    assert!(
        x_exceptions
            .iter()
            .all(|exception| exception["kind"] != "toolchain-component-unavailable"),
        "Node x closure inherited Cargo's exception: {x_exceptions:?}"
    );
}

/// Every entry under `dir`, with its content digest (or symlink target), so
/// two snapshots compare a whole tree byte for byte.
fn tree_snapshot(dir: &Path) -> Vec<(String, String)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let label = path.strip_prefix(root).unwrap().display().to_string();
            let metadata = std::fs::symlink_metadata(&path).unwrap();
            if metadata.file_type().is_symlink() {
                out.push((
                    label,
                    format!("-> {}", std::fs::read_link(&path).unwrap().display()),
                ));
            } else if metadata.is_dir() {
                out.push((label, "dir".into()));
                walk(root, &path, out);
            } else {
                out.push((
                    label,
                    hex::encode(Sha256::digest(std::fs::read(&path).unwrap())),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Run the store pnpm's real `install` in `project` from a home of its own,
/// the way the user would after a `tog` edit realized the tool:
/// `node_modules/.modules.yaml` then names a store tog is never given,
/// which is the starting state every later edit must survive.
fn install_with_store_pnpm(temp: &TempDir, project: &Path, store: &Path) {
    let x_root = std::fs::read_dir(temp.0.join("home/.tog/x"))
        .unwrap()
        .find_map(|entry| {
            let path = entry.ok()?.path();
            path.join("node_modules/.bin/pnpm")
                .is_file()
                .then_some(path)
        })
        .expect("pnpm x root");
    let node_bin = std::fs::read_dir(store.join("objects"))
        .unwrap()
        .find_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            (name.contains("-nodejs-") && path.join("bin/node").is_file())
                .then_some(path.join("bin"))
        })
        .expect("store node");
    let user_home = temp.0.join("user-home");
    std::fs::create_dir_all(&user_home).unwrap();
    let install = Command::new(x_root.join("node_modules/.bin/pnpm"))
        .current_dir(project)
        .args(["install", "--ignore-scripts", "--reporter", "append-only"])
        .env(
            "PATH",
            format!(
                "{}:{}",
                node_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", &user_home)
        .env("XDG_CONFIG_HOME", user_home.join("config"))
        .env("XDG_DATA_HOME", user_home.join("data"))
        .env("XDG_CACHE_HOME", user_home.join("cache"))
        .env("XDG_STATE_HOME", user_home.join("state"))
        .env("CI", "1")
        .output()
        .unwrap();
    assert_ok(install, "user's own pnpm install");
    let recorded = std::fs::read_to_string(project.join("node_modules/.modules.yaml")).unwrap();
    assert!(
        recorded.contains(&user_home.display().to_string()),
        "the user's install did not record its own store:\n{recorded}"
    );
}

/// pnpm keeps state in `node_modules` even under `--lockfile-only`: it reads
/// `.modules.yaml` and refuses a store other than the recorded one, at a
/// workspace root it installs outright, and its virtual store's `lock.yaml`
/// is rewritten. An already-installed project — the common starting state,
/// with `.modules.yaml` naming the user's own store — must therefore be
/// edited without touching anything under `node_modules`, without leaving a
/// tog-internal path in the project, and without any lifecycle script
/// running, `remove` included.
#[test]
#[ignore]
fn pnpm_edits_leave_an_installed_project_untouched() {
    let temp = TempDir::new("pnpm-installed");
    copy_fixture(&temp, "proj-pnpm");
    let project = &temp.0;
    let store = project.join("store");
    set_package_manager(project, "pnpm@9.12.3");
    let bin = binary();

    // A local dependency whose lifecycle scripts all leave a marker.
    let marker = temp.0.join("lifecycle-script-ran");
    let scripted = project.join("scripted");
    std::fs::create_dir_all(&scripted).unwrap();
    let script = format!(
        "node -e \"require('fs').writeFileSync({:?}, process.argv[1])\"",
        marker.display().to_string()
    );
    let manifest = serde_json::json!({
        "name": "scripted",
        "version": "1.0.0",
        "scripts": {
            "preinstall": format!("{script} preinstall"),
            "install": format!("{script} install"),
            "postinstall": format!("{script} postinstall"),
            "prepare": format!("{script} prepare"),
        }
    });
    std::fs::write(
        scripted.join("package.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let package_path = project.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&package_path).unwrap()).unwrap();
    package["dependencies"]["scripted"] = serde_json::Value::String("file:./scripted".into());
    std::fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--no-sync", "is-number@7.0.0"],
            &temp.0,
        ),
        "pnpm add (fresh project)",
    );
    assert!(
        !project.join("node_modules").exists(),
        "a lockfile-only edit created node_modules in the project"
    );

    // Install the project for real with the store's own pnpm, the way the
    // user would, from a home that is not tog's: `.modules.yaml` now
    // names a store tog will never be given.
    install_with_store_pnpm(&temp, project, &store);
    let modules_yaml = project.join("node_modules/.modules.yaml");
    let recorded = std::fs::read_to_string(&modules_yaml).unwrap();
    assert!(
        !marker.exists(),
        "the --ignore-scripts install ran a script"
    );
    let before = tree_snapshot(&project.join("node_modules"));
    assert!(before.iter().any(|(path, _)| path == ".modules.yaml"));
    assert!(before.iter().any(|(path, _)| path == ".pnpm/lock.yaml"));

    for (label, args) in [
        ("add", vec!["add", "--no-sync", "is-even@1.0.0"]),
        ("update", vec!["update", "--no-sync", "is-number"]),
        ("remove", vec!["remove", "--no-sync", "is-even"]),
    ] {
        assert_ok(
            run(&bin, project, &store, &args, &temp.0),
            &format!("pnpm {label} over an installed project"),
        );
        assert_eq!(
            tree_snapshot(&project.join("node_modules")),
            before,
            "pnpm {label} changed the project's node_modules"
        );
        assert!(
            !marker.exists(),
            "pnpm {label} ran a lifecycle script: {:?}",
            std::fs::read_to_string(&marker)
        );
        for file in ["package.json", "pnpm-lock.yaml"] {
            let text = std::fs::read_to_string(project.join(file)).unwrap();
            assert!(
                !text.contains("stage-") && !text.contains(&store.display().to_string()),
                "pnpm {label} left a tog-internal path in {file}:\n{text}"
            );
        }
        let leftover: Vec<_> = std::fs::read_dir(store.join("tmp"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("stage-"))
            .collect();
        assert!(
            leftover.is_empty(),
            "pnpm {label} left its scratch stage behind: {leftover:?}"
        );
    }
    let package = std::fs::read_to_string(&package_path).unwrap();
    assert!(!package.contains("is-even"), "{package}");
    assert!(package.contains("\"is-number\""), "{package}");
    assert_eq!(
        std::fs::read_to_string(&modules_yaml).unwrap(),
        recorded,
        "the user's .modules.yaml was rewritten"
    );
}

#[test]
#[ignore]
fn pnpm_workspace_member_and_root_roundtrip() {
    let temp = TempDir::new("pnpm-workspace");
    copy_fixture(&temp, "proj-pnpm-ws");
    let project = &temp.0;
    let member = project.join("packages/lib");
    let store = project.join("store");
    set_package_manager(project, "pnpm@9.12.3");
    let bin = binary();

    assert_ok(
        run(
            &bin,
            &member,
            &store,
            &["add", "--dev", "--no-sync", "is-even@1.0.0"],
            &temp.0,
        ),
        "pnpm workspace member add",
    );
    let member_package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(member.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(member_package["devDependencies"]["is-even"], "1.0.0");
    let root_package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.join("package.json")).unwrap())
            .unwrap();
    assert!(root_package.get("devDependencies").is_none());
    assert!(
        !project.join("node_modules").exists() && !member.join("node_modules").exists(),
        "a lockfile-only workspace edit created node_modules"
    );

    // From here on the workspace is installed by the user's own pnpm: a
    // workspace-root `add -w --lockfile-only` would otherwise install into
    // it outright, and every verb would refuse the foreign store recorded in
    // `.modules.yaml`. The whole installed tree must survive every edit.
    install_with_store_pnpm(&temp, project, &store);
    // A committed `.npmrc` is ordinary, and `node-linker` is an ordinary
    // setting in one. Written after the install, it disagrees with the
    // isolated layout on disk, which is exactly when it does damage: without
    // a forced `--config.node-linker=isolated` the delegate stops honouring
    // `enable-modules-dir=false`, becomes a real installer, and rewrites the
    // member's `node_modules` during a workspace-root edit. The snapshots
    // below are what catch it.
    std::fs::write(project.join(".npmrc"), "node-linker=hoisted\n").unwrap();
    let installed = (
        tree_snapshot(&project.join("node_modules")),
        tree_snapshot(&member.join("node_modules")),
    );
    assert!(installed.0.iter().any(|(path, _)| path == ".modules.yaml"));
    let installed_unchanged = |label: &str| {
        assert_eq!(
            (
                tree_snapshot(&project.join("node_modules")),
                tree_snapshot(&member.join("node_modules")),
            ),
            installed,
            "{label} changed an installed node_modules"
        );
    };

    assert_ok(
        run(
            &bin,
            &member,
            &store,
            &["remove", "--dev", "--no-sync", "is-even"],
            &temp.0,
        ),
        "pnpm workspace member remove",
    );
    installed_unchanged("workspace member remove");
    assert!(!std::fs::read_to_string(member.join("package.json"))
        .unwrap()
        .contains("is-even"));

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--dev", "--no-sync", "is-even@1.0.0"],
            &temp.0,
        ),
        "pnpm workspace root add",
    );
    installed_unchanged("workspace root add");
    let root_package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(root_package["devDependencies"]["is-even"], "1.0.0");
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--dev", "--no-sync", "is-even"],
            &temp.0,
        ),
        "pnpm workspace root remove",
    );
    installed_unchanged("workspace root remove");
    // `tog` projects its own node_modules over the user's install
    // (moving the existing directory aside, and saying so); that is sync's
    // documented behaviour, not the delegate's, so the snapshot ends here.
    assert_ok(
        run(&bin, project, &store, &["sync"], &temp.0),
        "pnpm workspace sync",
    );
    assert_status_synced(&bin, project, &store, &temp);
}

#[test]
#[ignore]
fn nested_independent_npm_project_does_not_use_ancestor_pnpm_lock() {
    let temp = TempDir::new("pnpm-nested-npm");
    copy_fixture(&temp, "proj-pnpm-ws");
    let project = &temp.0;
    let store = project.join("store");
    set_package_manager(project, "pnpm@9.12.3");
    let ancestor_lock = std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap();
    let nested = project.join("tools/nested-npm");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        nested.join("package.json"),
        "{\"name\":\"nested-npm\",\"version\":\"1.0.0\",\"dependencies\":{}}\n",
    )
    .unwrap();
    std::fs::write(
        nested.join("package-lock.json"),
        "{\"name\":\"nested-npm\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"requires\":true,\"packages\":{\"\":{\"name\":\"nested-npm\",\"version\":\"1.0.0\"}}}\n",
    )
    .unwrap();
    let bin = binary();

    assert_ok(
        run(
            &bin,
            &nested,
            &store,
            &["add", "--no-sync", "is-number@7.0.0"],
            &temp.0,
        ),
        "nested npm add",
    );
    assert!(std::fs::read_to_string(nested.join("package-lock.json"))
        .unwrap()
        .contains("is-number"));
    assert_eq!(
        std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap(),
        ancestor_lock
    );
}

#[test]
#[ignore]
fn cargo_add_update_remove_roundtrip() {
    let temp = TempDir::new("cargo");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"deps-e2e\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::create_dir(project.join("src")).unwrap();
    std::fs::write(project.join("src/lib.rs"), "pub fn marker() {}\n").unwrap();
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--no-sync", "itoa@1.0.15"],
            &temp.0,
        ),
        "cargo add",
    );
    assert!(std::fs::read_to_string(project.join("Cargo.toml"))
        .unwrap()
        .contains("itoa"));
    assert!(std::fs::read_to_string(project.join("Cargo.lock"))
        .unwrap()
        .contains("name = \"itoa\""));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["update", "--no-sync", "itoa"],
            &temp.0,
        ),
        "cargo update",
    );
    assert!(std::fs::read_to_string(project.join("Cargo.lock"))
        .unwrap()
        .contains("name = \"itoa\""));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--no-sync", "itoa"],
            &temp.0,
        ),
        "cargo remove",
    );
    let manifest = std::fs::read_to_string(project.join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("itoa"), "{manifest}");
}

#[test]
#[ignore]
fn go_add_update_remove_roundtrip() {
    let temp = TempDir::new("go");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(
        project.join("go.mod"),
        "module example.com/deps-e2e\n\ngo 1.24\n",
    )
    .unwrap();
    std::fs::write(
        project.join("main.go"),
        "package main\n\nimport _ \"rsc.io/quote\"\n\nfunc main() {}\n",
    )
    .unwrap();
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--no-sync", "rsc.io/quote@v1.5.2"],
            &temp.0,
        ),
        "go add",
    );
    assert!(std::fs::read_to_string(project.join("go.mod"))
        .unwrap()
        .contains("rsc.io/quote v1.5.2"));
    assert!(std::fs::read_to_string(project.join("go.sum"))
        .unwrap()
        .contains("rsc.io/quote v1.5.2"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["update", "--no-sync", "rsc.io/quote"],
            &temp.0,
        ),
        "go update",
    );
    assert!(std::fs::read_to_string(project.join("go.mod"))
        .unwrap()
        .contains("rsc.io/quote v1.5.2"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--no-sync", "rsc.io/quote"],
            &temp.0,
        ),
        "go remove",
    );
    let go_mod = std::fs::read_to_string(project.join("go.mod")).unwrap();
    assert!(!go_mod.contains("rsc.io/quote"), "{go_mod}");
}

#[test]
#[ignore]
fn ruby_add_update_remove_roundtrip() {
    let temp = TempDir::new("ruby");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(project.join("Gemfile"), "source \"https://rubygems.org\"\n").unwrap();
    let bin = binary();

    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["add", "--no-sync", "rake@13.2.1"],
            &temp.0,
        ),
        "ruby add",
    );
    assert!(std::fs::read_to_string(project.join("Gemfile"))
        .unwrap()
        .contains("gem \"rake\""));
    assert!(std::fs::read_to_string(project.join("Gemfile.lock"))
        .unwrap()
        .contains("rake (13.2.1)"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["update", "--no-sync", "rake"],
            &temp.0,
        ),
        "ruby update",
    );
    assert!(std::fs::read_to_string(project.join("Gemfile.lock"))
        .unwrap()
        .contains("rake (13.2.1)"));
    assert_ok(
        run(
            &bin,
            project,
            &store,
            &["remove", "--no-sync", "rake"],
            &temp.0,
        ),
        "ruby remove",
    );
    let gemfile = std::fs::read_to_string(project.join("Gemfile")).unwrap();
    assert!(!gemfile.contains("rake"), "{gemfile}");
}
