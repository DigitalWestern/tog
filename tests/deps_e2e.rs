//! Real dependency-edit delegation round trips.
//!
//! These tests deliberately exercise the pinned ecosystem tools. They are
//! ignored because each test may download a toolchain and resolve a package
//! from its registry.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Output;

use sha2::{Digest as _, Sha224, Sha256, Sha512};

mod common;

use common::{add_git_dependency, assert_ok, child, command, copy_tree, fixture, TempDir};

/// A scratch directory that is the project, with `home/` for tog's home and
/// `tmp/` for the child's `TMPDIR`, so neither lands among the project's
/// files.
fn scratch(label: &str) -> TempDir {
    let temp = TempDir::new(&format!("deps-e2e-{label}"));
    std::fs::create_dir_all(temp.0.join("home")).unwrap();
    std::fs::create_dir_all(temp.0.join("tmp")).unwrap();
    temp
}

/// Run the binary in `project` with the scratch directory's `home/` and
/// `tmp/`. A sandbox that cannot start fails the test instead of skipping
/// it, and the developer's `PNPM_HOME` cannot steer the pnpm tog runs.
fn run(project: &Path, store: &Path, args: &[&str], temp: &Path) -> Output {
    command(project, &temp.join("home"), store)
        .env("TMPDIR", temp.join("tmp"))
        .env("TOG_SANDBOX_TESTS", "required")
        .env_remove("PNPM_HOME")
        .args(args)
        .output()
        .expect("spawn tog")
}

/// `tog attest node` with a key the machine policy trusts: the record is
/// written and the lock is left byte for byte as it was.
fn attest_node(project: &Path, store: &Path, temp: &Path, lock: &str) {
    let home = temp.join("home");
    let key = home.join("signing.key");
    let public = tog::kernel::signing::generate(&key).unwrap();
    std::fs::create_dir_all(home.join(".tog")).unwrap();
    std::fs::write(
        home.join(".tog/policy.toml"),
        format!("deny = []\n\n[signing]\ntrusted = [\"{public}\"]\n"),
    )
    .unwrap();
    let before = std::fs::read(project.join(lock)).unwrap();
    let attest = command(project, &home, store)
        .env("TMPDIR", temp.join("tmp"))
        .env("TOG_SANDBOX_TESTS", "required")
        .env("TOG_SIGNING_KEY", &key)
        .args(["attest", "node"])
        .output()
        .unwrap();
    assert_ok(attest, "attest node");
    assert!(project.join(".tog/resolution/node.json").is_file());
    assert_eq!(
        std::fs::read(project.join(lock)).unwrap(),
        before,
        "attest changed {lock}"
    );
}

fn set_package_manager(project: &Path, value: &str) {
    let path = project.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    package["packageManager"] = serde_json::Value::String(value.to_string());
    std::fs::write(path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
}

fn assert_status_synced(project: &Path, store: &Path, temp: &TempDir) {
    let status = run(project, store, &["status"], &temp.0);
    assert_ok(status, "status");
    let status = run(project, store, &["status"], &temp.0);
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

/// The version `uv.lock` in `project` records for `name`.
fn uv_locked_version(project: &Path, name: &str) -> String {
    let lock: toml::Value =
        toml::from_str(&std::fs::read_to_string(project.join("uv.lock")).unwrap()).unwrap();
    lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{name} in uv.lock"))["version"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The version `package-lock.json` in `project` records for `name`.
fn npm_locked_version(project: &Path, name: &str) -> String {
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join("package-lock.json")).unwrap()).unwrap();
    lock["packages"][format!("node_modules/{name}")]["version"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} in package-lock.json"))
        .to_string()
}

/// The version `Cargo.lock` in `project` records for `name`.
fn cargo_locked_version(project: &Path, name: &str) -> String {
    let lock: toml::Value =
        toml::from_str(&std::fs::read_to_string(project.join("Cargo.lock")).unwrap()).unwrap();
    lock["package"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("{name} in Cargo.lock"))["version"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The version `go.mod` in `project` requires for `module`.
fn go_required_version(project: &Path, module: &str) -> String {
    let go_mod = std::fs::read_to_string(project.join("go.mod")).unwrap();
    go_mod
        .lines()
        .map(str::trim)
        .filter_map(|line| {
            line.strip_prefix("require ")
                .unwrap_or(line)
                .split_once(' ')
        })
        .find(|(name, _)| *name == module)
        .map(|(_, version)| version.split_whitespace().next().unwrap().to_string())
        .unwrap_or_else(|| panic!("{module} in go.mod:\n{go_mod}"))
}

/// The version `Gemfile.lock` in `project` records for `gem`.
fn gem_locked_version(project: &Path, gem: &str) -> String {
    let lock = std::fs::read_to_string(project.join("Gemfile.lock")).unwrap();
    lock.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix(gem)?.strip_prefix(" ("))
        .filter_map(|rest| rest.strip_suffix(')'))
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{gem} in Gemfile.lock:\n{lock}"))
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
    let temp = scratch("python-requirements");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(project.join("requirements.txt"), "idna==3.10\n").unwrap();

    assert_ok(
        run(
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
    // Update moves the lock within the requirement's range: loosen the pin
    // to a range and lock an older release, so only an update that
    // re-resolves reaches the top of the range.
    std::fs::write(
        project.join("requirements.txt"),
        "idna==3.10\ncharset-normalizer>=3.0,<=3.4.3\n",
    )
    .unwrap();
    std::fs::write(
        project.join("requirements.lock.txt"),
        "charset-normalizer==3.0.0\nidna==3.10\n",
    )
    .unwrap();
    assert_ok(
        run(
            project,
            &store,
            &["update", "--no-sync", "charset-normalizer"],
            &temp.0,
        ),
        "python requirements update",
    );
    let lock = std::fs::read_to_string(project.join("requirements.lock.txt")).unwrap();
    assert!(lock.contains("charset-normalizer==3.4.3"), "{lock}");
    assert!(!lock.contains("charset-normalizer==3.0.0"), "{lock}");
    assert_ok(
        run(
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
    let temp = scratch("python-uv");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"deps-e2e\"\nversion = \"0.1.0\"\ndependencies = []\n",
    )
    .unwrap();

    assert_ok(
        run(
            project,
            &store,
            &["add", "--dev", "--no-sync", "idna==3.7"],
            &temp.0,
        ),
        "uv add",
    );
    let pyproject = std::fs::read_to_string(project.join("pyproject.toml")).unwrap();
    assert!(pyproject.contains("idna==3.7"), "{pyproject}");
    assert_eq!(uv_locked_version(project, "idna"), "3.7");
    // Loosen the pin to a range the lock already satisfies: the locked 3.7
    // stays until an update re-resolves to the top of the range.
    std::fs::write(
        project.join("pyproject.toml"),
        pyproject.replace("idna==3.7", "idna>=3.7,<=3.10"),
    )
    .unwrap();
    assert_ok(
        run(project, &store, &["update", "--no-sync", "idna"], &temp.0),
        "uv update",
    );
    assert_eq!(uv_locked_version(project, "idna"), "3.10");
    assert_ok(
        run(
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
    let temp = scratch("npm");
    // The project is its own directory beside home and the store: npm runs
    // confined, and the door refuses a project that contains the signing
    // key under home.
    let project = &temp.0.join("project");
    std::fs::create_dir_all(project).unwrap();
    let store = temp.0.join("store");
    std::fs::write(
        project.join("package.json"),
        "{\"name\":\"deps-e2e\",\"version\":\"1.0.0\"}\n",
    )
    .unwrap();

    assert_ok(
        run(
            project,
            &store,
            &["add", "--no-sync", "is-number@6.0.0"],
            &temp.0,
        ),
        "npm add",
    );
    let mut package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(project.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(package["dependencies"]["is-number"], "^6.0.0");
    assert_eq!(npm_locked_version(project, "is-number"), "6.0.0");
    // Widen the range past the locked release: the lock keeps 6.0.0 until
    // an update re-resolves to the top of the range.
    package["dependencies"]["is-number"] = ">=6.0.0 <=7.0.0".into();
    std::fs::write(
        project.join("package.json"),
        serde_json::to_vec_pretty(&package).unwrap(),
    )
    .unwrap();
    assert_ok(
        run(
            project,
            &store,
            &["update", "--no-sync", "is-number"],
            &temp.0,
        ),
        "npm update",
    );
    assert_eq!(npm_locked_version(project, "is-number"), "7.0.0");
    assert_ok(
        run(
            project,
            &store,
            &["remove", "--no-sync", "is-number"],
            &temp.0,
        ),
        "npm remove",
    );
    let package = std::fs::read_to_string(project.join("package.json")).unwrap();
    assert!(!package.contains("is-number"), "{package}");
    // The lock an edit door wrote attests: npm's lock-only install leaves
    // it unchanged, confined, and the record is signed.
    assert_ok(run(project, &store, &[], &temp.0), "npm sync");
    attest_node(project, &store, &temp.0, "package-lock.json");
}

#[test]
#[ignore]
fn pnpm_add_update_remove_roundtrip() {
    let temp = scratch("pnpm");
    let project = &temp.0.join("project");
    copy_tree(&fixture("proj-pnpm"), project);
    let store = temp.0.join("store");
    set_package_manager(project, "pnpm@9.12.3");

    assert_ok(
        run(
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
    assert_status_synced(project, &store, &temp);
    // The pinned pnpm's frozen lock-only install attests the lock it
    // wrote, through the same door.
    attest_node(project, &store, &temp.0, "pnpm-lock.yaml");

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

    // Issue #413. A root whose request record is gone is never reused: the
    // delegated pnpm is realized again, and the root ends up `ready`.
    let record = x_root.join(".tog/x.json");
    std::fs::remove_file(&record).unwrap();
    assert_ok(
        run(
            project,
            &store,
            &["update", "--no-sync", "is-number"],
            &temp.0,
        ),
        "pnpm update after the request record was removed",
    );
    let request: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(request["state"], "ready", "{request}");

    let wrong_digest = {
        let mut value = corepack_sha224.clone().into_bytes();
        value[0] = if value[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(value).unwrap()
    };
    set_package_manager(project, &format!("pnpm@9.12.3+sha224.{wrong_digest}"));
    let package_before_wrong = std::fs::read_to_string(project.join("package.json")).unwrap();
    let lock_before_wrong = std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap();
    let wrong = run(
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
            project,
            &store,
            &["remove", "--dev", "--no-sync", "is-number"],
            &temp.0,
        ),
        "pnpm remove",
    );
    let package = std::fs::read_to_string(project.join("package.json")).unwrap();
    assert!(!package.contains("is-number"), "{package}");
    assert_ok(run(project, &store, &["sync"], &temp.0), "pnpm sync");
    assert_status_synced(project, &store, &temp);
}

/// A pnpm edit beside a Cargo project: the Cargo sync's exception (a git
/// dependency) is published on the Cargo closure and on no Node closure,
/// the project's or `tog x`'s.
#[test]
#[ignore]
fn mixed_cargo_pnpm_edit_keeps_cargo_exception_with_cargo() {
    let temp = scratch("mixed-cargo-pnpm");
    let project = &temp.0.join("project");
    let store = temp.0.join("store");
    copy_tree(&fixture("proj-pnpm"), project);
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
    let fixtures = TempDir::new("deps-e2e-mixed-cargo-pnpm-git");
    add_git_dependency(&fixtures.0, project);
    set_package_manager(project, "pnpm@9.12.3");

    assert_ok(
        run(project, &store, &["add", "npm:is-number@7.0.0"], &temp.0),
        "mixed pnpm add",
    );

    // The hand-written lock carries no resolution record, which Cargo's
    // door reports as `unrecorded-resolution`; it is set apart so the git
    // exception is the one traced.
    let (unrecorded, cargo_exceptions): (Vec<_>, Vec<_>) =
        closure_exceptions(&project.join(".tog/closures/cargo.json"))
            .into_iter()
            .partition(|exception| exception["kind"] == "unrecorded-resolution");
    assert_eq!(unrecorded.len(), 1, "cargo exceptions: {unrecorded:?}");
    assert_eq!(
        cargo_exceptions.len(),
        1,
        "cargo exceptions: {cargo_exceptions:?}"
    );
    assert_eq!(cargo_exceptions[0]["kind"], "git-dependency");
    assert_eq!(cargo_exceptions[0]["subject"], "gitdep@1.0.0");

    let pnpm_exceptions = closure_exceptions(&project.join(".tog/closures/node.json"));
    assert!(
        pnpm_exceptions
            .iter()
            .all(|exception| exception["kind"] != "git-dependency"),
        "pnpm closure inherited Cargo's exception: {pnpm_exceptions:?}"
    );

    let mut x_closures = Vec::new();
    find_files(&temp.0.join("home/.tog/x"), "node.json", &mut x_closures);
    assert_eq!(x_closures.len(), 1, "Node x closures: {x_closures:?}");
    let x_exceptions = closure_exceptions(&x_closures[0]);
    assert!(
        x_exceptions
            .iter()
            .all(|exception| exception["kind"] != "git-dependency"),
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
    let install = child(x_root.join("node_modules/.bin/pnpm"), &user_home)
        .current_dir(project)
        .args(["install", "--ignore-scripts", "--reporter", "append-only"])
        .arg("--store-dir")
        .arg(user_home.join("pnpm-store"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                node_bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
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
    let temp = scratch("pnpm-installed");
    let project = &temp.0.join("project");
    copy_tree(&fixture("proj-pnpm"), project);
    let store = temp.0.join("store");
    set_package_manager(project, "pnpm@9.12.3");

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
            run(project, &store, &args, &temp.0),
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
    let temp = scratch("pnpm-workspace");
    let project = &temp.0.join("project");
    copy_tree(&fixture("proj-pnpm-ws"), project);
    let member = project.join("packages/lib");
    let store = temp.0.join("store");
    set_package_manager(project, "pnpm@9.12.3");

    assert_ok(
        run(
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
        run(project, &store, &["sync"], &temp.0),
        "pnpm workspace sync",
    );
    assert_status_synced(project, &store, &temp);
}

#[test]
#[ignore]
fn nested_independent_npm_project_does_not_use_ancestor_pnpm_lock() {
    let temp = scratch("pnpm-nested-npm");
    let project = &temp.0.join("project");
    copy_tree(&fixture("proj-pnpm-ws"), project);
    let store = temp.0.join("store");
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

    assert_ok(
        run(
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

/// An npm workspace: the root `package.json` lists `packages/*`, and
/// `packages/app` depends on its sibling `@acme/util`. `tog add` and
/// `remove` in the member edit the member's manifest and the root's lock
/// (the first one, and then the existing one) through the confined npm,
/// which sees the whole workspace: the sibling resolves as a workspace
/// link, not from the registry, the member gets no lock of its own, and
/// the record is the root's. A sync run in the member before the root is
/// synced is sent to the root rather than resolving the member alone.
/// A pnpm workspace whose root has `pnpm-workspace.yaml` but no
/// `pnpm-lock.yaml` yet: an edit in a member writes the first lock at the
/// root, with the member as an importer, and nothing in the member but
/// its manifest; a sync in the member is sent to the root.
#[test]
#[ignore]
fn pnpm_workspace_member_edit_writes_the_first_root_lock() {
    let temp = scratch("pnpm-first-lock");
    let project = &temp.0.join("project");
    copy_tree(&fixture("proj-pnpm-ws"), project);
    std::fs::remove_file(project.join("pnpm-lock.yaml")).unwrap();
    let member = project.join("packages/lib");
    let store = temp.0.join("store");
    set_package_manager(project, "pnpm@9.12.3");

    let refused = run(&member, &store, &["sync"], &temp.0);
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("run this command in") && stderr.contains("pnpm-lock.yaml"),
        "{stderr}"
    );
    assert!(
        !project.join("pnpm-lock.yaml").exists() && !member.join("pnpm-lock.yaml").exists(),
        "a refused member sync wrote a lock"
    );

    assert_ok(
        run(
            &member,
            &store,
            &["add", "--dev", "--no-sync", "is-even@1.0.0"],
            &temp.0,
        ),
        "pnpm first-lock member add",
    );
    let member_package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(member.join("package.json")).unwrap())
            .unwrap();
    assert_eq!(member_package["devDependencies"]["is-even"], "1.0.0");
    let lock = std::fs::read_to_string(project.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains("\n  packages/lib:") && lock.contains("is-even@1.0.0"),
        "the root lock does not list the member and its new dependency:\n{lock}"
    );
    assert!(
        !member.join("pnpm-lock.yaml").exists()
            && !member.join(".tog").exists()
            && project.join(".tog/resolution/node.json").is_file(),
        "the lock and the record belong to the root"
    );
    assert!(
        !project.join("node_modules").exists() && !member.join("node_modules").exists(),
        "a lockfile-only workspace edit created node_modules"
    );
}

#[test]
#[ignore]
fn npm_workspace_member_edit_writes_the_root_lock() {
    let temp = scratch("npm-workspace");
    let root = &temp.0.join("project");
    let app = root.join("packages/app");
    let util = root.join("packages/util");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&util).unwrap();
    let store = temp.0.join("store");
    std::fs::write(
        root.join("package.json"),
        "{\"name\":\"ws\",\"version\":\"1.0.0\",\"workspaces\":[\"packages/*\"]}\n",
    )
    .unwrap();
    std::fs::write(
        util.join("package.json"),
        "{\"name\":\"@acme/util\",\"version\":\"1.0.0\"}\n",
    )
    .unwrap();
    std::fs::write(
        app.join("package.json"),
        "{\"name\":\"app\",\"version\":\"1.0.0\",\"dependencies\":{\"@acme/util\":\"1.0.0\"}}\n",
    )
    .unwrap();
    // A sync in the member of a never-synced workspace names the root
    // rather than resolving the member alone.
    let member_sync = run(&app, &store, &[], &temp.0);
    assert!(!member_sync.status.success(), "a member synced alone");
    let words = String::from_utf8_lossy(&member_sync.stderr);
    assert!(
        words.contains("run this command in") && words.contains(&root.display().to_string()),
        "{words}"
    );
    assert!(
        !app.join("package-lock.json").exists() && !root.join("package-lock.json").exists(),
        "a member sync wrote a lock"
    );

    // The root has no lock yet: the member's edit writes the first one, at
    // the root.
    assert_ok(
        run(&app, &store, &["add", "--no-sync", "is-odd@3.0.1"], &temp.0),
        "npm workspace member add",
    );
    let app_package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(app.join("package.json")).unwrap()).unwrap();
    assert_eq!(app_package["dependencies"]["is-odd"], "^3.0.1");
    let root_package: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("package.json")).unwrap()).unwrap();
    assert!(root_package.get("dependencies").is_none());
    assert!(
        !app.join("package-lock.json").exists() && !util.join("package-lock.json").exists(),
        "a member got a lock of its own"
    );
    let read_root_lock = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(root.join("package-lock.json")).unwrap())
            .unwrap()
    };
    let root_lock = read_root_lock();
    assert_eq!(
        root_lock["packages"]["node_modules/is-odd"]["version"],
        "3.0.1"
    );
    assert_eq!(
        root_lock["packages"]["node_modules/@acme/util"]["link"],
        true
    );
    assert_eq!(
        root_lock["packages"]["node_modules/@acme/util"]["resolved"],
        "packages/util"
    );
    assert!(
        root.join(".tog/resolution/node.json").is_file() && !app.join(".tog").exists(),
        "the record is the root's"
    );

    // With the root lock in place, a member edit still goes to the root.
    assert_ok(
        run(&app, &store, &["remove", "--no-sync", "is-odd"], &temp.0),
        "npm workspace member remove",
    );
    assert!(!std::fs::read_to_string(app.join("package.json"))
        .unwrap()
        .contains("is-odd"));
    let root_lock = read_root_lock();
    assert!(root_lock["packages"].get("node_modules/is-odd").is_none());
    assert_eq!(
        root_lock["packages"]["node_modules/@acme/util"]["link"],
        true
    );
    assert!(!app.join("package-lock.json").exists());

    assert_ok(run(root, &store, &[], &temp.0), "workspace sync");
    assert_status_synced(root, &store, &temp);
}

#[test]
#[ignore]
fn cargo_add_update_remove_roundtrip() {
    let temp = scratch("cargo");
    // The project is its own directory beside home and the store: cargo
    // runs confined, and the door refuses a project that contains the
    // signing key under home.
    let project = &temp.0.join("project");
    std::fs::create_dir_all(project).unwrap();
    let store = temp.0.join("store");
    std::fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"deps-e2e\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::create_dir(project.join("src")).unwrap();
    std::fs::write(project.join("src/lib.rs"), "pub fn marker() {}\n").unwrap();

    assert_ok(
        run(
            project,
            &store,
            &["add", "--no-sync", "itoa@1.0.10"],
            &temp.0,
        ),
        "cargo add",
    );
    // `cargo add itoa@1.0.10` writes the caret requirement `1.0.10` and
    // locks the newest release it admits, so the lock starts above the
    // floor; whatever that release is, it is not 1.0.10.
    let manifest = std::fs::read_to_string(project.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("itoa = \"1.0.10\""), "{manifest}");
    let added = cargo_locked_version(project, "itoa");
    assert_ne!(added, "1.0.10", "{manifest}");
    // Update re-resolves the lock to fit the manifest, in both directions:
    // pinned down to 1.0.10, then up to the top of a widened range. A
    // no-op update leaves the lock where `add` put it and fails here.
    let with_requirement = |requirement: &str| {
        std::fs::write(
            project.join("Cargo.toml"),
            manifest.replace("itoa = \"1.0.10\"", &format!("itoa = \"{requirement}\"")),
        )
        .unwrap();
        assert_ok(
            run(project, &store, &["update", "--no-sync", "itoa"], &temp.0),
            "cargo update",
        );
        cargo_locked_version(project, "itoa")
    };
    assert_eq!(with_requirement("=1.0.10"), "1.0.10");
    assert_eq!(with_requirement(">=1.0.10, <=1.0.15"), "1.0.15");
    assert_ok(
        run(project, &store, &["remove", "--no-sync", "itoa"], &temp.0),
        "cargo remove",
    );
    let manifest = std::fs::read_to_string(project.join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("itoa"), "{manifest}");
}

#[test]
#[ignore]
fn go_add_update_remove_roundtrip() {
    let temp = scratch("go");
    // The project is its own directory beside home and the store: Go runs
    // confined, and the door refuses a project that contains the signing
    // key under home.
    let project = &temp.0.join("project");
    std::fs::create_dir_all(project).unwrap();
    let store = temp.0.join("store");
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

    assert_ok(
        run(
            project,
            &store,
            &["add", "--no-sync", "rsc.io/quote@v1.5.1"],
            &temp.0,
        ),
        "go add",
    );
    assert_eq!(go_required_version(project, "rsc.io/quote"), "v1.5.1");
    assert!(std::fs::read_to_string(project.join("go.sum"))
        .unwrap()
        .contains("rsc.io/quote v1.5.1"));
    // Go modules pin the exact version in go.mod, so an update that
    // re-resolves moves the requirement itself: v1.5.2 is the newest
    // release of rsc.io/quote v1.
    assert_ok(
        run(
            project,
            &store,
            &["update", "--no-sync", "rsc.io/quote"],
            &temp.0,
        ),
        "go update",
    );
    assert_eq!(go_required_version(project, "rsc.io/quote"), "v1.5.2");
    assert!(std::fs::read_to_string(project.join("go.sum"))
        .unwrap()
        .contains("rsc.io/quote v1.5.2"));
    assert_ok(
        run(
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
    let temp = scratch("ruby");
    let project = &temp.0;
    let store = project.join("store");
    std::fs::write(project.join("Gemfile"), "source \"https://rubygems.org\"\n").unwrap();

    assert_ok(
        run(
            project,
            &store,
            &["add", "--no-sync", "rake@13.0.6"],
            &temp.0,
        ),
        "ruby add",
    );
    let gemfile = std::fs::read_to_string(project.join("Gemfile")).unwrap();
    assert!(gemfile.contains("gem \"rake\""), "{gemfile}");
    assert_eq!(gem_locked_version(project, "rake"), "13.0.6");
    // Loosen the pin to a range the lock already satisfies: the locked
    // 13.0.6 stays until an update re-resolves to the top of the range.
    let loosened = gemfile
        .lines()
        .map(|line| {
            if line.trim_start().starts_with("gem \"rake\"") {
                "gem \"rake\", \">= 13.0.6\", \"<= 13.2.1\"".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(project.join("Gemfile"), loosened).unwrap();
    assert_ok(
        run(project, &store, &["update", "--no-sync", "rake"], &temp.0),
        "ruby update",
    );
    assert_eq!(gem_locked_version(project, "rake"), "13.2.1");
    assert_ok(
        run(project, &store, &["remove", "--no-sync", "rake"], &temp.0),
        "ruby remove",
    );
    let gemfile = std::fs::read_to_string(project.join("Gemfile")).unwrap();
    assert!(!gemfile.contains("rake"), "{gemfile}");
}
