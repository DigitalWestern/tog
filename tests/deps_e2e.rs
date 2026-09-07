//! Real dependency-edit delegation round trips.
//!
//! These tests deliberately exercise the pinned ecosystem tools. They are
//! ignored because each test may download a toolchain and resolve a package
//! from its registry.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest as _, Sha224};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-deps-e2e-{label}-{}-{}",
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
        let _ = blanket::store::remove_tree(&self.0);
    }
}

fn run(binary: &Path, project: &Path, store: &Path, args: &[&str], tmp: &Path) -> Output {
    Command::new(binary)
        .current_dir(project)
        .env("BLANKET_STORE", store)
        .env("TMPDIR", tmp.join("tmp"))
        .env("HOME", tmp.join("home"))
        .env("BLANKET_SANDBOX_TESTS", "required")
        .env_remove("BLANKET_POLICY")
        .env_remove("BLANKET_STRICT")
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
    PathBuf::from(env!("CARGO_BIN_EXE_blanket"))
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

    let x_root = temp.0.join("home/.blanket/x");
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
        &std::fs::read_to_string(x_root.join(".blanket/closures/node.json")).unwrap(),
    )
    .unwrap();
    let pnpm = closure["body"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["path"] == "node_modules/pnpm")
        .unwrap();
    let digest = blanket::fetch::Digest::from_sri(pnpm["integrity"].as_str().unwrap()).unwrap();
    let tarball =
        std::fs::read(store.join("cache").join(digest.algo()).join(digest.hex())).unwrap();
    let corepack_sha224 = hex::encode(Sha224::digest(tarball));
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
    assert!(temp.0.join("home/.blanket/x").is_dir());

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
    set_package_manager(project, &format!("pnpm@9.12.3+sha224.{corepack_sha224}"));

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
