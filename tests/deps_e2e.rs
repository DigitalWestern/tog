//! Real dependency-edit delegation round trips.
//!
//! These tests deliberately exercise the pinned ecosystem tools with
//! `--no-sync`: the manifest/lock edit is the subject under test, while a
//! later sync remains outside this suite. They are ignored because each test
//! may download a toolchain and resolve a package from its registry.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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
