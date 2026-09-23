//! End-to-end Cargo tailor test. Heavy: downloads the pinned Rust toolchain
//! and crates.io closure on first run.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tog::kernel::platform::Platform;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-cargo-e2e-{}-{}",
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

fn copy_tree(src: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(from, to).unwrap();
        }
    }
}

fn tog(bin: &Path, project: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(project)
        .env("TOG_STORE", store)
        .args(args)
        .output()
        .unwrap()
}

fn tog_with_tmp(bin: &Path, project: &Path, store: &Path, tmp: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(project)
        .env("TOG_STORE", store)
        .env("TMPDIR", tmp)
        .env("HOME", tmp.join("home"))
        .env("TOG_SANDBOX_TESTS", "required")
        .env_remove("TOG_POLICY")
        .env_remove("TOG_STRICT")
        .args(args)
        .output()
        .unwrap()
}

fn assert_ok(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn assert_cargo_closure(project: &Path, store: &Path) -> (PathBuf, PathBuf) {
    let closure: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join(".tog/closures/cargo.json")).unwrap())
            .unwrap();
    let objects = store.canonicalize().unwrap().join("objects");
    let object_path = |key: &str| {
        let path = PathBuf::from(closure["body"][key]["path"].as_str().unwrap());
        let canonical = path.canonicalize().unwrap();
        assert!(
            canonical.starts_with(&objects),
            "{key} closure path escaped the fresh store: {}",
            canonical.display()
        );
        assert!(
            canonical.is_dir(),
            "{key} closure object is not a directory"
        );
        canonical
    };
    let rust = object_path("rust_object");
    let vendor = object_path("vendor_object");
    let rustlib = rust
        .join("lib/rustlib")
        .join(Platform::host().unwrap().triple());
    assert!(
        rustlib.is_dir(),
        "Rust object is missing the host rustlib tree: {}",
        rustlib.display()
    );
    (rust, vendor)
}

#[test]
#[ignore]
fn cargo_sync_build_and_run_again_offline() {
    let temp = TempDir::new();
    let project = temp.0.join("cargo-hello");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-hello"),
        &project,
    );
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));

    assert_ok(tog(&binary, &project, &store, &["sync"]), "sync");
    let (rust_obj, vendor_obj) = assert_cargo_closure(&project, &store);
    let rustc = assert_ok(
        tog(&binary, &project, &store, &["run", "rustc", "-vV"]),
        "rustc -vV",
    );
    assert!(
        rustc.contains("1.96.1"),
        "unexpected rustc version:\n{rustc}"
    );
    assert!(
        rustc
            .lines()
            .any(|line| { line.trim() == format!("host: {}", Platform::host().unwrap().triple()) }),
        "rustc reported the wrong host:\n{rustc}"
    );
    assert_ok(tog(&binary, &project, &store, &["build"]), "build");
    let executable = project.join("target/debug/cargo-hello");
    assert!(executable.is_file());
    let output = assert_ok(
        tog(
            &binary,
            &project,
            &store,
            &["run", "target/debug/cargo-hello"],
        ),
        "run",
    );
    assert_eq!(output.trim(), "hello 128");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&rust_obj).unwrap().permissions().mode() & 0o222,
            0
        );
        assert_eq!(
            std::fs::metadata(&vendor_obj).unwrap().permissions().mode() & 0o222,
            0
        );
    }

    // Rebuild from a clean target: everything must come from the store
    // (network denial is already enforced by `tog build` itself — the
    // seatbelt sandbox cannot nest, so no outer sandbox-exec wrapper here).
    std::fs::remove_dir_all(project.join("target")).unwrap();
    assert!(
        !executable.exists(),
        "the first build result was not removed"
    );
    assert_ok(tog(&binary, &project, &store, &["build"]), "rebuild");
    assert!(executable.is_file());
    let (rebuilt_rust_obj, rebuilt_vendor_obj) = assert_cargo_closure(&project, &store);
    assert_eq!(rebuilt_rust_obj, rust_obj);
    assert_eq!(rebuilt_vendor_obj, vendor_obj);
    let output = assert_ok(
        tog(
            &binary,
            &project,
            &store,
            &["run", "target/debug/cargo-hello"],
        ),
        "run after rebuild",
    );
    assert_eq!(output.trim(), "hello 128");
}

#[test]
#[ignore]
fn dependency_edit_exception_is_not_published_to_cargo_closure() {
    let temp = TempDir::new();
    let project = temp.0.join("cargo-hello");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-hello"),
        &project,
    );
    let tmp = temp.0.join("tmp");
    std::fs::create_dir_all(tmp.join("home")).unwrap();
    let store = temp.0.join("store");
    std::fs::write(
        project.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"clippy\"]\n",
    )
    .unwrap();
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));

    assert_ok(
        tog_with_tmp(&binary, &project, &store, &tmp, &["update"]),
        "dependency edit and sync",
    );

    let closures = project.join(".tog/closures");
    let cargo: serde_json::Value =
        serde_json::from_slice(&std::fs::read(closures.join("cargo.json")).unwrap()).unwrap();
    let exceptions = cargo["body"]["exceptions"].as_array().unwrap();
    assert_eq!(exceptions.len(), 1, "cargo exceptions: {exceptions:?}");
    assert_eq!(exceptions[0]["kind"], "toolchain-component-unavailable");
    assert!(
        exceptions[0]["subject"]
            .as_str()
            .is_some_and(|subject| subject.ends_with("rust-toolchain.toml")),
        "unexpected clippy subject: {}",
        exceptions[0]["subject"]
    );
    assert!(
        exceptions[0]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("clippy")),
        "unexpected clippy detail: {}",
        exceptions[0]["detail"]
    );

    for entry in std::fs::read_dir(&closures).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().and_then(|name| name.to_str()) == Some("cargo.json") {
            continue;
        }
        let closure: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let other = closure["body"]["exceptions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !other
                .iter()
                .any(|exception| { exception["kind"] == "toolchain-component-unavailable" }),
            "{} also contains the toolchain exception",
            path.display()
        );
    }
}

/// The build's sync is scoped to the ecosystem it builds (#158): beside a
/// Python project whose install cannot succeed, `tog build` still syncs
/// and builds the Cargo project, realizes nothing for Python, and the
/// toolchain lock it publishes keeps both sections. The bare `tog`, which
/// syncs everything, still fails on the Python install.
#[test]
#[ignore]
fn build_syncs_only_the_built_ecosystem_beside_a_failing_one() {
    let temp = TempDir::new();
    let project = temp.0.join("cargo-hello");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-hello"),
        &project,
    );
    // No index has this package, so Python's lock generation fails.
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n\
         dependencies = [\"tog-no-such-package-158\"]\n",
    )
    .unwrap();
    let tmp = temp.0.join("tmp");
    std::fs::create_dir_all(tmp.join("home")).unwrap();
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));

    let output = tog_with_tmp(&binary, &project, &store, &tmp, &["build"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_ok(output, "build beside a failing python project");
    assert!(stderr.contains("syncing first: cargo"), "{stderr}");
    assert!(project.join("target/debug/cargo-hello").is_file());
    assert_cargo_closure(&project, &store);
    let closures = project.join(".tog/closures");
    assert!(
        !closures.join("python.json").exists(),
        "the build realized the python environment"
    );
    let lock = std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap();
    assert!(lock.contains("[toolchain.python]"), "{lock}");
    assert!(lock.contains("[toolchain.rust]"), "{lock}");

    // Cargo is synced now, so the next build runs no sync; the whole
    // project is still checked. A changed Python toolchain input (stale
    // lock section) or a malformed one refuses, and the lock is untouched.
    let pyproject = std::fs::read_to_string(project.join("pyproject.toml")).unwrap();
    std::fs::write(project.join(".python-version"), "3.13\n").unwrap();
    for (label, expected) in [
        (
            "stale python section",
            "tog-toolchain.toml is stale for python",
        ),
        ("malformed requires-python", "invalid"),
    ] {
        if label.starts_with("malformed") {
            std::fs::remove_file(project.join(".python-version")).unwrap();
            std::fs::write(
                project.join("pyproject.toml"),
                pyproject.replace("[project]\n", "[project]\nrequires-python = \"invalid\"\n"),
            )
            .unwrap();
        }
        let output = tog_with_tmp(&binary, &project, &store, &tmp, &["build", "cargo"]);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{label}: build succeeded");
        assert!(!stderr.contains("syncing first"), "{label}: {stderr}");
        assert!(stderr.contains(expected), "{label}: {stderr}");
        assert_eq!(
            std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap(),
            lock,
            "{label}: the lock changed"
        );
    }
    std::fs::write(project.join("pyproject.toml"), &pyproject).unwrap();

    let output = tog_with_tmp(&binary, &project, &store, &tmp, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the python install was expected to fail\nstderr:\n{stderr}"
    );
    // The failure is the missing package, not something unrelated.
    assert!(stderr.contains("tog-no-such-package-158"), "{stderr}");
    assert!(!closures.join("python.json").exists());
}
