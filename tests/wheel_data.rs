//! End-to-end wheel `.data` scheme coverage. Heavy: resolves greenlet and
//! realizes CPython plus the selected manylinux/macosx wheel, so it is ignored.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-wheel-data-{}-{}",
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

fn assert_ok(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
#[ignore]
fn greenlet_headers_are_installed_and_importable() {
    let temp = TempDir::new();
    let project = temp.0.join("proj-greenlet");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proj-greenlet"),
        &project,
    );
    let store = std::env::var_os("TOG_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.0.join("store"));
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));

    assert_ok(tog(&binary, &project, &store, &["sync"]), "sync alias");

    let closure: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join(".tog/closures/python.json")).unwrap())
            .unwrap();
    let env = PathBuf::from(closure["body"]["env_object"].as_str().unwrap());
    assert!(
        env.is_dir(),
        "environment object is missing: {}",
        env.display()
    );
    assert!(
        env.join("include/site/python3.12/greenlet/greenlet.h")
            .is_file(),
        "greenlet header was not installed under {}",
        env.display()
    );

    let output = assert_ok(
        tog(
            &binary,
            &project,
            &store,
            [
                "run",
                "python",
                "-c",
                "import greenlet; print(greenlet.__version__)",
            ]
            .as_slice(),
        ),
        "tog run python",
    );
    assert_eq!(output.trim(), "3.5.5");
}
