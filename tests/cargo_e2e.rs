//! End-to-end Cargo tailor test. Heavy: downloads the pinned Rust toolchain
//! and crates.io closure on first run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-cargo-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
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

fn blanket(bin: &Path, project: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(project)
        .env("BLANKET_STORE", store)
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
fn cargo_sync_build_and_run_again_offline() {
    let temp = TempDir::new();
    let project = temp.0.join("cargo-hello");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-hello"),
        &project,
    );
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    assert_ok(blanket(&binary, &project, &store, &["sync"]), "sync");
    assert_ok(blanket(&binary, &project, &store, &["build"]), "build");
    assert!(project.join("target/debug/cargo-hello").is_file());
    let output = assert_ok(
        blanket(
            &binary,
            &project,
            &store,
            &["run", "target/debug/cargo-hello"],
        ),
        "run",
    );
    assert_eq!(output.trim(), "hello 128");

    // Rebuild from a clean target: everything must come from the store
    // (network denial is already enforced by `blanket build` itself — the
    // seatbelt sandbox cannot nest, so no outer sandbox-exec wrapper here).
    std::fs::remove_dir_all(project.join("target")).unwrap();
    assert_ok(blanket(&binary, &project, &store, &["build"]), "rebuild");
    assert!(project.join("target/debug/cargo-hello").is_file());
}
