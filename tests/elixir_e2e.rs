//! End-to-end Elixir tailor test. Heavy: downloads OTP + Elixir + Hex +
//! rebar3 and the dep closure (telemetry exercises the rebar3 manager).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-elixir-e2e-{}-{}",
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
fn elixir_sync_sandboxed_build_and_run() {
    let temp = TempDir::new();
    let project = temp.0.join("elixir-hello");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/elixir-hello"),
        &project,
    );
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    assert_ok(blanket(&binary, &project, &store, &["sync"]), "sync");
    // Sandboxed compile: telemetry (rebar3 manager) + jason, network denied.
    assert_ok(blanket(&binary, &project, &store, &["build"]), "build");
    let out = assert_ok(
        blanket(
            &binary,
            &project,
            &store,
            &["run", "mix", "run", "-e", "IO.puts(\"e2e: \" <> ExReal.hello())"],
        ),
        "run",
    );
    assert!(out.contains("e2e: {\"beam\":\"ok\"}"), "{out}");
    // Toolchain is the pinned store BEAM, not host.
    let vsn = assert_ok(
        blanket(&binary, &project, &store, &["run", "elixir", "--version"]),
        "elixir version",
    );
    assert!(vsn.contains("1.20.4"), "{vsn}");
}
