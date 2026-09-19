//! Networked manifest coverage.  Kept ignored because the fixtures exercise
//! real PyPI resolution and the Linux path requires bubblewrap.

use std::path::{Path, PathBuf};
use std::process::Command;

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(from, to).unwrap();
        }
    }
}

fn temp_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "tog-manifests-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
#[ignore]
fn all_manifest_fixtures_sync_and_run() {
    let root = temp_root();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let store = std::env::var_os("TOG_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("store"));
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));
    for (name, package) in [
        ("proj-poetry", "six"),
        ("proj-pdm", "six"),
        ("proj-setuppy", "setuppkg"),
        ("proj-setupcfg-call", "six"),
        ("proj-reqdir", "six"),
        ("proj-empty", "sys"),
    ] {
        let project = root.join(name);
        copy_tree(&fixtures.join(name), &project);
        let output = Command::new(&binary)
            .current_dir(&project)
            .env("TOG_STORE", &store)
            .env("TOG_SANDBOX_TESTS", "required")
            .args(["sync"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{name} sync failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let run = Command::new(&binary)
            .current_dir(&project)
            .env("TOG_STORE", &store)
            .args(["run", "python", "-c", &format!("import {package}")])
            .output()
            .unwrap();
        assert!(
            run.status.success(),
            "{name} run failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
#[ignore]
fn dynamic_vllm_shaped_fixture_syncs_real_dependencies() {
    let root = temp_root();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let project = root.join("proj-vllm-shaped");
    copy_tree(&fixtures.join("proj-vllm-shaped"), &project);
    let store = std::env::var_os("TOG_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("store"));
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));
    let output = Command::new(&binary)
        .current_dir(&project)
        .env("TOG_STORE", &store)
        .env("TOG_SANDBOX_TESTS", "required")
        .args(["sync"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "vllm-shaped sync failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run = Command::new(&binary)
        .current_dir(&project)
        .env("TOG_STORE", &store)
        .args(["run", "python", "-c", "import six, idna"])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "vllm-shaped dependencies missing: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let _ = std::fs::remove_dir_all(root);
}
