//! Ignored e2e for interpreter selection and warm lock/plan caches.

use blanket::platform::Platform;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-python-select-{}-{}",
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
fn pyproject_requires_python_selects_311_and_warm_sync_is_cached() {
    if !cfg!(target_os = "linux") {
        eprintln!("python_select: skipped on non-Linux host");
        return;
    }
    if Platform::host().unwrap() != Platform::X86_64UnknownLinuxGnu {
        eprintln!("skip python_select: host is not x86_64-unknown-linux-gnu");
        return;
    }

    let temp = TempDir::new();
    let project = temp.0.join("proj-py311");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proj-py311"),
        &project,
    );
    let store = std::env::var_os("BLANKET_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.0.join("store"));
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    let first = blanket(&binary, &project, &store, &["sync"]);
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(first.status.success(), "first sync failed: {first_stderr}");
    assert!(
        first_stderr.contains("python 3.11.16 selected"),
        "{first_stderr}"
    );
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".blanket/closures/python.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(closure["body"]["python"]["version"], "3.11.16");
    assert_eq!(closure["body"]["python"]["constraint"], ">=3.9,<3.12");
    assert_eq!(
        closure["body"]["python"]["constraint_source"],
        "pyproject.toml"
    );

    let run = assert_ok(
        blanket(
            &binary,
            &project,
            &store,
            &[
                "run",
                "python",
                "-c",
                "import sys,six; print(sys.version_info[:2])",
            ],
        ),
        "blanket run python",
    );
    assert_eq!(run.trim(), "(3, 11)");

    let plan_path = project.join(".blanket/plan.json");
    let lock_path = project.join("requirements.lock.txt");
    let stamp_path = project.join(".blanket/lock-source.hash");
    let plan_mtime = std::fs::metadata(&plan_path).unwrap().modified().unwrap();
    let lock_mtime = std::fs::metadata(&lock_path).unwrap().modified().unwrap();
    let stamp_mtime = std::fs::metadata(&stamp_path).unwrap().modified().unwrap();

    let second = blanket(&binary, &project, &store, &["sync"]);
    assert_ok(second, "warm sync");
    assert_eq!(
        std::fs::metadata(&plan_path).unwrap().modified().unwrap(),
        plan_mtime,
        "warm sync replanned"
    );
    assert_eq!(
        std::fs::metadata(&lock_path).unwrap().modified().unwrap(),
        lock_mtime,
        "warm sync re-locked"
    );
    assert_eq!(
        std::fs::metadata(&stamp_path).unwrap().modified().unwrap(),
        stamp_mtime,
        "warm sync rewrote lock stamp"
    );
}

#[test]
#[ignore]
fn unpinned_patch_request_fails_closed_before_opening_store() {
    let temp = TempDir::new();
    let project = temp.0.join("proj-unpinned-patch");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join(".python-version"), "3.12.3\n").unwrap();
    std::fs::write(project.join("requirements.txt"), "").unwrap();
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    let output = blanket(&binary, &project, &store, &["sync"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "unexpected status: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("3.12.3"), "{stderr}");
    assert!(stderr.contains(".python-version"), "{stderr}");
    assert!(stderr.contains("3.12.14"), "{stderr}");
    assert!(
        stderr.contains("pin 3.12 to accept the pinned patch"),
        "{stderr}"
    );
    assert!(stderr.contains("request one of:"), "{stderr}");
    assert!(!store.exists(), "store was opened: {store:?}");
}
