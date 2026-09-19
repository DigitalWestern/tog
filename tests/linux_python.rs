//! Linux Python round-trip test. Heavy: downloads CPython, uv, and the
//! manylinux wheels into a throwaway store, so it is ignored.

use tog::kernel::platform::Platform;
use tog::kernel::store::Store;
use tog::tailors::python;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-linux-python-{}-{}",
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
fn linux_python_sync_run_and_uv_round_trip() {
    if !cfg!(target_os = "linux") {
        eprintln!("linux_python: skipped on non-Linux host");
        return;
    }
    if Platform::host().unwrap() != Platform::X86_64UnknownLinuxGnu {
        eprintln!("skip linux_python: host is not x86_64-unknown-linux-gnu");
        return;
    }

    let temp = TempDir::new();
    let project = temp.0.join("proj-a");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proj-a"),
        &project,
    );
    let store_path = std::env::var_os("TOG_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.0.join("store"));
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));

    assert_ok(tog(&binary, &project, &store_path, &["sync"]), "sync");

    let imports = Command::new(project.join(".venv/bin/python"))
        .args([
            "-c",
            "import markupsafe, six; print(markupsafe.__version__, six.__version__)",
        ])
        .output()
        .unwrap();
    let imports = assert_ok(imports, "import markupsafe and six");
    assert_eq!(imports.trim(), "3.0.2 1.17.0");

    let run = assert_ok(
        tog(
            &binary,
            &project,
            &store_path,
            &[
                "run",
                "python",
                "-c",
                "import sys, sysconfig; print(sys.version.split()[0]); print(sysconfig.get_platform())",
            ],
        ),
        "tog run python",
    );
    let mut lines = run.lines();
    assert_eq!(lines.next(), Some("3.12.14"));
    assert!(
        lines
            .next()
            .is_some_and(|platform| platform.starts_with("linux-x86_64")),
        "unexpected sysconfig platform in {run:?}"
    );

    let store = Store {
        root: store_path.canonicalize().unwrap(),
    };
    let uv = python::ensure_uv_for(&store, Platform::host().unwrap()).unwrap();
    let uv_version = Command::new(uv.join("uv"))
        .arg("--version")
        .output()
        .unwrap();
    let uv_version = assert_ok(uv_version, "uv --version");
    assert!(uv_version.contains("0.12.7"), "{uv_version}");

    let plan_path = project.join(".tog/plan.json");
    let plan_mtime = std::fs::metadata(&plan_path).unwrap().modified().unwrap();
    assert_ok(
        tog(&binary, &project, &store_path, &["sync"]),
        "warm sync",
    );
    assert_eq!(
        std::fs::metadata(&plan_path).unwrap().modified().unwrap(),
        plan_mtime,
        "proj-a warm sync replanned"
    );
}
