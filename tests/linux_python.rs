//! Linux Python round-trip test. Heavy: downloads CPython, uv, and the
//! manylinux wheels into a throwaway store, so it is ignored.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::process::Command;

use tog::kernel::platform::Platform;
use tog::kernel::store::Store;
use tog::tailors::python;

mod common;

use common::{assert_ok, copy_tree, fixture, tog_at, warm_store, TempDir};

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

    let temp = TempDir::new("linux-python");
    let project = temp.0.join("proj-a");
    copy_tree(&fixture("proj-a"), &project);
    let store_path = warm_store(&temp);

    assert_ok(tog_at(&project, &temp.0, &store_path, &["sync"]), "sync");

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
        tog_at(
            &project,
            &temp.0,
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

    let store = Store::open_at(&store_path).unwrap();
    let activity = &store
        .activity(tog::kernel::activity::ActivityMode::Shared)
        .unwrap();
    let uv = python::ensure_uv_for(&store, activity, Platform::host().unwrap()).unwrap();
    let uv_version = Command::new(uv.join("uv"))
        .arg("--version")
        .output()
        .unwrap();
    let uv_version = assert_ok(uv_version, "uv --version");
    assert!(uv_version.contains("0.12.7"), "{uv_version}");

    let plan_path = project.join(".tog/plan.json");
    let plan_mtime = std::fs::metadata(&plan_path).unwrap().modified().unwrap();
    assert_ok(
        tog_at(&project, &temp.0, &store_path, &["sync"]),
        "warm sync",
    );
    assert_eq!(
        std::fs::metadata(&plan_path).unwrap().modified().unwrap(),
        plan_mtime,
        "proj-a warm sync replanned"
    );
}
