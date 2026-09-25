//! Networked manifest coverage.  Kept ignored because the fixtures exercise
//! real PyPI resolution and the Linux path requires bubblewrap.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

mod common;

use common::{command, copy_tree, fixture, tog_at, warm_store, TempDir};

#[test]
#[ignore]
fn all_manifest_fixtures_sync_and_run() {
    let temp = TempDir::new("manifests-e2e");
    let root = temp.path();
    let store = warm_store(&temp);
    for (name, package) in [
        ("proj-poetry", "six"),
        ("proj-pdm", "six"),
        ("proj-setuppy", "setuppkg"),
        ("proj-setupcfg-call", "six"),
        ("proj-reqdir", "six"),
        ("proj-empty", "sys"),
    ] {
        let project = root.join(name);
        copy_tree(&fixture(name), &project);
        let output = command(&project, root, &store)
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
        let run = tog_at(
            &project,
            root,
            &store,
            &["run", "python", "-c", &format!("import {package}")],
        );
        assert!(
            run.status.success(),
            "{name} run failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
}

#[test]
#[ignore]
fn dynamic_vllm_shaped_fixture_syncs_real_dependencies() {
    let temp = TempDir::new("manifests-e2e");
    let root = temp.path();
    let project = root.join("proj-vllm-shaped");
    copy_tree(&fixture("proj-vllm-shaped"), &project);
    let store = warm_store(&temp);
    let output = command(&project, root, &store)
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
    let run = tog_at(
        &project,
        root,
        &store,
        &["run", "python", "-c", "import six, idna"],
    );
    assert!(
        run.status.success(),
        "vllm-shaped dependencies missing: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}
