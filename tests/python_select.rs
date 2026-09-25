//! E2e for interpreter selection and warm lock/plan caches (network tests
//! are ignored; the preflight refusal runs offline).

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::process::Output;

use tog::kernel::platform::Platform;

mod common;

use common::{assert_ok, command, copy_tree, fixture, tog, tog_at, warm_store, TempDir};

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

    let temp = TempDir::new("python-select");
    let project = temp.0.join("proj-py311");
    copy_tree(&fixture("proj-py311"), &project);
    let store = warm_store(&temp);
    // The sync signs its closure with a key made here, and a machine policy
    // in a scratch HOME trusts it: the gate then passes the real record.
    let key = temp.0.join("signing.key");
    let public = tog::kernel::signing::generate(&key).unwrap();
    let home = temp.0.join("home");
    std::fs::create_dir_all(home.join(".tog")).unwrap();
    std::fs::write(
        home.join(".tog/policy.toml"),
        format!("[signing]\ntrusted = [\"{public}\"]\n"),
    )
    .unwrap();
    let signed = |args: &[&str]| -> Output {
        command(&project, &home, &store)
            .env("TOG_SIGNING_KEY", &key)
            .args(args)
            .output()
            .unwrap()
    };

    let first = signed(&["sync"]);
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(first.status.success(), "first sync failed: {first_stderr}");
    assert!(
        first_stderr.contains("python 3.11.16 selected"),
        "{first_stderr}"
    );
    assert!(
        !first_stderr.contains("written unsigned"),
        "a signed sync must not warn about unsigned closures: {first_stderr}"
    );
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".tog/closures/python.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(closure["signature"]["alg"], "ed25519");
    assert_eq!(closure["signature"]["key"], public.hex());
    assert_eq!(
        tog::kernel::signing::verify(&closure),
        tog::kernel::signing::Verification::Valid(public)
    );
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert!(
        audit.status.success()
            && report["passed"] == true
            && report["closures"][0]["verdict"] == "clean"
            && report["closures"][0]["signature"]["state"] == "trusted",
        "audit did not pass the signed sync record\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );
    // Editing the committed record is caught: no exception is judged. The
    // edit adds an exception the sync did not record, so the value changes
    // whatever the real sync recorded.
    let path = project.join(".tog/closures/python.json");
    let mut edited = closure.clone();
    edited["body"]["exceptions"] = serde_json::json!([
        {"kind": "git-dependency", "subject": "left-pad", "detail": "hand-added"}
    ]);
    std::fs::write(&path, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert_eq!(audit.status.code(), Some(1));
    assert_eq!(report["closures"][0]["verdict"], "bad-signature");
    std::fs::write(&path, serde_json::to_vec_pretty(&closure).unwrap()).unwrap();
    // An unsigned sync says so and its record is outdated.
    let unsigned = tog_at(&project, &home, &store, &["sync", "--fresh"]);
    assert!(
        unsigned.status.success(),
        "{}",
        String::from_utf8_lossy(&unsigned.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unsigned.stderr).contains("written unsigned"),
        "{}",
        String::from_utf8_lossy(&unsigned.stderr)
    );
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert_eq!(audit.status.code(), Some(1));
    assert_eq!(report["closures"][0]["verdict"], "outdated");
    assert_eq!(report["closures"][0]["signature"]["state"], "unsigned");
    let resigned = signed(&["sync"]);
    assert!(
        resigned.status.success(),
        "{}",
        String::from_utf8_lossy(&resigned.stderr)
    );
    let audit = signed(&["audit", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert!(
        audit.status.success() && report["closures"][0]["verdict"] == "clean",
        "re-syncing under the key did not restore a clean audit\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );
    assert_eq!(closure["body"]["python"]["version"], "3.11.16");
    assert_eq!(closure["body"]["python"]["constraint"], ">=3.9,<3.12");
    assert_eq!(
        closure["body"]["python"]["constraint_source"],
        "pyproject.toml"
    );

    let run = assert_ok(
        tog_at(
            &project,
            &home,
            &store,
            &[
                "run",
                "python",
                "-c",
                "import sys,six; print(sys.version_info[:2])",
            ],
        ),
        "tog run python",
    );
    assert_eq!(run.trim(), "(3, 11)");

    let plan_path = project.join(".tog/plan.json");
    let lock_path = project.join("requirements.lock.txt");
    let stamp_path = project.join(".tog/lock-source.hash");
    let plan_mtime = std::fs::metadata(&plan_path).unwrap().modified().unwrap();
    let lock_mtime = std::fs::metadata(&lock_path).unwrap().modified().unwrap();
    let stamp_mtime = std::fs::metadata(&stamp_path).unwrap().modified().unwrap();

    let second = signed(&["sync"]);
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

/// Offline and fast: the refusal happens before any download, so this runs
/// in the default suite and guards the preflight-before-store ordering.
#[test]
fn unpinned_patch_request_fails_closed_before_opening_store() {
    let temp = TempDir::new("python-select");
    let project = temp.0.join("proj-unpinned-patch");
    std::fs::create_dir_all(&project).unwrap();
    // 3.11.2 is a real CPython release python-build-standalone never
    // published a checksummed build of, so no catalog can carry it.
    std::fs::write(project.join(".python-version"), "3.11.2\n").unwrap();
    std::fs::write(project.join("requirements.txt"), "").unwrap();
    let store = temp.0.join("store");

    let output = tog(&project, &temp.0, &["sync"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "unexpected status: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("3.11.2"), "{stderr}");
    assert!(stderr.contains(".python-version"), "{stderr}");
    assert!(stderr.contains("3.11.1, 3.11.3"), "{stderr}");
    assert!(
        stderr.contains("pin 3.11 to accept the pinned patch"),
        "{stderr}"
    );
    assert!(stderr.contains("request one of:"), "{stderr}");
    assert!(!store.exists(), "store was opened: {store:?}");
}
