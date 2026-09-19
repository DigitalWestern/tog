//! E2e for interpreter selection and warm lock/plan caches (network tests
//! are ignored; the preflight refusal runs offline).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tog::kernel::platform::Platform;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-python-select-{}-{}",
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
    tog_env(bin, project, store, args, &[])
}

fn tog_env(
    bin: &Path,
    project: &Path,
    store: &Path,
    args: &[&str],
    env: &[(&str, &Path)],
) -> Output {
    let mut command = Command::new(bin);
    command
        .current_dir(project)
        .env("TOG_STORE", store)
        .args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
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
    let store = std::env::var_os("TOG_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.0.join("store"));
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));
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
    let signed: &[(&str, &Path)] = &[("TOG_SIGNING_KEY", &key), ("HOME", &home)];

    let first = tog_env(&binary, &project, &store, &["sync"], signed);
    let first_stderr = String::from_utf8_lossy(&first.stderr);
    assert!(first.status.success(), "first sync failed: {first_stderr}");
    assert!(
        first_stderr.contains("python 3.11.16 selected"),
        "{first_stderr}"
    );
    assert!(
        !first_stderr.contains("closures unsigned"),
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
    let audit = tog_env(&binary, &project, &store, &["audit", "--json"], signed);
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
    let audit = tog_env(&binary, &project, &store, &["audit", "--json"], signed);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert_eq!(audit.status.code(), Some(1));
    assert_eq!(report["closures"][0]["verdict"], "bad-signature");
    std::fs::write(&path, serde_json::to_vec_pretty(&closure).unwrap()).unwrap();
    // An unsigned sync says so and its record is outdated.
    let unsigned = tog_env(
        &binary,
        &project,
        &store,
        &["sync", "--fresh"],
        &[("HOME", &home)],
    );
    assert!(
        unsigned.status.success(),
        "{}",
        String::from_utf8_lossy(&unsigned.stderr)
    );
    assert!(
        String::from_utf8_lossy(&unsigned.stderr).contains("closures unsigned"),
        "{}",
        String::from_utf8_lossy(&unsigned.stderr)
    );
    let audit = tog_env(&binary, &project, &store, &["audit", "--json"], signed);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert_eq!(audit.status.code(), Some(1));
    assert_eq!(report["closures"][0]["verdict"], "outdated");
    assert_eq!(report["closures"][0]["signature"]["state"], "unsigned");
    let resigned = tog_env(&binary, &project, &store, &["sync"], signed);
    assert!(
        resigned.status.success(),
        "{}",
        String::from_utf8_lossy(&resigned.stderr)
    );
    let audit = tog_env(&binary, &project, &store, &["audit", "--json"], signed);
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
        tog(
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
        "tog run python",
    );
    assert_eq!(run.trim(), "(3, 11)");

    let plan_path = project.join(".tog/plan.json");
    let lock_path = project.join("requirements.lock.txt");
    let stamp_path = project.join(".tog/lock-source.hash");
    let plan_mtime = std::fs::metadata(&plan_path).unwrap().modified().unwrap();
    let lock_mtime = std::fs::metadata(&lock_path).unwrap().modified().unwrap();
    let stamp_mtime = std::fs::metadata(&stamp_path).unwrap().modified().unwrap();

    let second = tog_env(&binary, &project, &store, &["sync"], signed);
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
    let temp = TempDir::new();
    let project = temp.0.join("proj-unpinned-patch");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join(".python-version"), "3.12.3\n").unwrap();
    std::fs::write(project.join("requirements.txt"), "").unwrap();
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));

    let output = tog(&binary, &project, &store, &["sync"]);
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
