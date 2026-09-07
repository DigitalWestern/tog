//! End-to-end coverage for the Rust `blanket fmt` contract.
//!
//! Run with a disposable store and a disk-backed TMPDIR:
//! BLANKET_STORE=<dir> TMPDIR=<disk-dir> BLANKET_SANDBOX_TESTS=required
//! cargo test --target-dir target --test fmt_e2e -- --ignored --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "blanket-fmt-e2e-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = blanket::store::remove_tree(&self.0);
    }
}

fn copy_tree(src: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(from, to).unwrap();
        }
    }
}

fn blanket(bin: &Path, project: &Path, store: &Path, args: &[&str]) -> Output {
    blanket_at(bin, project, store, args)
}

fn blanket_at(bin: &Path, cwd: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(cwd)
        .env("BLANKET_STORE", store)
        .args(args)
        .output()
        .unwrap()
}

fn object_ids(store: &Path) -> Vec<String> {
    let mut ids = fs::read_dir(store.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn age(path: &Path) {
    let old = SystemTime::now()
        .checked_sub(Duration::from_secs(11 * 60))
        .unwrap();
    fs::File::open(path).unwrap().set_modified(old).unwrap();
}

#[test]
#[ignore]
fn fmt_is_lockless_cached_sandboxed_and_gc_rooted() {
    let temp = TempDir::new();
    let project = temp.0.join("cargo-hello");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cargo-hello"),
        &project,
    );
    fs::remove_file(project.join("Cargo.lock")).unwrap();
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    let first = blanket(&binary, &project, &store, &["fmt", "--check"]);
    assert_eq!(
        first.status.code(),
        Some(1),
        "first check did not preserve rustfmt status\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        String::from_utf8_lossy(&first.stderr).contains("fetching rustfmt"),
        "cold run did not report fetching rustfmt: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!project.join("Cargo.lock").exists());
    assert!(project.join(".blanket/closures/rustfmt.json").is_file());
    let metas = fs::read_dir(store.join("meta"))
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect::<Vec<_>>();
    assert!(
        metas
            .iter()
            .any(|meta| meta.contains(r#""kind": "rustfmt""#)),
        "rustfmt metadata was not published"
    );
    assert!(
        metas
            .iter()
            .all(|meta| !meta.contains(r#""kind": "cargo-vendor""#)),
        "fmt unexpectedly realized a Cargo vendor object"
    );
    let closure: serde_json::Value =
        serde_json::from_slice(&fs::read(project.join(".blanket/closures/rustfmt.json")).unwrap())
            .unwrap();
    let rust_id = closure["body"]["rust_object"]["id"].as_str().unwrap();
    let rustfmt_id = closure["body"]["rustfmt_object"]["id"].as_str().unwrap();
    let rustfmt_lib_link =
        fs::read_link(store.join("objects").join(rustfmt_id).join("lib")).unwrap();
    assert!(!rustfmt_lib_link.is_absolute());
    assert_eq!(rustfmt_lib_link, PathBuf::from(format!("../{rust_id}/lib")));
    let rustfmt_meta =
        fs::read_to_string(store.join("meta").join(format!("{rustfmt_id}.json"))).unwrap();
    assert!(
        rustfmt_meta.contains(&format!("\"{rust_id}\"")),
        "rustfmt metadata does not retain the Rust object reference"
    );

    let formatted = blanket(&binary, &project, &store, &["fmt"]);
    assert!(
        formatted.status.success(),
        "format run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&formatted.stdout),
        String::from_utf8_lossy(&formatted.stderr)
    );
    assert_eq!(
        fs::read_to_string(project.join("src/main.rs")).unwrap(),
        "fn main() {\n    println!(\"hello {}\", itoa::Buffer::new().format(128u64));\n}\n"
    );
    assert!(!project.join("Cargo.lock").exists());

    let before = object_ids(&store);
    let warm = blanket(&binary, &project, &store, &["fmt", "--check"]);
    assert!(
        warm.status.success(),
        "warm check failed: {:?}",
        warm.status
    );
    assert!(!String::from_utf8_lossy(&warm.stderr).contains("fetching rustfmt"));
    assert_eq!(object_ids(&store), before, "warm fmt created a new object");

    let listed = blanket(&binary, &project, &store, &["ls"]);
    assert!(listed.status.success());
    assert!(String::from_utf8_lossy(&listed.stdout).contains("rustfmt 1.96.1"));

    let help = blanket(&binary, &project, &store, &["fmt", "--", "--help"]);
    assert!(
        help.status.success(),
        "pass-through help failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );

    // This is cargo-fmt's own argument parser rejecting a malformed blanket
    // pass-through flag. Its status is 2, so status 1 would not prove
    // unchanged propagation from the formatter.
    let bad_tool_flag = blanket(&binary, &project, &store, &["fmt", "--", "--version=bad"]);
    let bad_tool_stderr = String::from_utf8_lossy(&bad_tool_flag.stderr).into_owned();
    assert_eq!(
        bad_tool_flag.status.code(),
        Some(2),
        "formatter status was not passed through unchanged\nstdout:\n{}\nstderr:\n{bad_tool_stderr}",
        String::from_utf8_lossy(&bad_tool_flag.stdout),
    );
    // Status 2 is also blanket's own usage exit, so the code alone cannot
    // tell pass-through from a blanket-side argument rejection: require
    // cargo-fmt's own diagnostic and the absence of blanket's usage line.
    assert!(
        bad_tool_stderr.contains("bad") && bad_tool_stderr.to_lowercase().contains("cargo fmt"),
        "status 2 did not come from cargo-fmt's own argument parser:\n{bad_tool_stderr}"
    );
    assert!(
        !bad_tool_stderr.contains("blanket: error:"),
        "status 2 was blanket's usage error, not the formatter's:\n{bad_tool_stderr}"
    );

    for entry in fs::read_dir(store.join("objects")).unwrap() {
        age(&entry.unwrap().path());
    }
    let gc = blanket(&binary, &project, &store, &["gc", "--keep-days", "0"]);
    assert!(
        gc.status.success(),
        "gc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&gc.stdout),
        String::from_utf8_lossy(&gc.stderr)
    );
    assert!(store.join("objects").join(rust_id).is_dir());
    assert!(store.join("objects").join(rustfmt_id).is_dir());
}

#[test]
#[ignore]
fn fmt_script_precedence_runs_script_from_a_project_subdirectory() {
    let temp = TempDir::new();
    let project = temp.0.join("fmt-script");
    fs::create_dir_all(project.join("src")).unwrap();
    fs::write(
        project.join("package.json"),
        r#"{"name":"fmt-script","version":"1.0.0","scripts":{"fmt":"sh -c 'echo script-fmt \"$@\"; exit 7' sh"}}"#,
    )
    .unwrap();
    fs::write(
        project.join("package-lock.json"),
        r#"{"name":"fmt-script","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"fmt-script","version":"1.0.0"}}}"#,
    )
    .unwrap();
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"fmt-script\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(project.join("Cargo.lock"), "version = 4\n").unwrap();
    fs::write(project.join("src/main.rs"), "fn main() {}\n").unwrap();

    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));
    let synced = blanket(&binary, &project, &store, &["sync"]);
    assert!(
        synced.status.success(),
        "sync failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&synced.stdout),
        String::from_utf8_lossy(&synced.stderr)
    );
    assert!(project.join(".blanket/closures/node.json").is_file());

    let run = blanket_at(
        &binary,
        &project.join("src"),
        &store,
        &["fmt", "--check", "extra"],
    );
    assert_eq!(
        run.status.code(),
        Some(7),
        "package script status was not preserved\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&run.stdout).contains("script-fmt --check extra"),
        "script did not receive fmt arguments\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        !project.join(".blanket/closures/rustfmt.json").exists(),
        "script precedence unexpectedly realized rustfmt"
    );
}
