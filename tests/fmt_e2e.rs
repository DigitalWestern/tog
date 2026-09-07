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
    Command::new(bin)
        .current_dir(project)
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
