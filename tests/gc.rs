//! Ignored end-to-end coverage for project roots and cross-ecosystem GC.
//!
//! Run on a Linux host with a throwaway store:
//! BLANKET_STORE=$HOME/scratch/tmp/nxgc-store TMPDIR=$HOME/scratch/tmp \
//! cargo test --test gc -- --ignored --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let base = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = base.join(format!(
            "blanket-gc-e2e-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
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
        let _ = fs::remove_dir_all(&self.0);
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

fn blanket(bin: &Path, cwd: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(cwd)
        .env("BLANKET_STORE", store)
        .args(args)
        .output()
        .unwrap()
}

fn ok(output: Output, label: &str) -> String {
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
fn gc_drops_deleted_node_project_but_keeps_python_root() {
    let store = std::env::var_os("BLANKET_STORE")
        .map(PathBuf::from)
        .expect("gc e2e requires BLANKET_STORE to be a throwaway store");
    let temp = TempDir::new();
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let python = temp.0.join("proj-a");
    let node = temp.0.join("proj-npm");
    copy_tree(&fixtures.join("proj-a"), &python);
    copy_tree(&fixtures.join("proj-npm"), &node);
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    ok(blanket(&bin, &python, &store, &["sync"]), "sync proj-a");
    ok(blanket(&bin, &node, &store, &["sync"]), "sync proj-npm");
    fs::remove_dir_all(&node).unwrap();

    let dry = ok(
        blanket(&bin, &python, &store, &["gc", "--dry-run", "--keep-days", "0"]),
        "gc dry-run",
    );
    assert!(dry.contains("node-env"), "dry-run did not list node objects:\n{dry}");

    // The production safeguard intentionally keeps objects touched in the
    // last ten minutes. Age only the now-unrooted node objects so this test
    // exercises the sweep without sleeping.
    for entry in fs::read_dir(store.join("objects")).unwrap() {
        let entry = entry.unwrap();
        let meta = store.join("meta").join(format!(
            "{}.json",
            entry.file_name().to_string_lossy()
        ));
        let text = fs::read_to_string(meta).unwrap();
        if text.contains(r#""kind": "node-env""#) {
            let status = Command::new("/usr/bin/touch")
                .args(["-d", "11 minutes ago"])
                .arg(entry.path())
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    ok(blanket(&bin, &python, &store, &["gc"]), "gc");
    let objects = fs::read_dir(store.join("objects"))
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            fs::read_to_string(
                store
                    .join("meta")
                    .join(format!("{}.json", entry.file_name().to_string_lossy())),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(
        objects.iter().all(|meta| !meta.contains(r#""kind": "node-env""#)),
        "node object survived GC"
    );
    ok(
        blanket(
            &bin,
            &python,
            &store,
            &["run", "python", "-c", "import six"],
        ),
        "python after gc",
    );
}
