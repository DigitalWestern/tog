//! End-to-end Go tailor test. Heavy: downloads the pinned Go toolchain and
//! module closure on first run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-go-e2e-{}-{}",
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
fn go_sync_build_and_rebuild_offline() {
    let temp = TempDir::new();
    let project = temp.0.join("go-hello");
    copy_tree(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-hello"),
        &project,
    );
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    assert_ok(blanket(&binary, &project, &store, &["sync"]), "sync");
    assert_ok(blanket(&binary, &project, &store, &["build"]), "build");
    let hello = project.join("hello");
    assert!(hello.is_file(), "staged binary moved into project");
    let out = Command::new(&hello).output().unwrap();
    assert!(out.status.success(), "hello executable failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "Hello, world.");

    // Clean rebuild: everything must come from the store (blanket build is
    // itself the network-denied sandbox; sandboxes cannot nest on macOS).
    std::fs::remove_file(&hello).unwrap();
    assert_ok(blanket(&binary, &project, &store, &["build", "go"]), "rebuild");
    assert!(hello.is_file());
    let out = Command::new(&hello).output().unwrap();
    assert!(out.status.success(), "rebuilt hello failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "Hello, world.");

    // blanket run uses the pinned toolchain + immutable modcache.
    let version = assert_ok(
        blanket(&binary, &project, &store, &["run", "go", "version"]),
        "run go version",
    );
    assert!(version.contains("go1.27.0"), "{version}");
    if cfg!(target_os = "linux") {
        assert!(version.contains("linux/amd64"), "{version}");
    }

    let goroot = assert_ok(
        blanket(&binary, &project, &store, &["run", "go", "env", "GOROOT"]),
        "run go env GOROOT",
    );
    let goroot = PathBuf::from(goroot.trim());
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".blanket/closures/go.json")).unwrap(),
    )
    .unwrap();
    let committed_go = PathBuf::from(
        closure["body"]["go_object"]["path"]
            .as_str()
            .expect("Go closure records its object path"),
    )
    .canonicalize()
    .unwrap();
    assert!(
        goroot.canonicalize().unwrap().starts_with(&committed_go),
        "GOROOT {} is outside committed Go object {}",
        goroot.display(),
        committed_go.display()
    );

    if cfg!(target_os = "linux") {
        let cgo_project = temp.0.join("go-cgo");
        std::fs::create_dir_all(&cgo_project).unwrap();
        std::fs::write(
            cgo_project.join("go.mod"),
            "module cgohello\n\ngo 1.27\n",
        )
        .unwrap();
        std::fs::write(
            cgo_project.join("main.go"),
            r#"package main

/*
#include <stdint.h>
static int blanket_answer(void) {
    return 42;
}
*/
import "C"

import "fmt"

func main() {
    fmt.Println(C.blanket_answer())
}
"#,
        )
        .unwrap();
        assert_ok(
            blanket(&binary, &cgo_project, &store, &["sync"]),
            "Linux cgo sync",
        );
        assert_ok(
            blanket(&binary, &cgo_project, &store, &["build"]),
            "Linux cgo build (requires gcc and glibc-devel)",
        );
        let cgo_binary = cgo_project.join("cgohello");
        assert!(cgo_binary.is_file(), "cgo executable was staged");
        let cgo_output = Command::new(&cgo_binary).output().unwrap();
        assert!(
            cgo_output.status.success(),
            "cgo executable failed; gcc and glibc-devel are required: {cgo_output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&cgo_output.stdout).trim(),
            "42"
        );
    }
}
