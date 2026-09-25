//! End-to-end Go tailor test. Heavy: downloads the pinned Go toolchain and
//! module closure on first run.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::process::Command;

mod common;

use common::{assert_ok, copy_tree, fixture, tog, TempDir};

#[test]
#[ignore]
fn go_sync_build_and_rebuild_offline() {
    let temp = TempDir::new("go-e2e");
    let project = temp.0.join("go-hello");
    copy_tree(&fixture("go-hello"), &project);
    let home = temp.path();

    assert_ok(tog(&project, home, &["sync"]), "sync");
    assert_ok(tog(&project, home, &["build"]), "build");
    let hello = project.join("hello");
    assert!(hello.is_file(), "staged binary moved into project");
    let out = Command::new(&hello)
        .env("LC_ALL", "en_US.UTF-8")
        .output()
        .unwrap();
    assert!(out.status.success(), "hello executable failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "Hello, world.");

    // Clean rebuild: everything must come from the store (tog build is
    // itself the network-denied sandbox; sandboxes cannot nest on macOS).
    std::fs::remove_file(&hello).unwrap();
    assert_ok(tog(&project, home, &["build", "go"]), "rebuild");
    assert!(hello.is_file());
    let out = Command::new(&hello)
        .env("LC_ALL", "en_US.UTF-8")
        .output()
        .unwrap();
    assert!(out.status.success(), "rebuilt hello failed: {out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "Hello, world.");

    // tog run uses the pinned toolchain + immutable modcache.
    let version = assert_ok(
        tog(&project, home, &["run", "go", "version"]),
        "run go version",
    );
    assert!(version.contains("go1.27.0"), "{version}");
    if cfg!(target_os = "linux") {
        assert!(version.contains("linux/amd64"), "{version}");
    }

    let goroot = assert_ok(
        tog(&project, home, &["run", "go", "env", "GOROOT"]),
        "run go env GOROOT",
    );
    let goroot = PathBuf::from(goroot.trim());
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".tog/closures/go.json")).unwrap(),
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
        std::fs::write(cgo_project.join("go.mod"), "module cgohello\n\ngo 1.27\n").unwrap();
        std::fs::write(
            cgo_project.join("main.go"),
            r#"package main

/*
#include <stdint.h>
static int tog_answer(void) {
    return 42;
}
*/
import "C"

import "fmt"

func main() {
    fmt.Println(C.tog_answer())
}
"#,
        )
        .unwrap();
        assert_ok(tog(&cgo_project, home, &["sync"]), "Linux cgo sync");
        assert_ok(
            tog(&cgo_project, home, &["build"]),
            "Linux cgo build (requires gcc and glibc-devel)",
        );
        let cgo_binary = cgo_project.join("cgohello");
        assert!(cgo_binary.is_file(), "cgo executable was staged");
        let cgo_output = Command::new(&cgo_binary).output().unwrap();
        assert!(
            cgo_output.status.success(),
            "cgo executable failed; gcc and glibc-devel are required: {cgo_output:?}"
        );
        assert_eq!(String::from_utf8_lossy(&cgo_output.stdout).trim(), "42");
    }
}
