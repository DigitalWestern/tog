//! End-to-end Go tailor test. Heavy: downloads the pinned Go toolchain and
//! module closure on first run.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::process::Command;

mod common;

use common::{assert_ok, copy_tree, fixture, snapshot, text, tog, tog_at, TempDir};

/// The closure's `resolution_basis` names go.mod and go.sum (when present)
/// by the digests of the files on disk: what the plan read.
fn assert_basis_matches_disk(project: &std::path::Path, step: &str) {
    use sha2::{Digest, Sha256};
    let closure: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(project.join(".tog/closures/go.json")).unwrap(),
    )
    .unwrap();
    let mut expected = serde_json::Map::new();
    for name in ["go.mod", "go.sum"] {
        if let Ok(bytes) = std::fs::read(project.join(name)) {
            expected.insert(
                name.into(),
                serde_json::json!(hex::encode(Sha256::digest(bytes))),
            );
        }
    }
    assert!(expected.contains_key("go.mod"));
    assert_eq!(
        closure["body"]["resolution_basis"],
        serde_json::Value::Object(expected),
        "{step}"
    );
}

#[test]
#[ignore]
fn go_sync_build_and_rebuild_offline() {
    let temp = TempDir::new("go-e2e");
    let project = temp.0.join("go-hello");
    copy_tree(&fixture("go-hello"), &project);
    let home = temp.path();

    assert_ok(tog(&project, home, &["sync"]), "sync");
    // A fresh plan: the closure's basis is go.mod and go.sum as on disk.
    assert_basis_matches_disk(&project, "sync");
    assert_ok(tog(&project, home, &["build"]), "build");
    // The build reuses the cached plan and writes the closure again.
    assert!(project.join(".tog/go-plan.json").is_file());
    assert_basis_matches_disk(&project, "build");
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

    // A planted plan cache: the key still matches the repo's own go.mod and
    // go.sum, but the plan lists a module go.sum never vouched for. A hit
    // is held to the go.sum ledger, so tog refuses it and names the way
    // out; deleting the cache lets the next run plan fresh.
    let cache_path = project.join(".tog/go-plan.json");
    let mut cache: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cache_path).unwrap()).unwrap();
    cache["plan"]["modules"]
        .as_array_mut()
        .expect("the cached plan lists its modules")
        .push(serde_json::json!({
            "path": "example.com/planted",
            "version": "v0.0.1",
            "h1": format!("h1:{}=", "A".repeat(43)),
            "zip_sha256": "a".repeat(64),
            "modfile_h1": format!("h1:{}=", "B".repeat(43)),
            "modfile_sha256": "b".repeat(64),
            "info_sha256": "c".repeat(64),
        }));
    std::fs::write(&cache_path, serde_json::to_vec_pretty(&cache).unwrap()).unwrap();
    let planted = tog(&project, home, &["sync"]);
    assert!(!planted.status.success(), "a planted plan cache was served");
    let stderr = text(&planted.stderr);
    assert!(
        stderr.contains("example.com/planted@v0.0.1") && stderr.contains("go-plan.json"),
        "{stderr}"
    );
    std::fs::remove_file(&cache_path).unwrap();
    assert_ok(
        tog(&project, home, &["sync"]),
        "sync after deleting the cache",
    );

    // An unreadable go.sum is an error, never an empty ledger. A plain sync
    // meets it first in prepare's store `go mod tidy`; --frozen skips
    // prepare, so the plan's own go.sum read is the one that must refuse.
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        use std::os::unix::fs::PermissionsExt;
        let gosum = project.join("go.sum");
        std::fs::set_permissions(&gosum, std::fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = tog(&project, home, &["sync"]);
        let frozen = tog(&project, home, &["--frozen"]);
        std::fs::set_permissions(&gosum, std::fs::Permissions::from_mode(0o644)).unwrap();
        for (label, out) in [("sync", &unreadable), ("--frozen", &frozen)] {
            assert!(
                !out.status.success(),
                "{label} succeeded with an unreadable go.sum"
            );
            let stderr = text(&out.stderr);
            assert!(
                stderr.contains("go.sum") && stderr.to_lowercase().contains("permission denied"),
                "{label}: {stderr}"
            );
        }
        let stderr = text(&frozen.stderr);
        assert!(!stderr.contains("go mod tidy"), "{stderr}");
        assert_ok(
            tog(&project, home, &["sync"]),
            "sync after restoring go.sum",
        );
    }

    // Without go.sum the pair is not tidy: --frozen refuses without
    // touching the project, and a plan tidies it again with the store Go.
    std::fs::remove_file(project.join("go.sum")).unwrap();
    let before = snapshot(&project);
    let frozen = tog(&project, home, &["--frozen"]);
    assert!(!frozen.status.success(), "--frozen synced an untidy module");
    let stderr = text(&frozen.stderr);
    assert!(
        stderr.contains("go.mod and go.sum in") && stderr.contains("--frozen never updates them"),
        "{stderr}"
    );
    assert_eq!(snapshot(&project), before, "--frozen changed the project");
    assert_ok(tog(&project, home, &["plan"]), "plan tidies the module");
    assert!(
        project.join("go.sum").is_file(),
        "plan did not restore go.sum"
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

/// `.tog/go-plan.json` is project state and outlives the store it was
/// planned against. Synced into a second, empty store, the cached plan names
/// artifacts that store never downloaded, so the sync plans again and
/// fetches them instead of failing on the first missing cache entry; the
/// module cache object is the same in both stores.
#[test]
#[ignore]
fn go_sync_into_a_second_store_replans_a_cached_plan() {
    let temp = TempDir::new("go-second-store");
    let project = temp.0.join("go-hello");
    copy_tree(&fixture("go-hello"), &project);
    let home = temp.path();

    // `synced:` lines go to stderr.
    let sync = |store: &str| {
        let out = tog_at(&project, home, &temp.0.join(store), &["sync"]);
        assert!(
            out.status.success(),
            "sync into {store}: {}",
            text(&out.stderr)
        );
        text(&out.stderr)
    };
    let first = sync("store-1");
    assert!(project.join(".tog/go-plan.json").is_file());
    assert_basis_matches_disk(&project, "first store");
    let second = sync("store-2");
    assert_basis_matches_disk(&project, "second store");
    let object = |out: &str| {
        out.lines()
            .find(|line| line.starts_with("synced: go modcache"))
            .and_then(|line| line.rsplit('/').next())
            .map(str::to_string)
            .unwrap_or_else(|| panic!("no go modcache line: {out}"))
    };
    assert_eq!(object(&first), object(&second));
}
