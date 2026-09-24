//! End-to-end coverage for the Rust `tog fmt` contract.
//!
//! Run with a disposable store and a disk-backed TMPDIR:
//! TOG_STORE=<dir> TMPDIR=<disk-dir> TOG_SANDBOX_TESTS=required
//! cargo test --target-dir target --test fmt_e2e -- --ignored --nocapture

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

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
            "tog-fmt-e2e-{}-{}",
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
        let _ = tog::kernel::store::remove_tree(&self.0);
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

fn tog(bin: &Path, project: &Path, store: &Path, args: &[&str]) -> Output {
    tog_at(bin, project, store, args)
}

fn tog_at(bin: &Path, cwd: &Path, store: &Path, args: &[&str]) -> Output {
    tog_env(bin, cwd, store, args, &[])
}

fn tog_env(bin: &Path, cwd: &Path, store: &Path, args: &[&str], env: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(bin);
    command.current_dir(cwd).env("TOG_STORE", store).args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
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

/// The Rust a project with no toolchain file gets: the shipped catalog's
/// explicit default.
fn default_rust() -> String {
    tog::kernel::toolchain::shipped(&tog::kernel::provider::rust::toolchain_catalog().unwrap())
        .unwrap()
        .version("rustc")
        .unwrap()
        .to_string()
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
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));
    // `fmt` signs the rustfmt record like every closure; a scratch HOME's
    // machine policy trusts the key so the gate can judge it.
    let key = temp.0.join("signing.key");
    let public = tog::kernel::signing::generate(&key).unwrap();
    let home = temp.0.join("home");
    fs::create_dir_all(home.join(".tog")).unwrap();
    fs::write(
        home.join(".tog/policy.toml"),
        format!("[signing]\ntrusted = [\"{public}\"]\n"),
    )
    .unwrap();
    let signed: &[(&str, &Path)] = &[("TOG_SIGNING_KEY", &key), ("HOME", &home)];

    let first = tog_env(&binary, &project, &store, &["fmt", "--check"], signed);
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
    assert!(project.join(".tog/closures/rustfmt.json").is_file());
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
        serde_json::from_slice(&fs::read(project.join(".tog/closures/rustfmt.json")).unwrap())
            .unwrap();
    let rust_id = closure["body"]["rust_object"]["id"].as_str().unwrap();
    let rustfmt_id = closure["body"]["rustfmt_object"]["id"].as_str().unwrap();
    assert_eq!(
        closure["body"]["inputs"]["rustfmt_object"], rustfmt_id,
        "the fmt closure must record the rustfmt it ran as its input"
    );
    assert_eq!(
        tog::kernel::signing::verify(&closure),
        tog::kernel::signing::Verification::Valid(public),
        "fmt must sign the rustfmt record with the configured key"
    );
    // The record names the pinned rustfmt and is signed by a trusted key,
    // so the gate passes it; the report still fails because the Cargo
    // project was never synced (no cargo.json), which is `missing`.
    let audit = tog_env(&binary, &project, &store, &["audit", "--json"], signed);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    assert!(
        audit.status.code() == Some(1)
            && report["closures"][0]["verdict"] == "clean"
            && report["closures"][0]["freshness"] == "current"
            && report["closures"][0]["signature"]["state"] == "trusted"
            && report["missing"] == serde_json::json!(["cargo"]),
        "audit did not pass the fresh fmt record\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );
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

    let formatted = tog(&binary, &project, &store, &["fmt"]);
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
    let warm = tog(&binary, &project, &store, &["fmt", "--check"]);
    assert!(
        warm.status.success(),
        "warm check failed: {:?}",
        warm.status
    );
    assert!(!String::from_utf8_lossy(&warm.stderr).contains("fetching rustfmt"));
    assert_eq!(object_ids(&store), before, "warm fmt created a new object");

    let listed = tog(&binary, &project, &store, &["ls"]);
    assert!(listed.status.success());
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains(&format!("rustfmt {}", default_rust()))
    );
    // `ls` prints a rustfmt row, so `ls rustfmt` must be a legal filter.
    let listed_one = tog(&binary, &project, &store, &["ls", "rustfmt"]);
    assert!(
        listed_one.status.success(),
        "ls rustfmt failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&listed_one.stdout),
        String::from_utf8_lossy(&listed_one.stderr)
    );

    // Every closure consumer must survive the package-free fmt closure:
    // `sbom` reads every .tog/closures/*.json and fails the whole
    // document on the first ecosystem it does not know.
    let sbom = tog(&binary, &project, &store, &["sbom"]);
    assert!(
        sbom.status.success(),
        "sbom failed after fmt\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&sbom.stdout),
        String::from_utf8_lossy(&sbom.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&sbom.stdout).unwrap();
    let toolchains: Vec<(String, String)> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|component| component["type"] == "application")
        .map(|component| {
            (
                component["name"].as_str().unwrap().to_string(),
                component["properties"][0]["value"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    assert_eq!(
        toolchains,
        [
            ("rust".to_string(), rust_id.to_string()),
            ("rustfmt".to_string(), rustfmt_id.to_string()),
        ],
        "sbom did not inventory the fmt toolchain objects: {}",
        String::from_utf8_lossy(&sbom.stdout)
    );

    let help = tog(&binary, &project, &store, &["fmt", "--", "--help"]);
    assert!(
        help.status.success(),
        "pass-through help failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );

    // This is cargo-fmt's own argument parser rejecting a malformed tog
    // pass-through flag. Its status is 2, so status 1 would not prove
    // unchanged propagation from the formatter.
    let bad_tool_flag = tog(&binary, &project, &store, &["fmt", "--", "--version=bad"]);
    let bad_tool_stderr = String::from_utf8_lossy(&bad_tool_flag.stderr).into_owned();
    assert_eq!(
        bad_tool_flag.status.code(),
        Some(2),
        "formatter status was not passed through unchanged\nstdout:\n{}\nstderr:\n{bad_tool_stderr}",
        String::from_utf8_lossy(&bad_tool_flag.stdout),
    );
    // Status 2 is also tog's own usage exit, so the code alone cannot
    // tell pass-through from a tog-side argument rejection: require
    // cargo-fmt's own diagnostic and the absence of tog's usage line.
    assert!(
        bad_tool_stderr.contains("bad") && bad_tool_stderr.to_lowercase().contains("cargo fmt"),
        "status 2 did not come from cargo-fmt's own argument parser:\n{bad_tool_stderr}"
    );
    assert!(
        !bad_tool_stderr.contains("tog: error:"),
        "status 2 was tog's usage error, not the formatter's:\n{bad_tool_stderr}"
    );

    for entry in fs::read_dir(store.join("objects")).unwrap() {
        age(&entry.unwrap().path());
    }
    let gc = tog(&binary, &project, &store, &["gc", "--keep-days", "0"]);
    assert!(
        gc.status.success(),
        "gc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&gc.stdout),
        String::from_utf8_lossy(&gc.stderr)
    );
    assert!(store.join("objects").join(rust_id).is_dir());
    assert!(store.join("objects").join(rustfmt_id).is_dir());
}

/// Run from a workspace member, `tog fmt` formats with the Rust the
/// workspace root's lock pins, the lock `audit` judges its record against,
/// so the record it writes at the root is current, not stale. The root pins
/// a release other than the catalog's default, which is what the member,
/// having no lock or toolchain file of its own, would otherwise get.
#[test]
#[ignore]
fn fmt_from_a_workspace_member_uses_the_root_lock() {
    let pinned = "1.96.1";
    assert_ne!(default_rust(), pinned);
    let temp = TempDir::new();
    let root = temp.0.join("workspace");
    let member = root.join("member");
    fs::create_dir_all(member.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    fs::write(
        root.join("rust-toolchain.toml"),
        format!("[toolchain]\nchannel = \"{pinned}\"\n"),
    )
    .unwrap();
    fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(
        member.join("src/lib.rs"),
        "pub fn one() -> u32 {\n    1\n}\n",
    )
    .unwrap();
    let store = temp.0.join("store");
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));
    let key = temp.0.join("signing.key");
    let public = tog::kernel::signing::generate(&key).unwrap();
    let home = temp.0.join("home");
    fs::create_dir_all(home.join(".tog")).unwrap();
    fs::write(
        home.join(".tog/policy.toml"),
        format!("[signing]\ntrusted = [\"{public}\"]\n"),
    )
    .unwrap();
    let signed: &[(&str, &Path)] = &[("TOG_SIGNING_KEY", &key), ("HOME", &home)];

    let locked = tog_env(
        &binary,
        &root,
        &store,
        &["update", "--toolchain", "rust", "--no-sync"],
        signed,
    );
    assert!(
        locked.status.success(),
        "update failed\nstderr:\n{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let lock = fs::read_to_string(root.join("tog-toolchain.toml")).unwrap();
    assert!(lock.contains(&format!("version = \"{pinned}\"")), "{lock}");

    let checked = tog_env(&binary, &member, &store, &["fmt", "--check"], signed);
    assert!(
        checked.status.success(),
        "fmt --check from the member failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(!member.join("tog-toolchain.toml").exists());
    assert!(!member.join(".tog/closures/rustfmt.json").exists());
    let closure: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(".tog/closures/rustfmt.json")).unwrap())
            .unwrap();
    let rust_id = closure["body"]["rust_object"]["id"].as_str().unwrap();
    assert!(
        rust_id.ends_with(&format!("-rust-{pinned}")),
        "fmt ran on {rust_id}, not the root lock's Rust {pinned}"
    );

    let audit = tog_env(&binary, &root, &store, &["audit", "--json"], signed);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap_or_default();
    let rustfmt = report["closures"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|closure| closure["ecosystem"] == "rustfmt")
        .cloned()
        .unwrap_or_default();
    assert!(
        rustfmt["verdict"] == "clean"
            && rustfmt["freshness"] == "current"
            && rustfmt["signature"]["state"] == "trusted",
        "audit did not judge the member-run record current\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr)
    );
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
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_tog"));
    let synced = tog(&binary, &project, &store, &["sync"]);
    assert!(
        synced.status.success(),
        "sync failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&synced.stdout),
        String::from_utf8_lossy(&synced.stderr)
    );
    assert!(project.join(".tog/closures/node.json").is_file());

    let run = tog_at(
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
        !project.join(".tog/closures/rustfmt.json").exists(),
        "script precedence unexpectedly realized rustfmt"
    );
}
