//! End-to-end coverage for the Rust `tog fmt` contract.
//!
//! Each test syncs into its own scratch store; a disk-backed TMPDIR keeps
//! those off the small /tmp quota:
//! TMPDIR=<disk-dir> TOG_SANDBOX_TESTS=required
//! cargo test --test fmt_e2e -- --ignored --nocapture

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

mod common;

use common::{copy_tree, fixture, tog, tog_at, TempDir};

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

/// The store object of identity kind `kind`, read from the store's
/// metadata: `tog fmt` writes no record naming the objects it ran.
fn object_of_kind(store: &Path, kind: &str) -> String {
    let ids: Vec<String> = fs::read_dir(store.join("meta"))
        .unwrap()
        .filter_map(|entry| {
            let text = fs::read_to_string(entry.unwrap().path()).ok()?;
            let meta: serde_json::Value = serde_json::from_str(&text).ok()?;
            (meta["identity"]["kind"] == kind).then(|| meta["id"].as_str().unwrap().to_string())
        })
        .collect();
    assert_eq!(ids.len(), 1, "expected one {kind} object, found {ids:?}");
    ids.into_iter().next().unwrap()
}

/// A `rustfmt` closure as an older `tog fmt` wrote it.
fn write_legacy_record(dir: &Path) -> PathBuf {
    let closures = dir.join(".tog/closures");
    fs::create_dir_all(&closures).unwrap();
    let path = closures.join("rustfmt.json");
    fs::write(
        &path,
        r#"{"schema":"closure/1","ecosystem":"rustfmt","projected_at":1,
            "body":{"rust_version":"1.96.1","exceptions":[],
                    "rust_object":{"path":"/store/objects/r","id":"r"},
                    "rustfmt_object":{"path":"/store/objects/f","id":"f"}}}"#,
    )
    .unwrap();
    path
}

/// `tog fmt` needs no lock and no sync, caches its formatter, and writes
/// no closure: the lock pins the formatter, so there is nothing to record.
/// A record an older tog left alone in a never-synced project is removed
/// when the store has no gc root for the project (#416). Nothing roots the
/// formatter objects, so gc may reclaim them between runs and the next run
/// fetches them again.
#[test]
#[ignore]
fn fmt_is_lockless_cached_writes_no_record_and_roots_nothing() {
    let temp = TempDir::new("fmt-e2e");
    let project = temp.0.join("cargo-hello");
    copy_tree(&fixture("cargo-hello"), &project);
    fs::remove_file(project.join("Cargo.lock")).unwrap();
    let legacy = write_legacy_record(&project);
    let store = temp.0.join("store");
    let home = temp.0.join("home");
    fs::create_dir_all(&home).unwrap();

    let first = tog_at(&project, &home, &store, &["fmt", "--check"]);
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
    assert!(legacy.is_file(), "fmt --check changed the checkout");
    let metas = fs::read_dir(store.join("meta"))
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect::<Vec<_>>();
    assert!(
        metas
            .iter()
            .all(|meta| !meta.contains(r#""kind": "cargo-vendor""#)),
        "fmt unexpectedly realized a Cargo vendor object"
    );
    let rust_id = object_of_kind(&store, "rust");
    let rustfmt_id = object_of_kind(&store, "rustfmt");
    assert!(
        rust_id.ends_with(&format!("-rust-{}", default_rust())),
        "{rust_id}"
    );
    let rustfmt_lib_link =
        fs::read_link(store.join("objects").join(&rustfmt_id).join("lib")).unwrap();
    assert!(!rustfmt_lib_link.is_absolute());
    assert_eq!(rustfmt_lib_link, PathBuf::from(format!("../{rust_id}/lib")));
    let rustfmt_meta =
        fs::read_to_string(store.join("meta").join(format!("{rustfmt_id}.json"))).unwrap();
    assert!(
        rustfmt_meta.contains(&format!("\"{rust_id}\"")),
        "rustfmt metadata does not retain the Rust object reference"
    );

    let formatted = tog_at(&project, &home, &store, &["fmt"]);
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
    // The run wrote no closure of its own, and removed the lone legacy
    // record: this store has no gc root for the project, so nothing is
    // left pointing at an empty closures directory (#416).
    let closures: Vec<_> = fs::read_dir(project.join(".tog/closures"))
        .map(|dir| dir.map(|entry| entry.unwrap().file_name()).collect())
        .unwrap_or_default();
    assert!(closures.is_empty(), "{closures:?}");

    let before = object_ids(&store);
    let warm = tog_at(&project, &home, &store, &["fmt", "--check"]);
    assert!(
        warm.status.success(),
        "warm check failed: {:?}",
        warm.status
    );
    assert!(!String::from_utf8_lossy(&warm.stderr).contains("fetching rustfmt"));
    assert_eq!(object_ids(&store), before, "warm fmt created a new object");

    let help = tog_at(&project, &home, &store, &["fmt", "--", "--help"]);
    assert!(
        help.status.success(),
        "pass-through help failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&help.stdout),
        String::from_utf8_lossy(&help.stderr)
    );

    // This is cargo-fmt's own argument parser rejecting a malformed tog
    // pass-through flag. Its status is 2, so status 1 would not prove
    // unchanged propagation from the formatter.
    let bad_tool_flag = tog_at(&project, &home, &store, &["fmt", "--", "--version=bad"]);
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

    // Nothing roots the formatter objects. A registered project keeps the
    // registry non-empty (an empty one makes the sweep refuse) and roots
    // objects of its own, which the same aged sweep has to keep, along with
    // reclaiming a stale `store/tmp/stage-*` an interrupted fmt left.
    let other = temp.0.join("other");
    fs::create_dir_all(&other).unwrap();
    fs::write(other.join("requirements.txt"), "six==1.17.0\n").unwrap();
    let synced = tog_at(&other, &home, &store, &["sync"]);
    assert!(
        synced.status.success(),
        "second project sync failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&synced.stdout),
        String::from_utf8_lossy(&synced.stderr)
    );
    let python_closure: serde_json::Value =
        serde_json::from_slice(&fs::read(other.join(".tog/closures/python.json")).unwrap())
            .unwrap();
    let python_env = PathBuf::from(python_closure["body"]["env_object"].as_str().unwrap());
    assert!(python_env.is_dir(), "{}", python_env.display());
    for entry in fs::read_dir(store.join("objects")).unwrap() {
        age(&entry.unwrap().path());
    }
    let leftover = store.join("tmp/stage-rustfmt-run-leftover");
    fs::create_dir_all(&leftover).unwrap();
    fs::write(leftover.join("scratch"), b"leftover").unwrap();
    fs::File::open(&leftover)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(2 * 24 * 60 * 60))
        .unwrap();
    let swept = tog_at(&project, &home, &store, &["gc", "--keep-days", "0"]);
    assert!(
        swept.status.success(),
        "gc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&swept.stdout),
        String::from_utf8_lossy(&swept.stderr)
    );
    assert!(!leftover.exists(), "gc left the stale stage behind");
    assert!(
        !store.join("objects").join(&rustfmt_id).exists(),
        "gc kept the unrooted rustfmt object"
    );
    assert!(
        python_env.is_dir(),
        "gc swept the other project's rooted environment"
    );

    // The next run realizes the formatter again (from the download cache
    // when gc left the archive there) and formats as before.
    let again = tog_at(&project, &home, &store, &["fmt", "--check"]);
    assert!(
        again.status.success(),
        "fmt after gc failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&again.stdout),
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(store.join("objects").join(&rustfmt_id).is_dir());
}

/// Run from a workspace member, `tog fmt` formats with the Rust the
/// workspace root's lock pins. The root pins a release other than the
/// catalog's default, which is what the member, having no lock or
/// toolchain file of its own, would otherwise get. No record is written in
/// either directory.
#[test]
#[ignore]
fn fmt_from_a_workspace_member_uses_the_root_lock() {
    let pinned = "1.96.1";
    assert_ne!(default_rust(), pinned);
    let temp = TempDir::new("fmt-e2e");
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
    let legacy = write_legacy_record(&root);
    let store = temp.0.join("store");
    let home = temp.0.join("home");
    fs::create_dir_all(&home).unwrap();

    let locked = tog_at(
        &root,
        &home,
        &store,
        &["update", "--toolchain", "rust", "--no-sync"],
    );
    assert!(
        locked.status.success(),
        "update failed\nstderr:\n{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let lock = fs::read_to_string(root.join("tog-toolchain.toml")).unwrap();
    assert!(lock.contains(&format!("version = \"{pinned}\"")), "{lock}");

    let formatted = tog_at(&member, &home, &store, &["fmt"]);
    assert!(
        formatted.status.success(),
        "fmt from the member failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&formatted.stdout),
        String::from_utf8_lossy(&formatted.stderr)
    );
    assert!(!member.join("tog-toolchain.toml").exists());
    assert!(!member.join(".tog/closures/rustfmt.json").exists());
    assert!(
        !legacy.exists(),
        "a lone legacy record with no gc root must be removed (#416)"
    );
    let rust_id = object_of_kind(&store, "rust");
    assert!(
        rust_id.ends_with(&format!("-rust-{pinned}")),
        "fmt ran on {rust_id}, not the root lock's Rust {pinned}"
    );
}

#[test]
#[ignore]
fn fmt_script_precedence_runs_script_from_a_project_subdirectory() {
    let temp = TempDir::new("fmt-e2e");
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

    let synced = tog(&project, &temp.0, &["sync"]);
    assert!(
        synced.status.success(),
        "sync failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&synced.stdout),
        String::from_utf8_lossy(&synced.stderr)
    );
    assert!(project.join(".tog/closures/node.json").is_file());

    let run = tog(&project.join("src"), &temp.0, &["fmt", "--check", "extra"]);
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
