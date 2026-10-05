//! Ignored end-to-end coverage for project roots and cross-ecosystem GC.
//!
//! Run on a Linux host with TMPDIR under $HOME, so the scratch stores stay
//! off the small /tmp quota:
//! TMPDIR=$HOME/scratch/tmp cargo test --test gc -- --ignored --nocapture

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

mod common;

use common::{assert_ok, command, copy_tree, fixture, tog, tog_at, TempDir};

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn wait_output(mut self) -> Output {
        self.0
            .take()
            .expect("child guard still owns its child")
            .wait_with_output()
            .unwrap()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Like `assert_ok`, for commands that narrate instead of printing a result.
/// CLI.md: stdout is results, stderr is narration. `tog gc` writes its whole
/// report to stderr, so assertions on gc narration read that stream.
fn ok_narration(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stderr).unwrap()
}

/// Parse `tog store roots` output: one "<key>  <path>" line per root.
fn roots_listing(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (key, path) = line.split_once("  ")?;
            Some((key.to_string(), path.to_string()))
        })
        .collect()
}

#[test]
#[ignore]
fn gc_keeps_deleted_node_project_until_forgotten() {
    let temp = TempDir::new("gc-e2e");
    // Keep this test independent of the shared store used by the ignored
    // end-to-end suite. Other projects may legitimately retain node objects.
    let home = temp.path();
    let store = home.join("store");
    let python = temp.0.join("proj-a");
    let node = temp.0.join("proj-npm");
    copy_tree(&fixture("proj-a"), &python);
    copy_tree(&fixture("proj-npm"), &node);

    assert_ok(tog(&python, home, &["sync"]), "sync proj-a");
    assert_ok(tog(&node, home, &["sync"]), "sync proj-npm");
    let node_canonical = node.canonicalize().unwrap();
    fs::remove_dir_all(&node).unwrap();

    // The production safeguard intentionally keeps objects touched in the
    // last ten minutes. Age only the now-unreachable node objects so this
    // test exercises the sweep without sleeping.
    for entry in fs::read_dir(store.join("objects")).unwrap() {
        let entry = entry.unwrap();
        let meta = store
            .join("meta")
            .join(format!("{}.json", entry.file_name().to_string_lossy()));
        let text = fs::read_to_string(meta).unwrap();
        if text.contains(r#""kind": "node-env""#) {
            let old = SystemTime::now()
                .checked_sub(Duration::from_secs(11 * 60))
                .unwrap();
            fs::File::open(entry.path())
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
    }

    // A root/2 record carries its own object set, so a deleted project no
    // longer blocks collection and its tools remain protected. A real
    // sweep, not a dry run: only a sweep that deletes can prove the record
    // kept the aged, now-unreachable node objects.
    let retained = tog(&python, home, &["gc", "--keep-days", "0"]);
    assert!(
        retained.status.success(),
        "gc refused a self-sufficient root record: stdout={} stderr={}",
        String::from_utf8_lossy(&retained.stdout),
        String::from_utf8_lossy(&retained.stderr)
    );
    assert!(
        fs::read_dir(store.join("objects")).unwrap().any(|entry| {
            let entry = entry.unwrap();
            fs::read_to_string(
                store
                    .join("meta")
                    .join(format!("{}.json", entry.file_name().to_string_lossy())),
            )
            .unwrap()
            .contains(r#""kind": "node-env""#)
        }),
        "gc swept a deleted project's rooted node object"
    );

    let keys = roots_listing(&assert_ok(
        tog(&python, home, &["store", "roots"]),
        "store roots",
    ));
    let node_key = keys
        .iter()
        .find(|(_, path)| Path::new(path) == node_canonical)
        .map(|(key, _)| key.clone())
        .expect("node root key in listing");

    // Dry-run forget simulates only; the record survives.
    let dry = ok_narration(
        tog(&python, home, &["gc", "--dry-run", "--forget", &node_key]),
        "gc dry-run forget",
    );
    assert!(dry.contains("would forget root"), "{dry}");
    assert!(
        roots_listing(&assert_ok(
            tog(&python, home, &["store", "roots"]),
            "store roots"
        ))
        .iter()
        .any(|(key, _)| key == &node_key),
        "dry-run forgot the record"
    );

    assert_ok(
        tog(
            &python,
            home,
            &["gc", "--forget", &node_key, "--keep-days", "0"],
        ),
        "forget the node root",
    );
    let objects_after_forget = fs::read_dir(store.join("objects"))
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
        objects_after_forget
            .iter()
            .any(|meta| meta.contains(r#""kind": "node-env""#)),
        "forget unexpectedly swept store objects"
    );
    assert_ok(tog(&python, home, &["gc"]), "gc");
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
        objects
            .iter()
            .all(|meta| !meta.contains(r#""kind": "node-env""#)),
        "node object survived GC after its record was forgotten"
    );
    assert_ok(
        tog(&python, home, &["run", "python", "-c", "import six"]),
        "python after gc",
    );
}

#[test]
#[ignore]
fn x_clean_removes_registered_environment_and_running_x_is_busy() {
    let temp = TempDir::new("gc-e2e");
    let store = temp.0.join("store");
    let home = temp.0.join("home");
    let project = temp.0.join("project");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project).unwrap();

    assert_ok(
        tog_at(&project, &home, &store, &["x", "py:ruff", "--version"]),
        "realize x ruff",
    );
    let x_dir = home.join(".tog/x");
    let ruff_root = fs::read_dir(&x_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join(".tog/x.json").is_file())
        .expect("ruff x root");
    let ruff_canonical = ruff_root.canonicalize().unwrap();
    let closure: serde_json::Value = serde_json::from_reader(
        fs::File::open(ruff_root.join(".tog/closures/python.json")).unwrap(),
    )
    .unwrap();
    let env_object = PathBuf::from(closure["body"]["env_object"].as_str().unwrap());
    assert!(env_object.is_dir(), "realized environment object");

    // A ready marker is not enough to accept a cache hit: deleting the
    // projection must make the next run reproject the cached environment.
    fs::remove_file(ruff_root.join(".venv")).unwrap();
    assert_ok(
        tog_at(&project, &home, &store, &["x", "py:ruff", "--version"]),
        "repair missing x projection",
    );
    assert!(ruff_root.join(".venv").is_symlink());

    let roots = assert_ok(
        tog_at(&project, &home, &store, &["store", "roots"]),
        "x root registration",
    );
    assert!(roots_listing(&roots)
        .iter()
        .any(|(_, path)| Path::new(path) == ruff_canonical));

    let cleaned = assert_ok(
        tog_at(&project, &home, &store, &["x", "--clean", "py:ruff"]),
        "clean x ruff",
    );
    assert!(cleaned.contains("removed x environment"), "{cleaned}");
    assert!(!ruff_root.exists());
    // The per-root lock is unlinked while cleanup still holds it, so `.locks`
    // does not keep one stale file per environment ever created.
    let ruff_lock = x_dir.join(".locks").join(format!(
        "{}.lock",
        ruff_root.file_name().unwrap().to_string_lossy()
    ));
    assert!(
        !ruff_lock.exists(),
        "cleanup left {} behind",
        ruff_lock.display()
    );
    let roots = assert_ok(
        tog_at(&project, &home, &store, &["store", "roots"]),
        "removed x root registration",
    );
    assert!(!roots_listing(&roots)
        .iter()
        .any(|(_, path)| Path::new(path) == ruff_canonical));

    // ACTIVE_WINDOW is deliberately independent of the lock. Age only the
    // now-unrooted x environment so the following GC proves cleanup leaves
    // immutable objects for the ordinary collector.
    fs::File::open(&env_object)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(11 * 60))
        .unwrap();
    assert_ok(
        tog_at(&project, &home, &store, &["gc", "--keep-days", "0"]),
        "gc after x clean",
    );
    assert!(
        !env_object.exists(),
        "gc retained the unrooted x environment"
    );

    // Prewarm pytest so the busy process reaches the test body quickly and
    // the readiness handshake below tests lock inheritance, not PyPI latency.
    assert_ok(
        tog_at(
            &project,
            &home,
            &store,
            &["x", "--py", "pytest", "--version"],
        ),
        "prewarm x pytest",
    );
    let pytest_root = fs::read_dir(&x_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("py-pytest-"))
                && path.join(".tog/x.json").is_file()
        })
        .expect("prewarmed pytest x root");
    let ready = project.join("pytest-started");
    let release = project.join("pytest-release");
    fs::write(
        project.join("test_sleep.py"),
        "import os\nimport time\nfrom pathlib import Path\n\ndef test_sleep():\n    Path(os.environ[\"TOG_TEST_READY\"]).write_text(\"ready\")\n    release = Path(os.environ[\"TOG_TEST_RELEASE\"])\n    while not release.is_file():\n        time.sleep(0.1)\n",
    )
    .unwrap();
    let running = ChildGuard(Some(
        command(&project, &home, &store)
            .env("TOG_TEST_READY", &ready)
            .env("TOG_TEST_RELEASE", &release)
            .args(["x", "--py", "pytest", "-q", "test_sleep.py"])
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready.is_file() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        ready.is_file(),
        "pytest did not reach the readiness handshake"
    );
    let busy = tog_at(&project, &home, &store, &["x", "--clean", "pytest"]);
    assert_eq!(busy.status.code(), Some(1), "a clean that skips exits 1");
    let busy_text = String::from_utf8_lossy(&busy.stdout);
    assert!(
        busy_text.contains("in use by a running tool; retry later"),
        "{busy_text}"
    );
    assert!(pytest_root.exists(), "busy x root was removed");
    fs::write(&release, b"release").unwrap();
    let child = running.wait_output();
    assert!(
        child.status.success(),
        "pytest x failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );

    let cleaned = assert_ok(
        tog_at(&project, &home, &store, &["x", "--clean", "pytest"]),
        "clean pytest after exit",
    );
    assert!(cleaned.contains("removed x environment"), "{cleaned}");
    assert!(!pytest_root.exists());
}

/// `tog x npm:<tool>` end to end: npm resolves through the store Node, the
/// environment is projected as a `node_modules` forest link under an
/// `npm-` cache directory, the tool runs on the store Node (never a `node`
/// from the inherited PATH), a second run is a cache hit, a deleted projection is
/// repaired, and `--clean` removes the root with the forest hint.
#[test]
#[ignore]
fn x_runs_an_npm_tool_on_the_store_node_and_cleans_it() {
    let temp = TempDir::new("gc-e2e");
    let store = temp.0.join("store");
    let home = temp.0.join("home");
    let project = temp.0.join("project");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project).unwrap();
    // `semver` is a dependency-free package whose bin is a
    // `#!/usr/bin/env node` script. tog itself needs the system PATH (tar
    // shells out to gzip), so the inherited PATH leads with a decoy `node`
    // that fails loudly: the tool prints its answer only if `x` put the
    // store Node ahead of everything inherited, host Node included.
    let decoy = temp.0.join("decoy-bin");
    fs::create_dir_all(&decoy).unwrap();
    fs::write(
        decoy.join("node"),
        "#!/bin/sh\necho 'decoy node ran instead of the store node' >&2\nexit 97\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(decoy.join("node"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:/usr/bin:/bin", decoy.display());
    let run = || {
        command(&project, &home, &store)
            .env("PATH", &path)
            .args(["x", "npm:semver@7.6.3", "1.2.3", "-r", ">=1"])
            .output()
            .unwrap()
    };

    let first = run();
    let first_stderr = String::from_utf8_lossy(&first.stderr).into_owned();
    let stdout = assert_ok(first, "first x semver");
    assert!(first_stderr.contains("resolving"), "{first_stderr}");
    assert_eq!(stdout.trim(), "1.2.3");

    let x_dir = home.join(".tog/x");
    let root = fs::read_dir(&x_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join(".tog/x.json").is_file())
        .expect("semver x root");
    let name = root.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("npm-semver-"), "{name}");
    assert!(root.join("node_modules").is_symlink());
    assert!(root.join(".tog/closures/node.json").is_file());

    // A cache hit resolves nothing.
    let second = run();
    let stderr = String::from_utf8_lossy(&second.stderr).into_owned();
    assert_eq!(assert_ok(second, "cached x semver").trim(), "1.2.3");
    assert!(!stderr.contains("resolving"), "{stderr}");

    // A deleted projection is reprojected, not trusted.
    fs::remove_file(root.join("node_modules")).unwrap();
    assert_eq!(assert_ok(run(), "repair x semver").trim(), "1.2.3");
    assert!(root.join("node_modules").is_symlink());

    let cleaned = assert_ok(
        tog_at(&project, &home, &store, &["x", "--clean", "npm:semver"]),
        "clean x semver",
    );
    assert!(cleaned.contains("removed x environment"), "{cleaned}");
    assert!(
        cleaned.contains("'tog gc --project' also reclaims the node_modules forest"),
        "{cleaned}"
    );
    assert!(!root.exists());
}
