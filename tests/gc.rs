//! Ignored end-to-end coverage for project roots and cross-ecosystem GC.
//!
//! Run on a Linux host with a throwaway store:
//! BLANKET_STORE=$HOME/scratch/tmp/nxgc-store TMPDIR=$HOME/scratch/tmp \
//! cargo test --test gc -- --ignored --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

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

fn blanket(bin: &Path, cwd: &Path, store: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(cwd)
        .env("BLANKET_STORE", store)
        .args(args)
        .output()
        .unwrap()
}

fn blanket_home(bin: &Path, cwd: &Path, store: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .current_dir(cwd)
        .env("BLANKET_STORE", store)
        .env("HOME", home)
        .env_remove("BLANKET_POLICY")
        .env_remove("BLANKET_STRICT")
        .env("NO_COLOR", "1")
        .args(args)
        .output()
        .unwrap()
}

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

fn ok(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn age(path: &Path) {
    let old = SystemTime::now()
        .checked_sub(Duration::from_secs(2 * 24 * 60 * 60))
        .unwrap();
    fs::File::open(path).unwrap().set_modified(old).unwrap();
}

/// Parse `blanket store roots` output: one "<key>  <path>" line per root.
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
    let temp = TempDir::new();
    // Keep this test independent of the shared store used by the ignored
    // end-to-end suite. Other projects may legitimately retain node objects.
    let store = temp.0.join("store");
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let python = temp.0.join("proj-a");
    let node = temp.0.join("proj-npm");
    copy_tree(&fixtures.join("proj-a"), &python);
    copy_tree(&fixtures.join("proj-npm"), &node);
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    ok(blanket(&bin, &python, &store, &["sync"]), "sync proj-a");
    ok(blanket(&bin, &node, &store, &["sync"]), "sync proj-npm");
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
    // longer blocks collection and its tools remain protected.
    let retained = blanket(
        &bin,
        &python,
        &store,
        &["gc", "--dry-run", "--keep-days", "0"],
    );
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

    let keys = roots_listing(&ok(
        blanket(&bin, &python, &store, &["store", "roots"]),
        "store roots",
    ));
    let node_key = keys
        .iter()
        .find(|(_, path)| Path::new(path) == node_canonical)
        .map(|(key, _)| key.clone())
        .expect("node root key in listing");

    // Dry-run forget simulates only; the record survives.
    let dry = ok(
        blanket(
            &bin,
            &python,
            &store,
            &["gc", "--dry-run", "--forget", &node_key],
        ),
        "gc dry-run forget",
    );
    assert!(dry.contains("would forget root"), "{dry}");
    assert!(
        roots_listing(&ok(
            blanket(&bin, &python, &store, &["store", "roots"]),
            "store roots"
        ))
        .iter()
        .any(|(key, _)| key == &node_key),
        "dry-run forgot the record"
    );

    ok(
        blanket(
            &bin,
            &python,
            &store,
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
        objects
            .iter()
            .all(|meta| !meta.contains(r#""kind": "node-env""#)),
        "node object survived GC after its record was forgotten"
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

/// Upgrade scenario: objects and closure files can predate the roots
/// registry, while the project's root entry was never written. A default GC
/// must refuse to sweep before migration, regardless of --keep-days.
#[test]
#[ignore]
fn gc_upgrade_does_not_collect_unregistered_legacy_project() {
    let temp = TempDir::new();
    let store = temp.0.join("store");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        fs::create_dir_all(store.join(sub)).unwrap();
    }
    let id = format!("{}-legacy", "a".repeat(40));
    let object = store.join("objects").join(&id);
    fs::create_dir_all(&object).unwrap();
    fs::write(object.join("payload"), b"pre-registry object").unwrap();
    fs::write(
        store.join("meta").join(format!("{id}.json")),
        serde_json::json!({
            "id": id,
            "identity": {"kind": "legacy-project", "inputs": {}}
        })
        .to_string(),
    )
    .unwrap();
    age(&object);

    let project = temp.0.join("never-resynced");
    fs::create_dir_all(project.join(".blanket/closures")).unwrap();
    fs::write(
        project.join(".blanket/closures/python.json"),
        serde_json::json!({
            "schema": "closure/1",
            "ecosystem": "python",
            "body": {"env_object": object.display().to_string()}
        })
        .to_string(),
    )
    .unwrap();

    let bin = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));
    let refused = blanket(&bin, &project, &store, &["gc", "--keep-days", "0"]);
    assert!(
        !refused.status.success(),
        "uninitialized GC unexpectedly ran"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("refusing to sweep"),
        "unexpected error: {stderr}"
    );
    assert!(
        stderr.contains("--register"),
        "migration hint missing: {stderr}"
    );
    assert!(object.is_dir(), "default upgrade GC deleted the old object");

    let registered = blanket(
        &bin,
        &project,
        &store,
        &["gc", "--register", project.to_str().unwrap()],
    );
    assert!(
        !registered.status.success(),
        "registration unexpectedly started a sweep with uncertified metadata"
    );
    assert!(
        String::from_utf8_lossy(&registered.stderr).contains("--migrate-metadata"),
        "unresolved metadata recovery hint missing: {}",
        String::from_utf8_lossy(&registered.stderr)
    );
    assert!(
        fs::read_dir(store.join("roots"))
            .unwrap()
            .any(|entry| entry.unwrap().file_name() != ".initialized"),
        "explicit root registration was not durable before migration refusal"
    );
    assert!(object.is_dir(), "registered legacy object was collected");
}

#[test]
#[ignore]
fn x_clean_removes_registered_environment_and_running_x_is_busy() {
    let temp = TempDir::new();
    let store = temp.0.join("store");
    let home = temp.0.join("home");
    let project = temp.0.join("project");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project).unwrap();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_blanket"));

    ok(
        blanket_home(
            &bin,
            &project,
            &store,
            &home,
            &["x", "py:ruff", "--version"],
        ),
        "realize x ruff",
    );
    let x_dir = home.join(".blanket/x");
    let ruff_root = fs::read_dir(&x_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join(".blanket/x.json").is_file())
        .expect("ruff x root");
    let ruff_canonical = ruff_root.canonicalize().unwrap();
    let closure: serde_json::Value = serde_json::from_reader(
        fs::File::open(ruff_root.join(".blanket/closures/python.json")).unwrap(),
    )
    .unwrap();
    let env_object = PathBuf::from(closure["body"]["env_object"].as_str().unwrap());
    assert!(env_object.is_dir(), "realized environment object");

    // A ready marker is not enough to accept a cache hit: deleting the
    // projection must make the next run reproject the cached environment.
    fs::remove_file(ruff_root.join(".venv")).unwrap();
    ok(
        blanket_home(
            &bin,
            &project,
            &store,
            &home,
            &["x", "py:ruff", "--version"],
        ),
        "repair missing x projection",
    );
    assert!(ruff_root.join(".venv").is_symlink());

    let roots = ok(
        blanket_home(&bin, &project, &store, &home, &["store", "roots"]),
        "x root registration",
    );
    assert!(roots_listing(&roots)
        .iter()
        .any(|(_, path)| Path::new(path) == ruff_canonical));

    let cleaned = ok(
        blanket_home(&bin, &project, &store, &home, &["x", "--clean", "py:ruff"]),
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
    let roots = ok(
        blanket_home(&bin, &project, &store, &home, &["store", "roots"]),
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
    ok(
        blanket_home(&bin, &project, &store, &home, &["gc", "--keep-days", "0"]),
        "gc after x clean",
    );
    assert!(
        !env_object.exists(),
        "gc retained the unrooted x environment"
    );

    // Prewarm pytest so the busy process reaches the test body quickly and
    // the readiness handshake below tests lock inheritance, not PyPI latency.
    ok(
        blanket_home(
            &bin,
            &project,
            &store,
            &home,
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
                && path.join(".blanket/x.json").is_file()
        })
        .expect("prewarmed pytest x root");
    let ready = project.join("pytest-started");
    let release = project.join("pytest-release");
    fs::write(
        project.join("test_sleep.py"),
        "import os\nimport time\nfrom pathlib import Path\n\ndef test_sleep():\n    Path(os.environ[\"BLANKET_TEST_READY\"]).write_text(\"ready\")\n    release = Path(os.environ[\"BLANKET_TEST_RELEASE\"])\n    while not release.is_file():\n        time.sleep(0.1)\n",
    )
    .unwrap();
    let running = ChildGuard(Some(
        Command::new(&bin)
            .current_dir(&project)
            .env("BLANKET_STORE", &store)
            .env("HOME", &home)
            .env("BLANKET_TEST_READY", &ready)
            .env("BLANKET_TEST_RELEASE", &release)
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
    let busy = blanket_home(&bin, &project, &store, &home, &["x", "--clean", "pytest"]);
    assert_eq!(busy.status.code(), Some(0), "clean while busy failed");
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

    let cleaned = ok(
        blanket_home(&bin, &project, &store, &home, &["x", "--clean", "pytest"]),
        "clean pytest after exit",
    );
    assert!(cleaned.contains("removed x environment"), "{cleaned}");
    assert!(!pytest_root.exists());
}
