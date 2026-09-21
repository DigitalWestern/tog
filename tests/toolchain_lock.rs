//! The toolchain lock as a user meets it: `tog sync` writing and honoring
//! `tog-toolchain.toml`, `tog sync --frozen` validating one without touching
//! anything, `tog update --toolchain` replacing one, and `tog status`
//! reporting what the committed file says about the project.
//!
//! Every case here is offline. Nothing in this file downloads a toolchain:
//! the fixtures either stop before realization (a refusal, which is the
//! whole point of most of them) or use a manifest whose planner fails in
//! the project directory, which happens after the lock has been published
//! and before any network call.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use tog::comforter::toolchain as project_toolchain;
use tog::kernel::fsroot::ProjectRoot;
use tog::kernel::platform::Platform;
use tog::kernel::toolchain::input::{self, InputRow};
use tog::kernel::toolchain::lock::{ToolchainLock, LOCK_PATH};
use tog::kernel::toolchain::{select_for, Catalog, Source};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-lock-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
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

/// A project and the throwaway home its store, policy and `x` cache live
/// in, so nothing here can read the developer's configuration.
struct Fixture {
    home: TempDir,
    project: TempDir,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let fixture = Self {
            home: TempDir::new(&format!("{label}-home")),
            project: TempDir::new(&format!("{label}-project")),
        };
        // A project boundary, so an ancestor checkout's manifests and
        // policy cannot reach these fixtures.
        std::fs::create_dir_all(fixture.home.0.join(".tog")).unwrap();
        fixture
    }

    fn dir(&self) -> &Path {
        &self.project.0
    }

    fn store(&self) -> PathBuf {
        self.home.0.join("store")
    }

    fn write(&self, name: &str, text: &str) {
        let path = self.project.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, text).unwrap();
    }

    fn lock_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(self.project.0.join(LOCK_PATH)).ok()
    }

    fn tog(&self, args: &[&str]) -> Output {
        self.tog_env(args, &[])
    }

    fn tog_env(&self, args: &[&str], env: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tog"));
        command
            .args(args)
            .current_dir(&self.project.0)
            .env("TOG_STORE", self.store())
            .env("HOME", &self.home.0)
            .env_remove("TOG_POLICY")
            .env_remove("TOG_STRICT")
            .env_remove("TOG_SIGNING_KEY")
            .env("NO_COLOR", "1");
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().expect("spawn tog")
    }

    /// Publish a `tog-toolchain.toml` describing the project exactly as it
    /// is right now, for `ecosystem`. Tests then change one source file and
    /// watch what the lock says about the change.
    fn commit_lock(&self, ecosystem: &str) {
        let lock = build_lock(self.dir(), &[ecosystem]);
        std::fs::write(self.project.0.join(LOCK_PATH), lock.canonical_bytes()).unwrap();
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn catalog_of(ecosystem: &str) -> Catalog {
    let tailor = tog::tailors::registry()
        .iter()
        .find(|tailor| tailor.lock_ecosystem() == ecosystem)
        .unwrap_or_else(|| panic!("no tailor for {ecosystem}"));
    tailor.toolchain_catalog().unwrap()
}

fn rows_of(dir: &Path, ecosystem: &str) -> Vec<InputRow> {
    let root = ProjectRoot::open(dir).unwrap();
    input::discover(&root, ecosystem).unwrap()
}

/// The lock a writable sync of `dir` would write for these ecosystems,
/// built through the same selection and the same writer the binary uses.
fn build_lock(dir: &Path, ecosystems: &[&str]) -> ToolchainLock {
    let mut lock = ToolchainLock::new(env!("CARGO_PKG_VERSION"));
    for ecosystem in ecosystems {
        let rows = rows_of(dir, ecosystem);
        let catalog = catalog_of(ecosystem);
        let bundle = select_for(&catalog, ecosystem, &rows).unwrap();
        lock.set_ecosystem(ecosystem, bundle, &rows).unwrap();
    }
    lock
}

/// Two CPython versions the shipped catalog has for every platform, newest
/// first. Tests pin one, then move the source to the other.
fn two_python_versions() -> (String, String) {
    let catalog = catalog_of("python");
    let mut versions: Vec<String> = catalog
        .bundles()
        .iter()
        .filter(|bundle| Platform::ALL.iter().all(|p| bundle.complete_for(*p)))
        .filter_map(|bundle| {
            bundle
                .component("cpython")
                .map(|entry| entry.version.clone())
        })
        .collect();
    versions.dedup();
    assert!(
        versions.len() >= 2,
        "the shipped catalog needs two complete CPython releases for these tests"
    );
    (versions[0].clone(), versions[1].clone())
}

/// A Python manifest whose planner refuses in the project directory, before
/// it asks the network for anything. A sync of this project gets as far as
/// publishing the lock and then fails, which is exactly the window these
/// tests need to observe.
const UNPLANNABLE_PYPROJECT: &str = "\
[project]
name = \"fixture\"
version = \"0.1.0\"

[project.optional-dependencies]
a = [\"optional-package\"]
z = \"malformed group\"
";

const PLAIN_PYPROJECT: &str = "\
[project]
name = \"fixture\"
version = \"0.1.0\"
";

// ---------------------------------------------------------------------------
// creation

/// The first writable sync of a project with no lock writes one, at the
/// project root, in canonical bytes, naming what it selected. The sync
/// after it fails on the manifest, which is how this stays offline; the
/// lock is published before any tailor runs, so it is there either way.
#[test]
fn no_pin_creation() {
    let fixture = Fixture::new("create");
    let (newest, _) = two_python_versions();
    fixture.write("pyproject.toml", UNPLANNABLE_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));

    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("wrote tog-toolchain.toml; commit it"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("selected cpython {newest}")),
        "{stderr}"
    );

    let bytes = fixture.lock_bytes().expect("the lock was published");
    let lock = ToolchainLock::parse(&bytes).expect("the published lock parses");
    assert_eq!(
        lock.canonical_bytes(),
        bytes,
        "the published bytes are canonical"
    );
    let section = lock
        .ecosystem("python")
        .expect("a [toolchain.python] section");
    assert_eq!(section.runtime(), "cpython");
    assert_eq!(
        section
            .inputs()
            .iter()
            .find(|row| row.path == Path::new(".python-version"))
            .and_then(|row| row.value.clone()),
        Some(newest)
    );
}

/// The same thing with a real sync: a project with no lock ends synced,
/// with a committed lock, and the sync after it is a hit that rewrites
/// nothing. Needs the network for the toolchain, so it is off by default.
#[test]
#[ignore]
fn no_pin_creation_end_to_end() {
    if !cfg!(target_os = "linux") {
        eprintln!("toolchain_lock: skipped on non-Linux host");
        return;
    }
    let fixture = Fixture::new("create-e2e");
    let (newest, _) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));

    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let bytes = fixture.lock_bytes().expect("the lock was published");
    assert!(fixture.dir().join(".venv").exists(), "{stderr}");

    // A second sync honors what the first wrote.
    let again = fixture.tog(&["sync"]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again.stderr));
    assert!(
        !text(&again.stderr).contains("wrote tog-toolchain.toml"),
        "{}",
        text(&again.stderr)
    );
    assert_eq!(fixture.lock_bytes().unwrap(), bytes);

    // And status agrees with both of them.
    let status = fixture.tog(&["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", text(&status.stdout));
}

/// A lock is honored, not re-derived: a second sync reads the committed
/// file and leaves it exactly as it found it.
#[test]
fn an_existing_lock_is_honored_and_never_rewritten() {
    let fixture = Fixture::new("honor");
    let (newest, _) = two_python_versions();
    fixture.write("pyproject.toml", UNPLANNABLE_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");
    let before = fixture.lock_bytes().unwrap();

    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(!stderr.contains("wrote tog-toolchain.toml"), "{stderr}");
    assert_eq!(fixture.lock_bytes().unwrap(), before);
}

// ---------------------------------------------------------------------------
// staleness

/// The one staleness rule, at the surface: a recorded value that no longer
/// matches the file stops the sync, names both values, and names the only
/// verb that may move the runtime.
#[test]
fn stale_refusal_names_both_values() {
    let fixture = Fixture::new("stale");
    let (newest, older) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");
    let before = fixture.lock_bytes().unwrap();
    fixture.write(".python-version", &format!("{older}\n"));

    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("tog-toolchain.toml is stale for python"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&newest) && stderr.contains(&older),
        "{stderr}"
    );
    assert!(stderr.contains("tog update --toolchain python"), "{stderr}");
    assert_eq!(
        fixture.lock_bytes().unwrap(),
        before,
        "a refusal rewrote the lock"
    );
    assert!(!fixture.store().exists(), "a refusal created the store");
}

/// A source appearing where the lock recorded `absent` is the case that
/// only a complete consulted-path list can see: the winning row did not
/// change, a *higher*-precedence file simply arrived.
#[test]
fn added_higher_precedence_source_is_stale() {
    let fixture = Fixture::new("absent");
    let (newest, _) = two_python_versions();
    fixture.write(
        "pyproject.toml",
        &format!(
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\nrequires-python = \"=={newest}\"\n"
        ),
    );
    // No .python-version yet: the lock records that row absent.
    fixture.commit_lock("python");
    let recorded = ToolchainLock::parse(&fixture.lock_bytes().unwrap()).unwrap();
    let row = recorded
        .ecosystem("python")
        .unwrap()
        .inputs()
        .into_iter()
        .find(|row| row.path == Path::new(".python-version"))
        .expect("the consulted list has a row for every path, present or not");
    assert!(row.absent && row.value.is_none(), "{row:?}");

    // The same version, stated by a file the lock says is not there.
    fixture.write(".python-version", &format!("{newest}\n"));
    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("tog-toolchain.toml is stale for python"),
        "{stderr}"
    );
    assert!(stderr.contains(".python-version"), "{stderr}");
    assert!(stderr.contains("recorded absent"), "{stderr}");
}

/// A lock with no section for an ecosystem the project just gained is
/// stale, not absent: sync refuses rather than quietly inventing a runtime,
/// and `update --toolchain` is what adds the section.
#[test]
fn a_lock_with_no_section_for_a_new_ecosystem_is_stale() {
    let fixture = Fixture::new("neweco");
    let (newest, _) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");

    fixture.write(
        "package.json",
        "{\"name\":\"fixture\",\"version\":\"0.0.0\"}\n",
    );
    fixture.write(
        "package-lock.json",
        "{\"name\":\"fixture\",\"lockfileVersion\":3,\"packages\":{}}\n",
    );
    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("no [toolchain.node] section"), "{stderr}");
    assert!(stderr.contains("tog update --toolchain node"), "{stderr}");
}

// ---------------------------------------------------------------------------
// --frozen

/// `--frozen` never creates a lock, and the refusal lands before anything
/// is written: no lock, no store tree, no projection, no `.tog` metadata.
#[test]
fn frozen_validation_failure_precedes_all_writes() {
    let fixture = Fixture::new("frozen-nowrite");
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", "3.12.14\n");

    let out = fixture.tog(&["sync", "--frozen"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("--frozen never creates it"), "{stderr}");
    assert!(stderr.contains("commit the file"), "{stderr}");
    assert!(fixture.lock_bytes().is_none(), "--frozen wrote a lock");
    assert!(!fixture.store().exists(), "--frozen created the store");
    assert!(
        !fixture.dir().join(".tog").exists(),
        "--frozen wrote project metadata"
    );
    assert!(!fixture.dir().join(".venv").exists(), "--frozen projected");
}

/// A stale lock is refused under `--frozen` exactly as it is under an
/// ordinary sync; `--frozen` adds "never write one", not a second rule for
/// deciding what is stale.
#[test]
fn frozen_refuses_a_stale_lock_without_rewriting_it() {
    let fixture = Fixture::new("frozen-stale");
    let (newest, older) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");
    let before = fixture.lock_bytes().unwrap();
    fixture.write(".python-version", &format!("{older}\n"));

    let out = fixture.tog(&["sync", "--frozen"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("tog-toolchain.toml is stale for python"),
        "{stderr}"
    );
    assert_eq!(fixture.lock_bytes().unwrap(), before);
    assert!(!fixture.store().exists());
}

/// Frozen validation evaluates no project code. A Gemfile is a Ruby program
/// and the `ruby` directive sits beside arbitrary statements, so this one
/// writes a marker file when it is evaluated: validation finishes, and the
/// marker is not there.
#[test]
fn frozen_never_evaluates_project_code() {
    let fixture = Fixture::new("frozen-gemfile");
    fixture.write(
        "Gemfile",
        "File.write(File.join(__dir__, 'evaluated.marker'), 'ran')\n\
         ruby \"3.3.4\"\n\
         source \"https://rubygems.org\"\n",
    );
    fixture.write("Gemfile.lock", "DEPENDENCIES\n\nBUNDLED WITH\n   2.5.9\n");

    let out = fixture.tog(&["sync", "--frozen"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("tog-toolchain.toml"), "{stderr}");
    assert!(
        !fixture.dir().join("evaluated.marker").exists(),
        "frozen validation evaluated the Gemfile: {stderr}"
    );
    assert!(!fixture.store().exists(), "{stderr}");
}

// ---------------------------------------------------------------------------
// update --toolchain

/// The one verb that replaces a lock. It re-reads the sources, rewrites the
/// file, and leaves every dependency lock alone.
#[test]
fn update_toolchain_replaces_a_stale_lock() {
    let fixture = Fixture::new("update");
    let (newest, older) = two_python_versions();
    fixture.write("pyproject.toml", UNPLANNABLE_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");
    fixture.write("requirements.lock.txt", "# pinned by hand\n");
    let dependency_lock_before =
        std::fs::read(fixture.dir().join("requirements.lock.txt")).unwrap();
    fixture.write(".python-version", &format!("{older}\n"));

    let out = fixture.tog(&["update", "--toolchain"]);
    let stderr = text(&out.stderr);
    assert!(stderr.contains("updated tog-toolchain.toml"), "{stderr}");
    assert!(
        stderr.contains(&format!("selected cpython {older}")),
        "{stderr}"
    );

    let lock = ToolchainLock::parse(&fixture.lock_bytes().unwrap()).unwrap();
    assert_eq!(
        lock.ecosystem("python")
            .unwrap()
            .inputs()
            .iter()
            .find(|row| row.path == Path::new(".python-version"))
            .and_then(|row| row.value.clone()),
        Some(older)
    );
    assert_eq!(
        std::fs::read(fixture.dir().join("requirements.lock.txt")).unwrap(),
        dependency_lock_before,
        "update --toolchain rewrote a dependency lock"
    );
}

/// Naming an ecosystem updates that one and leaves the other sections as
/// they are, which is what makes the narrow form worth having.
#[test]
fn update_toolchain_for_one_ecosystem_leaves_the_others_alone() {
    let fixture = Fixture::new("update-one");
    let (newest, older) = two_python_versions();
    fixture.write("pyproject.toml", UNPLANNABLE_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.write(
        "package.json",
        "{\"name\":\"fixture\",\"version\":\"0.0.0\"}\n",
    );
    fixture.write(
        "package-lock.json",
        "{\"name\":\"fixture\",\"lockfileVersion\":3,\"packages\":{}}\n",
    );
    fixture.commit_lock("python");
    let node_absent = ToolchainLock::parse(&fixture.lock_bytes().unwrap()).unwrap();
    assert!(node_absent.ecosystem("node").is_none());
    fixture.write(".python-version", &format!("{older}\n"));

    // The node section is what this adds; python is untouched, so the
    // python row still records the newest version even though the file
    // moved. The sync that follows is an ordinary sync, and it refuses
    // that stale python row instead of realizing from it.
    let out = fixture.tog(&["update", "--toolchain", "node"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("tog-toolchain.toml is stale for python"),
        "{stderr}"
    );
    assert!(
        stderr.contains("run `tog update --toolchain python`"),
        "{stderr}"
    );
    let lock = ToolchainLock::parse(&fixture.lock_bytes().unwrap()).unwrap();
    assert!(lock.ecosystem("node").is_some(), "{stderr}");
    assert_eq!(
        lock.ecosystem("python")
            .unwrap()
            .inputs()
            .iter()
            .find(|row| row.path == Path::new(".python-version"))
            .and_then(|row| row.value.clone()),
        Some(newest),
        "{stderr}"
    );
}

/// `update --toolchain` is a different verb wearing the same word: it takes
/// an ecosystem, never a package.
#[test]
fn update_toolchain_takes_an_ecosystem_and_nothing_else() {
    let fixture = Fixture::new("update-grammar");
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);

    for argv in [
        vec!["update", "--toolchain", "serde"],
        vec!["update", "serde", "--toolchain"],
        vec!["update", "--toolchain", "python", "node"],
    ] {
        let out = fixture.tog(&argv);
        assert_eq!(out.status.code(), Some(2), "{argv:?}");
        let message = text(&out.stderr);
        assert!(
            message.contains("takes an ecosystem name, not a package"),
            "{message}"
        );
        assert!(message.contains("python, node, rust"), "{message}");
    }

    // `cargo` is the name every other verb uses for the ecosystem the lock
    // calls `rust`, so it is accepted as a spelling of it; naming an
    // ecosystem the project does not have is a refusal, not a usage error.
    let none = fixture.tog(&["update", "--toolchain", "cargo"]);
    assert_eq!(none.status.code(), Some(1), "{}", text(&none.stderr));
    assert!(
        text(&none.stderr).contains("no rust project found here"),
        "{}",
        text(&none.stderr)
    );
}

/// `update --toolchain --no-sync` stops after the lock is written, and it
/// touches no dependency lock on the way there.
#[test]
fn unchanged_dependency_locks() {
    let fixture = Fixture::new("nosync");
    let (newest, older) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");
    fixture.write("requirements.lock.txt", "# pinned by hand\nsix==1.17.0\n");
    let dependency_lock = std::fs::read(fixture.dir().join("requirements.lock.txt")).unwrap();
    fixture.write(".python-version", &format!("{older}\n"));

    let out = fixture.tog(&["update", "--toolchain", "--no-sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("updated tog-toolchain.toml"), "{stderr}");
    assert!(stderr.contains("--no-sync"), "{stderr}");

    let lock = ToolchainLock::parse(&fixture.lock_bytes().unwrap()).unwrap();
    assert_eq!(
        lock.ecosystem("python")
            .unwrap()
            .inputs()
            .iter()
            .find(|row| row.path == Path::new(".python-version"))
            .and_then(|row| row.value.clone()),
        Some(older)
    );
    assert_eq!(
        std::fs::read(fixture.dir().join("requirements.lock.txt")).unwrap(),
        dependency_lock,
        "update --toolchain rewrote a dependency lock"
    );
    // Stopping after the lock means nothing was projected either.
    assert!(!fixture.dir().join(".venv").exists(), "{stderr}");
}

/// Both flags are in the help text the binary prints, because that text is
/// the specification of the surface.
#[test]
fn the_help_screens_carry_the_frozen_flag_and_the_toolchain_update() {
    let fixture = Fixture::new("help");
    let sync = text(&fixture.tog(&["help", "sync"]).stdout);
    assert!(sync.contains("--frozen"), "{sync}");
    assert!(
        sync.contains("--frozen never modifies project inputs, tog-toolchain.toml, or the catalog"),
        "{sync}"
    );
    let update = text(&fixture.tog(&["help", "update"]).stdout);
    assert!(
        update.contains("tog update --toolchain [<ecosystem>]"),
        "{update}"
    );
    assert!(
        update.contains("leaves every\ndependency lock alone"),
        "{update}"
    );
}

// ---------------------------------------------------------------------------
// status

/// The verdicts `tog status` reports about the committed lock, through the
/// binary: each one names its own next step, and each exits 1.
#[test]
fn exact_statuses() {
    let fixture = Fixture::new("status");
    let (newest, older) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");
    let bundle_id = ToolchainLock::parse(&fixture.lock_bytes().unwrap())
        .unwrap()
        .ecosystem("python")
        .unwrap()
        .bundle_id()
        .to_string();
    write_python_closure(fixture.dir(), Some(&bundle_id));

    // A moved source: stale, with both values and the one verb that moves a
    // locked runtime.
    fixture.write(".python-version", &format!("{older}\n"));
    let stale = fixture.tog(&["status", "--json"]);
    assert_eq!(stale.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&stale.stdout).unwrap();
    assert_eq!(value["synced"], serde_json::json!(false));
    assert_eq!(value["ecosystems"][0]["state"], "changed");
    let detail = value["ecosystems"][0]["detail"][0].as_str().unwrap();
    assert!(detail.starts_with("tog-toolchain.toml stale: "), "{detail}");
    assert!(
        detail.contains(&newest) && detail.contains(&older),
        "{detail}"
    );
    assert!(
        detail.ends_with("run 'tog update --toolchain python'"),
        "{detail}"
    );
    fixture.write(".python-version", &format!("{newest}\n"));

    // A closure written before the lock existed cannot be compared.
    write_python_closure(fixture.dir(), None);
    let unchecked = fixture.tog(&["status", "--json"]);
    assert_eq!(unchecked.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&unchecked.stdout).unwrap();
    assert_eq!(value["ecosystems"][0]["state"], "unchecked");
    assert_eq!(
        value["ecosystems"][0]["detail"],
        "toolchain not recorded by this sync; run 'tog sync' once"
    );

    // The lock this projection was synced against is gone.
    write_python_closure(fixture.dir(), Some(&bundle_id));
    std::fs::remove_file(fixture.dir().join(LOCK_PATH)).unwrap();
    let missing = fixture.tog(&["status", "--json"]);
    assert_eq!(missing.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(
        value["ecosystems"][0]["detail"][0],
        "tog-toolchain.toml (missing; run 'tog sync' to create it)"
    );
    let prose = text(&fixture.tog(&["status"]).stdout);
    assert!(
        prose.contains("changed     tog-toolchain.toml (missing; run 'tog sync' to create it)"),
        "{prose}"
    );
}

/// A python closure whose dependency side is current for this fixture, so
/// the lock verdict is the only thing left to decide the row.
fn write_python_closure(dir: &Path, bundle_id: Option<&str>) {
    let closures = dir.join(".tog/closures");
    std::fs::create_dir_all(&closures).unwrap();
    let env = dir.join("env-object");
    std::fs::create_dir_all(env.join("bin")).unwrap();
    let venv = dir.join(".venv");
    let _ = std::fs::remove_file(&venv);
    std::os::unix::fs::symlink(&env, &venv).unwrap();
    let mut body = serde_json::json!({
        "env_object": env,
        "python": {"version": "3.12.14"},
        "plan": {"packages": []},
        "inputs": [{
            "path": "pyproject.toml",
            "sha256": hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
                std::fs::read(dir.join("pyproject.toml")).unwrap(),
            )),
        }],
    });
    if let Some(bundle_id) = bundle_id {
        body["toolchain"] = serde_json::json!({"bundle_id": bundle_id});
    }
    let record = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": "python",
        "platform": Platform::host().unwrap().triple(),
        "projected_at": 1,
        "body": body,
    });
    std::fs::write(closures.join("python.json"), record.to_string()).unwrap();
}

// ---------------------------------------------------------------------------
// replay and platforms

/// Honoring a lock consults no catalog, so a lock replays in a second store
/// unchanged — including the upgrade case, where the catalog no longer has
/// the `release` key the row was minted from at all. A `release` that no
/// longer exists is provenance, not a lookup key.
#[test]
fn two_store_replay() {
    let fixture = Fixture::new("replay");
    let (newest, _) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");
    let release = ToolchainLock::parse(&fixture.lock_bytes().unwrap())
        .unwrap()
        .ecosystem("python")
        .unwrap()
        .release()
        .to_string();

    // A catalog the lock's release has left. Selection is what reads a
    // catalog, and honoring a lock does not select.
    let full = catalog_of("python");
    let without = Catalog::new(
        "python",
        full.bundles()
            .iter()
            .filter(|bundle| bundle.release != release)
            .cloned()
            .collect(),
    )
    .unwrap();
    assert!(without.bundles().len() < full.bundles().len());

    let root = ProjectRoot::open(fixture.dir()).unwrap();
    let mut ids = Vec::new();
    for catalog in [full, without] {
        let resolved = project_toolchain::resolve(
            &root,
            Platform::host().unwrap(),
            vec![project_toolchain::EcosystemInput {
                lock_ecosystem: "python".into(),
                catalog,
                legacy: None,
            }],
            project_toolchain::Mode::ReadOnly,
            false,
        )
        .expect("the committed lock still answers");
        let selected = resolved.get("python").unwrap();
        assert_eq!(selected.source, Source::Lock);
        assert_eq!(selected.version("cpython").unwrap(), newest);
        assert!(resolved.pending.is_none(), "honoring a lock wrote nothing");
        ids.push(selected.bundle_id());
    }
    assert_eq!(ids[0], ids[1], "the catalog changed the answer");

    // And through the binary, in two stores. Neither run has anything to
    // say about the lock: the store is not part of the answer.
    fixture.write("pyproject.toml", UNPLANNABLE_PYPROJECT);
    let before = fixture.lock_bytes().unwrap();
    for store in ["store-a", "store-b"] {
        let out = fixture.tog_env(
            &["sync", "--frozen"],
            &[("TOG_STORE", fixture.home.0.join(store).to_str().unwrap())],
        );
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(
            stderr.contains("optional-dependencies"),
            "the lock, not the manifest, stopped {store}: {stderr}"
        );
        assert_eq!(fixture.lock_bytes().unwrap(), before, "{store} rewrote it");
    }
}

/// The lock carries a row per platform, so the file a Linux machine writes
/// and the file a Mac writes for the same project are the same bytes:
/// selection reads the intersection of complete releases across every
/// supported platform, never the host.
#[test]
fn linux_lock_bytes_are_platform_independent() {
    let fixture = Fixture::new("platforms");
    let (newest, _) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));

    let root = ProjectRoot::open(fixture.dir()).unwrap();
    let mut bytes: Vec<(Platform, Vec<u8>)> = Vec::new();
    for platform in Platform::ALL {
        let resolved = project_toolchain::resolve(
            &root,
            *platform,
            vec![project_toolchain::EcosystemInput {
                lock_ecosystem: "python".into(),
                catalog: catalog_of("python"),
                legacy: None,
            }],
            project_toolchain::Mode::Writable,
            false,
        )
        .unwrap();
        bytes.push((
            *platform,
            resolved.pending.as_ref().unwrap().canonical_bytes(),
        ));
    }
    assert!(bytes.len() >= 2, "there is only one supported platform");
    let (first, expected) = &bytes[0];
    for (platform, written) in &bytes[1..] {
        assert_eq!(
            written,
            expected,
            "{} and {} would commit different locks",
            first.triple(),
            platform.triple()
        );
    }
    // Both platforms' artifact rows are in that one file.
    let lock = ToolchainLock::parse(expected).unwrap();
    let bundle = lock.ecosystem("python").unwrap().bundle().unwrap();
    for platform in Platform::ALL {
        assert!(
            bundle.complete_for(*platform),
            "no rows for {}",
            platform.triple()
        );
    }
}

/// A lock with no artifact row for this host is refused rather than
/// realized from the other platform's bytes. The message names the release
/// and the triple that is missing.
#[test]
fn foreign_platform_lock_is_refused() {
    let fixture = Fixture::new("foreign");
    let (newest, _) = two_python_versions();
    fixture.write("pyproject.toml", PLAIN_PYPROJECT);
    fixture.write(".python-version", &format!("{newest}\n"));
    fixture.commit_lock("python");

    // A lock minted from a bundle that has no rows for this host. It is
    // internally consistent — its bundle_id matches its rows, so parsing
    // succeeds — and the refusal has to come from checking the rows
    // against the host, which is where it belongs.
    let host = Platform::host().unwrap();
    let full = ToolchainLock::parse(&fixture.lock_bytes().unwrap()).unwrap();
    let section = full.ecosystem("python").unwrap();
    let mut foreign = section.bundle().unwrap();
    foreign.artifacts.retain(|row| row.platform != host);
    assert!(!foreign.artifacts.is_empty(), "no foreign rows to keep");
    let mut lock = ToolchainLock::new(env!("CARGO_PKG_VERSION"));
    lock.set_ecosystem("python", &foreign, &section.inputs())
        .unwrap();
    std::fs::write(fixture.dir().join(LOCK_PATH), lock.canonical_bytes()).unwrap();

    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains(host.triple()), "{stderr}");
    assert!(stderr.contains("tog update --toolchain python"), "{stderr}");
    assert!(!fixture.store().exists(), "a refusal created the store");

    // The same file with this host's table simply deleted is no longer
    // the bundle its id names, and is refused as an edited file before any
    // row is consulted.
    let text_form = String::from_utf8(fixture.lock_bytes().unwrap()).unwrap();
    fixture.commit_lock("python");
    let intact = String::from_utf8(fixture.lock_bytes().unwrap()).unwrap();
    let marker = format!("[toolchain.python.platforms.\"{}\"", host.triple());
    let start = intact.find(&marker).expect("a table for this host");
    let end = intact[start..]
        .match_indices("\n[toolchain.python.platforms.")
        .nth(1)
        .map(|(at, _)| start + at + 1)
        .unwrap_or(intact.len());
    let trimmed = format!("{}{}", &intact[..start], &intact[end..]);
    assert_ne!(trimmed, text_form);
    std::fs::write(fixture.dir().join(LOCK_PATH), trimmed).unwrap();
    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("does not match its rows"), "{stderr}");
    assert!(!fixture.store().exists(), "a refusal created the store");
}
