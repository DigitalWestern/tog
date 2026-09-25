//! The toolchain lock as a user meets it: `tog` writing and honoring
//! `tog-toolchain.toml`, `tog --frozen` validating one without touching
//! anything, `tog update --toolchain` replacing one, and `tog status`
//! reporting what the committed file says about the project.
//!
//! Every case here is offline. Nothing in this file downloads a toolchain:
//! the fixtures either stop before realization (a refusal, which is the
//! whole point of most of them), use a manifest whose planner fails in
//! the project directory, which happens after the lock has been published
//! and before any network call, or name a local toolchain directory
//! (`[toolchain] path`), which is imported, not fetched. The `#[ignore]`d
//! end-to-end cases are the exception: they sync for real.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::Output;

mod common;

use common::{snapshot, text, tog, tog_at, TempDir};

use tog::comforter::toolchain as project_toolchain;
use tog::kernel::fsroot::ProjectRoot;
use tog::kernel::platform::Platform;
use tog::kernel::toolchain::input::{self, InputRow};
use tog::kernel::toolchain::lock::{ToolchainLock, LOCK_PATH};
use tog::kernel::toolchain::{select_for, Catalog, Source};

/// A project and the throwaway home its store, policy and `x` cache live
/// in, so nothing here can read the developer's configuration.
struct Fixture {
    home: TempDir,
    project: TempDir,
}

impl Fixture {
    fn new(label: &str) -> Self {
        Self {
            // The home is its own project boundary; the project is not,
            // because tests here watch for the `.tog` directory a sync
            // creates, and one run in place (`home` as cwd) must not see a
            // checkout's manifests above it.
            home: TempDir::boundary(&format!("lock-{label}-home")),
            project: TempDir::new(&format!("lock-{label}-project")),
        }
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
        tog(&self.project.0, &self.home.0, args)
    }

    /// Publish a `tog-toolchain.toml` describing the project exactly as it
    /// is right now, for `ecosystem`. Tests then change one source file and
    /// watch what the lock says about the change.
    fn commit_lock(&self, ecosystem: &str) {
        let lock = build_lock(self.dir(), &[ecosystem]);
        std::fs::write(self.project.0.join(LOCK_PATH), lock.canonical_bytes()).unwrap();
    }
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

/// The fastuuid 0.14.0 sdist: a pyo3/maturin Rust extension with a
/// Cargo.lock and no toolchain file of its own. Pinning only the sdist's
/// hash is the `--no-binary` of a hash-pinned requirements file: the wheels
/// PyPI also serves do not match, so tog must build this archive.
const RUST_SDIST_REQUIREMENTS: &str = "fastuuid==0.14.0 \\\n    \
    --hash=sha256:178947fc2f995b38497a74172adee64fdeb8b7ec18f2a5934d037641ba265d26\n";

/// The `sdist-build` object the store holds for `name`: its identity's
/// `rust` input, the id of the Rust object the wheel was compiled with.
fn sdist_build_rust(store: &Path, name: &str) -> Vec<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(store.join("meta")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let identity = &meta["identity"];
        if identity["inputs"]["schema"]
            .as_str()
            .is_some_and(|schema| schema.starts_with("sdist-build/"))
            && identity["name"] == name
        {
            found.push(identity["inputs"]["rust"].as_str().unwrap().to_string());
        }
    }
    found.sort();
    found
}

/// A Python project syncs a Rust-extension sdist from source through tog.
/// The lock pins the Rust that sdist compiles with, the wheel is built with
/// exactly that Rust object, and a lock written before the pin existed
/// builds it with Rust 1.96.1 instead, as those locks always did. Needs
/// the network (PyPI, static.rust-lang.org) and bubblewrap, so it is off by
/// default: `cargo test --test toolchain_lock -- --ignored rust_sdist`.
#[test]
#[ignore]
fn a_rust_sdist_builds_with_the_rust_the_python_section_pins() {
    if !cfg!(target_os = "linux") {
        eprintln!("toolchain_lock: skipped on non-Linux host");
        return;
    }
    let platform = Platform::host().unwrap();
    let default =
        tog::kernel::toolchain::shipped(&tog::kernel::provider::rust::toolchain_catalog().unwrap())
            .unwrap()
            .version("rustc")
            .unwrap()
            .to_string();
    let fixture = Fixture::new("rust-sdist");
    fixture.write("requirements.txt", RUST_SDIST_REQUIREMENTS);
    fixture.write(".python-version", "3.12.14\n");

    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let lock = String::from_utf8(fixture.lock_bytes().unwrap()).unwrap();
    let pin = format!("[toolchain.python.helpers]\nrust = \"{default}\"\n");
    assert!(lock.contains(&pin), "{lock}");
    assert!(!lock.contains("[toolchain.rust]"), "{lock}");
    // The wheel was compiled with the pinned release's Rust object.
    let pinned_rust = tog::kernel::provider::rust::rust_object_id(platform, &default).unwrap();
    assert_eq!(
        sdist_build_rust(&fixture.store(), "fastuuid"),
        std::slice::from_ref(&pinned_rust)
    );
    assert!(fixture.store().join("objects").join(&pinned_rust).is_dir());
    let run = fixture.tog(&[
        "run",
        "python",
        "-c",
        "import fastuuid; print(len(str(fastuuid.uuid4())))",
    ]);
    assert_eq!(run.status.code(), Some(0), "{}", text(&run.stderr));
    assert_eq!(text(&run.stdout).trim(), "36");

    // The same lock as a tog from before the pin wrote it: the sdist builds
    // on 1.96.1, the Rust those locks' wheels were built with.
    // Such a lock has no pin and the bundle's own id.
    let mut old = ToolchainLock::parse(lock.as_bytes()).unwrap();
    old.set_helpers("python", &Default::default()).unwrap();
    assert!(!String::from_utf8(old.canonical_bytes())
        .unwrap()
        .contains("helpers"));
    std::fs::write(fixture.dir().join(LOCK_PATH), old.canonical_bytes()).unwrap();
    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(!String::from_utf8(fixture.lock_bytes().unwrap())
        .unwrap()
        .contains("helpers"));
    let legacy_rust = tog::kernel::provider::rust::rust_object_id(platform, "1.96.1").unwrap();
    let mut both = vec![pinned_rust, legacy_rust];
    both.sort();
    assert_eq!(sdist_build_rust(&fixture.store(), "fastuuid"), both);
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

/// The dependency lock is the tailor's to generate, and `--frozen` skips
/// that step: a project whose toolchain lock is current but whose Gemfile
/// has no Gemfile.lock is refused by name, before any toolchain is
/// downloaded, and nothing in the project changes.
#[test]
fn frozen_refuses_a_missing_dependency_lock_before_any_download() {
    let fixture = Fixture::new("frozen-deplock");
    fixture.write(
        "Gemfile",
        "ruby \"3.3.4\"\nsource \"https://rubygems.org\"\n",
    );
    fixture.commit_lock("ruby");
    let before = snapshot(fixture.dir());

    let out = fixture.tog(&["sync", "--frozen"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("Gemfile.lock is missing and --frozen never creates it"),
        "{stderr}"
    );
    assert!(
        stderr.contains("run `tog` once without --frozen"),
        "{stderr}"
    );
    assert_eq!(
        snapshot(fixture.dir()),
        before,
        "--frozen changed the project"
    );
    let objects = fixture.store().join("objects");
    let realized = std::fs::read_dir(&objects)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(
        realized, 0,
        "--frozen realized a toolchain for a refused sync"
    );
}

/// The same for Node, whose lock generation already lived in `prepare`: a
/// package.json with no lock tog can import is a refusal under `--frozen`,
/// not a silent "nothing to sync".
#[test]
fn frozen_refuses_a_node_project_without_a_lock() {
    let fixture = Fixture::new("frozen-nodelock");
    fixture.write(
        "package.json",
        "{\"name\": \"hello\", \"version\": \"1.0.0\"}\n",
    );
    fixture.commit_lock("node");
    let before = snapshot(fixture.dir());

    let out = fixture.tog(&["sync", "--frozen"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("package-lock.json is missing and --frozen never creates it"),
        "{stderr}"
    );
    assert_eq!(
        snapshot(fixture.dir()),
        before,
        "--frozen changed the project"
    );
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
        "toolchain not recorded by this sync; run 'tog' once"
    );

    // The lock this projection was synced against is gone.
    write_python_closure(fixture.dir(), Some(&bundle_id));
    std::fs::remove_file(fixture.dir().join(LOCK_PATH)).unwrap();
    let missing = fixture.tog(&["status", "--json"]);
    assert_eq!(missing.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(
        value["ecosystems"][0]["detail"][0],
        "tog-toolchain.toml (missing; run 'tog' to create it)"
    );
    let prose = text(&fixture.tog(&["status"]).stdout);
    assert!(
        prose.contains("changed     tog-toolchain.toml (missing; run 'tog' to create it)"),
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
                external: None,
                helper_pins: Default::default(),
                legacy_helper_pins: Default::default(),
                declared_helpers: Default::default(),
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
        let out = tog_at(
            fixture.dir(),
            &fixture.home.0,
            &fixture.home.0.join(store),
            &["sync", "--frozen"],
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
                external: None,
                helper_pins: Default::default(),
                legacy_helper_pins: Default::default(),
                declared_helpers: Default::default(),
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

// ---------------------------------------------------------------------------
// Rust toolchain files beyond a channel

/// A stand-in for a rustup-built toolchain directory: `bin/rustc -vV` and
/// `bin/cargo -V` print what the real ones print for this host, `cargo
/// locate-project` answers from its working directory, and the tree has the
/// layout a Rust object needs. Nothing here compiles. The sync these tests
/// run needs no compiler, only the toolchain's identity and layout.
fn fake_rust_tree(tree: &Path, release: &str) {
    use std::os::unix::fs::PermissionsExt;
    let host = Platform::host().unwrap().triple();
    std::fs::create_dir_all(tree.join("bin")).unwrap();
    std::fs::create_dir_all(tree.join(format!("lib/rustlib/{host}/lib"))).unwrap();
    let script = |name: &str, body: String| {
        let path = tree.join("bin").join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    script(
        "rustc",
        format!(
            "printf 'rustc {release} (0123abcde 2026-06-26)\\nbinary: rustc\\n\
             commit-hash: 0123abcde\\nhost: {host}\\nrelease: {release}\\n'\n"
        ),
    );
    script(
        "cargo",
        format!(
            "case \"$1\" in\n\
             -V) printf 'cargo {release} (4567fedcb 2026-06-26)\\n' ;;\n\
             locate-project) printf '%s/Cargo.toml\\n' \"$(pwd -P)\" ;;\n\
             *) echo \"fake cargo: $*\" >&2; exit 1 ;;\n\
             esac\n"
        ),
    );
    std::fs::write(
        tree.join(format!("lib/rustlib/{host}/lib/libstd.rlib")),
        b"std",
    )
    .unwrap();
}

const PLAIN_CARGO_TOML: &str = "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
const PLAIN_CARGO_LOCK: &str = "version = 3\n\n[[package]]\nname = \"p\"\nversion = \"0.1.0\"\n";

/// `[toolchain] path` names a toolchain directory on this machine. The lock
/// records it by content: a row marked `source = "path"`, with the tree's
/// URL, both version lines and the tree hash. A sync imports it and records
/// the `external-toolchain` exception, a policy can deny that, and once the
/// tree changes every sync refuses it until `tog update --toolchain` locks
/// the new tree.
#[test]
fn a_local_toolchain_is_locked_by_content_and_fails_closed_when_it_changes() {
    let fixture = Fixture::new("rust-path");
    let trees = TempDir::new("lock-rust-path-tree");
    let tree = trees.0.join("custom-rust");
    fake_rust_tree(&tree, "1.97.0-nightly");
    let tree = tree.canonicalize().unwrap();
    fixture.write("Cargo.toml", PLAIN_CARGO_TOML);
    fixture.write("Cargo.lock", PLAIN_CARGO_LOCK);
    fixture.write(
        "rust-toolchain.toml",
        &format!("[toolchain]\npath = \"{}\"\n", tree.display()),
    );

    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("exception external-toolchain"), "{stderr}");
    let bytes = fixture.lock_bytes().unwrap();
    let written = String::from_utf8(bytes.clone()).unwrap();
    assert!(written.contains("release = \"path\""), "{written}");
    assert!(
        written.contains("source = \"path\"\nprovider = \"path\"\n"),
        "{written}"
    );
    assert!(
        written.contains(&format!("url = \"file://{}\"", tree.display())),
        "{written}"
    );
    assert!(
        written.contains(
            "build = \"rustc 1.97.0-nightly (0123abcde 2026-06-26); cargo 1.97.0-nightly (4567fedcb 2026-06-26)\""
        ),
        "{written}"
    );
    assert!(written.contains("field = \"toolchain.path\""), "{written}");
    let lock = ToolchainLock::parse(&bytes).unwrap();
    let bundle = lock.ecosystem("rust").unwrap().bundle().unwrap();
    assert_eq!(bundle.component("rustc").unwrap().version, "1.97.0");
    let closure = std::fs::read_to_string(fixture.dir().join(".tog/closures/cargo.json")).unwrap();
    assert!(closure.contains("\"external-toolchain\""), "{closure}");
    assert!(closure.contains(&tree.display().to_string()), "{closure}");

    // A second sync honors the lock, re-checks the tree, uses the import,
    // and records the exception again.
    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("exception external-toolchain"), "{stderr}");
    assert_eq!(fixture.lock_bytes().unwrap(), bytes);

    // A policy that denies the kind refuses the sync.
    fixture.write(".tog/policy.toml", "deny = [\"external-toolchain\"]\n");
    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("carries exception(s): external-toolchain"),
        "{stderr}"
    );
    std::fs::remove_file(fixture.dir().join(".tog/policy.toml")).unwrap();

    // The tree is used as it is, so `tog fmt` needs the tree's own rustfmt.
    let out = fixture.tog(&["fmt"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("has no bin/rustfmt"), "{stderr}");

    // The tree changes (rustfmt is added to it): the lock no longer names
    // it, and sync fails closed.
    {
        use std::os::unix::fs::PermissionsExt;
        for (name, body) in [
            ("rustfmt", "exit 0\n"),
            ("cargo-fmt", "echo \"$@\" > formatted.txt\n"),
        ] {
            let path = tree.join("bin").join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let out = fixture.tog(&["sync"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("changed since tog-toolchain.toml locked it"),
        "{stderr}"
    );
    assert!(stderr.contains("tog update --toolchain rust"), "{stderr}");
    assert_eq!(
        fixture.lock_bytes().unwrap(),
        bytes,
        "a refusal rewrote the lock"
    );

    // Locking the tree as it is now is the way forward.
    let out = fixture.tog(&["update", "--toolchain", "rust"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_ne!(fixture.lock_bytes().unwrap(), bytes);
    let out = fixture.tog(&["sync"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));

    // Now the tree's own formatter runs, and the import is the formatter
    // object the rustfmt record names.
    let out = fixture.tog(&["fmt", "--check"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        std::fs::read_to_string(fixture.dir().join("formatted.txt")).unwrap(),
        "--check\n"
    );
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.dir().join(".tog/closures/rustfmt.json")).unwrap(),
    )
    .unwrap();
    let body = &record["body"];
    assert_eq!(body["rustfmt_object"]["id"], body["rust_object"]["id"]);
    assert_eq!(body["rust_version"], "1.97.0");
    // And status reads the closure as current.
    let out = fixture.tog(&["status"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(
        stdout.contains("cargo  synced      (rust 1.97.0;"),
        "{stdout}"
    );
}

/// A toolchain table with components and no channel means rustup's default
/// toolchain. tog's is the catalog's explicit default, which the lock
/// records as the selection, beside the components it will provision.
#[test]
fn a_components_only_toolchain_file_locks_the_catalog_default() {
    let fixture = Fixture::new("rust-components-only");
    fixture.write("Cargo.toml", PLAIN_CARGO_TOML);
    fixture.write(
        "rust-toolchain.toml",
        "[toolchain]\ncomponents = [\"clippy\", \"rust-src\"]\n",
    );
    let out = fixture.tog(&["update", "--toolchain", "--no-sync"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let lock = ToolchainLock::parse(&fixture.lock_bytes().unwrap()).unwrap();
    let section = lock.ecosystem("rust").unwrap();
    let catalog = catalog_of("rust");
    let default = catalog.default_release().unwrap();
    assert_eq!(section.release(), default.release);
    assert_eq!(section.bundle_id(), default.bundle_id());
    let inputs = section.inputs();
    let row = |field: &str| {
        inputs
            .iter()
            .find(|row| row.path == Path::new("rust-toolchain.toml") && row.field == field)
            .cloned()
            .unwrap()
    };
    assert_eq!(row("toolchain.channel").value, None);
    assert!(row("toolchain.channel").sha256.is_some());
    assert_eq!(
        row("toolchain.components").value.as_deref(),
        Some("clippy,rust-src")
    );
    // What realization provisions is read back from those rows.
    let extras = tog::kernel::provider::rust_extras::Extras::from_rows(&inputs);
    assert_eq!(extras.components, ["clippy", "rust-src"]);
}
