//! Git dependencies realized by commit (NEXT.md item 4). Heavy: realizes Node
//! and a git source, so it is ignored by default.
//!
//! The fixture repository is local and served over `file://`, so this needs no
//! network beyond the pinned Node toolchain.

use blanket::npm::{self, NpmPackage, NpmPlan};
use blanket::store::Store;
use blanket::{platform::Platform, policy};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Temp(PathBuf);
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = blanket::store::remove_tree(&self.0);
    }
}

fn temp(tag: &str) -> Temp {
    let path = std::env::temp_dir().join(format!(
        "blanket-gitdep-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&path).unwrap();
    Temp(path)
}

fn git(args: &[&str], cwd: &Path) -> String {
    let out = Command::new("/usr/bin/git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// A repository holding one npm package, plus a `prepare` script so the
/// exception path is exercised too.
fn fixture_repo(root: &Path) -> (String, String) {
    let repo = root.join("dep-repo");
    std::fs::create_dir_all(&repo).unwrap();
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["config", "user.email", "t@example.invalid"], &repo);
    git(&["config", "user.name", "t"], &repo);
    std::fs::write(
        repo.join("package.json"),
        r#"{"name":"git-dep","version":"1.0.0","main":"index.js","scripts":{"prepare":"exit 1"}}"#,
    )
    .unwrap();
    std::fs::write(repo.join("index.js"), "module.exports = 'from-git';\n").unwrap();
    git(&["add", "-A"], &repo);
    git(&["commit", "-qm", "one"], &repo);
    let commit = git(&["rev-parse", "HEAD"], &repo);
    (format!("git+file://{}", repo.display()), commit)
}

fn store_at(root: &Path) -> Store {
    let store_root = root.join("store");
    for sub in ["objects", "meta", "cache/sha256", "tmp"] {
        std::fs::create_dir_all(store_root.join(sub)).unwrap();
    }
    Store { root: store_root.canonicalize().unwrap() }
}

#[test]
#[ignore]
fn npm_git_dependency_is_realized_from_its_commit() {
    let platform = Platform::host().expect("host platform");
    let root = temp("npm");
    let (url, commit) = fixture_repo(&root.0);
    let store = store_at(&root.0);
    policy::clear();

    let lock = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/git-dep":{{"version":"1.0.0","resolved":"{url}#{commit}"}}}}}}"#
    );
    let plan = npm::plan_npm(platform, &lock).expect("plan");
    assert_eq!(plan.packages.len(), 1);
    let package: &NpmPackage = &plan.packages[0];
    let source = package.git.as_ref().expect("git source parsed from the lockfile");
    assert_eq!(source.commit, commit);
    assert_eq!(package.integrity, format!("git:{commit}"));

    let env = npm::realize_node_env(&store, platform, &plan, &[]).expect("realize");
    assert_eq!(
        std::fs::read_to_string(env.join("node_modules/git-dep/index.js")).unwrap(),
        "module.exports = 'from-git';\n"
    );
    // The repository's own .git must never reach the environment.
    assert!(!env.join("node_modules/git-dep/.git").exists());

    // The commit is the identity: the same plan hits the cache, and a
    // different commit is a different environment.
    let again = npm::realize_node_env(&store, platform, &plan, &[]).expect("second realize");
    assert_eq!(env, again);

    let kinds: Vec<String> = policy::pending()
        .iter()
        .map(|exception| exception.kind.clone())
        .collect();
    assert!(
        kinds.iter().filter(|k| *k == "git-dependency").count() >= 2,
        "expected the source and its unrun prepare script to be recorded: {kinds:?}"
    );
}

#[test]
#[ignore]
fn an_unpinned_git_reference_is_refused() {
    let platform = Platform::host().expect("host platform");
    let root = temp("unpinned");
    let (url, _) = fixture_repo(&root.0);
    let lock = format!(
        r#"{{"lockfileVersion":3,"packages":{{"":{{}},"node_modules/git-dep":{{"version":"1.0.0","resolved":"{url}#main"}}}}}}"#
    );
    let error = npm::plan_npm(platform, &lock)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        error.contains("npm_git_dep") || error.contains("commit"),
        "an unpinned ref must be refused, got: {error:?}"
    );
}

fn _unused(_: NpmPlan) {}

/// A minimal installable Python package in a local repository.
fn python_fixture_repo(root: &Path) -> (String, String) {
    let repo = root.join("py-repo");
    std::fs::create_dir_all(repo.join("gitdep")).unwrap();
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["config", "user.email", "t@example.invalid"], &repo);
    git(&["config", "user.name", "t"], &repo);
    std::fs::write(
        repo.join("pyproject.toml"),
        "[build-system]\nrequires = [\"setuptools>=40.8.0\", \"wheel\"]\nbuild-backend = \"setuptools.build_meta\"\n\n[project]\nname = \"gitdep\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("gitdep/__init__.py"),
        "VALUE = 'from-git-python'\n",
    )
    .unwrap();
    git(&["add", "-A"], &repo);
    git(&["commit", "-qm", "one"], &repo);
    let commit = git(&["rev-parse", "HEAD"], &repo);
    (format!("git+file://{}", repo.display()), commit)
}

#[test]
#[ignore]
fn python_git_dependency_builds_a_wheel_from_its_commit() {
    let platform = Platform::host().expect("host platform");
    let root = temp("py");
    let (url, commit) = python_fixture_repo(&root.0);
    let store = store_at(&root.0);
    policy::clear();

    let requirement = format!("gitdep @ {url}@{commit}");
    let reqs = blanket::pypi::parse_requirements(&requirement).expect("parse");
    let packages = blanket::pypi::lock_requirements(
        platform,
        blanket::pypi::Glibc(0, 0),
        &reqs,
        "cp312",
    )
    .expect("lock");
    assert_eq!(packages.len(), 1);
    assert!(packages[0].git.is_some(), "the package carries its git source");

    let plan = blanket::types::Plan {
        ecosystem: "python".into(),
        python_version: "3.12.14".into(),
        packages,
    };
    let env = blanket::project::realize_env(&store, platform, &plan).expect("realize");
    let site = env.join("lib/python3.12/site-packages/gitdep/__init__.py");
    assert_eq!(
        std::fs::read_to_string(&site).unwrap(),
        "VALUE = 'from-git-python'\n"
    );

    // The commit determines the environment: realizing again is a cache hit.
    let again = blanket::project::realize_env(&store, platform, &plan).expect("second realize");
    assert_eq!(env, again);
}

/// A local repository holding one small library crate.
fn cargo_fixture_repo(root: &Path) -> (String, String) {
    let repo = root.join("crate-repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git(&["init", "-q", "-b", "main"], &repo);
    git(&["config", "user.email", "t@example.invalid"], &repo);
    git(&["config", "user.name", "t"], &repo);
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"gitdep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn value() -> u32 { 7 }\n").unwrap();
    git(&["add", "-A"], &repo);
    git(&["commit", "-qm", "one"], &repo);
    let commit = git(&["rev-parse", "HEAD"], &repo);
    (format!("file://{}", repo.display()), commit)
}

#[test]
#[ignore]
fn cargo_git_dependency_is_vendored_from_its_commit() {
    let root = temp("cargo");
    let (url, commit) = cargo_fixture_repo(&root.0);
    let store = store_at(&root.0);
    policy::clear();

    let source = format!("git+{url}?rev={commit}#{commit}");
    let lock = format!(
        "version = 3\n\n[[package]]\nname = \"gitdep\"\nversion = \"1.0.0\"\nsource = \"{source}\"\n"
    );
    let plan = blanket::cargo::plan_cargo(&lock, "1.96.1").expect("plan");
    assert_eq!(plan.crates.len(), 1);
    assert!(plan.crates[0].git.is_some(), "the crate carries its git source");

    let vendor = blanket::cargo::realize_vendor(&store, &plan).expect("vendor");
    let crate_dir = vendor.join("gitdep-1.0.0");
    assert_eq!(
        std::fs::read_to_string(crate_dir.join("src/lib.rs")).unwrap(),
        "pub fn value() -> u32 { 7 }\n"
    );
    // cargo's directory source requires this file; git sources carry no package hash.
    assert_eq!(
        std::fs::read_to_string(crate_dir.join(".cargo-checksum.json")).unwrap(),
        r#"{"files":{},"package":null}"#
    );
    assert!(!crate_dir.join(".git").exists(), "the .git directory must not be vendored");

    // Realizing again is a cache hit on the same object.
    let again = blanket::cargo::realize_vendor(&store, &plan).expect("second vendor");
    assert_eq!(vendor, again);
}
