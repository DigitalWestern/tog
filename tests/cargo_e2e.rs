//! End-to-end Cargo tailor test. Heavy: downloads the pinned Rust toolchain
//! and crates.io closure on first run.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tog::kernel::platform::Platform;

mod common;

use common::{
    assert_frozen_never_writes_the_lock, assert_ok, command, copy_tree, fixture, tog, TempDir,
};

/// The binary with a private `TMPDIR` and `HOME` under `tmp`, and the
/// sandbox required: these suites prove the build runs sandboxed, so a
/// sandbox that cannot start must fail them rather than skip.
fn tog_with_tmp(project: &Path, store: &Path, tmp: &Path, args: &[&str]) -> Output {
    command(project, &tmp.join("home"), store)
        .env("TMPDIR", tmp)
        .env("TOG_SANDBOX_TESTS", "required")
        .args(args)
        .output()
        .unwrap()
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

/// A local git repository holding one library crate, and the Cargo project
/// at `project` made to depend on it at its commit. A git dependency is a
/// `git-dependency` exception the Cargo sync records, which is what the
/// attribution tests trace.
fn add_git_dependency(root: &Path, project: &Path) -> String {
    let repo = root.join("gitdep-repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    let git = |args: &[&str]| {
        let output = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    };
    git(&["init", "-q", "-b", "main"]);
    git(&["config", "user.email", "t@example.invalid"]);
    git(&["config", "user.name", "t"]);
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"gitdep\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn value() -> u32 { 7 }\n").unwrap();
    git(&["add", "-A"]);
    git(&["commit", "-qm", "one"]);
    let commit = git(&["rev-parse", "HEAD"]);
    let url = format!("file://{}", repo.display());

    let manifest = std::fs::read_to_string(project.join("Cargo.toml")).unwrap();
    let manifest = if manifest.contains("[dependencies]\n") {
        manifest.replace(
            "[dependencies]\n",
            &format!("[dependencies]\ngitdep = {{ git = \"{url}\", rev = \"{commit}\" }}\n"),
        )
    } else {
        format!("{manifest}\n[dependencies]\ngitdep = {{ git = \"{url}\", rev = \"{commit}\" }}\n")
    };
    std::fs::write(project.join("Cargo.toml"), manifest).unwrap();
    let lock = std::fs::read_to_string(project.join("Cargo.lock")).unwrap();
    let package = |name: &str| format!("[[package]]\nname = \"{name}\"\n");
    let root_name = manifest_name(project);
    let mut lock = lock;
    let root_entry = package(&root_name);
    let at = lock.find(&root_entry).unwrap() + root_entry.len();
    let rest = &lock[at..];
    let version_end = rest.find('\n').unwrap() + 1;
    let insert = at + version_end;
    if lock[insert..].starts_with("dependencies = [\n") {
        let list = insert + "dependencies = [\n".len();
        lock.insert_str(list, " \"gitdep\",\n");
    } else {
        lock.insert_str(insert, "dependencies = [\n \"gitdep\",\n]\n");
    }
    lock.push_str(&format!(
        "\n[[package]]\nname = \"gitdep\"\nversion = \"1.0.0\"\nsource = \"git+{url}?rev={commit}#{commit}\"\n"
    ));
    std::fs::write(project.join("Cargo.lock"), lock).unwrap();
    url
}

fn manifest_name(project: &Path) -> String {
    let manifest = std::fs::read_to_string(project.join("Cargo.toml")).unwrap();
    let line = manifest
        .lines()
        .find(|line| line.starts_with("name = "))
        .unwrap();
    line.trim_start_matches("name = ")
        .trim_matches('"')
        .to_string()
}

fn assert_cargo_closure(project: &Path, store: &Path) -> (PathBuf, PathBuf) {
    let closure: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join(".tog/closures/cargo.json")).unwrap())
            .unwrap();
    let objects = store.canonicalize().unwrap().join("objects");
    let object_path = |key: &str| {
        let path = PathBuf::from(closure["body"][key]["path"].as_str().unwrap());
        let canonical = path.canonicalize().unwrap();
        assert!(
            canonical.starts_with(&objects),
            "{key} closure path escaped the fresh store: {}",
            canonical.display()
        );
        assert!(
            canonical.is_dir(),
            "{key} closure object is not a directory"
        );
        canonical
    };
    let rust = object_path("rust_object");
    let vendor = object_path("vendor_object");
    let rustlib = rust
        .join("lib/rustlib")
        .join(Platform::host().unwrap().triple());
    assert!(
        rustlib.is_dir(),
        "Rust object is missing the host rustlib tree: {}",
        rustlib.display()
    );
    (rust, vendor)
}

#[test]
#[ignore]
fn cargo_sync_build_and_run_again_offline() {
    let temp = TempDir::new("cargo-e2e");
    let project = temp.0.join("cargo-hello");
    copy_tree(&fixture("cargo-hello"), &project);
    let store = temp.0.join("store");

    assert_ok(tog(&project, &temp.0, &["sync"]), "sync");
    let (rust_obj, vendor_obj) = assert_cargo_closure(&project, &store);
    let rustc = assert_ok(
        tog(&project, &temp.0, &["run", "rustc", "-vV"]),
        "rustc -vV",
    );
    assert!(
        rustc.contains(&format!("release: {}", default_rust())),
        "unexpected rustc version:\n{rustc}"
    );
    assert!(
        rustc
            .lines()
            .any(|line| { line.trim() == format!("host: {}", Platform::host().unwrap().triple()) }),
        "rustc reported the wrong host:\n{rustc}"
    );
    assert_ok(tog(&project, &temp.0, &["build"]), "build");
    let executable = project.join("target/debug/cargo-hello");
    assert!(executable.is_file());
    let output = assert_ok(
        tog(&project, &temp.0, &["run", "target/debug/cargo-hello"]),
        "run",
    );
    assert_eq!(output.trim(), "hello 128");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&rust_obj).unwrap().permissions().mode() & 0o222,
            0
        );
        assert_eq!(
            std::fs::metadata(&vendor_obj).unwrap().permissions().mode() & 0o222,
            0
        );
    }

    // Rebuild from a clean target: everything must come from the store
    // (network denial is already enforced by `tog build` itself — the
    // seatbelt sandbox cannot nest, so no outer sandbox-exec wrapper here).
    std::fs::remove_dir_all(project.join("target")).unwrap();
    assert!(
        !executable.exists(),
        "the first build result was not removed"
    );
    assert_ok(tog(&project, &temp.0, &["build"]), "rebuild");
    assert!(executable.is_file());
    let (rebuilt_rust_obj, rebuilt_vendor_obj) = assert_cargo_closure(&project, &store);
    assert_eq!(rebuilt_rust_obj, rust_obj);
    assert_eq!(rebuilt_vendor_obj, vendor_obj);
    let output = assert_ok(
        tog(&project, &temp.0, &["run", "target/debug/cargo-hello"]),
        "run after rebuild",
    );
    assert_eq!(output.trim(), "hello 128");
    // Without its lock the project is refused under --frozen and left
    // alone; a plan regenerates the lock with the store Cargo.
    assert_frozen_never_writes_the_lock(&project, &temp.0, "Cargo.lock");
}

/// A Cargo exception is published on the Cargo closure only. A git
/// dependency is the exception a Cargo sync records.
#[test]
#[ignore]
fn dependency_edit_exception_is_not_published_to_cargo_closure() {
    let temp = TempDir::new("cargo-e2e");
    let project = temp.0.join("cargo-hello");
    copy_tree(&fixture("cargo-hello"), &project);
    let tmp = temp.0.join("tmp");
    std::fs::create_dir_all(tmp.join("home")).unwrap();
    let store = temp.0.join("store");
    let url = add_git_dependency(&temp.0, &project);

    assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["sync"]),
        "sync with a git dependency",
    );

    let closures = project.join(".tog/closures");
    let cargo: serde_json::Value =
        serde_json::from_slice(&std::fs::read(closures.join("cargo.json")).unwrap()).unwrap();
    let exceptions = cargo["body"]["exceptions"].as_array().unwrap();
    assert_eq!(exceptions.len(), 1, "cargo exceptions: {exceptions:?}");
    assert_eq!(exceptions[0]["kind"], "git-dependency");
    assert_eq!(exceptions[0]["subject"], "gitdep@1.0.0");
    assert!(
        exceptions[0]["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains(&url)),
        "unexpected detail: {}",
        exceptions[0]["detail"]
    );

    for entry in std::fs::read_dir(&closures).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().and_then(|name| name.to_str()) == Some("cargo.json") {
            continue;
        }
        let closure: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let other = closure["body"]["exceptions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !other
                .iter()
                .any(|exception| exception["kind"] == "git-dependency"),
            "{} also contains the Cargo exception",
            path.display()
        );
    }
}

/// Components and targets a `rust-toolchain.toml` asks for are provisioned
/// from the pinned channel manifest (#134): after one sync, `clippy` and
/// `rustfmt` run through Cargo, the `wasm32-unknown-unknown` standard
/// library links, and nothing is recorded as an exception on any closure.
/// The toolchain object is a different, assembled one than a plain project
/// gets, and the lock records both lists.
#[test]
#[ignore]
fn toolchain_file_components_and_targets_are_provisioned() {
    let temp = TempDir::new("cargo-e2e");
    let project = temp.0.join("cargo-hello");
    copy_tree(&fixture("cargo-hello"), &project);
    let tmp = temp.0.join("tmp");
    std::fs::create_dir_all(tmp.join("home")).unwrap();
    let store = temp.0.join("store");

    // The base toolchain of the same release first, so the assembled object
    // can be told apart from it and shown to link its files.
    std::fs::write(
        project.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.96.1\"\n",
    )
    .unwrap();
    assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["sync"]),
        "plain sync",
    );
    let (base, _) = assert_cargo_closure(&project, &store);

    std::fs::write(
        project.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.96.1\"\n\
         components = [\"clippy\", \"rustfmt\", \"rust-src\"]\n\
         targets = [\"wasm32-unknown-unknown\"]\n",
    )
    .unwrap();
    // The lock is stale until the toolchain is updated on purpose.
    assert!(
        !tog_with_tmp(&project, &store, &tmp, &["--frozen", "sync"])
            .status
            .success(),
        "a frozen sync accepted an edited toolchain file"
    );
    assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["update", "--toolchain", "rust"]),
        "toolchain update",
    );
    let lock = std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap();
    assert!(
        lock.contains("value = \"clippy,rust-src,rustfmt\""),
        "{lock}"
    );
    assert!(
        lock.contains("value = \"wasm32-unknown-unknown\""),
        "{lock}"
    );
    assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["sync"]),
        "sync with extras",
    );

    let (rust, _) = assert_cargo_closure(&project, &store);
    assert_ne!(rust, base, "extras did not produce a new toolchain object");
    assert!(rust.join("lib/rustlib/wasm32-unknown-unknown/lib").is_dir());
    assert!(rust.join("lib/rustlib/src/rust/library").is_dir());
    // The assembled tree links the base's files rather than copying them,
    // and rustc still resolves its sysroot to the assembled object.
    {
        use std::os::unix::fs::MetadataExt;
        let inode = |path: &Path| std::fs::metadata(path).unwrap().ino();
        assert_eq!(
            inode(&rust.join("bin/rustc")),
            inode(&base.join("bin/rustc"))
        );
    }
    let sysroot = assert_ok(
        tog_with_tmp(
            &project,
            &store,
            &tmp,
            &["run", "rustc", "--print", "sysroot"],
        ),
        "rustc --print sysroot",
    );
    assert_eq!(
        PathBuf::from(sysroot.trim()).canonicalize().unwrap(),
        rust,
        "rustc resolved its sysroot outside the assembled toolchain"
    );

    for (args, expect) in [
        (&["run", "cargo", "clippy", "--version"][..], "clippy"),
        (&["run", "cargo", "fmt", "--version"][..], "rustfmt"),
    ] {
        let output = assert_ok(tog_with_tmp(&project, &store, &tmp, args), &args.join(" "));
        assert!(output.contains(expect), "{args:?}: {output}");
    }
    assert_ok(
        tog_with_tmp(
            &project,
            &store,
            &tmp,
            &["build", "--target", "wasm32-unknown-unknown"],
        ),
        "wasm build",
    );
    assert!(project
        .join("target/wasm32-unknown-unknown/debug/cargo-hello.wasm")
        .is_file());

    // Nothing here is an exception any more, on any closure.
    for entry in std::fs::read_dir(project.join(".tog/closures")).unwrap() {
        let path = entry.unwrap().path();
        let closure: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let exceptions = closure["body"]["exceptions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(exceptions.is_empty(), "{}: {exceptions:?}", path.display());
    }

    // A profile expands like rustup's: `default` adds rust-docs to what is
    // already named, as a new toolchain that still links the same base.
    std::fs::write(
        project.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.96.1\"\nprofile = \"default\"\n\
         components = [\"rust-src\"]\ntargets = [\"wasm32-unknown-unknown\"]\n",
    )
    .unwrap();
    assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["update", "--toolchain", "rust"]),
        "toolchain update with a profile",
    );
    let lock = std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap();
    assert!(
        lock.contains("field = \"toolchain.profile\"\nvalue = \"default\""),
        "{lock}"
    );
    assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["sync"]),
        "sync with a profile",
    );
    let (profiled, _) = assert_cargo_closure(&project, &store);
    assert_ne!(profiled, rust);
    assert!(profiled.join("share/doc/rust/html").is_dir());
    let output = assert_ok(
        tog_with_tmp(
            &project,
            &store,
            &tmp,
            &["run", "cargo", "clippy", "--version"],
        ),
        "clippy from the default profile",
    );
    assert!(output.contains("clippy"), "{output}");

    // An unpublished component is refused by name, and the last good
    // closure stands.
    std::fs::write(
        project.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.96.1\"\ncomponents = [\"no-such-component\"]\n",
    )
    .unwrap();
    let output = tog_with_tmp(&project, &store, &tmp, &["update", "--toolchain", "rust"]);
    let output = if output.status.success() {
        tog_with_tmp(&project, &store, &tmp, &["sync"])
    } else {
        output
    };
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no-such-component"), "{stderr}");
    assert_eq!(assert_cargo_closure(&project, &store).0, profiled);
}

/// The build's sync is scoped to the ecosystem it builds (#158): beside a
/// Python project whose install cannot succeed, `tog build` still syncs
/// and builds the Cargo project, realizes nothing for Python, and the
/// toolchain lock it publishes keeps both sections. The bare `tog`, which
/// syncs everything, still fails on the Python install.
#[test]
#[ignore]
fn build_syncs_only_the_built_ecosystem_beside_a_failing_one() {
    let temp = TempDir::new("cargo-e2e");
    let project = temp.0.join("cargo-hello");
    copy_tree(&fixture("cargo-hello"), &project);
    // No index has this package, so Python's lock generation fails.
    std::fs::write(
        project.join("pyproject.toml"),
        "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n\
         dependencies = [\"tog-no-such-package-158\"]\n",
    )
    .unwrap();
    let tmp = temp.0.join("tmp");
    std::fs::create_dir_all(tmp.join("home")).unwrap();
    let store = temp.0.join("store");

    let output = tog_with_tmp(&project, &store, &tmp, &["build"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_ok(output, "build beside a failing python project");
    assert!(stderr.contains("syncing first: cargo"), "{stderr}");
    assert!(project.join("target/debug/cargo-hello").is_file());
    assert_cargo_closure(&project, &store);
    let closures = project.join(".tog/closures");
    assert!(
        !closures.join("python.json").exists(),
        "the build realized the python environment"
    );
    let lock = std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap();
    assert!(lock.contains("[toolchain.python]"), "{lock}");
    assert!(lock.contains("[toolchain.rust]"), "{lock}");

    // Cargo is synced now, so the next build runs no sync; the whole
    // project is still checked. A changed Python toolchain input (stale
    // lock section) or a malformed one refuses, and the lock is untouched.
    let pyproject = std::fs::read_to_string(project.join("pyproject.toml")).unwrap();
    std::fs::write(project.join(".python-version"), "3.13\n").unwrap();
    for (label, expected) in [
        (
            "stale python section",
            "tog-toolchain.toml is stale for python",
        ),
        ("malformed requires-python", "invalid"),
    ] {
        if label.starts_with("malformed") {
            std::fs::remove_file(project.join(".python-version")).unwrap();
            std::fs::write(
                project.join("pyproject.toml"),
                pyproject.replace("[project]\n", "[project]\nrequires-python = \"invalid\"\n"),
            )
            .unwrap();
        }
        let output = tog_with_tmp(&project, &store, &tmp, &["build", "cargo"]);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{label}: build succeeded");
        assert!(!stderr.contains("syncing first"), "{label}: {stderr}");
        assert!(stderr.contains(expected), "{label}: {stderr}");
        assert_eq!(
            std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap(),
            lock,
            "{label}: the lock changed"
        );
    }
    std::fs::write(project.join("pyproject.toml"), &pyproject).unwrap();

    let output = tog_with_tmp(&project, &store, &tmp, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "the python install was expected to fail\nstderr:\n{stderr}"
    );
    // The failure is the missing package, not something unrelated.
    assert!(stderr.contains("tog-no-such-package-158"), "{stderr}");
    assert!(!closures.join("python.json").exists());
}

/// A real toolchain directory named by `[toolchain] path`: the catalog's
/// Rust, synced once, is copied out of the store to stand in for a local
/// rustup toolchain. The project then builds and runs with the imported
/// copy, the closure records `external-toolchain`, and an edit to the
/// directory makes the next sync refuse until `tog update --toolchain`.
#[test]
#[ignore]
fn a_local_toolchain_directory_builds_the_project() {
    let temp = TempDir::new("cargo-e2e");
    let project = temp.0.join("cargo-hello");
    copy_tree(&fixture("cargo-hello"), &project);
    let tmp = temp.0.join("tmp");
    std::fs::create_dir_all(tmp.join("home")).unwrap();
    let store = temp.0.join("store");

    assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["sync"]),
        "catalog sync",
    );
    let (catalog_rust, _) = assert_cargo_closure(&project, &store);
    let local = temp.0.join("local-rust");
    let copied = Command::new("/bin/cp")
        .arg("-R")
        .arg(&catalog_rust)
        .arg(&local)
        .status()
        .unwrap();
    assert!(copied.success());
    let restored = Command::new("/bin/chmod")
        .args(["-R", "u+w"])
        .arg(&local)
        .status()
        .unwrap();
    assert!(restored.success());
    let local = local.canonicalize().unwrap();
    std::fs::write(
        project.join("rust-toolchain.toml"),
        format!("[toolchain]\npath = \"{}\"\n", local.display()),
    )
    .unwrap();

    // The toolchain file changed, so the lock is stale until updated.
    let output = tog_with_tmp(&project, &store, &tmp, &["sync"]);
    assert!(!output.status.success(), "a stale lock synced");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("tog update --toolchain rust"), "{stderr}");
    let output = tog_with_tmp(&project, &store, &tmp, &["update", "--toolchain", "rust"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_ok(output, "update to the local toolchain");
    assert!(stderr.contains("exception external-toolchain"), "{stderr}");
    let lock = std::fs::read_to_string(project.join("tog-toolchain.toml")).unwrap();
    assert!(lock.contains("source = \"path\""), "{lock}");
    assert!(
        lock.contains(&format!("url = \"file://{}\"", local.display())),
        "{lock}"
    );

    let (imported, _) = assert_cargo_closure(&project, &store);
    assert_ne!(
        imported, catalog_rust,
        "the import reused the catalog object"
    );
    let closure = std::fs::read_to_string(project.join(".tog/closures/cargo.json")).unwrap();
    assert!(closure.contains("\"external-toolchain\""), "{closure}");
    assert_ok(tog_with_tmp(&project, &store, &tmp, &["build"]), "build");
    let output = assert_ok(
        tog_with_tmp(&project, &store, &tmp, &["run", "target/debug/cargo-hello"]),
        "run",
    );
    assert_eq!(output.trim(), "hello 128");

    // Editing the directory breaks the lock's content hash: fail closed.
    std::fs::write(local.join("lib/rustlib/extra.txt"), b"edited").unwrap();
    let output = tog_with_tmp(&project, &store, &tmp, &["sync"]);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(!output.status.success(), "a changed tree synced\n{stderr}");
    assert!(
        stderr.contains("changed since tog-toolchain.toml locked it"),
        "{stderr}"
    );
}
