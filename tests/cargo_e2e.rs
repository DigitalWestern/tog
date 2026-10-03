//! End-to-end Cargo tailor test. Heavy: downloads the pinned Rust toolchain
//! and crates.io closure on first run.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tog::kernel::platform::Platform;

mod common;

use common::{
    add_git_dependency, assert_frozen_never_writes_the_lock, assert_ok, command, copy_tree,
    fixture, tog, TempDir,
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
    // Cargo resolves through a door, so `--strict` wants the lock to carry
    // a signed resolution record: `tog attest cargo` checks the committed
    // lock (`cargo metadata --locked`, confined) and signs one with a key
    // the machine policy trusts.
    let key = temp.0.join("signing.key");
    let public = tog::kernel::signing::generate(&key).unwrap();
    std::fs::create_dir_all(temp.0.join(".tog")).unwrap();
    std::fs::write(
        temp.0.join(".tog/policy.toml"),
        format!("deny = []\n\n[signing]\ntrusted = [\"{public}\"]\n"),
    )
    .unwrap();
    let lock_before = std::fs::read(project.join("Cargo.lock")).unwrap();
    let attest = command(&project, &temp.0, &store)
        .env("TOG_SIGNING_KEY", &key)
        .args(["attest", "cargo"])
        .output()
        .unwrap();
    assert!(
        attest.status.success(),
        "attest cargo: {}",
        String::from_utf8_lossy(&attest.stderr)
    );
    assert!(project.join(".tog/resolution/cargo.json").is_file());
    assert_eq!(
        std::fs::read(project.join("Cargo.lock")).unwrap(),
        lock_before,
        "attest changed the lock"
    );
    // On a synced project no sync runs in front of the build, so the only
    // policy load is build's own: `--strict` must reach it all the same.
    let strict = tog(&project, &temp.0, &["-v", "--strict", "build"]);
    let strict_stderr = String::from_utf8_lossy(&strict.stderr).into_owned();
    assert!(
        strict.status.success(),
        "strict build failed: {strict_stderr}"
    );
    assert!(
        strict_stderr.contains("policy: strict (--strict)"),
        "strict build never loaded a strict policy: {strict_stderr}"
    );
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
/// dependency is the exception a Cargo sync records; the project is also a
/// Python project, so there is a second closure the exception must stay
/// off.
#[test]
#[ignore]
fn git_dependency_exception_is_published_on_the_cargo_closure_only() {
    let temp = TempDir::new("cargo-e2e");
    let project = temp.0.join("cargo-hello");
    copy_tree(&fixture("cargo-hello"), &project);
    std::fs::write(project.join("requirements.txt"), "six==1.17.0\n").unwrap();
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
    // The committed lock carries no resolution record, which Cargo's door
    // reports as `unrecorded-resolution` on the same closure; it is set
    // apart here so the git exception is the one traced.
    let (unrecorded, exceptions): (Vec<_>, Vec<_>) = cargo["body"]["exceptions"]
        .as_array()
        .unwrap()
        .iter()
        .partition(|exception| exception["kind"] == "unrecorded-resolution");
    assert_eq!(unrecorded.len(), 1, "cargo exceptions: {unrecorded:?}");
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

    let mut others = Vec::new();
    for entry in std::fs::read_dir(&closures).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().and_then(|name| name.to_str()) == Some("cargo.json") {
            continue;
        }
        others.push(path.file_name().unwrap().to_string_lossy().to_string());
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
    // The loop above checked something: the Python closure is there.
    assert_eq!(others, ["python.json"], "the closures besides cargo.json");
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

    // Nothing about the toolchain is an exception any more, on any
    // closure. The committed lock carries no resolution record, which is
    // `unrecorded-resolution` on the Cargo closure and nothing toolchain.
    for entry in std::fs::read_dir(project.join(".tog/closures")).unwrap() {
        let path = entry.unwrap().path();
        let closure: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let exceptions: Vec<_> = closure["body"]["exceptions"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|exception| {
                !(path.ends_with("cargo.json") && exception["kind"] == "unrecorded-resolution")
            })
            .collect();
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

/// Every way a Cargo project or cargo's own home can put the signing key in
/// front of cargo, with the real toolchain, so each command reaches the
/// step that reads the file: no byte of the key reaches stdout or stderr of
/// sync, attest, add or fmt, and each refusal names the file.
///
/// - cargo's home config includes a file hard-linked to the key: no cargo
///   runs on the host and a confined one gets a scratch `CARGO_HOME`, so
///   every command succeeds.
/// - `.cargo/config.toml` a symlink to the key outside the project, and the
///   `target/key` alias (a hard link in `target/`, the config a symlink to
///   `../target/key`): sync, attest, add and fmt refuse it by name.
/// - the toolchain files hard-linked to the key: `add` reaches them with
///   the toolchain realized.
/// - a workspace member in a hidden directory, 13 levels down, whose
///   manifest is a hard link to the key: refused by name.
/// - a member reached through a symlinked directory that holds a manifest
///   hard-linked to the key: attest and add refuse the workspace (the
///   confined cargo would resolve without the member), and fmt's sandbox
///   does not mount the target, so cargo-fmt cannot read it (a host
///   `cargo fmt --all` there quotes the key).
#[test]
#[ignore]
fn the_signing_key_never_reaches_the_output_through_cargo_files() {
    let temp = TempDir::new("cargo-e2e-key");
    let store = temp.0.join("store");
    let key = temp.0.join("keys/signing.key");
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    let public = tog::kernel::signing::generate(&key).unwrap();
    let contents = std::fs::read_to_string(&key).unwrap();
    let seed = contents.trim().rsplit(':').next().unwrap().to_string();
    assert!(seed.len() >= 32, "{contents}");
    std::fs::create_dir_all(temp.0.join(".tog")).unwrap();
    std::fs::write(
        temp.0.join(".tog/policy.toml"),
        format!("deny = []\n\n[signing]\ntrusted = [\"{public}\"]\n"),
    )
    .unwrap();
    let run = |project: &Path, args: &[&str]| -> (bool, String) {
        let out = command(project, &temp.0, &store)
            .env("TOG_SIGNING_KEY", &key)
            .env("CARGO_HOME", temp.0.join(".cargo"))
            .args(args)
            .output()
            .unwrap();
        let (stdout, stderr) = (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        assert!(
            !stdout.contains(&seed) && !stderr.contains(&seed),
            "{args:?}: the key reached the output\n{stdout}\n{stderr}"
        );
        (out.status.success(), stderr)
    };
    let refused = |project: &Path, args: &[&str]| {
        let (ok, stderr) = run(project, args);
        assert!(!ok, "{args:?} succeeded: {stderr}");
        assert!(
            stderr.contains("is the signing key"),
            "{args:?} was not refused for the key: {stderr}"
        );
    };
    let fresh = |name: &str| {
        let project = temp.0.join(name);
        copy_tree(&fixture("cargo-hello"), &project);
        project
    };
    let commands: [&[&str]; 4] = [
        &["sync"],
        &["attest", "cargo"],
        &["add", "--no-sync", "cargo:itoa"],
        &["fmt"],
    ];

    // cargo's home config including the key: nothing reads it.
    let cargo_home = temp.0.join(".cargo");
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(cargo_home.join("config.toml"), "include = [\"key.toml\"]\n").unwrap();
    std::fs::hard_link(&key, cargo_home.join("key.toml")).unwrap();
    let project = fresh("home-include");
    for args in commands {
        let (ok, stderr) = run(&project, args);
        assert!(ok, "{args:?}: {stderr}");
    }
    std::fs::remove_dir_all(&cargo_home).unwrap();

    // The project's config leading to the key: a symlink out of the
    // project, and the `target/key` alias.
    for (name, alias) in [("config-symlink", false), ("config-target-alias", true)] {
        let project = fresh(name);
        std::fs::create_dir_all(project.join(".cargo")).unwrap();
        let config = project.join(".cargo/config.toml");
        if alias {
            std::fs::create_dir_all(project.join("target")).unwrap();
            std::fs::hard_link(&key, project.join("target/key")).unwrap();
            std::os::unix::fs::symlink("../target/key", &config).unwrap();
        } else {
            std::os::unix::fs::symlink(&key, &config).unwrap();
        }
        // sync reads the config as a resolution input (its digest goes in
        // the closure), so it refuses too, before any cargo runs.
        for args in commands {
            refused(&project, args);
        }
    }

    // The toolchain files, read by add after the toolchain is realized.
    for file in ["rust-toolchain.toml", "rust-toolchain"] {
        let project = fresh(&format!("toolchain-{file}"));
        std::fs::hard_link(&key, project.join(file)).unwrap();
        let (ok, stderr) = run(&project, &["add", "--no-sync", "cargo:itoa"]);
        assert!(!ok, "{file}: add succeeded");
        assert!(
            stderr.contains("is the signing key") || stderr.contains("[signing key redacted]"),
            "{file}: {stderr}"
        );
    }

    // A hidden, deep member hard-linked to the key.
    let project = fresh("deep-member");
    let member: PathBuf = std::iter::once(".hidden".to_string())
        .chain((1..=13).map(|level| level.to_string()))
        .collect();
    std::fs::create_dir_all(project.join(&member)).unwrap();
    std::fs::hard_link(&key, project.join(&member).join("Cargo.toml")).unwrap();
    let manifest = project.join("Cargo.toml");
    let mut text = std::fs::read_to_string(&manifest).unwrap();
    text.push_str(&format!(
        "\n[workspace]\nmembers = [\"{}\"]\n",
        member.display()
    ));
    std::fs::write(&manifest, text).unwrap();
    for args in &commands[1..] {
        refused(&project, args);
    }
    run(&project, &["sync"]);

    // A member through a symlinked directory.
    let project = fresh("linked-member");
    let outside = temp.0.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::hard_link(&key, outside.join("Cargo.toml")).unwrap();
    std::os::unix::fs::symlink(&outside, project.join("linked")).unwrap();
    let manifest = project.join("Cargo.toml");
    let mut text = std::fs::read_to_string(&manifest).unwrap();
    text.push_str("\n[workspace]\nmembers = [\"linked\"]\n");
    std::fs::write(&manifest, text).unwrap();
    // sync writes tog-toolchain.toml, which attest needs.
    run(&project, &["sync"]);
    // The confined cargo would not see the member: attest and edits are
    // refused, naming it.
    for args in [
        &["attest", "cargo"][..],
        &["add", "--no-sync", "cargo:itoa"],
    ] {
        let (ok, stderr) = run(&project, args);
        assert!(
            !ok && stderr.contains("symlinked directory"),
            "{args:?}: {stderr}"
        );
    }
    run(&project, &["fmt"]);
    run(&project, &["fmt", "--all"]);
}
