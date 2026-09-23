//! `tog update --self` and the `version` row of `tog doctor`, exercised
//! through the real binary against a release laid out the way GitHub
//! serves one: a manifest naming the assets, a tarball holding `tog`, and
//! the `.sha256` file beside it. Everything is served from `file://` URLs
//! (`TOG_RELEASE_MANIFEST`), so nothing here touches the network, and the
//! binary being replaced is always a copy in a throwaway HOME, never the
//! one cargo built.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]

use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-selfupdate-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        fs::create_dir_all(path.join(".tog")).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A test that made a directory read-only puts it back so the
        // fixture can go.
        if let Ok(meta) = fs::metadata(self.0.join("bin")) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(self.0.join("bin"), perms);
        }
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn triple() -> &'static str {
    tog::kernel::platform::Platform::host().unwrap().triple()
}

/// A shell script that answers `--version` the way a tog binary does, so
/// the update's smoke test accepts it and the test can tell the new file
/// from the old one by what it prints.
fn fake_tog(version_line: &str) -> String {
    format!("#!/bin/sh\nprintf '%s\\n' '{version_line}'\n")
}

/// The pieces of a release the manifest can point at. Each knob breaks one
/// rule on purpose so the test can watch the refusal.
struct Release<'a> {
    tag: &'a str,
    /// The `tog` member of the tarball; `None` ships a tarball without one.
    binary: Option<&'a str>,
    /// The digest the `.sha256` file claims; `None` uses the real one.
    claimed_sha256: Option<&'a str>,
    /// Leave the platform's assets out of the manifest entirely.
    no_assets: bool,
}

impl Release<'_> {
    fn newer() -> Self {
        Release {
            tag: "v99.0.0",
            binary: Some("tog 99.0.0 (test)"),
            claimed_sha256: None,
            no_assets: false,
        }
    }
}

/// Lay the release out under `home/release` and return the manifest URL.
fn publish(home: &Path, release: &Release<'_>) -> String {
    let dir = home.join("release");
    let stage = home.join("stage");
    fs::create_dir_all(&dir).unwrap();
    fs::create_dir_all(&stage).unwrap();
    let asset = format!("tog-{}.tar.gz", triple());
    let member = match release.binary {
        Some(version_line) => {
            fs::write(stage.join("tog"), fake_tog(version_line)).unwrap();
            fs::set_permissions(stage.join("tog"), fs::Permissions::from_mode(0o755)).unwrap();
            "tog"
        }
        None => {
            fs::write(stage.join("README"), "no binary here\n").unwrap();
            "README"
        }
    };
    let status = Command::new("/usr/bin/tar")
        .args(["-C"])
        .arg(&stage)
        .arg("-czf")
        .arg(dir.join(&asset))
        .arg(member)
        .status()
        .unwrap();
    assert!(status.success());
    let digest = match release.claimed_sha256 {
        Some(claimed) => claimed.to_string(),
        None => sha256_hex(&fs::read(dir.join(&asset)).unwrap()),
    };
    fs::write(
        dir.join(format!("{asset}.sha256")),
        format!("{digest}  {asset}\n"),
    )
    .unwrap();
    let assets = if release.no_assets {
        serde_json::json!([])
    } else {
        serde_json::json!([
            {
                "name": asset,
                "browser_download_url": format!("file://{}", dir.join(&asset).display()),
            },
            {
                "name": format!("{asset}.sha256"),
                "browser_download_url": format!("file://{}", dir.join(format!("{asset}.sha256")).display()),
            },
        ])
    };
    let manifest = dir.join("latest.json");
    fs::write(
        &manifest,
        serde_json::to_string_pretty(&serde_json::json!({
            "tag_name": release.tag,
            "assets": assets,
        }))
        .unwrap(),
    )
    .unwrap();
    format!("file://{}", manifest.display())
}

/// A copy of the built binary at `home/bin/tog`: the one the test runs and
/// the one the update is allowed to replace.
fn install_copy(home: &Path) -> PathBuf {
    let bin = home.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let target = bin.join("tog");
    fs::copy(env!("CARGO_BIN_EXE_tog"), &target).unwrap();
    target
}

fn run(binary: &Path, home: &Path, manifest: &str, args: &[&str]) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .current_dir(home)
        .env("HOME", home)
        .env("TOG_STORE", home.join("store"))
        .env("TOG_RELEASE_MANIFEST", manifest)
        .env_remove("TOG_POLICY")
        .env_remove("TOG_STRICT")
        .env_remove("TOG_SIGNING_KEY")
        .env("NO_COLOR", "1");
    output_of(&mut command)
}

/// Run a binary this test just wrote. Another test thread that forks
/// while our copy is still open for writing holds that descriptor until
/// its child execs, and exec of a file open for writing fails with
/// ETXTBSY; the window is short, so wait it out.
fn output_of(command: &mut Command) -> Output {
    for _ in 0..50 {
        match command.output() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            result => return result.expect("spawn tog"),
        }
    }
    command.output().expect("spawn tog")
}

fn version_of(binary: &Path) -> String {
    text(&output_of(Command::new(binary).arg("--version")).stdout)
        .trim()
        .to_string()
}

/// Nothing named `.tog.update.*` may survive next to the binary, whatever
/// happened.
fn no_leftovers(dir: &Path) {
    let stray: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".tog.update."))
        .collect();
    assert!(stray.is_empty(), "{stray:?}");
}

fn running_line() -> String {
    tog::cli::version_line()
}

#[test]
fn a_newer_release_replaces_the_binary_in_place() {
    let home = TempDir::new("newer");
    let binary = install_copy(&home.0);
    let before = version_of(&binary);
    assert_eq!(before, running_line());
    let manifest = publish(&home.0, &Release::newer());

    let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("downloading v99.0.0"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "updated {before} -> tog 99.0.0 (test) at {}",
            binary.canonicalize().unwrap().display()
        )),
        "{stderr}"
    );
    assert_eq!(version_of(&binary), "tog 99.0.0 (test)");
    assert_eq!(
        fs::metadata(&binary).unwrap().permissions().mode() & 0o777,
        0o755
    );
    no_leftovers(binary.parent().unwrap());
}

#[test]
fn the_same_or_an_older_release_leaves_the_binary_alone() {
    let home = TempDir::new("current");
    let binary = install_copy(&home.0);
    let bytes = fs::read(&binary).unwrap();
    for (tag, word) in [
        (
            format!("v{}", env!("CARGO_PKG_VERSION")),
            "is at the latest release's version",
        ),
        ("v0.0.1".to_string(), "is newer than the latest release"),
    ] {
        let manifest = publish(
            &home.0,
            &Release {
                tag: &tag,
                ..Release::newer()
            },
        );
        let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{stderr}");
        assert!(
            stderr.contains(&format!("{} {word} ({tag}); nothing to do", running_line())),
            "{stderr}"
        );
        assert!(!stderr.contains("downloading"), "{stderr}");
        assert_eq!(fs::read(&binary).unwrap(), bytes);
    }
    // Quiet silences the narration and still exits 0.
    let manifest = publish(
        &home.0,
        &Release {
            tag: "v0.0.1",
            ..Release::newer()
        },
    );
    let out = run(&binary, &home.0, &manifest, &["-q", "update", "--self"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
}

#[test]
fn a_bad_download_never_touches_the_binary() {
    let home = TempDir::new("refused");
    let binary = install_copy(&home.0);
    let bytes = fs::read(&binary).unwrap();
    let wrong = "0".repeat(64);
    for (release, expected) in [
        (
            Release {
                claimed_sha256: Some(&wrong),
                ..Release::newer()
            },
            "hash mismatch",
        ),
        (
            Release {
                claimed_sha256: Some("not-a-digest"),
                ..Release::newer()
            },
            "does not hold a sha256",
        ),
        (
            Release {
                binary: None,
                ..Release::newer()
            },
            "did not contain a 'tog' binary",
        ),
        (
            Release {
                binary: Some("something else"),
                ..Release::newer()
            },
            "does not identify itself",
        ),
        (
            Release {
                binary: Some("tog 1.0.0 (wrong asset)"),
                ..Release::newer()
            },
            "says it is 1.0.0, not 99.0.0",
        ),
        (
            Release {
                no_assets: true,
                ..Release::newer()
            },
            &format!("release v99.0.0 has no tog-{}.tar.gz", triple()),
        ),
    ] {
        let manifest = publish(&home.0, &release);
        let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("tog: error: "), "{stderr}");
        assert!(stderr.contains(expected), "{expected}: {stderr}");
        assert_eq!(fs::read(&binary).unwrap(), bytes, "{expected}");
        no_leftovers(binary.parent().unwrap());
    }
    // A manifest that cannot be read names the releases page.
    let out = run(
        &binary,
        &home.0,
        &format!("file://{}", home.0.join("missing.json").display()),
        &["update", "--self"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("cannot read the latest release (")
            && stderr.contains("https://github.com/DigitalWestern/tog/releases"),
        "{stderr}"
    );
    assert_eq!(fs::read(&binary).unwrap(), bytes);
}

#[test]
fn an_unwritable_directory_is_refused_before_anything_is_downloaded() {
    let home = TempDir::new("readonly");
    let binary = install_copy(&home.0);
    let bin = binary.parent().unwrap().to_path_buf();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::File::create(bin.join(".probe")).is_ok() {
        // root, or a filesystem that ignores the mode: nothing to prove.
        let _ = fs::remove_file(bin.join(".probe"));
        return;
    }
    let manifest = publish(&home.0, &Release::newer());
    let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
    let stderr = text(&out.stderr);
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "cannot write to {} (",
            bin.canonicalize().unwrap().display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("install.sh"), "{stderr}");
    assert!(!stderr.contains("downloading"), "{stderr}");
    assert_eq!(version_of(&binary), running_line());
    no_leftovers(&bin);
}

#[test]
fn a_symlinked_binary_updates_its_target_and_names_it() {
    let home = TempDir::new("symlink");
    let target = install_copy(&home.0);
    let link_dir = home.0.join("link");
    fs::create_dir_all(&link_dir).unwrap();
    let link = link_dir.join("tog");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let manifest = publish(&home.0, &Release::newer());

    let out = run(&link, &home.0, &manifest, &["update", "--self"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains(&format!("at {}", target.canonicalize().unwrap().display())),
        "{stderr}"
    );
    assert!(!stderr.contains(&link.display().to_string()), "{stderr}");
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(version_of(&target), "tog 99.0.0 (test)");
    assert_eq!(version_of(&link), "tog 99.0.0 (test)");
    no_leftovers(target.parent().unwrap());
    no_leftovers(&link_dir);
}

#[test]
fn self_takes_nothing_else_and_needs_no_project_or_store() {
    let home = TempDir::new("usage");
    let binary = install_copy(&home.0);
    let manifest = publish(&home.0, &Release::newer());
    for args in [
        &["update", "--self", "serde"][..],
        &["update", "--self", "--toolchain"],
        &["update", "--self", "--no-sync"],
    ] {
        let out = run(&binary, &home.0, &manifest, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            text(&out.stderr).contains("update --self replaces the tog binary"),
            "{}",
            text(&out.stderr)
        );
    }
    // A successful update from an empty directory never created a store.
    let out = run(&binary, &home.0, &manifest, &["update", "--self"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!home.0.join("store").exists());
}

#[test]
fn doctor_reports_the_build_and_whether_a_release_is_newer() {
    let home = TempDir::new("doctor");
    let binary = install_copy(&home.0);
    let running = running_line();

    let manifest = publish(&home.0, &Release::newer());
    let out = run(&binary, &home.0, &manifest, &["doctor"]);
    let stdout = text(&out.stdout);
    let first = stdout.lines().next().unwrap();
    assert_eq!(
        first,
        format!("warn  version      {running}; v99.0.0 is out (run 'tog update --self')"),
        "{stdout}"
    );
    // A stale binary is a warning, not a failure. Other rows may fail on
    // the host running this (no bubblewrap, no C toolchain), so only
    // the version row is judged.
    assert!(
        !stdout.lines().any(|line| line.starts_with("fail  version")),
        "{stdout}"
    );
    let out = run(&binary, &home.0, &manifest, &["doctor", "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["checks"][0]["name"], "version");
    assert_eq!(value["checks"][0]["level"], "warn");
    assert!(value["checks"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("tog update --self"));

    let manifest = publish(
        &home.0,
        &Release {
            tag: &format!("v{}", env!("CARGO_PKG_VERSION")),
            ..Release::newer()
        },
    );
    let out = run(&binary, &home.0, &manifest, &["doctor"]);
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with(&format!(
            "ok    version      {running}; the latest release is v{} (same version; releases are compared by version, not by commit)\n",
            env!("CARGO_PKG_VERSION")
        )),
        "{stdout}"
    );

    let out = run(
        &binary,
        &home.0,
        &format!("file://{}", home.0.join("missing.json").display()),
        &["doctor"],
    );
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with(&format!(
            "ok    version      {running}; newer release not checked ("
        )),
        "{stdout}"
    );
}
