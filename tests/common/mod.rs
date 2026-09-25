//! The one harness for the integration suites: a scratch directory that is
//! removed even when the store inside it is read-only, and a way to run the
//! binary that never sees the developer's home, store, or policy.
//!
//! Each `tests/*.rs` file is its own crate and compiles this module with
//! `mod common;`, so a helper one suite does not use is dead code there.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// A scratch directory under the temp root (`TMPDIR` when set), named
/// `tog-<label>-<pid>-<nanos>` so a leftover names the suite that made it.
/// Gone on drop: store objects are read-only by design, so a plain
/// `remove_dir_all` fails on them and the tree stays behind, and enough
/// leftovers fill the per-user /tmp quota until every shell command in the
/// developer's session returns nothing.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "tog-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        // tog records object paths under the store's canonicalized root and
        // compares them exactly; on macOS the temp dir sits under /var, a
        // symlink to /private/var.
        Self(path.canonicalize().unwrap())
    }

    /// A scratch directory that is its own project boundary: it carries an
    /// empty `.tog` directory, so ancestor discovery stops there. For
    /// fixtures that are run in place, which could otherwise sit below a
    /// developer checkout with package manifests of its own.
    pub fn boundary(label: &str) -> Self {
        let temp = Self::new(label);
        std::fs::create_dir_all(temp.0.join(".tog")).unwrap();
        temp
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = tog::kernel::store::remove_tree(&self.0);
    }
}

/// The store a heavy suite should use: the developer's `TOG_STORE` when set,
/// so repeated runs of an ignored suite reuse the toolchains it downloaded,
/// else `store/` under the scratch directory. Only the store is shared; the
/// binary still runs with the scratch home and no policy.
pub fn warm_store(temp: &TempDir) -> PathBuf {
    std::env::var_os("TOG_STORE")
        .map(PathBuf::from)
        .unwrap_or_else(|| temp.0.join("store"))
}

/// The binary, configured to run in `cwd` against `store` with `home` as
/// its `HOME`. Every `TOG_*` variable of the developer's session is dropped
/// first, so the machine policy is `home/.tog/policy.toml` (absent unless
/// the test writes it), no signing key or strictness leaks in, and the
/// release check `doctor` makes points at a file that does not exist so the
/// suite stays offline. `TOG_SANDBOX_TESTS` passes through: CI sets it to
/// make a sandbox that cannot start a failure rather than a skip.
pub fn command(cwd: &Path, home: &Path, store: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tog"));
    for (name, _) in std::env::vars_os() {
        let leaks = name
            .to_str()
            .is_some_and(|name| name.starts_with("TOG_") && name != "TOG_SANDBOX_TESTS");
        if leaks {
            command.env_remove(&name);
        }
    }
    command
        .current_dir(cwd)
        .env("HOME", home)
        .env("TOG_STORE", store)
        .env(
            "TOG_RELEASE_MANIFEST",
            format!("file://{}", home.join("no-release.json").display()),
        )
        .env("NO_COLOR", "1");
    command
}

/// Run the binary in `cwd` with `home` as its home and `home/store` as its
/// store: the shape every offline suite uses, where the scratch directory
/// is the home.
pub fn tog(cwd: &Path, home: &Path, args: &[&str]) -> Output {
    tog_at(cwd, home, &home.join("store"), args)
}

/// [`tog`] with extra environment for the child; values are anything that
/// reads as an `OsStr`, so `&[("TOG_STRICT", "1")]` and `&[("TMPDIR", path)]`
/// both work.
pub fn tog_env<V>(cwd: &Path, home: &Path, args: &[&str], env: &[(&str, &V)]) -> Output
where
    V: AsRef<OsStr> + ?Sized,
{
    let mut command = command(cwd, home, &home.join("store"));
    command.args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("spawn tog")
}

/// Run the binary against a store that is not under `home`, such as the
/// one [`warm_store`] names.
pub fn tog_at(cwd: &Path, home: &Path, store: &Path, args: &[&str]) -> Output {
    command(cwd, home, store)
        .args(args)
        .output()
        .expect("spawn tog")
}

/// The stdout of a run that must have succeeded; a failure shows both
/// streams under `label`.
pub fn assert_ok(output: Output, label: &str) -> String {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Copy a fixture tree into scratch space, files and directories only:
/// fixtures carry no symlinks, and a test that needs one makes it itself.
pub fn copy_tree(src: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(from, to).unwrap();
        }
    }
}

/// The fixture directory under `tests/fixtures`.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}
