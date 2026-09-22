//! Stamp the binary with the commit it was built from, so `tog --version`
//! can answer "how old is this?" and a bug report can name its build.
//!
//! Two values, both read from git at build time and both `unknown` outside
//! a checkout (a source tarball, a vendored build): the short commit id and
//! the commit date. The commit date is used rather than the wall clock so
//! the same commit always produces the same version line, and so the date
//! says how old the *source* is, which is the question a stale binary
//! raises. `TOG_BUILD_COMMIT` and `TOG_BUILD_DATE` in the environment
//! override git for a build that has no checkout to ask.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Is this source tree its own repository? `git` searches upward, so a
/// source tarball unpacked inside some other checkout would otherwise be
/// stamped with that repository's commit. Only a top level equal to the
/// crate directory counts.
fn in_own_checkout() -> bool {
    let Some(top) = git(&["rev-parse", "--show-toplevel"]) else {
        return false;
    };
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return false;
    };
    match (fs::canonicalize(top), fs::canonicalize(manifest_dir)) {
        (Ok(top), Ok(manifest_dir)) => top == manifest_dir,
        _ => false,
    }
}

/// The files whose change means a different commit: HEAD, the ref it
/// points at when it is symbolic, and packed-refs, where a ref lands after
/// `git gc`. Every path comes from `--git-path`, which is what makes a
/// worktree right: its HEAD is private, its refs and packed-refs are the
/// main checkout's. The ref's directory is watched as well as the ref, so
/// a loose ref that `pack-refs` removed and a later commit recreated still
/// restamps the build. Without these, cargo would keep an old stamp until
/// something else forced a rebuild.
fn watch_git_files() {
    let mut paths = vec!["HEAD".to_string(), "packed-refs".to_string()];
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some((dir, _)) = reference.rsplit_once('/') {
            paths.push(dir.to_string());
        }
        paths.push(reference);
    }
    for name in paths {
        let Some(path) = git(&["rev-parse", "--git-path", &name]).map(PathBuf::from) else {
            continue;
        };
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=TOG_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=TOG_BUILD_DATE");
    let checkout = in_own_checkout();
    if checkout {
        watch_git_files();
    }
    let from_git = |args: &[&str]| if checkout { git(args) } else { None };
    let commit = std::env::var("TOG_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| from_git(&["rev-parse", "--short=7", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let date = std::env::var("TOG_BUILD_DATE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| from_git(&["log", "-1", "--format=%cs", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=TOG_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=TOG_BUILD_DATE={date}");
}
