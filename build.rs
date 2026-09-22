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

use std::path::{Path, PathBuf};
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

/// The files whose change means a different commit: HEAD, the ref it
/// points at when it is symbolic, and packed-refs, where a ref lands after
/// `git gc`. Without these, cargo would keep an old stamp until something
/// else forced a rebuild.
fn watch_git_files() {
    let Some(dir) = git(&["rev-parse", "--git-dir"]).map(PathBuf::from) else {
        return;
    };
    for name in ["HEAD", "packed-refs"] {
        let path = dir.join(name);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        // `--git-path` resolves a worktree's shared refs directory too.
        if let Some(path) = git(&["rev-parse", "--git-path", &reference]) {
            let path = Path::new(&path);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=TOG_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=TOG_BUILD_DATE");
    watch_git_files();
    let commit = std::env::var("TOG_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| git(&["rev-parse", "--short=7", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let date = std::env::var("TOG_BUILD_DATE")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| git(&["log", "-1", "--format=%cs", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=TOG_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=TOG_BUILD_DATE={date}");
}
