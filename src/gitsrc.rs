//! Git sources realized by commit (NEXT.md item 4).
//!
//! A commit hash is a fingerprint, so a git dependency fits the store's model
//! exactly: the object's identity is the normalized repository URL plus the
//! commit, and its content is that tree with `.git` removed. Fetching needs
//! the network, so it happens at realization time like any other download —
//! never inside a build sandbox.

use crate::store::Store;
use crate::types::Identity;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const GIT: &str = "/usr/bin/git";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitSource {
    /// Normalized: no scheme credentials, no `git+` prefix, no `.git` suffix.
    pub url: String,
    /// Full 40-character commit hash.
    pub commit: String,
    /// Package subdirectory inside the repository, if the dependency names one.
    pub subdirectory: Option<String>,
}

fn err(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

pub fn is_full_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Normalize a repository URL so two spellings of one repository share an
/// object: drop the `git+` prefix, any credentials, a trailing `.git`, and a
/// trailing slash. `scp`-style `git@host:owner/repo` becomes `ssh://host/owner/repo`.
pub fn normalize_url(raw: &str) -> String {
    let mut url = raw.trim();
    if let Some(rest) = url.strip_prefix("git+") {
        url = rest;
    }
    if let Some((before, _)) = url.split_once('#') {
        url = before;
    }
    let mut url = url.to_string();
    if !url.contains("://") {
        if let Some((host, path)) = url.split_once(':') {
            let host = host.rsplit('@').next().unwrap_or(host);
            url = format!("ssh://{host}/{}", path.trim_start_matches('/'));
        }
    } else if let Some((scheme, rest)) = url.split_once("://") {
        // Strip credentials: scheme://user:token@host/path -> scheme://host/path
        let rest = match rest.split_once('@') {
            Some((_, after)) => after.to_string(),
            None => rest.to_string(),
        };
        url = format!("{scheme}://{rest}");
    }
    let url = url.trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);
    // Lockfile spellings like `github.com/owner/repo` name a host but no
    // protocol; git needs one, and https is what every registry lock means.
    if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    }
}

/// `github.com/owner/repo` -> `owner-repo`, for a readable object name.
fn slug(url: &str) -> String {
    let tail = url.rsplit("://").next().unwrap_or(url);
    let mut parts: Vec<&str> = tail.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() > 2 {
        parts = parts[parts.len() - 2..].to_vec();
    }
    let joined = parts.join("-");
    let cleaned: String = joined
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' })
        .collect();
    if cleaned.is_empty() { "repo".to_string() } else { cleaned }
}

fn identity(source: &GitSource) -> Identity {
    Identity {
        kind: "git-source".into(),
        name: slug(&source.url),
        version: source.commit.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "git-source/1".to_string()),
            ("url".to_string(), source.url.clone()),
            ("commit".to_string(), source.commit.clone()),
        ]),
    }
}

pub fn object_id(source: &GitSource) -> String {
    identity(source).object_id()
}

fn run_git(args: &[&str], cwd: Option<&Path>) -> io::Result<std::process::Output> {
    let mut command = Command::new(GIT);
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    // A prompt would hang a background sync forever.
    command.env("GIT_TERMINAL_PROMPT", "0");
    command.env("GIT_ASKPASS", "/bin/true");
    command.output().map_err(|e| {
        io::Error::new(e.kind(), format!("run {GIT} {}: {e}", args.join(" ")))
    })
}

fn git_ok(args: &[&str], cwd: Option<&Path>, what: &str) -> io::Result<String> {
    let output = run_git(args, cwd)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(6).collect();
        return Err(err(format!(
            "{what} failed ({}): {}",
            output.status,
            tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Resolve a branch/tag/short ref to a full commit. Needs the network; used at
/// plan time so the commit can be recorded before anything is realized.
pub fn resolve_ref(url: &str, reference: &str) -> io::Result<String> {
    if is_full_commit(reference) {
        return Ok(reference.to_ascii_lowercase());
    }
    let url = normalize_url(url);
    let out = git_ok(
        &["ls-remote", &url, reference],
        None,
        &format!("git ls-remote {url} {reference}"),
    )?;
    let commit = out
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| err(format!("{url}: ref {reference} not found")))?;
    if !is_full_commit(commit) {
        return Err(err(format!("{url}: ref {reference} resolved to {commit:?}")));
    }
    Ok(commit.to_ascii_lowercase())
}

fn remove_git_dirs(root: &Path) -> io::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                if entry.file_name() == ".git" {
                    crate::store::remove_tree(&path)?;
                } else {
                    stack.push(path);
                }
            } else if entry.file_name() == ".git" {
                // A submodule's .git is a file pointing into the parent.
                std::fs::remove_file(&path)?;
            }
        }
    }
    Ok(())
}

/// Realize a git source in the store and return its object path.
pub fn ensure_git_source(store: &Store, source: &GitSource) -> io::Result<PathBuf> {
    if !is_full_commit(&source.commit) {
        return Err(err(format!(
            "{}: git sources must be pinned to a full commit, got {:?}",
            source.url, source.commit
        )));
    }
    let identity = identity(source);
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let work = store.stage()?;
    let result = (|| -> io::Result<()> {
        git_ok(&["init", "-q"], Some(&work), "git init")?;
        // A reachable-sha fetch is the cheap path; servers that refuse it
        // (uploadpack.allowReachableSHA1InWant off) need the full history.
        let shallow = run_git(
            &["fetch", "--depth", "1", "--quiet", &source.url, &source.commit],
            Some(&work),
        )?;
        if !shallow.status.success() {
            git_ok(
                &["fetch", "--quiet", "--tags", &source.url],
                Some(&work),
                &format!("git fetch {}", source.url),
            )?;
        }
        git_ok(
            &["checkout", "-q", "--detach", &source.commit],
            Some(&work),
            &format!("git checkout {}", source.commit),
        )?;
        let head = git_ok(&["rev-parse", "HEAD"], Some(&work), "git rev-parse HEAD")?;
        if head.to_ascii_lowercase() != source.commit.to_ascii_lowercase() {
            return Err(err(format!(
                "{}: checked out {head}, expected {}",
                source.url, source.commit
            )));
        }
        if work.join(".gitmodules").is_file() {
            git_ok(
                &["submodule", "update", "--init", "--recursive", "--depth", "1"],
                Some(&work),
                "git submodule update",
            )?;
        }
        remove_git_dirs(&work)
    })();
    if let Err(e) = result {
        let _ = crate::store::remove_tree(&work);
        return Err(e);
    }
    store.commit(&identity, &work, &[]).map(|(path, _)| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_normalize_to_one_spelling() {
        let expected = "https://github.com/owner/repo";
        for raw in [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo.git",
            "git+https://github.com/owner/repo.git",
            "https://token:x-oauth-basic@github.com/owner/repo.git",
            "https://github.com/owner/repo/",
            "git+https://github.com/owner/repo.git#deadbeef",
        ] {
            assert_eq!(normalize_url(raw), expected, "{raw}");
        }
        assert_eq!(
            normalize_url("git@github.com:owner/repo.git"),
            "ssh://github.com/owner/repo"
        );
        assert_eq!(
            normalize_url("git+ssh://git@github.com/owner/repo.git"),
            "ssh://github.com/owner/repo"
        );
        // A scheme-less repository (how npm lockfiles spell GitHub archives)
        // becomes an https URL git can actually fetch.
        assert_eq!(normalize_url("github.com/owner/repo"), expected);
    }

    #[test]
    fn commits_must_be_full_hashes() {
        assert!(is_full_commit(&"a".repeat(40)));
        assert!(!is_full_commit(&"a".repeat(39)));
        assert!(!is_full_commit("main"));
        assert!(!is_full_commit(&format!("{}z", "a".repeat(39))));
    }

    #[test]
    fn identity_commits_to_url_and_commit_only() {
        let base = GitSource {
            url: "https://github.com/owner/repo".into(),
            commit: "a".repeat(40),
            subdirectory: None,
        };
        // The subdirectory selects part of the tree; it does not change the
        // tree's bytes, so it must not change the object id.
        let with_subdir = GitSource { subdirectory: Some("packages/x".into()), ..base.clone() };
        assert_eq!(object_id(&base), object_id(&with_subdir));
        let other_commit = GitSource { commit: "b".repeat(40), ..base.clone() };
        assert_ne!(object_id(&base), object_id(&other_commit));
        let other_url = GitSource { url: "https://github.com/owner/other".into(), ..base.clone() };
        assert_ne!(object_id(&base), object_id(&other_url));
        assert!(object_id(&base).ends_with(&format!("-owner-repo-{}", "a".repeat(40))));
    }

    #[test]
    fn slugs_are_readable_and_safe() {
        assert_eq!(slug("https://github.com/owner/repo"), "owner-repo");
        assert_eq!(slug("ssh://github.com/owner/repo"), "owner-repo");
        assert_eq!(slug("https://example.com/a/b/c/d"), "c-d");
    }
}

#[cfg(test)]
mod realization_tests {
    use super::*;

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = crate::store::remove_tree(&self.0);
        }
    }
    fn temp(tag: &str) -> Temp {
        let path = std::env::temp_dir().join(format!(
            "blanket-gitsrc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Temp(path)
    }

    /// A local repository with one commit; `file://` keeps this offline.
    fn fixture_repo(root: &Path) -> (String, String) {
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_ok(&["init", "-q", "-b", "main"], Some(&repo), "init").unwrap();
        git_ok(&["config", "user.email", "t@example.invalid"], Some(&repo), "cfg").unwrap();
        git_ok(&["config", "user.name", "t"], Some(&repo), "cfg").unwrap();
        std::fs::write(repo.join("index.js"), "module.exports = 42;\n").unwrap();
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        std::fs::write(repo.join("sub/thing.txt"), "deep\n").unwrap();
        git_ok(&["add", "-A"], Some(&repo), "add").unwrap();
        git_ok(&["commit", "-qm", "one"], Some(&repo), "commit").unwrap();
        let commit = git_ok(&["rev-parse", "HEAD"], Some(&repo), "rev-parse").unwrap();
        (format!("file://{}", repo.display()), commit)
    }

    fn store_at(root: &Path) -> crate::store::Store {
        let store_root = root.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        crate::store::Store { root: store_root.canonicalize().unwrap() }
    }

    #[test]
    fn realizes_a_commit_and_strips_git_metadata() {
        let root = temp("realize");
        let (url, commit) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let source = GitSource { url: normalize_url(&url), commit: commit.clone(), subdirectory: None };
        let object = ensure_git_source(&store, &source).unwrap();
        assert_eq!(
            std::fs::read_to_string(object.join("index.js")).unwrap(),
            "module.exports = 42;\n"
        );
        assert_eq!(std::fs::read_to_string(object.join("sub/thing.txt")).unwrap(), "deep\n");
        assert!(!object.join(".git").exists(), "the .git directory must not be stored");
        // Second call is a cache hit on the same object.
        let again = ensure_git_source(&store, &source).unwrap();
        assert_eq!(object, again);
    }

    #[test]
    fn a_wrong_commit_is_refused() {
        let root = temp("wrong");
        let (url, _) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let source = GitSource {
            url: normalize_url(&url),
            commit: "0".repeat(40),
            subdirectory: None,
        };
        let error = ensure_git_source(&store, &source).unwrap_err().to_string();
        assert!(error.contains("fetch") || error.contains("checkout"), "{error}");
    }

    #[test]
    fn an_unpinned_ref_is_refused_and_resolve_ref_pins_it() {
        let root = temp("ref");
        let (url, commit) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let unpinned = GitSource {
            url: normalize_url(&url),
            commit: "main".into(),
            subdirectory: None,
        };
        let error = ensure_git_source(&store, &unpinned).unwrap_err().to_string();
        assert!(error.contains("full commit"), "{error}");
        assert_eq!(resolve_ref(&normalize_url(&url), "main").unwrap(), commit);
        assert_eq!(resolve_ref(&normalize_url(&url), &commit).unwrap(), commit);
    }
}
