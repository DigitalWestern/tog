//! Git sources realized by commit (NEXT.md item 4).
//!
//! A commit hash is a fingerprint, so a git dependency fits the store's model
//! exactly: the object's identity is the normalized repository URL plus the
//! commit, and its content is that tree with `.git` removed. Fetching needs
//! the network, so it happens at realization time like any other download —
//! never inside a build sandbox.

use crate::kernel::store::Store;
pub use crate::kernel::types::GitSource;
use crate::kernel::types::Identity;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const GIT: &str = "/usr/bin/git";

fn err(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

/// Schemes git may be asked to fetch. Anything else — or a value that could be
/// read as an option — is refused before it reaches the git command line,
/// because lockfile URLs are attacker-editable.
const ALLOWED_SCHEMES: &[&str] = &["https://", "ssh://", "git://", "file://"];

/// A name or version safe to use as a path component and an archive member.
pub fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with('-')
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-' || b == b'+')
}

/// Refuse a source git must not be handed: an unknown scheme, an
/// option-looking URL, or a malformed commit.
pub fn validate_source(source: &GitSource) -> io::Result<()> {
    if !is_full_commit(&source.commit) {
        return Err(err(format!(
            "{}: git sources must be pinned to a full commit, got {:?}",
            source.url, source.commit
        )));
    }
    if source.url.starts_with('-') || !ALLOWED_SCHEMES.iter().any(|s| source.url.starts_with(s)) {
        return Err(err(format!(
            "refusing git URL {:?}: expected one of {}",
            source.url,
            ALLOWED_SCHEMES.join(", ")
        )));
    }
    if let Some(subdirectory) = &source.subdirectory {
        if subdirectory.starts_with('/') || subdirectory.split(['/', '\\']).any(|part| part == "..")
        {
            return Err(err(format!(
                "refusing git subdirectory {subdirectory:?}: it escapes the checkout"
            )));
        }
    }
    Ok(())
}

pub fn is_full_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Normalize a repository URL without changing the transport username or
/// repository path. In particular, `@` in a path is not userinfo, `.git` may
/// be part of a local file URL, and `git@host` is meaningful to SSH.
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
            url = format!("ssh://{host}/{}", path.trim_start_matches('/'));
        }
    } else if let Some((scheme, rest)) = url.split_once("://") {
        // Userinfo belongs to the authority, which ends at the first slash.
        // Looking for `@` in the complete remainder incorrectly rewrites a
        // valid path such as `/mirror@other/repo`.
        let authority_end = rest
            .find(|character| character == '/' || character == '?')
            .unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let path = &rest[authority_end..];
        let authority = if scheme.eq_ignore_ascii_case("ssh") {
            authority
        } else {
            authority
                .rsplit_once('@')
                .map(|(_, host)| host)
                .unwrap_or(authority)
        };
        url = format!("{scheme}://{authority}{path}");
    }
    // Lockfile spellings like `github.com/owner/repo` name a host but no
    // protocol; git needs one, and https is what every registry lock means.
    if url.contains("://") {
        url
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
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "repo".to_string()
    } else {
        cleaned
    }
}

fn identity(source: &GitSource) -> Identity {
    Identity {
        kind: "git-source".into(),
        name: slug(&source.url),
        version: source.commit.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "git-source/2".to_string()),
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
    configure_git(&mut command, args, cwd);
    command
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("run {GIT} {}: {e}", args.join(" "))))
}

fn configure_git(command: &mut Command, args: &[&str], cwd: Option<&Path>) {
    let ssh_auth_sock = std::env::var_os("SSH_AUTH_SOCK");
    // Git reads a surprisingly large ambient surface: global/system config,
    // helper commands, hooks, filters, alternate object stores, and worktree
    // overrides. A source commit's fingerprint must describe the raw tree,
    // not this process's environment.
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin");
    command.env("HOME", "/nonexistent");
    command.env("XDG_CONFIG_HOME", "/nonexistent");
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    command.env("GIT_CONFIG_SYSTEM", "/dev/null");
    if let Some(sock) = ssh_auth_sock {
        // Agent authentication is transport state, not Git configuration.
        command.env("SSH_AUTH_SOCK", sock);
    }
    command.args(args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    // A prompt would hang a background sync forever.
    command.env("GIT_TERMINAL_PROMPT", "0");
    command.env("GIT_ASKPASS", "/bin/true");
}

fn run_git_with_activity(
    args: &[&str],
    cwd: Option<&Path>,
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<std::process::Output> {
    let mut command = Command::new(GIT);
    configure_git(&mut command, args, cwd);
    crate::kernel::supervise::output(&mut command, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run {GIT} {}: {e}", args.join(" "))))
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

fn git_ok_with_activity(
    args: &[&str],
    cwd: Option<&Path>,
    what: &str,
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<String> {
    let output = run_git_with_activity(args, cwd, activity)?;
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
    if url.starts_with('-') || !ALLOWED_SCHEMES.iter().any(|s| url.starts_with(s)) {
        return Err(err(format!("refusing git URL {url:?}")));
    }
    if reference.starts_with('-') || reference.contains(char::is_whitespace) {
        return Err(err(format!("refusing git ref {reference:?}")));
    }
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
        return Err(err(format!(
            "{url}: ref {reference} resolved to {commit:?}"
        )));
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
                if entry.file_name() == ".git" {
                    fs::remove_file(path)?;
                }
                continue;
            }
            if file_type.is_dir() {
                if entry.file_name() == ".git" {
                    crate::kernel::store::remove_tree(&path)?;
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

/// Verify that symlinks in a checkout can only resolve within that checkout.
/// `canonicalize` alone is insufficient because a deliberately broken link is
/// valid source content; resolve existing path components while retaining the
/// lexical containment check for missing targets.
pub(crate) fn validate_symlinks(root: &Path) -> io::Result<()> {
    let root = root.canonicalize()?;
    let mut links = Vec::new();
    collect_symlinks(&root, &mut links)?;
    for link in links {
        resolve_symlink_path(&root, &link, &mut std::collections::BTreeSet::new())?;
    }
    Ok(())
}

fn collect_symlinks(root: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            out.push(path);
        } else if file_type.is_dir() {
            collect_symlinks(&path, out)?;
        }
    }
    Ok(())
}

fn resolve_symlink_path(
    root: &Path,
    link: &Path,
    seen: &mut std::collections::BTreeSet<PathBuf>,
) -> io::Result<()> {
    if !seen.insert(link.to_path_buf()) {
        // Reject cycles conservatively: they are not useful source content
        // and make containment dependent on filesystem traversal behavior.
        return Err(err(format!("symlink cycle involving {}", link.display())));
    }
    let target = fs::read_link(link)?;
    let parent = link.parent().ok_or_else(|| err("symlink has no parent"))?;
    resolve_target_components(root, parent, &target, seen).map(|_| ())
}

/// Resolve path components in kernel order. We must process a symlink before
/// applying a later `..`: `link-to-dot/../outside` escapes even though a
/// purely lexical normalization would incorrectly keep it under `root`.
fn resolve_target_components(
    root: &Path,
    base: &Path,
    target: &Path,
    seen: &mut std::collections::BTreeSet<PathBuf>,
) -> io::Result<PathBuf> {
    if target.is_absolute() {
        return Err(err("symlink target has an absolute path"));
    }
    let mut current = base.to_path_buf();
    if !current.starts_with(root) {
        return Err(err("symlink target escaped the checkout"));
    }
    for component in target.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if current == root || !current.pop() || !current.starts_with(root) {
                    return Err(err("symlink target escaped the checkout"));
                }
            }
            std::path::Component::Normal(part) => {
                let candidate = current.join(part);
                let is_symlink = match fs::symlink_metadata(&candidate) {
                    Ok(metadata) => metadata.file_type().is_symlink(),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(error) => return Err(error),
                };
                if is_symlink {
                    let nested = fs::read_link(&candidate)?;
                    if !seen.insert(candidate.clone()) {
                        return Err(err(format!(
                            "symlink cycle involving {}",
                            candidate.display()
                        )));
                    }
                    current = resolve_target_components(
                        root,
                        candidate
                            .parent()
                            .ok_or_else(|| err("symlink has no parent"))?,
                        &nested,
                        seen,
                    )?;
                } else {
                    current = candidate;
                }
                if !current.starts_with(root) {
                    return Err(err("symlink target escaped the checkout"));
                }
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(err("symlink target has an absolute path"));
            }
        }
    }
    Ok(current)
}

fn validate_checkout_tree_with_activity(
    root: &Path,
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<()> {
    validate_checkout_tree_at_with_activity(root, 0, activity)
}

fn validate_checkout_tree_at_with_activity(
    root: &Path,
    depth: usize,
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<()> {
    if depth > 32 {
        return Err(err("git submodule nesting exceeds 32 levels"));
    }
    use std::os::unix::ffi::OsStringExt;
    let output = run_git_with_activity(&["ls-files", "-s", "-z"], Some(root), activity)?;
    if !output.status.success() {
        return Err(err("git ls-files failed while validating the checkout"));
    }
    for record in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| err("malformed git index entry"))?;
        let metadata =
            std::str::from_utf8(&record[..tab]).map_err(|_| err("git index entry is not UTF-8"))?;
        let mut fields = metadata.split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| err("git index entry has no mode"))?;
        let expected = fields
            .next()
            .ok_or_else(|| err("git index entry has no hash"))?;
        let path = std::ffi::OsString::from_vec(record[tab + 1..].to_vec());
        let path = root.join(path);
        if mode == "160000" {
            let path_text = path
                .to_str()
                .ok_or_else(|| err("git submodule path is not UTF-8"))?;
            let actual = git_ok_with_activity(
                &["-C", path_text, "rev-parse", "HEAD"],
                Some(root),
                "git submodule rev-parse",
                activity,
            )?;
            if actual.to_ascii_lowercase() != expected {
                return Err(err(format!(
                    "git submodule {} checked out {actual}, expected {expected}",
                    path.display()
                )));
            }
            validate_checkout_tree_at_with_activity(&path, depth + 1, activity)?;
            continue;
        }
        let bytes = if mode == "120000" {
            fs::read_link(&path)?.into_os_string().into_vec()
        } else {
            fs::read(&path)?
        };
        let header = format!("blob {}\0", bytes.len());
        let mut hasher = sha1::Sha1::new();
        use sha1::Digest;
        hasher.update(header.as_bytes());
        hasher.update(&bytes);
        let actual = hex::encode(hasher.finalize());
        if actual != expected {
            return Err(err(format!(
                "git checkout transformed {}; raw blob {expected}, got {actual}",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Realize a git source in the store and return its object path.
pub fn ensure_git_source(store: &Store, source: &GitSource) -> io::Result<PathBuf> {
    validate_source(source)?;
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let identity = identity(source);
    let id = identity.object_id();
    if store.has_with_activity(&activity, &id)? {
        crate::kernel::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let work = store.stage_with_activity(&activity)?;
    let result = (|| -> io::Result<()> {
        git_ok_with_activity(
            &["init", "-q", "--template="],
            Some(&work),
            "git init",
            &activity,
        )?;
        // Besides naming the fetched repository, origin is what Git uses to
        // resolve relative URLs in .gitmodules. Without it, a submodule such
        // as `../shared.git` is resolved against the temporary worktree.
        git_ok_with_activity(
            &["remote", "add", "origin", &source.url],
            Some(&work),
            "git remote add origin",
            &activity,
        )?;
        // A reachable-sha fetch is the cheap path; servers that refuse it
        // (uploadpack.allowReachableSHA1InWant off) need the full history.
        let shallow = run_git_with_activity(
            &[
                "fetch",
                "--depth",
                "1",
                "--quiet",
                &source.url,
                &source.commit,
            ],
            Some(&work),
            &activity,
        )?;
        if !shallow.status.success() {
            git_ok_with_activity(
                &[
                    "fetch",
                    "--quiet",
                    "--tags",
                    &source.url,
                    "+refs/heads/*:refs/remotes/origin/*",
                ],
                Some(&work),
                &format!("git fetch {}", source.url),
                &activity,
            )?;
        }
        git_ok_with_activity(
            &["checkout", "-q", "--detach", &source.commit],
            Some(&work),
            &format!("git checkout {}", source.commit),
            &activity,
        )?;
        let head = git_ok_with_activity(
            &["rev-parse", "HEAD"],
            Some(&work),
            "git rev-parse HEAD",
            &activity,
        )?;
        if head.to_ascii_lowercase() != source.commit.to_ascii_lowercase() {
            return Err(err(format!(
                "{}: checked out {head}, expected {}",
                source.url, source.commit
            )));
        }
        if work.join(".gitmodules").is_file() {
            let submodule_args: &[&str] = if source.url.starts_with("file://") {
                // Git rejects the file transport for submodules by default.
                // A file:// source was explicitly selected by the lockfile,
                // so permit its relative submodules while keeping the safer
                // default for network repositories.
                &[
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                    "--depth",
                    "1",
                ]
            } else {
                &[
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                    "--depth",
                    "1",
                ]
            };
            git_ok_with_activity(
                submodule_args,
                Some(&work),
                "git submodule update",
                &activity,
            )?;
        }
        validate_checkout_tree_with_activity(&work, &activity)?;
        remove_git_dirs(&work)?;
        validate_symlinks(&work)
    })();
    if let Err(e) = result {
        let _ = crate::kernel::store::remove_tree(&work);
        return Err(e);
    }
    store
        .commit_with_activity_and_deps(
            &activity,
            &identity,
            &work,
            &[],
            &crate::kernel::store::ObjectDeps::new(),
        )
        .map(|(path, _)| path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_normalize_to_one_spelling() {
        let expected = "https://github.com/owner/repo";
        for raw in [
            "https://github.com/owner/repo",
            "git+https://github.com/owner/repo#deadbeef",
            "https://token:x-oauth-basic@github.com/owner/repo",
        ] {
            assert_eq!(normalize_url(raw), expected, "{raw}");
        }
        assert_eq!(
            normalize_url("git@github.com:owner/repo.git"),
            "ssh://git@github.com/owner/repo.git"
        );
        assert_eq!(
            normalize_url("git+ssh://git@github.com/owner/repo.git"),
            "ssh://git@github.com/owner/repo.git"
        );
        assert_eq!(
            normalize_url("https://github.com/mirror@other/repo.git"),
            "https://github.com/mirror@other/repo.git"
        );
        // A scheme-less repository (how npm lockfiles spell GitHub archives)
        // becomes an https URL git can actually fetch.
        assert_eq!(normalize_url("github.com/owner/repo"), expected);
        // `.git` is a meaningful path for local repositories and must not be
        // stripped into a nonexistent sibling.
        assert_eq!(
            normalize_url("file:///tmp/repo.git"),
            "file:///tmp/repo.git"
        );
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
        let with_subdir = GitSource {
            subdirectory: Some("packages/x".into()),
            ..base.clone()
        };
        assert_eq!(object_id(&base), object_id(&with_subdir));
        let other_commit = GitSource {
            commit: "b".repeat(40),
            ..base.clone()
        };
        assert_ne!(object_id(&base), object_id(&other_commit));
        let other_url = GitSource {
            url: "https://github.com/owner/other".into(),
            ..base.clone()
        };
        assert_ne!(object_id(&base), object_id(&other_url));
        assert!(object_id(&base).ends_with(&format!("-owner-repo-{}", "a".repeat(40))));
    }

    #[test]
    fn slugs_are_readable_and_safe() {
        assert_eq!(slug("https://github.com/owner/repo"), "owner-repo");
        assert_eq!(slug("ssh://github.com/owner/repo"), "owner-repo");
        assert_eq!(slug("https://example.com/a/b/c/d"), "c-d");
    }

    #[test]
    fn symlinks_must_stay_inside_checkout_even_through_chains() {
        let root = std::env::temp_dir().join(format!(
            "blanket-gitsrc-links-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("safe.txt"), b"safe").unwrap();
        std::os::unix::fs::symlink("safe.txt", root.join("safe-link")).unwrap();
        validate_symlinks(&root).unwrap();
        std::os::unix::fs::symlink("../outside", root.join("escape")).unwrap();
        assert!(validate_symlinks(&root).is_err());
        fs::remove_file(root.join("escape")).unwrap();
        std::os::unix::fs::symlink(".", root.join("a")).unwrap();
        std::os::unix::fs::symlink("a/../outside", root.join("escape-via-dot")).unwrap();
        assert!(validate_symlinks(&root).is_err());
        fs::remove_file(root.join("a")).unwrap();
        fs::remove_file(root.join("escape-via-dot")).unwrap();
        std::os::unix::fs::symlink("chain-end", root.join("chain-start")).unwrap();
        std::os::unix::fs::symlink("../../outside", root.join("chain-end")).unwrap();
        assert!(validate_symlinks(&root).is_err());
        let _ = crate::kernel::store::remove_tree(&root);
    }
}

#[cfg(test)]
mod realization_tests {
    use super::*;

    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = crate::kernel::store::remove_tree(&self.0);
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
        git_ok(
            &["config", "user.email", "t@example.invalid"],
            Some(&repo),
            "cfg",
        )
        .unwrap();
        git_ok(&["config", "user.name", "t"], Some(&repo), "cfg").unwrap();
        std::fs::write(repo.join("index.js"), "module.exports = 42;\n").unwrap();
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        std::fs::write(repo.join("sub/thing.txt"), "deep\n").unwrap();
        git_ok(&["add", "-A"], Some(&repo), "add").unwrap();
        git_ok(&["commit", "-qm", "one"], Some(&repo), "commit").unwrap();
        let commit = git_ok(&["rev-parse", "HEAD"], Some(&repo), "rev-parse").unwrap();
        (format!("file://{}", repo.display()), commit)
    }

    fn store_at(root: &Path) -> crate::kernel::store::Store {
        let store_root = root.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        crate::kernel::store::Store {
            root: store_root.canonicalize().unwrap(),
        }
    }

    #[test]
    fn realizes_a_commit_and_strips_git_metadata() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = temp("realize");
        let (url, commit) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let source = GitSource {
            url: normalize_url(&url),
            commit: commit.clone(),
            subdirectory: None,
        };
        let object = ensure_git_source(&store, &source).unwrap();
        assert_eq!(
            std::fs::read_to_string(object.join("index.js")).unwrap(),
            "module.exports = 42;\n"
        );
        assert_eq!(
            std::fs::read_to_string(object.join("sub/thing.txt")).unwrap(),
            "deep\n"
        );
        assert!(
            !object.join(".git").exists(),
            "the .git directory must not be stored"
        );
        // Second call is a cache hit on the same object.
        let again = ensure_git_source(&store, &source).unwrap();
        assert_eq!(object, again);
    }

    #[test]
    fn a_wrong_commit_is_refused() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = temp("wrong");
        let (url, _) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let source = GitSource {
            url: normalize_url(&url),
            commit: "0".repeat(40),
            subdirectory: None,
        };
        let error = ensure_git_source(&store, &source).unwrap_err().to_string();
        assert!(
            error.contains("fetch") || error.contains("checkout"),
            "{error}"
        );
    }

    #[test]
    fn an_unpinned_ref_is_refused_and_resolve_ref_pins_it() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = temp("ref");
        let (url, commit) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let unpinned = GitSource {
            url: normalize_url(&url),
            commit: "main".into(),
            subdirectory: None,
        };
        let error = ensure_git_source(&store, &unpinned)
            .unwrap_err()
            .to_string();
        assert!(error.contains("full commit"), "{error}");
        assert_eq!(resolve_ref(&normalize_url(&url), "main").unwrap(), commit);
        assert_eq!(resolve_ref(&normalize_url(&url), &commit).unwrap(), commit);
    }

    #[test]
    fn checkout_rejects_attribute_transformed_content() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = temp("attributes");
        let repo = root.0.join("repo");
        fs::create_dir_all(&repo).unwrap();
        git_ok(&["init", "-q", "-b", "main"], Some(&repo), "init").unwrap();
        git_ok(
            &["config", "user.email", "t@example.invalid"],
            Some(&repo),
            "cfg",
        )
        .unwrap();
        git_ok(&["config", "user.name", "t"], Some(&repo), "cfg").unwrap();
        fs::write(repo.join(".gitattributes"), b"*.txt text eol=crlf\n").unwrap();
        fs::write(repo.join("line.txt"), b"line\n").unwrap();
        git_ok(&["add", "-A"], Some(&repo), "add").unwrap();
        git_ok(&["commit", "-qm", "attrs"], Some(&repo), "commit").unwrap();
        let commit = git_ok(&["rev-parse", "HEAD"], Some(&repo), "rev-parse").unwrap();
        let source = GitSource {
            url: normalize_url(&format!("file://{}", repo.display())),
            commit,
            subdirectory: None,
        };
        let error = ensure_git_source(&store_at(&root.0), &source)
            .unwrap_err()
            .to_string();
        assert!(error.contains("transformed"), "{error}");
    }

    #[test]
    fn pack_keeps_safe_links_empty_dirs_and_verbatim_names() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let root = temp("pack");
        let checkout = root.0.join("checkout");
        fs::create_dir_all(checkout.join("empty")).unwrap();
        fs::write(checkout.join("line\nname"), b"content\n").unwrap();
        std::os::unix::fs::symlink("line\nname", checkout.join("safe-link")).unwrap();
        let store = store_at(&root.0);
        let platform = crate::kernel::platform::Platform::host().unwrap();
        let (hash, filename) = pack_checkout(&store, platform, &checkout, "pkg", "1.0").unwrap();
        let archive = store.cache_path("sha256", &hash);
        let unpacked = root.0.join("unpacked");
        fs::create_dir_all(&unpacked).unwrap();
        let extracted = Command::new("/usr/bin/tar")
            .args(["-xzf"])
            .arg(&archive)
            .arg("-C")
            .arg(&unpacked)
            .output()
            .unwrap();
        assert!(
            extracted.status.success(),
            "{}",
            String::from_utf8_lossy(&extracted.stderr)
        );
        assert!(unpacked.join("pkg-1.0/empty").is_dir());
        assert!(unpacked.join("pkg-1.0/safe-link").is_symlink());
        assert_eq!(
            fs::read_to_string(unpacked.join("pkg-1.0/line\nname")).unwrap(),
            "content\n"
        );
        assert_eq!(filename, "pkg-1.0.tar.gz");

        // Recreate the same tree in a different directory-entry order. The
        // archive bytes must remain identical after metadata normalization.
        let checkout_two = root.0.join("checkout-two");
        fs::create_dir_all(checkout_two.join("empty")).unwrap();
        std::os::unix::fs::symlink("line\nname", checkout_two.join("safe-link")).unwrap();
        fs::write(checkout_two.join("line\nname"), b"content\n").unwrap();
        let (same_hash, _) = pack_checkout(&store, platform, &checkout_two, "pkg", "1.0").unwrap();
        assert_eq!(hash, same_hash);
    }

    /// Boundaries of the ustar name/prefix split. Verified against bsdtar by
    /// packing each shape and counting surviving entries; GNU tar agrees.
    /// Over-rejecting here would refuse trees that pack fine today, so both
    /// directions matter.
    #[test]
    fn ustar_fits_matches_the_header_layout() {
        let seg = |n: usize| "a".repeat(n);
        let fits = |path: String, is_dir: bool| ustar_fits(path.as_bytes(), is_dir);

        assert!(fits(seg(100), false));
        assert!(!fits(seg(101), false));
        // A directory spends one name byte on its trailing slash.
        assert!(fits(seg(99), true));
        assert!(!fits(seg(100), true));
        // Splitting needs a separator at or before byte 155, leaving <= 100.
        assert!(fits(format!("{}/{}", seg(155), seg(100)), false));
        assert!(!fits(format!("{}/{}", seg(156), seg(100)), false));
        assert!(!fits(format!("{}/{}", seg(155), seg(101)), false));
        assert!(fits(format!("{}/{}/{}", seg(60), seg(94), seg(100)), false));
        assert!(!fits(
            format!("{}/{}/{}", seg(60), seg(95), seg(100)),
            false
        ));
        // No separator to split on, however long.
        assert!(!fits(seg(200), false));
    }

    #[test]
    fn pack_rejects_paths_and_links_that_no_ustar_header_can_hold() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let platform = crate::kernel::platform::Platform::host().unwrap();

        // bsdtar drops an overlong path and still exits 0, so relying on the
        // subprocess would cache a truncated archive here instead of failing.
        let root = temp("pack-failure");
        let checkout = root.0.join("checkout");
        let long_dir = "d".repeat(119);
        fs::create_dir_all(checkout.join(&long_dir)).unwrap();
        fs::write(checkout.join(&long_dir).join("f".repeat(119)), b"too long").unwrap();
        let error = pack_checkout(&store_at(&root.0), platform, &checkout, "pkg", "1.0")
            .expect_err("ustar path overflow must fail packing")
            .to_string();
        assert!(error.contains("packing"), "{error}");

        // The linkname field is 100 bytes with no prefix to spill into.
        let link_root = temp("pack-link-failure");
        let link_checkout = link_root.0.join("checkout");
        fs::create_dir_all(&link_checkout).unwrap();
        fs::write(link_checkout.join("target"), b"content\n").unwrap();
        std::os::unix::fs::symlink("x".repeat(101), link_checkout.join("link")).unwrap();
        let error = pack_checkout(
            &store_at(&link_root.0),
            platform,
            &link_checkout,
            "pkg",
            "1.0",
        )
        .expect_err("overlong symlink target must fail packing")
        .to_string();
        assert!(error.contains("packing"), "{error}");
    }
}

struct StageGuard(PathBuf);

impl Drop for StageGuard {
    fn drop(&mut self) {
        let _ = crate::kernel::store::remove_tree(&self.0);
    }
}

/// Pack a realized checkout into a deterministic `.tar.gz` and insert it into
/// the artifact cache, returning (sha256, filename).
///
/// Everything downstream of this — build-system inspection, isolated build
/// environments, derivation identity — is the ordinary sdist path, so a git
/// dependency needs no parallel machinery. The archive is reproducible (sorted
/// names, fixed mtime/owner/mode), so the same commit always yields the same
/// hash, and that hash is what the wheel's identity commits to.
pub fn pack_checkout(
    store: &Store,
    platform: crate::kernel::platform::Platform,
    source_root: &Path,
    name: &str,
    version: &str,
) -> io::Result<(String, String)> {
    if !is_safe_component(name) || !is_safe_component(version) {
        return Err(err(format!(
            "refusing to pack {name:?}-{version:?}: names and versions must be [A-Za-z0-9._+-]"
        )));
    }
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let work = store.stage_with_activity(&activity)?;
    let _cleanup = StageGuard(work.clone());
    let prefix = format!("{name}-{version}");
    let filename = format!("{prefix}.tar.gz");
    // Copy under the final prefix directory so the archive needs no name
    // rewriting: --transform/-s differ between GNU tar and bsdtar, and both
    // would take a rewrite expression built from these strings.
    let staged = work.join(&prefix);
    crate::comforter::clone_tree_for_store(store, source_root, &staged, platform)?;
    validate_symlinks(&staged)?;
    normalize_for_packing(&staged)?;

    // Determinism, portably: an explicit sorted null-delimited list (GNU tar
    // and bsdtar both accept --null; GNU additionally spells out verbatim
    // handling), the ustar header format, zeroed mtimes and owners, and gzip
    // -n so the container
    // carries no timestamp either. Null + verbatim is required for names
    // containing newlines, backslashes, or a leading dash.
    let mut files = Vec::new();
    collect_paths(&staged, &work, &mut files)?;
    files.sort_by(|a, b| {
        use std::os::unix::ffi::OsStrExt;
        a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes())
    });
    let list = work.join(".blanket-filelist");
    {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        let mut bytes = Vec::new();
        for file in &files {
            let path = file.as_os_str().as_bytes();
            let meta = fs::symlink_metadata(work.join(file))?;
            if !ustar_fits(path, meta.is_dir()) {
                return Err(err(format!(
                    "packing {} failed: {} is too long for a ustar header",
                    source_root.display(),
                    file.display()
                )));
            }
            if meta.is_symlink() && fs::read_link(work.join(file))?.as_os_str().len() > 100 {
                return Err(err(format!(
                    "packing {} failed: symlink target of {} is too long for a ustar header",
                    source_root.display(),
                    file.display()
                )));
            }
            bytes.extend_from_slice(path);
            bytes.push(0);
        }
        fs::File::create(&list)?.write_all(&bytes)?;
    }

    let archive = work.join(&filename);
    let uncompressed = work.join(format!("{prefix}.tar"));
    let owner_flags: &[&str] = if platform.is_macos() {
        // bsdtar
        &["--uid", "0", "--gid", "0", "--numeric-owner"]
    } else {
        // GNU tar
        &["--owner=0", "--group=0", "--numeric-owner"]
    };
    let list_flags: &[&str] = if platform.is_macos() {
        // bsdtar treats --null input as verbatim; it has no GNU
        // --verbatim-files-from option.
        &["--null"]
    } else {
        &["--null", "--verbatim-files-from"]
    };
    let mut tar = Command::new("/usr/bin/tar");
    tar.args(["-cf"])
        .arg(&uncompressed)
        .args(["--format=ustar", "--no-recursion"])
        .args(owner_flags)
        .args(list_flags)
        .arg("-C")
        .arg(&work)
        .arg("-T")
        .arg(&list);
    let tar_status = crate::kernel::supervise::status(&mut tar, &activity)?;
    if !tar_status.success() {
        let _ = fs::remove_file(&uncompressed);
        return Err(err(format!(
            "packing {} failed (tar {tar_status})",
            source_root.display()
        )));
    }
    let mut gzip = Command::new("/usr/bin/gzip");
    gzip.args(["-n", "-9", "-c"])
        .arg(&uncompressed)
        .stdout(fs::File::create(&archive)?);
    let gzip_status = crate::kernel::supervise::status(&mut gzip, &activity)?;
    let _ = fs::remove_file(&uncompressed);
    if !gzip_status.success() {
        return Err(err(format!(
            "packing {} failed (tar {}, gzip {})",
            source_root.display(),
            tar_status,
            gzip_status,
        )));
    }
    let (sha256, _) = crate::kernel::fetch::cache_insert(store, &archive)?;
    Ok((sha256, filename))
}

/// Give every non-symlink entry a fixed mode and set all tree-entry mtimes to
/// the epoch without following symlinks.
fn normalize_for_packing(root: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let epoch = std::time::SystemTime::UNIX_EPOCH;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                stack.push(path);
                continue;
            }
            let executable = fs::metadata(&path)?.permissions().mode() & 0o111 != 0;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
            )?;
            fs::File::options()
                .write(true)
                .open(&path)?
                .set_modified(epoch)?;
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    let mut entries = Vec::new();
    collect_paths(root, root, &mut entries)?;
    for relative in entries {
        set_mtime_epoch(&root.join(relative))?;
    }
    Ok(())
}

fn set_mtime_epoch(path: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| err(format!("path contains NUL: {}", path.display())))?;
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    ];
    let result = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Can a ustar header hold this path? Name field is 100 bytes, prefix 155,
/// joined by a `/`, so the split has to land on a separator; directories carry
/// a trailing `/` that counts against the name field.
///
/// We decide this ourselves instead of reading tar's exit code because the two
/// tars disagree: GNU tar fails the run, while bsdtar prints "Pathname too
/// long", *skips the entry*, and still exits 0. Trusting the subprocess would
/// let macOS cache a silently truncated archive under a hash claiming to be
/// the whole tree.
fn ustar_fits(path: &[u8], is_dir: bool) -> bool {
    let len = path.len() + usize::from(is_dir);
    len <= 100 || (1..path.len().min(156)).any(|i| path[i] == b'/' && len - i - 1 <= 100)
}

/// Every tree entry under `root`, including directories and symlinks, as a
/// path relative to `base`.
fn collect_paths(root: &Path, base: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let relative = root
        .strip_prefix(base)
        .map_err(|_| err("packed path escaped the staging directory"))?;
    out.push(relative.to_path_buf());
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_paths(&path, base, out)?;
        } else if file_type.is_file() || file_type.is_symlink() {
            let relative = path
                .strip_prefix(base)
                .map_err(|_| err("packed path escaped the staging directory"))?;
            out.push(relative.to_path_buf());
        }
    }
    Ok(())
}
