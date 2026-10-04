//! Git sources realized by commit.
//!
//! A commit hash is a fingerprint, so a git dependency fits the store's model
//! exactly: the object's identity is the normalized repository URL plus the
//! commit, and its content is that tree with `.git` removed. Fetching needs
//! the network, so it happens at realization time like any other download —
//! never inside a build sandbox.

use crate::kernel::activity::StoreActivity;
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

/// Does the host, or the user before it, start with a dash? Git hands the
/// authority of an `ssh://` URL to ssh as its host and login, and an
/// option-looking one is handed to it before git's own guard would run.
/// `normalize_url` turns `-oProxyCommand=x:repo` into
/// `ssh://-oProxyCommand=x/repo`, so a leading dash has to be caught on the
/// authority, not only on the whole URL.
fn option_looking_authority(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    // Git percent-decodes the authority and takes an IPv6 host out of its
    // brackets before handing it on, so the check looks at what ssh would
    // see: `%2Dhost` and `[-host]` are `-host`.
    let authority = percent_decode(&rest[..rest.find(['/', '?']).unwrap_or(rest.len())]);
    // One bracket layer comes off, and only when it closes, as git takes
    // it off: `[-host` and `[[-host]]` reach ssh with a `[` in front.
    let leads_with_dash = |part: &str| {
        part.strip_prefix('[')
            .filter(|_| part.contains(']'))
            .unwrap_or(part)
            .starts_with('-')
    };
    leads_with_dash(&authority)
        || authority
            .rsplit_once('@')
            .is_some_and(|(_, host)| leads_with_dash(host))
}

/// `%XX` escapes decoded, everything else as it was. A malformed escape is
/// kept literally, as git keeps it.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let escape = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(value) = escape.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                out.push(value);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Refuse a source git must not be handed: an unknown scheme, an
/// option-looking URL or host, or a malformed commit.
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
    if option_looking_authority(&source.url) {
        return Err(err(format!(
            "refusing git URL {:?}: the host looks like an option",
            source.url
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
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
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

#[cfg(test)]
pub(crate) fn live_identity_for_test() -> Identity {
    identity(&GitSource {
        url: "https://example.invalid/repo.git".into(),
        commit: "a".repeat(40),
        subdirectory: None,
    })
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
        crate::kernel::fsroot::start_in(command, cwd);
    }
    // A prompt would hang a background sync forever.
    command.env("GIT_TERMINAL_PROMPT", "0");
    command.env("GIT_ASKPASS", "/bin/true");
}

// Reviewed site (tests/architecture.rs): tog's own git fetch: tog verifies what it brings back, so it is not a resolution door, and it needs the network, so it is no host-local helper either.
#[allow(clippy::disallowed_methods)]
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

/// Which of `paths` (relative to `dir`) hold at least one file git tracks
/// in the repository around `dir`. Outside a repository, or on a host
/// without git, none do: the only question is whether moving a directory
/// away would delete committed source.
pub fn tracked_among(
    dir: &Path,
    paths: &[String],
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<Vec<String>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    // Literal pathspecs: a workspace path is a name, never a glob. The
    // repository's own fsmonitor hook is not run for a read of the index.
    let mut args = vec![
        "--literal-pathspecs",
        "-c",
        "core.fsmonitor=false",
        "ls-files",
        "-z",
        "--",
    ];
    args.extend(paths.iter().map(String::as_str));
    let output = match run_git_with_activity(&args, Some(dir), activity) {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if !output.status.success() {
        return Ok(Vec::new());
    }
    use std::os::unix::ffi::OsStrExt;
    let listed: Vec<&Path> = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|file| !file.is_empty())
        .map(|file| Path::new(std::ffi::OsStr::from_bytes(file)))
        .collect();
    Ok(paths
        .iter()
        .filter(|path| listed.iter().any(|file| file.starts_with(path)))
        .cloned()
        .collect())
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

/// How many link expansions one link's resolution may take. The cycle set
/// only holds the chain being expanded, so an acyclic web of links could
/// otherwise double the work at every level; a few dozen links would stall
/// the walk. Real source trees resolve in a handful.
const MAX_LINK_EXPANSIONS: u32 = 64;

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
    let mut expansions = 0;
    resolve_target_components(root, parent, &target, seen, &mut expansions).map(|_| ())
}

/// Resolve path components in kernel order. We must process a symlink before
/// applying a later `..`: `link-to-dot/../outside` escapes even though a
/// purely lexical normalization would incorrectly keep it under `root`.
fn resolve_target_components(
    root: &Path,
    base: &Path,
    target: &Path,
    seen: &mut std::collections::BTreeSet<PathBuf>,
    expansions: &mut u32,
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
                    *expansions += 1;
                    if *expansions > MAX_LINK_EXPANSIONS {
                        return Err(err(format!(
                            "symlink chain too long involving {}",
                            candidate.display()
                        )));
                    }
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
                        expansions,
                    )?;
                    // `seen` is the chain being expanded, not every link
                    // ever visited: a target that passes through the same
                    // link twice on its way (`alias/../../alias/file`) is
                    // not a cycle, so the link leaves the set once its
                    // expansion is complete.
                    seen.remove(&candidate);
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

#[cfg(test)]
thread_local! {
    /// Treat the by-sha fetch as refused so tests reach the all-refs
    /// fallback. Local transports accept any sha, so no server config can.
    static REFUSE_SHA_FETCH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Realize a git source in the store and return its object path.
pub fn ensure_git_source(
    store: &Store,
    activity: &StoreActivity,
    source: &GitSource,
) -> io::Result<PathBuf> {
    validate_source(source)?;
    let identity = identity(source);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        return Ok(store.object_path(&id));
    }

    let work = store.stage_with_activity(activity)?;
    let result = (|| -> io::Result<()> {
        git_ok_with_activity(
            &["init", "-q", "--template="],
            Some(&work),
            "git init",
            activity,
        )?;
        // Besides naming the fetched repository, origin is what Git uses to
        // resolve relative URLs in .gitmodules. Without it, a submodule such
        // as `../shared.git` is resolved against the temporary worktree.
        git_ok_with_activity(
            &["remote", "add", "origin", &source.url],
            Some(&work),
            "git remote add origin",
            activity,
        )?;
        // Asking for the pinned commit by sha is the cheap path, and it works
        // whichever branch (if any) the commit sits on. Servers that refuse
        // sha wants (uploadpack.allowReachableSHA1InWant off) need the full
        // history of every ref they advertise, not only branches and tags.
        let fetch_by_sha = || -> io::Result<bool> {
            let output = run_git_with_activity(
                &[
                    "fetch",
                    "--depth",
                    "1",
                    "--quiet",
                    &source.url,
                    &source.commit,
                ],
                Some(&work),
                activity,
            )?;
            Ok(output.status.success())
        };
        #[cfg(test)]
        let refused = REFUSE_SHA_FETCH.with(|refuse| refuse.get()) || !fetch_by_sha()?;
        #[cfg(not(test))]
        let refused = !fetch_by_sha()?;
        if refused {
            git_ok_with_activity(
                &[
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    &source.url,
                    "+refs/*:refs/fetched/*",
                ],
                Some(&work),
                &format!("git fetch {}", source.url),
                activity,
            )?;
        }
        // Name a missing commit plainly. Otherwise checkout reports "unable
        // to read tree", which reads like a fetch bug rather than a pin that
        // names no commit in this repository.
        let present = run_git_with_activity(
            &["cat-file", "-e", &format!("{}^{{commit}}", source.commit)],
            Some(&work),
            activity,
        )?;
        if !present.status.success() {
            return Err(err(format!(
                "{}: commit {} is not in the repository (the fetch by sha \
                 failed and no ref reaches it)",
                source.url, source.commit
            )));
        }
        git_ok_with_activity(
            &["checkout", "-q", "--detach", &source.commit],
            Some(&work),
            &format!("git checkout {}", source.commit),
            activity,
        )?;
        let head = git_ok_with_activity(
            &["rev-parse", "HEAD"],
            Some(&work),
            "git rev-parse HEAD",
            activity,
        )?;
        if !head.eq_ignore_ascii_case(&source.commit) {
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
                activity,
            )?;
        }
        validate_checkout_tree_with_activity(&work, activity)?;
        remove_git_dirs(&work)?;
        validate_symlinks(&work)
    })();
    if let Err(e) = result {
        let _ = crate::kernel::store::remove_tree(&work);
        return Err(e);
    }
    store
        .commit_with_activity_and_deps(
            activity,
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
    use crate::kernel::testutil::TempDir;

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
        let temp = TempDir::named("gitsrc-links");
        let root = &temp.0;
        fs::write(root.join("safe.txt"), b"safe").unwrap();
        std::os::unix::fs::symlink("safe.txt", root.join("safe-link")).unwrap();
        validate_symlinks(root).unwrap();
        let escaped = |root: &Path| {
            let error = validate_symlinks(root).expect_err("an escaping symlink was accepted");
            assert_eq!(error.to_string(), "symlink target escaped the checkout");
        };
        std::os::unix::fs::symlink("../outside", root.join("escape")).unwrap();
        escaped(root);
        fs::remove_file(root.join("escape")).unwrap();
        std::os::unix::fs::symlink(".", root.join("a")).unwrap();
        std::os::unix::fs::symlink("a/../outside", root.join("escape-via-dot")).unwrap();
        escaped(root);
        fs::remove_file(root.join("a")).unwrap();
        fs::remove_file(root.join("escape-via-dot")).unwrap();
        std::os::unix::fs::symlink("chain-end", root.join("chain-start")).unwrap();
        std::os::unix::fs::symlink("../../outside", root.join("chain-end")).unwrap();
        escaped(root);
    }
}

#[cfg(test)]
mod realization_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// Git with no store lease, for building fixture repositories outside
    /// any store. Production runs go through `run_git_with_activity`.
    fn run_git(args: &[&str], cwd: Option<&Path>) -> io::Result<std::process::Output> {
        let mut command = Command::new(GIT);
        configure_git(&mut command, args, cwd);
        command
            .output()
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
        crate::kernel::store::Store::for_test(store_root.canonicalize().unwrap())
    }

    #[test]
    fn realizes_a_commit_and_strips_git_metadata() {
        let root = TempDir::named("gitsrc-realize");
        let (url, commit) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let source = GitSource {
            url: normalize_url(&url),
            commit: commit.clone(),
            subdirectory: None,
        };
        let object = ensure_git_source(&store, activity, &source).unwrap();
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
        let again = ensure_git_source(&store, activity, &source).unwrap();
        assert_eq!(object, again);
    }

    #[test]
    fn a_wrong_commit_is_refused() {
        let root = TempDir::named("gitsrc-wrong");
        let (url, _) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let source = GitSource {
            url: normalize_url(&url),
            commit: "0".repeat(40),
            subdirectory: None,
        };
        let error = ensure_git_source(&store, activity, &source)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!(
                "commit {} is not in the repository",
                "0".repeat(40)
            )),
            "{error}"
        );
    }

    /// Add a commit to the fixture repository that no branch tip reaches:
    /// the default branch is left where it was. Returns the new commit.
    fn off_branch_commit(url: &str, file: &str) -> String {
        let repo = PathBuf::from(url.strip_prefix("file://").unwrap());
        git_ok(&["checkout", "-q", "--detach"], Some(&repo), "detach").unwrap();
        std::fs::write(repo.join(file), "off the default branch\n").unwrap();
        git_ok(&["add", "-A"], Some(&repo), "add").unwrap();
        git_ok(&["commit", "-qm", file], Some(&repo), "commit").unwrap();
        let commit = git_ok(&["rev-parse", "HEAD"], Some(&repo), "rev-parse").unwrap();
        git_ok(&["checkout", "-q", "main"], Some(&repo), "checkout main").unwrap();
        commit
    }

    fn realize(root: &Path, url: &str, commit: &str) -> io::Result<PathBuf> {
        let store = store_at(root);
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        ensure_git_source(
            &store,
            activity,
            &GitSource {
                url: normalize_url(url),
                commit: commit.to_string(),
                subdirectory: None,
            },
        )
    }

    /// A local transport would hand over the commit by sha alone, so the
    /// sha fetch is refused here: the commit arrives only if the fallback
    /// fetches the non-default ref that reaches it, a branch or a
    /// `refs/pull/*` ref that is neither branch nor tag.
    #[test]
    fn a_commit_reachable_only_from_a_non_default_ref_is_realized_by_the_ref_fallback() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REFUSE_SHA_FETCH.with(|refuse| refuse.set(false));
            }
        }
        let _reset = Reset;
        REFUSE_SHA_FETCH.with(|refuse| refuse.set(true));
        for reference in ["refs/heads/side", "refs/pull/1/head"] {
            let root = TempDir::named("gitsrc-side");
            let (url, _) = fixture_repo(&root.0);
            let commit = off_branch_commit(&url, "side.txt");
            let repo = root.0.join("repo");
            git_ok(&["update-ref", reference, &commit], Some(&repo), "ref").unwrap();
            let object = realize(&root.0, &url, &commit)
                .unwrap_or_else(|error| panic!("{reference}: {error}"));
            assert_eq!(
                std::fs::read_to_string(object.join("side.txt")).unwrap(),
                "off the default branch\n",
                "{reference}"
            );
        }
    }

    /// The pin is the unadvertised parent of `refs/pull/1/head`, so only a
    /// fallback that fetches every ref (not just branches and tags) has it.
    #[test]
    fn a_refused_sha_fetch_falls_back_to_every_advertised_ref() {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                REFUSE_SHA_FETCH.with(|refuse| refuse.set(false));
            }
        }
        let _reset = Reset;
        REFUSE_SHA_FETCH.with(|refuse| refuse.set(true));
        let root = TempDir::named("gitsrc-fallback");
        let (url, _) = fixture_repo(&root.0);
        let parent = off_branch_commit(&url, "side.txt");
        let repo = root.0.join("repo");
        git_ok(
            &["checkout", "-q", "--detach", &parent],
            Some(&repo),
            "detach",
        )
        .unwrap();
        std::fs::write(repo.join("child.txt"), "child\n").unwrap();
        git_ok(&["add", "-A"], Some(&repo), "add").unwrap();
        git_ok(&["commit", "-qm", "child"], Some(&repo), "commit").unwrap();
        let child = git_ok(&["rev-parse", "HEAD"], Some(&repo), "rev-parse").unwrap();
        git_ok(&["checkout", "-q", "main"], Some(&repo), "checkout main").unwrap();
        git_ok(
            &["update-ref", "refs/pull/1/head", &child],
            Some(&repo),
            "ref",
        )
        .unwrap();
        let object = realize(&root.0, &url, &parent).unwrap();
        assert_eq!(
            std::fs::read_to_string(object.join("side.txt")).unwrap(),
            "off the default branch\n"
        );
        assert!(
            !object.join("child.txt").exists(),
            "the pinned parent, not the ref tip, is checked out"
        );
    }

    /// No ref reaches the pin, so the all-refs fallback cannot supply it:
    /// only the fetch by sha can. A local transport accepts any sha, so no
    /// server setting is involved.
    #[test]
    fn an_unreferenced_commit_is_fetched_by_sha() {
        let root = TempDir::named("gitsrc-anysha");
        let (url, _) = fixture_repo(&root.0);
        let commit = off_branch_commit(&url, "dangling.txt");
        let object = realize(&root.0, &url, &commit).unwrap();
        assert_eq!(
            std::fs::read_to_string(object.join("dangling.txt")).unwrap(),
            "off the default branch\n"
        );
    }

    #[test]
    fn a_commit_no_ref_reaches_is_named_as_missing() {
        let root = TempDir::named("gitsrc-missing");
        let (url, _) = fixture_repo(&root.0);
        // A pin that names no commit (NextChat's lock once produced one from
        // a tarball's sha1) is refused before checkout, in plain words.
        let commit = "ab".repeat(20);
        let error = realize(&root.0, &url, &commit).unwrap_err().to_string();
        assert!(
            error.contains(&format!("commit {commit} is not in the repository")),
            "{error}"
        );
    }

    #[test]
    fn an_unpinned_ref_is_refused() {
        let root = TempDir::named("gitsrc-ref");
        let (url, _) = fixture_repo(&root.0);
        let store = store_at(&root.0);
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let unpinned = GitSource {
            url: normalize_url(&url),
            commit: "main".into(),
            subdirectory: None,
        };
        let error = ensure_git_source(&store, activity, &unpinned)
            .unwrap_err()
            .to_string();
        assert!(error.contains("full commit"), "{error}");
    }

    #[test]
    fn checkout_rejects_attribute_transformed_content() {
        let root = TempDir::named("gitsrc-attributes");
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
        let store = store_at(&root.0);
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let error = ensure_git_source(&store, activity, &source)
            .unwrap_err()
            .to_string();
        assert!(error.contains("transformed"), "{error}");
    }

    #[test]
    fn pack_keeps_safe_links_empty_dirs_and_verbatim_names() {
        let root = TempDir::named("gitsrc-pack");
        let checkout = root.0.join("checkout");
        fs::create_dir_all(checkout.join("empty")).unwrap();
        fs::write(checkout.join("line\nname"), b"content\n").unwrap();
        std::os::unix::fs::symlink("line\nname", checkout.join("safe-link")).unwrap();
        let store = store_at(&root.0);
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let platform = crate::kernel::platform::Platform::host().unwrap();
        let (hash, filename) =
            pack_checkout(&store, activity, platform, &checkout, "pkg", "1.0").unwrap();
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
        let (same_hash, _) =
            pack_checkout(&store, activity, platform, &checkout_two, "pkg", "1.0").unwrap();
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
        let platform = crate::kernel::platform::Platform::host().unwrap();

        // bsdtar drops an overlong path and still exits 0, so relying on the
        // subprocess would cache a truncated archive here instead of failing.
        let root = TempDir::named("gitsrc-pack-failure");
        let checkout = root.0.join("checkout");
        let long_dir = "d".repeat(119);
        fs::create_dir_all(checkout.join(&long_dir)).unwrap();
        fs::write(checkout.join(&long_dir).join("f".repeat(119)), b"too long").unwrap();
        let store = store_at(&root.0);
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let error = pack_checkout(&store, activity, platform, &checkout, "pkg", "1.0")
            .expect_err("ustar path overflow must fail packing")
            .to_string();
        assert!(error.contains("packing"), "{error}");

        // The linkname field is 100 bytes with no prefix to spill into.
        let link_root = TempDir::named("gitsrc-pack-link-failure");
        let link_checkout = link_root.0.join("checkout");
        fs::create_dir_all(&link_checkout).unwrap();
        fs::write(link_checkout.join("target"), b"content\n").unwrap();
        std::os::unix::fs::symlink("x".repeat(101), link_checkout.join("link")).unwrap();
        let link_store = store_at(&link_root.0);
        let link_activity = &link_store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let error = pack_checkout(
            &link_store,
            link_activity,
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
    activity: &StoreActivity,
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
    let work = store.stage_with_activity(activity)?;
    let _cleanup = StageGuard(work.clone());
    let prefix = format!("{name}-{version}");
    let filename = format!("{prefix}.tar.gz");
    // Copy under the final prefix directory so the archive needs no name
    // rewriting: --transform/-s differ between GNU tar and bsdtar, and both
    // would take a rewrite expression built from these strings.
    let staged = work.join(&prefix);
    crate::comforter::clone_tree_with_activity(activity, source_root, &staged, platform)?;
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
    let list = work.join(".tog-filelist");
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
    crate::kernel::archive::pack_ustar_with_activity(
        activity,
        &uncompressed,
        &work,
        &list,
        platform.is_macos(),
    )
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("packing {} failed: {e}", source_root.display()),
        )
    })?;
    let mut gzip = Command::new("/usr/bin/gzip");
    gzip.args(["-n", "-9", "-c"])
        .arg(&uncompressed)
        .stdout(fs::File::create(&archive)?);
    let gzip_status = crate::kernel::supervise::local_status(&mut gzip, activity)?;
    let _ = fs::remove_file(&uncompressed);
    if !gzip_status.success() {
        return Err(err(format!(
            "packing {} failed (gzip {})",
            source_root.display(),
            gzip_status,
        )));
    }
    let (sha256, _) = crate::kernel::fetch::cache_insert(store, activity, &archive)?;
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
    // SAFETY: `path` is a NUL-terminated C string that outlives the call and
    // `times` is a two-element timespec array, which is what utimensat reads.
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

/// Offline tests for what git is never handed (#348): a source that is not
/// pinned, a URL or ref that could be read as an option, a scheme outside
/// the allow-list, a subdirectory that escapes the checkout, and symlinks
/// that leave it or loop. Each refusal returns before any git command
/// runs, so nothing here needs a repository or the network.
#[cfg(test)]
mod refusal_tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn source(url: &str, commit: &str, subdirectory: Option<&str>) -> GitSource {
        GitSource {
            url: url.into(),
            commit: commit.into(),
            subdirectory: subdirectory.map(str::to_string),
        }
    }

    fn refusal(source: &GitSource) -> String {
        validate_source(source)
            .expect_err("the source must be refused")
            .to_string()
    }

    #[test]
    fn a_source_not_pinned_to_a_full_commit_is_refused() {
        for commit in [
            "main",
            "v1.2.3",
            &COMMIT[..39],
            &format!("{}g", &COMMIT[..39]),
            "",
        ] {
            assert_eq!(
                refusal(&source("https://example.invalid/repo.git", commit, None)),
                format!(
                    "https://example.invalid/repo.git: git sources must be pinned to a full commit, got {commit:?}"
                ),
                "{commit}"
            );
        }
    }

    #[test]
    fn a_url_git_could_read_as_an_option_or_an_unknown_scheme_is_refused() {
        for url in [
            "-oProxyCommand=touch /tmp/pwned",
            "--upload-pack=touch /tmp/pwned",
            "http://example.invalid/repo.git",
            "ftp://example.invalid/repo.git",
            "ext::sh -c 'touch /tmp/pwned'",
            "github.com/owner/repo",
            "/srv/git/repo.git",
            "",
        ] {
            assert_eq!(
                refusal(&source(url, COMMIT, None)),
                format!(
                    "refusing git URL {url:?}: expected one of https://, ssh://, git://, file://"
                ),
                "{url}"
            );
        }
        // The scheme is fine; the host, or the login before it, is what
        // ssh would read as an option. This is what a normalized
        // `-oProxyCommand=x:repo` looks like.
        for url in [
            "ssh://-oProxyCommand=touch/repo",
            "ssh://git@-oProxyCommand=touch/repo",
            "ssh://-oProxyCommand=touch@github.com/repo",
            "https://-host/repo",
            "git://-host/repo",
            // What git would decode or unbracket into a dash-led host.
            "ssh://%2DoProxyCommand=touch/repo",
            "ssh://git@%2dhost/repo",
            "ssh://[-oProxyCommand=touch]/repo",
            "ssh://git@[-host]:22/repo",
        ] {
            assert_eq!(
                refusal(&source(url, COMMIT, None)),
                format!("refusing git URL {url:?}: the host looks like an option"),
                "{url}"
            );
        }
        // A dash inside the host, the login, or the path is ordinary, as
        // are bracketed IPv6 hosts, ports, escapes elsewhere, and the
        // empty authority of a file:// URL.
        for url in [
            "ssh://git@github.com/owner/-repo",
            "https://github.com/-owner/repo",
            "file:///srv/-git/repo",
            "file:///srv/%2Dgit/repo",
            "https://user-name@git-host.example/repo",
            "ssh://[::1]/repo",
            "https://git@[2001:db8::1]:8443/owner/repo",
            "https://github.com/owner/repo%2D",
            "https://github.com/%/repo",
            // Git takes one bracket layer off, and only a closed one, so
            // these reach ssh with a `[` in front and are not options.
            "ssh://git@%5B-host/repo",
            "ssh://git@[[-host]]/repo",
        ] {
            validate_source(&source(url, COMMIT, None)).unwrap_or_else(|e| panic!("{url}: {e}"));
        }
    }

    #[test]
    fn a_subdirectory_that_escapes_the_checkout_is_refused() {
        for subdirectory in [
            "/etc",
            "/",
            "..",
            "../sibling",
            "pkg/../../outside",
            "pkg/..",
            "..\\outside",
            "pkg\\..\\..\\outside",
        ] {
            assert_eq!(
                refusal(&source(
                    "https://example.invalid/repo.git",
                    COMMIT,
                    Some(subdirectory)
                )),
                format!("refusing git subdirectory {subdirectory:?}: it escapes the checkout"),
                "{subdirectory}"
            );
        }
    }

    #[test]
    fn the_commit_is_checked_before_the_url_and_the_url_before_the_subdirectory() {
        let error = refusal(&source("http://x/repo", "main", Some("/etc")));
        assert!(error.contains("must be pinned to a full commit"), "{error}");
        let error = refusal(&source("http://x/repo", COMMIT, Some("/etc")));
        assert!(error.starts_with("refusing git URL"), "{error}");
    }

    #[test]
    fn control_every_allowed_scheme_passes_with_a_contained_subdirectory() {
        for url in [
            "https://github.com/owner/repo",
            "ssh://git@github.com/owner/repo.git",
            "git://example.invalid/repo.git",
            "file:///srv/git/repo.git",
        ] {
            validate_source(&source(url, COMMIT, None)).unwrap();
            for subdirectory in ["pkg", "python/pkg", ".", "pkg/./sub", "..pkg", "pkg.."] {
                validate_source(&source(url, COMMIT, Some(subdirectory))).unwrap();
            }
        }
    }

    fn link(target: &str, at: &Path) {
        std::os::unix::fs::symlink(target, at).unwrap();
    }

    fn symlink_refusal(root: &Path) -> String {
        validate_symlinks(root)
            .expect_err("the checkout must be refused")
            .to_string()
    }

    #[test]
    fn a_symlink_with_an_absolute_target_is_refused() {
        let temp = TempDir::named("gitsrc-absolute");
        let root = &temp.0;
        link("/etc/passwd", &root.join("passwd"));
        assert_eq!(symlink_refusal(root), "symlink target has an absolute path");
        // Even one that points back inside the checkout: the checkout moves
        // when it is imported, and the absolute path does not move with it.
        fs::remove_file(root.join("passwd")).unwrap();
        fs::write(root.join("inside"), b"x").unwrap();
        link(
            root.join("inside").to_str().unwrap(),
            &root.join("self-absolute"),
        );
        assert_eq!(symlink_refusal(root), "symlink target has an absolute path");
    }

    #[test]
    fn a_symlink_that_loops_is_refused() {
        let temp = TempDir::named("gitsrc-cycle");
        let root = &temp.0;
        let canonical = root.canonicalize().unwrap();
        let named =
            |name: &str| format!("symlink cycle involving {}", canonical.join(name).display());
        link("me", &root.join("me"));
        assert_eq!(symlink_refusal(root), named("me"));
        fs::remove_file(root.join("me")).unwrap();
        // A two-link cycle: whichever link the walk reaches first is the
        // one the message names.
        link("b", &root.join("a"));
        link("a", &root.join("b"));
        let error = symlink_refusal(root);
        assert!(error == named("a") || error == named("b"), "{error}");
        fs::remove_file(root.join("a")).unwrap();
        fs::remove_file(root.join("b")).unwrap();
        // One that goes through a directory.
        fs::create_dir(root.join("dir")).unwrap();
        link("../dir/loop", &root.join("dir/loop"));
        assert_eq!(symlink_refusal(root), named("dir/loop"));
    }

    #[test]
    fn control_a_target_that_passes_the_same_link_twice_is_not_a_cycle() {
        // `alias/../../alias/file` goes through `alias` twice on its way to
        // a file that is inside the checkout. Only a link that expands to
        // itself is a cycle.
        let temp = TempDir::named("gitsrc-twice");
        let root = &temp.0;
        fs::create_dir_all(root.join("dir/sub")).unwrap();
        fs::write(root.join("dir/sub/file"), b"x").unwrap();
        link("dir/sub", &root.join("alias"));
        link("alias/../../alias/file", &root.join("twice"));
        validate_symlinks(root).unwrap();
    }

    #[test]
    fn a_web_of_links_that_doubles_at_every_level_is_refused_not_walked() {
        // a1 -> a2/a2, a2 -> a3/a3, ... aN -> . : acyclic, inside the
        // checkout, and 2^N expansions to resolve. The budget refuses it
        // long before that; without the budget this test would not finish.
        let temp = TempDir::named("gitsrc-doubling");
        let root = &temp.0;
        let depth = 40;
        for i in 1..depth {
            link(
                &format!("a{}/a{}", i + 1, i + 1),
                &root.join(format!("a{i}")),
            );
        }
        link(".", &root.join(format!("a{depth}")));
        let error = symlink_refusal(root);
        assert!(
            error.starts_with("symlink chain too long involving "),
            "{error}"
        );
        // A plain chain well under the budget resolves.
        let temp = TempDir::named("gitsrc-chain");
        let root = &temp.0;
        fs::write(root.join("end"), b"x").unwrap();
        for i in 0..32 {
            let target = if i == 0 {
                "end".to_string()
            } else {
                format!("c{}", i - 1)
            };
            link(&target, &root.join(format!("c{i}")));
        }
        validate_symlinks(root).unwrap();
    }

    #[test]
    fn a_symlink_that_escapes_from_a_subdirectory_is_refused_exactly() {
        let temp = TempDir::named("gitsrc-escape");
        let root = &temp.0;
        fs::create_dir_all(root.join("a/b")).unwrap();
        // Two levels up from a/b is the root: allowed. Three is out.
        link("../../inside", &root.join("a/b/up-two"));
        validate_symlinks(root).unwrap();
        link("../../../outside", &root.join("a/b/up-three"));
        assert_eq!(symlink_refusal(root), "symlink target escaped the checkout");
    }

    #[test]
    fn control_broken_and_nested_links_inside_the_checkout_pass() {
        let temp = TempDir::named("gitsrc-inside");
        let root = &temp.0;
        fs::create_dir_all(root.join("src/lib")).unwrap();
        fs::write(root.join("src/lib/mod.rs"), b"x").unwrap();
        // Relative into a sibling directory, through a directory link, and
        // a dangling link: all stay inside, so all are valid source content.
        link("src/lib", &root.join("lib-link"));
        link("../lib-link/mod.rs", &root.join("src/via-link"));
        link("does-not-exist", &root.join("dangling"));
        link("./src/../src/lib", &root.join("dotted"));
        validate_symlinks(root).unwrap();
    }
}
