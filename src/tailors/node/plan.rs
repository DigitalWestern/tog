//! package-lock.json planning (node tailor): platform/libc filtering,
//! git-source recognition, and the lock-freshness check.

use super::*;

/// A git dependency URL pinned to a full commit, in any of the spellings npm,
/// pnpm and yarn write. An unpinned ref returns None: the
/// caller reports it rather than guessing which commit was meant.
pub(crate) fn git_source_from_url(url: &str) -> Option<crate::kernel::gitsrc::GitSource> {
    let (repo, commit) = git_repo_and_commit(url)?;
    if !crate::kernel::gitsrc::is_full_commit(&commit) {
        return None;
    }
    let source = crate::kernel::gitsrc::GitSource {
        url: crate::kernel::gitsrc::normalize_url(&repo),
        commit: commit.to_ascii_lowercase(),
        subdirectory: None,
    };
    crate::kernel::gitsrc::validate_source(&source).ok()?;
    Some(source)
}

/// A dependency that must be realized from git: the lockfile names the git
/// protocol outright. A GitHub archive/codeload tarball is deliberately NOT
/// included — when the lock carries an SRI for it, those bytes are what the
/// lock attests, and a checkout of the same commit can legitimately differ
/// (`.gitattributes` export-ignore/export-subst). Such an entry only falls
/// back to git when the lock gives no integrity to verify.
pub(crate) fn explicit_git_source(url: &str) -> Option<crate::kernel::gitsrc::GitSource> {
    url.starts_with("git+")
        .then(|| git_source_from_url(url))
        .flatten()
}

/// Why a git dependency that is not pinned to a full commit cannot be
/// realized. The wording is persisted verbatim, down to its trailing tag: it
/// is recorded as `git-dependency` exception detail in closures and store
/// object metadata, and a cache hit compares exceptions exactly, so rewording
/// it would make existing store objects refuse with "published concurrently
/// with different exceptions". `tests/hitrate.py` also matches it.
pub(crate) fn git_dependency_detail(name: &str, url: &str) -> Option<String> {
    let (repo, commit) = git_repo_and_commit(url)?;
    Some(format!(
        "npm_git_dep: {name}: repo {repo}, commit {commit}; git sources are deferred to NEXT.md item 4"
    ))
}

/// Parse a git dependency URL into (repository, commit-or-placeholder).
pub(crate) fn git_repo_and_commit(url: &str) -> Option<(String, String)> {
    let mut repo = None;
    let mut commit = None;
    let mut source = url;
    let was_git = source.starts_with("git+");
    if let Some(stripped) = source.strip_prefix("git+") {
        source = stripped;
    }
    let (source_without_fragment, fragment) = source.split_once('#').unwrap_or((source, ""));
    source = source_without_fragment;
    let fragment_commit = (!fragment.is_empty()).then(|| fragment.to_string());
    if source.starts_with("git://")
        || source.starts_with("ssh://")
        || source.starts_with("git@")
        // An explicit `git+` prefix names the protocol outright, whatever it is.
        || was_git && source.contains("://")
    {
        // Preserve the repository path verbatim. In particular, `.git` is
        // part of a local file URL and must not be stripped before gitsrc
        // normalizes and validates it.
        repo = Some(source.to_string());
        commit = fragment_commit;
    } else if let Some(path) = source.strip_prefix("https://codeload.github.com/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 && parts[2] == "tar.gz" {
            repo = Some(format!("github.com/{}/{}", parts[0], parts[1]));
            commit =
                fragment_commit.or_else(|| Some(parts[3].trim_end_matches(".tar.gz").to_string()));
        }
    } else if let Some(path) = source.strip_prefix("https://github.com/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 && parts[2] == "archive" {
            repo = Some(format!("github.com/{}/{}", parts[0], parts[1]));
            commit =
                fragment_commit.or_else(|| Some(parts[3].trim_end_matches(".tar.gz").to_string()));
        } else if parts.len() >= 2 && parts[0] != "" && parts[1] != "" {
            // Yarn also emits the repository URL itself for some GitHub
            // dependencies (not an immutable registry tarball).
            repo = Some(format!("github.com/{}/{}", parts[0], parts[1]));
            commit = fragment_commit;
        }
    }
    let repo = repo?;
    let commit = commit.unwrap_or_else(|| "unspecified commit".into());
    Some((repo, commit))
}

/// Derive the package name from the last node_modules/ segment of the key.
pub(super) fn name_from_path(path: &str) -> String {
    match path.rfind("node_modules/") {
        Some(i) => path[i + "node_modules/".len()..].to_string(),
        None => path.to_string(),
    }
}

/// The Linux host's libc, as npm's `os`/`cpu`/`libc` lists name it. The port
/// targets glibc only; musl is a foreign value here.
pub(super) const LINUX_LIBC: &str = "glibc";

/// A lock entry's `os`/`cpu`/`libc` restriction as npm accepts it: an array
/// of strings, or a bare string standing for a one-element list.
pub(super) fn restriction_values<'a>(
    entry: &'a serde_json::Value,
    field: &str,
) -> Option<Vec<&'a str>> {
    if let Some(list) = entry[field].as_array() {
        return Some(list.iter().filter_map(|value| value.as_str()).collect());
    }
    entry[field].as_str().map(|value| vec![value])
}

/// npm's `checkList` (npm-install-checks): a sole `any` accepts everything;
/// otherwise a matching `!value` denies, then a matching positive is
/// required if any positives exist, and an all-negated list accepts what
/// it does not exclude.
pub(super) fn npm_list_compatible(values: &[&str], ours: &str) -> bool {
    if values == ["any"] {
        return true;
    }
    let mut negated = 0;
    let mut matched = false;
    for value in values {
        if let Some(denied) = value.strip_prefix('!') {
            negated += 1;
            if denied == ours {
                return false;
            }
        } else {
            matched |= *value == ours;
        }
    }
    matched || negated == values.len()
}

/// Darwin semantics from before Linux support, kept byte-for-byte: only array
/// restrictions count, and any negated entry makes positives irrelevant.
/// (A shared correction to npm's semantics is a separate decision.)
pub(super) fn darwin_list_compatible(entry: &serde_json::Value, field: &str, ours: &str) -> bool {
    match entry[field].as_array() {
        None => true,
        Some(list) => {
            let allowed: Vec<&str> = list.iter().filter_map(|v| v.as_str()).collect();
            let negated: Vec<&str> = allowed.iter().filter_map(|s| s.strip_prefix('!')).collect();
            if !negated.is_empty() {
                !negated.contains(&ours)
            } else {
                allowed.is_empty() || allowed.contains(&ours)
            }
        }
    }
}

pub(super) fn platform_list_compatible(
    platform: Platform,
    entry: &serde_json::Value,
    field: &str,
    ours: &str,
) -> bool {
    if platform.is_macos() {
        return darwin_list_compatible(entry, field, ours);
    }
    restriction_values(entry, field)
        .map(|values| npm_list_compatible(&values, ours))
        .unwrap_or(true)
}

/// `libc` restrictions only apply on Linux; Darwin keeps ignoring the field.
pub(super) fn libc_compatible(platform: Platform, entry: &serde_json::Value) -> bool {
    if platform.is_macos() {
        return true;
    }
    restriction_values(entry, "libc")
        .map(|values| npm_list_compatible(&values, LINUX_LIBC))
        .unwrap_or(true)
}

/// A `link: true` lock entry: a symlink into the project's own source. The
/// target comes from the lockfile (attacker-editable), so it is validated
/// before it can become a projected symlink.
fn lock_link_entry(path: &str, entry: &serde_json::Value) -> io::Result<NpmLink> {
    let target = entry["resolved"].as_str().unwrap_or_default();
    let ok = !target.is_empty()
        && !target.starts_with('/')
        && target
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    if !ok {
        return Err(err(format!("{path}: unsafe link target {target:?}")));
    }
    Ok(NpmLink {
        path: path.to_string(),
        target: target.to_string(),
    })
}

/// Platform filtering: lock entries carry os/cpu/libc restrictions.
/// Incompatible optional deps are skipped (npm does the same), which is what
/// `Ok(false)` means; incompatible required deps are an error. Linux uses
/// npm's list semantics (deny a matching exclusion, then require a matching
/// positive when positives exist), while Darwin keeps its established
/// behavior.
fn entry_platform_compatible(
    platform: Platform,
    entry: &serde_json::Value,
    path: &str,
) -> io::Result<bool> {
    let os_ok = platform_list_compatible(platform, entry, "os", platform.npm_os());
    let cpu_ok = platform_list_compatible(platform, entry, "cpu", platform.npm_cpu());
    let libc_ok = libc_compatible(platform, entry);
    if os_ok && cpu_ok && libc_ok {
        return Ok(true);
    }
    if entry["optional"].as_bool() == Some(true) {
        return Ok(false);
    }
    let restriction = if !libc_ok {
        format!(
            "libc restriction {:?} is incompatible with host {LINUX_LIBC}",
            entry["libc"]
        )
    } else if !os_ok {
        format!("os restriction {:?} is incompatible", entry["os"])
    } else {
        format!("cpu restriction {:?} is incompatible", entry["cpu"])
    };
    Err(err(format!(
        "{path}: required dependency does not support host {} ({}; npm {}/{})",
        platform.triple(),
        restriction,
        platform.npm_os(),
        platform.npm_cpu()
    )))
}

/// Outcome of classifying a lock entry's `resolved` URL as a git source.
enum PinnedGit {
    /// The entry is realizable: `Some` from git, `None` from its tarball.
    Resolved(Option<crate::kernel::gitsrc::GitSource>),
    /// An unrealizable git dependency that is optional: recorded as a policy
    /// exception and dropped with its subtree.
    SkipOptional,
}

/// A git dependency pinned to a full commit is realizable; anything
/// else (a branch, a tag, a bare repo URL) is not, because the bytes it names
/// can change.
///
/// An explicit git+ URL is always realized from git. Anything else (a
/// codeload/archive tarball) is only realized from git when the lock has no
/// integrity to verify it with.
fn pinned_git_for_entry(
    path: &str,
    name: &str,
    resolved: &str,
    entry: &serde_json::Value,
) -> io::Result<PinnedGit> {
    let pinned_git = explicit_git_source(resolved).or_else(|| {
        entry["integrity"]
            .as_str()
            .is_none()
            .then(|| git_source_from_url(resolved))
            .flatten()
    });
    if pinned_git.is_none() {
        if let Some(detail) = git_dependency_detail(name, resolved) {
            if entry["optional"].as_bool() == Some(true) {
                crate::kernel::policy::record(
                    crate::kernel::policy::GIT_DEPENDENCY,
                    path,
                    &detail,
                )?;
                return Ok(PinnedGit::SkipOptional);
            }
            return Err(err(format!("{path}: {detail}")));
        }
    }
    if pinned_git.is_none() && !resolved.starts_with("https://") {
        return Err(err(format!(
            "{path}: only https registry tarballs supported (v0), got {resolved}"
        )));
    }
    Ok(PinnedGit::Resolved(pinned_git))
}

/// A git package's content is verified by the commit hash, so the lockfile
/// carries no SRI for it.
fn entry_integrity(
    path: &str,
    entry: &serde_json::Value,
    pinned_git: &Option<crate::kernel::gitsrc::GitSource>,
) -> io::Result<String> {
    if pinned_git.is_some() {
        return Ok(String::new());
    }
    let integrity = entry["integrity"].as_str().ok_or_else(|| {
        err(format!(
            "{path}: missing 'integrity' (regenerate the lockfile)"
        ))
    })?;
    let digest = Digest::from_sri(integrity)?; // validate early
    if digest.algo() == "sha1" {
        if let Err(policy_error) = crate::kernel::policy::record(
            crate::kernel::policy::WEAK_INTEGRITY,
            path,
            "sha1 integrity accepted and verified, but is cryptographically weak",
        ) {
            return Err(err(format!(
                "unsupported integrity algorithm: sha1 ({policy_error})"
            )));
        }
    }
    Ok(integrity.to_string())
}

fn npm_package_from_entry(
    path: &str,
    entry: &serde_json::Value,
    resolved: &str,
    git: Option<crate::kernel::gitsrc::GitSource>,
    integrity: String,
) -> NpmPackage {
    let name = entry["name"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| name_from_path(path));
    let version = entry["version"].as_str().unwrap_or("0.0.0").to_string();
    let mut bin = Vec::new();
    if let Some(map) = entry["bin"].as_object() {
        for (k, val) in map {
            if let Some(rel) = val.as_str() {
                bin.push((k.clone(), rel.to_string()));
            }
        }
    }
    NpmPackage {
        path: path.to_string(),
        name,
        version,
        url: resolved.to_string(),
        integrity: match &git {
            Some(source) => format!("git:{}", source.commit),
            None => integrity,
        },
        bin,
        patch: None,
        git,
        optional: entry["optional"].as_bool() == Some(true),
    }
}

/// Parse package-lock.json (lockfileVersion 2 or 3) into a plan.
/// Pure parsing: no network. Deterministic (sorted by path).
///
/// `node_version` is the version the project's toolchain selection names:
/// the plan records the Node this sync will realize, never a table lookup
/// that could disagree with the lock.
pub fn plan_npm(platform: Platform, lock_json: &str) -> io::Result<NpmPlan> {
    let shipped = crate::tailors::node::shipped_selection()?;
    plan_npm_with(platform, lock_json, shipped.version("node")?)
}

/// `plan_npm` for a caller that holds a selection: the plan records the
/// Node this sync will realize.
pub fn plan_npm_with(
    platform: Platform,
    lock_json: &str,
    node_version: &str,
) -> io::Result<NpmPlan> {
    let v: serde_json::Value =
        serde_json::from_str(lock_json).map_err(|e| err(format!("package-lock.json: {e}")))?;
    let lockfile_version = v["lockfileVersion"].as_u64().unwrap_or(0);
    if lockfile_version != 2 && lockfile_version != 3 {
        return Err(err(format!(
            "unsupported lockfileVersion {lockfile_version} (need 2 or 3; run npm install --package-lock-only with npm >= 7)"
        )));
    }
    let packages = v["packages"]
        .as_object()
        .ok_or_else(|| err("package-lock.json has no packages map"))?;

    let mut out = Vec::new();
    let mut links = Vec::new();
    // Workspace source dirs appear as lock entries whose path is NOT under
    // any node_modules/ (e.g. "packages/lib"). They are the user's own
    // source, not installed content. A package nested inside a workspace
    // ("packages/lib/node_modules/c", npm's placement on a version conflict)
    // is installed content and must be realized like any other package;
    // treating it as a workspace both dropped it from the plan and made
    // projection try to plant a node_modules symlink beneath the workspace's
    // own node_modules symlink.
    let workspace_dirs: Vec<&str> = packages
        .keys()
        .filter(|p| {
            !p.is_empty() && !p.starts_with("node_modules/") && !p.contains("/node_modules/")
        })
        .map(String::as_str)
        .collect();
    // Sorted so parents precede children ("a/node_modules/b" sorts after
    // "a"), letting a skipped parent drop its whole subtree.
    let mut paths: Vec<&String> = packages.keys().collect();
    paths.sort();
    let mut skipped: Vec<String> = Vec::new();
    for path in paths {
        let entry = &packages[path];
        if path.is_empty() {
            continue; // root project entry
        }
        if workspace_dirs.contains(&path.as_str()) {
            continue; // workspace source dir definition
        }
        validate_lock_path(path)?;
        if skipped.iter().any(|s| path.starts_with(s.as_str())) {
            continue; // descendant of a platform-skipped package
        }
        if entry["link"].as_bool() == Some(true) {
            links.push(lock_link_entry(path, entry)?);
            continue;
        }
        // Bundled deps ship inside the parent tarball (covered by the
        // parent's integrity hash) and carry no resolved/integrity of
        // their own; extraction of the parent materializes them.
        if entry["inBundle"].as_bool() == Some(true) {
            continue;
        }
        if !entry_platform_compatible(platform, entry, path)? {
            skipped.push(format!("{path}/"));
            continue;
        }
        let resolved = entry["resolved"].as_str().ok_or_else(|| {
            err(format!(
                "{path}: missing 'resolved' URL (regenerate the lockfile)"
            ))
        })?;
        let name = entry["name"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| name_from_path(path));
        let pinned_git = match pinned_git_for_entry(path, &name, resolved, entry)? {
            PinnedGit::Resolved(pinned_git) => pinned_git,
            PinnedGit::SkipOptional => {
                skipped.push(format!("{path}/"));
                continue;
            }
        };
        let integrity = entry_integrity(path, entry, &pinned_git)?;
        out.push(npm_package_from_entry(
            path, entry, resolved, pinned_git, integrity,
        ));
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    links.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(NpmPlan {
        node_version: node_version.to_string(),
        packages: out,
        links,
        workspaces: workspace_dirs.into_iter().map(str::to_string).collect(),
        lock_source: "package-lock.json".into(),
    })
}

/// Reject a package.json whose dependency maps disagree with the lock's
/// root entry (npm ci does the same). No solver needed: name -> spec
/// equality on dependencies/devDependencies/optionalDependencies.
pub fn check_lock_freshness(pkg_json: &str, lock_json: &str) -> io::Result<()> {
    let p: serde_json::Value =
        serde_json::from_str(pkg_json).map_err(|e| err(format!("package.json: {e}")))?;
    let l: serde_json::Value =
        serde_json::from_str(lock_json).map_err(|e| err(format!("package-lock.json: {e}")))?;
    let root = &l["packages"][""];
    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        let a = p[field].as_object().cloned().unwrap_or_default();
        let b = root[field].as_object().cloned().unwrap_or_default();
        if a != b {
            return Err(err(format!(
                "package.json {field} disagree with package-lock.json; regenerate the lock (npm install --package-lock-only)"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lock-freshness refusal is printed to the user verbatim, so it has
    /// to read as one sentence: no run of spaces left behind by re-wrapping
    /// the `format!`.
    #[test]
    fn the_lock_freshness_refusal_reads_as_one_sentence() {
        let package = r#"{"dependencies":{"is-odd":"^3.0.0"}}"#;
        let stale = r#"{"packages":{"":{"dependencies":{"is-odd":"^2.0.0"}}}}"#;
        let error = check_lock_freshness(package, stale)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "package.json dependencies disagree with package-lock.json; \
             regenerate the lock (npm install --package-lock-only)"
        );
        assert!(!error.contains("  "), "{error}");

        let fresh = r#"{"packages":{"":{"dependencies":{"is-odd":"^3.0.0"}}}}"#;
        check_lock_freshness(package, fresh).unwrap();
    }
}
