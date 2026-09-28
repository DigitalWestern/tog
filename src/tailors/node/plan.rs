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

/// A GitHub archive tarball (codeload `tar.gz/<commit>` or
/// `github.com/<o>/<r>/archive/<commit>.tar.gz`). Its commit is in the path,
/// so any `#fragment` on it is a hash of the bytes, never a commit.
pub(crate) fn is_github_archive_url(url: &str) -> bool {
    let url = url.split_once('#').map_or(url, |(url, _)| url);
    let archive = |path: &str, marker: &str| {
        let parts: Vec<&str> = path.split('/').collect();
        parts.len() >= 4 && parts[2] == marker
    };
    url.strip_prefix("https://codeload.github.com/")
        .is_some_and(|path| archive(path, "tar.gz"))
        || url
            .strip_prefix("https://github.com/")
            .is_some_and(|path| archive(path, "archive"))
}

/// Why tog will not fetch a locked tarball URL as written. Each importer
/// words `NotHttps` its own way; `Credentials` never echoes the URL, since a
/// `user:pass@` authority would copy the secret into the plan and into
/// fetch errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TarballUrlRefusal {
    NotHttps,
    Credentials,
}

pub(crate) const TARBALL_URL_CREDENTIALS: &str =
    "tarball URL carries credentials (user:pass@ before its host); tog will not record them";

/// A locked URL parsed the way the fetcher parses it (ureq, through the
/// `url` crate), so the check here and the download there read one URL:
/// `https:///u:p@host` has credentials to both. `None` when ureq could not
/// request it at all.
fn fetcher_url(url: &str) -> Option<ureq::RequestUrl> {
    ureq::get(url).request_url().ok()
}

/// The refusal for a locked tarball URL, if any: tog never fetches from a
/// URL with userinfo, and fetches https only. Credentials are checked
/// first, so a credentialed http URL is refused without being echoed.
pub(crate) fn tarball_url_refusal(url: &str) -> Option<TarballUrlRefusal> {
    let Some(parsed) = fetcher_url(url) else {
        return Some(TarballUrlRefusal::NotHttps);
    };
    let parsed = parsed.as_url();
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some(TarballUrlRefusal::Credentials);
    }
    (parsed.scheme() != "https").then_some(TarballUrlRefusal::NotHttps)
}

/// The external-dependency detail for a refused tarball URL, if refused:
/// `not_https` is the importer's own wording, followed by the redacted URL.
pub(crate) fn tarball_url_detail(url: &str, not_https: &str) -> Option<String> {
    Some(match tarball_url_refusal(url)? {
        TarballUrlRefusal::NotHttps => format!("{not_https} {}", redact_url_userinfo(url)),
        TarballUrlRefusal::Credentials => TARBALL_URL_CREDENTIALS.to_string(),
    })
}

/// `text` for a message, with any URL userinfo replaced by `***`. Text the
/// fetcher cannot parse is withheld whole when an `@` follows its `://`,
/// since where its credentials end cannot be told; other text (a plain
/// version) is returned as written.
pub(crate) fn redact_url_userinfo(text: &str) -> String {
    let Some(parsed) = fetcher_url(text) else {
        return match text.split_once("://") {
            Some((_, rest)) if rest.contains('@') => {
                "<URL withheld: it may carry credentials>".to_string()
            }
            _ => text.to_string(),
        };
    };
    let mut url = parsed.as_url().clone();
    if url.username().is_empty() && url.password().is_none() {
        return text.to_string();
    }
    let _ = url.set_username("***");
    if url.password().is_some() {
        let _ = url.set_password(Some("***"));
    }
    url.to_string()
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
        // The commit an archive URL downloads is the one in its path. A
        // fragment on it is Yarn 1's sha1 of the tarball bytes, not a commit.
        if parts.len() >= 4 && parts[2] == "tar.gz" {
            repo = Some(format!("github.com/{}/{}", parts[0], parts[1]));
            commit = Some(parts[3].trim_end_matches(".tar.gz").to_string());
        }
    } else if let Some(path) = source.strip_prefix("https://github.com/") {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 4 && parts[2] == "archive" {
            repo = Some(format!("github.com/{}/{}", parts[0], parts[1]));
            commit = Some(parts[3].trim_end_matches(".tar.gz").to_string());
        } else if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            // Yarn also emits the repository URL itself for some GitHub
            // dependencies (not an immutable registry tarball). Only the
            // bare repository counts: any deeper path, such as a release
            // asset `/releases/download/<tag>/<file>.tgz#<sha1>`, is an
            // ordinary tarball whose fragment is Yarn's sha1 of its bytes.
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
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
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
                record(crate::kernel::policy::GIT_DEPENDENCY, path, &detail)?;
                return Ok(PinnedGit::SkipOptional);
            }
            return Err(err(format!("{path}: {detail}")));
        }
    }
    match pinned_git.is_none().then(|| tarball_url_refusal(resolved)) {
        Some(Some(TarballUrlRefusal::NotHttps)) => {
            return Err(err(format!(
                "{path}: only https registry tarballs supported (v0), got {}",
                redact_url_userinfo(resolved)
            )))
        }
        Some(Some(TarballUrlRefusal::Credentials)) => {
            return Err(err(format!("{path}: {TARBALL_URL_CREDENTIALS}")))
        }
        _ => {}
    }
    Ok(PinnedGit::Resolved(pinned_git))
}

/// A git package's content is verified by the commit hash, so the lockfile
/// carries no SRI for it.
fn entry_integrity(
    path: &str,
    entry: &serde_json::Value,
    pinned_git: &Option<crate::kernel::gitsrc::GitSource>,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
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
        if let Err(policy_error) = record(
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
    plan_npm_recording(
        platform,
        lock_json,
        node_version,
        &mut crate::kernel::policy::record,
    )
}

/// `plan_npm_with` recording exceptions through `record`, so a test can
/// pass a policy of its own instead of the process one.
fn plan_npm_recording(
    platform: Platform,
    lock_json: &str,
    node_version: &str,
    record: &mut impl FnMut(&str, &str, &str) -> io::Result<()>,
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
    // Bundled packages are not fetched, but their parent's extraction
    // still creates their directories.
    let mut bundled: Vec<&str> = Vec::new();
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
            bundled.push(path.as_str());
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
        let pinned_git = match pinned_git_for_entry(path, &name, resolved, entry, record)? {
            PinnedGit::Resolved(pinned_git) => pinned_git,
            PinnedGit::SkipOptional => {
                skipped.push(format!("{path}/"));
                continue;
            }
        };
        let integrity = entry_integrity(path, entry, &pinned_git, record)?;
        out.push(npm_package_from_entry(
            path, entry, resolved, pinned_git, integrity,
        ));
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    links.sort_by(|a, b| a.path.cmp(&b.path));
    refuse_case_colliding_paths(
        out.iter()
            .map(|package| package.path.as_str())
            .chain(links.iter().map(|link| link.path.as_str()))
            .chain(bundled),
    )?;
    Ok(NpmPlan {
        node_version: node_version.to_string(),
        packages: out,
        links,
        workspaces: workspace_dirs.into_iter().map(str::to_string).collect(),
        lock_source: "package-lock.json".into(),
    })
}

#[cfg(test)]
mod lock_shape_tests {
    use super::super::tests::{lock, TEST_SRI};
    use super::*;

    /// sha1 of twenty zero bytes, as an SRI: well-formed, and weak.
    const SHA1_SRI: &str = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn entry(path: &str, resolved: &str, integrity: &str) -> String {
        lock(&format!(
            r#""{path}":{{"version":"1.0.0","resolved":"{resolved}","integrity":"{integrity}"}}"#
        ))
    }

    fn refused(lock: &str) -> io::Error {
        plan_npm(Platform::X86_64UnknownLinuxGnu, lock)
            .map(drop)
            .unwrap_err()
    }

    /// Inside an attribution a sha1 entry is accepted, verified by its
    /// digest, and recorded as a weak-integrity exception on its lock path.
    #[test]
    fn sha1_integrity_is_accepted_and_recorded_inside_an_attribution() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let _attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        // An explicit permissive policy: TOG_STRICT=1 in the environment
        // would otherwise refuse the exception this test expects recorded.
        let permissive = crate::kernel::policy::Policy::default();
        let shipped = crate::tailors::node::shipped_selection().unwrap();
        let plan = plan_npm_recording(
            Platform::X86_64UnknownLinuxGnu,
            &entry("node_modules/a", "https://r/a.tgz", SHA1_SRI),
            shipped.version("node").unwrap(),
            &mut |kind: &str, subject: &str, detail: &str| {
                crate::kernel::policy::record_with(&permissive, kind, subject, detail)
            },
        )
        .unwrap();
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.packages[0].integrity, SHA1_SRI);
        let exceptions = crate::kernel::policy::drain();
        assert_eq!(exceptions.len(), 1, "{exceptions:?}");
        assert_eq!(exceptions[0].kind, crate::kernel::policy::WEAK_INTEGRITY);
        assert_eq!(exceptions[0].subject, "node_modules/a");
        assert_eq!(
            exceptions[0].detail,
            "sha1 integrity accepted and verified, but is cryptographically weak"
        );
    }

    /// With no attribution to record the exception into, the sha1 entry is
    /// refused, carrying the policy's reason.
    #[test]
    fn sha1_integrity_is_refused_outside_any_attribution() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let error = refused(&entry("node_modules/a", "https://r/a.tgz", SHA1_SRI));
        assert_eq!(
            error.to_string(),
            "unsupported integrity algorithm: sha1 (exception recorded outside any attribution)"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// A strong digest needs no attribution at all: nothing is recorded,
    /// since a record here, outside any attribution, would have failed.
    #[test]
    fn sha512_integrity_records_nothing() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let plan = plan_npm(
            Platform::X86_64UnknownLinuxGnu,
            &entry("node_modules/a", "https://r/a.tgz", TEST_SRI),
        )
        .unwrap();
        assert_eq!(plan.packages[0].integrity, TEST_SRI);
    }

    #[test]
    fn non_https_registry_tarballs_are_refused() {
        for resolved in [
            "http://registry.npmjs.org/a/-/a-1.0.0.tgz",
            "file:../a-1.0.0.tgz",
            "ftp://r/a.tgz",
            "https:///",
            "not a url",
        ] {
            let error = refused(&entry("node_modules/a", resolved, TEST_SRI));
            assert_eq!(
                error.to_string(),
                format!(
                    "node_modules/a: only https registry tarballs supported (v0), got {resolved}"
                )
            );
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        let plan = plan_npm(
            Platform::X86_64UnknownLinuxGnu,
            &entry(
                "node_modules/a",
                "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                TEST_SRI,
            ),
        )
        .unwrap();
        assert_eq!(
            plan.packages[0].url,
            "https://registry.npmjs.org/a/-/a-1.0.0.tgz"
        );
    }

    /// A tarball URL with userinfo is refused without echoing it; an `@` in
    /// the path (a scoped package) is not userinfo.
    #[test]
    fn a_tarball_url_carrying_credentials_is_refused() {
        // The fetcher's parser skips the extra slash of `https:///` and sees
        // the userinfo; credentials win over the scheme, so an http URL
        // with a secret is not echoed either.
        for resolved in [
            "https://user:secret@r/a.tgz",
            "https://token@r/a.tgz",
            "https://user@r/a.tgz",
            "https://:secret@r/a.tgz",
            "https://u:secret@r?x#y",
            "https:///user:secret@r/a.tgz",
            "http://user:secret@r/a.tgz",
            "HTTPS://user:secret@r/a.tgz",
        ] {
            let error = refused(&entry("node_modules/a", resolved, TEST_SRI));
            assert_eq!(
                error.to_string(),
                "node_modules/a: tarball URL carries credentials (user:pass@ before its host); tog will not record them",
                "{resolved}"
            );
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        // An `@` after the authority, in a query or fragment, is not
        // userinfo; an uppercase scheme is still https.
        for resolved in [
            "https://r?by=a@b",
            "https://r#a@b",
            "https://r/a.tgz?x=@y",
            "https://r/@s/a.tgz",
            "HTTPS://r/a.tgz",
        ] {
            let plan = plan_npm(
                Platform::X86_64UnknownLinuxGnu,
                &entry("node_modules/a", resolved, TEST_SRI),
            )
            .unwrap();
            assert_eq!(plan.packages[0].url, resolved);
        }
        let scoped = "https://r/@s/a/-/a-1.0.0.tgz";
        let plan = plan_npm(
            Platform::X86_64UnknownLinuxGnu,
            &entry("node_modules/@s/a", scoped, TEST_SRI),
        )
        .unwrap();
        assert_eq!(plan.packages[0].url, scoped);
    }

    /// A URL the fetcher cannot parse is non-https, and shown withheld when
    /// it might carry credentials.
    #[test]
    fn an_unparseable_credentialed_url_is_withheld() {
        let error = refused(&entry("node_modules/a", "http://user:secret@", TEST_SRI));
        assert_eq!(
            error.to_string(),
            "node_modules/a: only https registry tarballs supported (v0), got <URL withheld: it may carry credentials>"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// Messages show a URL with its userinfo replaced; a plain version and
    /// a URL without userinfo are shown as written.
    #[test]
    fn url_userinfo_is_redacted_for_messages() {
        for (text, shown) in [
            ("https://user:secret@r/a.tgz", "https://***:***@r/a.tgz"),
            ("https://user@r/a.tgz", "https://***@r/a.tgz"),
            ("https:///user:secret@r/a.tgz", "https://***:***@r/a.tgz"),
            (
                "http://u:secret@r/a.tgz(p@1)",
                "http://***:***@r/a.tgz(p@1)",
            ),
            (
                "http://user:secret@",
                "<URL withheld: it may carry credentials>",
            ),
            ("HTTPS://r/a.tgz", "HTTPS://r/a.tgz"),
            ("https://r/@s/a.tgz", "https://r/@s/a.tgz"),
            ("1.0.0(react@18.0.0)", "1.0.0(react@18.0.0)"),
            ("file:../a@1.tgz", "file:../a@1.tgz"),
        ] {
            assert_eq!(redact_url_userinfo(text), shown, "{text}");
        }
    }

    /// `node_modules/Foo` and `node_modules/foo` are distinct lock paths but
    /// one directory on a case-insensitive filesystem; a link counts too.
    #[test]
    fn destinations_differing_only_in_case_are_refused() {
        let pair = |first: &str, second: &str| {
            lock(&format!(
                r#""{first}":{{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}"}},{second}"#
            ))
        };
        let error = refused(&pair(
            "node_modules/Foo",
            &format!(
                r#""node_modules/foo":{{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}"}}"#
            ),
        ));
        assert_eq!(
            error.to_string(),
            "lockfile paths node_modules/Foo and node_modules/foo differ only in letter case; a case-insensitive filesystem would put both in one directory"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let error = refused(&pair(
            "node_modules/foo",
            r#""packages/lib":{"version":"1.0.0"},"node_modules/FOO":{"resolved":"packages/lib","link":true}"#,
        ));
        assert_eq!(
            error.to_string(),
            "lockfile paths node_modules/foo and node_modules/FOO differ only in letter case; a case-insensitive filesystem would put both in one directory"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // An ancestor counts: the link's directory is the package's parent.
        let error = refused(&pair(
            "node_modules/foo/node_modules/bar",
            r#""packages/lib":{"version":"1.0.0"},"node_modules/Foo":{"resolved":"packages/lib","link":true}"#,
        ));
        assert_eq!(
            error.to_string(),
            "lockfile paths node_modules/foo and node_modules/Foo differ only in letter case; a case-insensitive filesystem would put both in one directory"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // And the other way round: the package's parent spelled uppercase.
        let error = refused(&pair(
            "node_modules/Foo/node_modules/bar",
            r#""packages/lib":{"version":"1.0.0"},"node_modules/foo":{"resolved":"packages/lib","link":true}"#,
        ));
        assert_eq!(
            error.to_string(),
            "lockfile paths node_modules/Foo and node_modules/foo differ only in letter case; a case-insensitive filesystem would put both in one directory"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // A bundled package is not fetched, but its directory is created.
        let error = refused(&pair(
            "node_modules/a/node_modules/foo",
            &format!(
                r#""node_modules/a":{{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}"}},"node_modules/a/node_modules/Foo":{{"version":"1.0.0","inBundle":true}}"#
            ),
        ));
        assert_eq!(
            error.to_string(),
            "lockfile paths node_modules/a/node_modules/foo and node_modules/a/node_modules/Foo differ only in letter case; a case-insensitive filesystem would put both in one directory"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // A scope directory that is no destination is shared harmlessly.
        let plan = plan_npm(
            Platform::X86_64UnknownLinuxGnu,
            &pair(
                "node_modules/@Scope/a",
                &format!(
                    r#""node_modules/@scope/b":{{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}"}}"#
                ),
            ),
        )
        .unwrap();
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["node_modules/@Scope/a", "node_modules/@scope/b"]
        );
        // One spelling shared by a package and its nested child is fine.
        let plan = plan_npm(
            Platform::X86_64UnknownLinuxGnu,
            &pair(
                "node_modules/foo/node_modules/bar",
                &format!(
                    r#""node_modules/foo":{{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}"}}"#
                ),
            ),
        )
        .unwrap();
        assert_eq!(plan.packages.len(), 2);
        let plan = plan_npm(
            Platform::X86_64UnknownLinuxGnu,
            &pair(
                "node_modules/foo",
                &format!(
                    r#""node_modules/bar":{{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}"}}"#
                ),
            ),
        )
        .unwrap();
        assert_eq!(plan.packages.len(), 2);
    }

    /// Anything but lockfileVersion 2 or 3 is refused; a missing or
    /// non-integer version reads as 0.
    #[test]
    fn unsupported_lockfile_versions_are_refused() {
        for (version, shown) in [
            ("1", "1"),
            ("4", "4"),
            ("0", "0"),
            (r#""3""#, "0"),
            ("3.0", "0"),
            ("-3", "0"),
            ("null", "0"),
        ] {
            let lock = format!(r#"{{"lockfileVersion":{version},"packages":{{}}}}"#);
            let error = refused(&lock);
            assert_eq!(
                error.to_string(),
                format!(
                    "unsupported lockfileVersion {shown} (need 2 or 3; run npm install --package-lock-only with npm >= 7)"
                ),
                "{version}"
            );
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        let error = refused(r#"{"packages":{}}"#);
        assert_eq!(
            error.to_string(),
            "unsupported lockfileVersion 0 (need 2 or 3; run npm install --package-lock-only with npm >= 7)"
        );
    }

    #[test]
    fn lockfile_versions_2_and_3_plan() {
        for version in [2, 3] {
            let lock = format!(
                r#"{{"name":"x","lockfileVersion":{version},"packages":{{"":{{"name":"x"}},
                   "node_modules/a":{{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}"}}}}}}"#
            );
            let plan = plan_npm(Platform::X86_64UnknownLinuxGnu, &lock).unwrap();
            assert_eq!(plan.packages.len(), 1, "v{version}");
            assert_eq!(plan.packages[0].path, "node_modules/a");
        }
    }

    /// An npm alias (`"foo": "npm:bar@1.0.0"`) sits at node_modules/foo,
    /// while the package it installs is bar: the name comes from the entry,
    /// the path from the key.
    #[test]
    fn an_npm_alias_is_placed_by_its_key_and_named_by_its_entry() {
        let lock = lock(&format!(
            r#""node_modules/foo":{{"name":"bar","version":"1.0.0","resolved":"https://r/bar-1.0.0.tgz","integrity":"{TEST_SRI}"}},
               "node_modules/@s/alias":{{"name":"@t/real","version":"2.0.0","resolved":"https://r/real-2.0.0.tgz","integrity":"{TEST_SRI}"}}"#
        ));
        let plan = plan_npm(Platform::X86_64UnknownLinuxGnu, &lock).unwrap();
        let placed: Vec<(&str, &str, &str, &str)> = plan
            .packages
            .iter()
            .map(|p| {
                (
                    p.path.as_str(),
                    p.name.as_str(),
                    p.version.as_str(),
                    p.url.as_str(),
                )
            })
            .collect();
        assert_eq!(
            placed,
            vec![
                (
                    "node_modules/@s/alias",
                    "@t/real",
                    "2.0.0",
                    "https://r/real-2.0.0.tgz"
                ),
                (
                    "node_modules/foo",
                    "bar",
                    "1.0.0",
                    "https://r/bar-1.0.0.tgz"
                ),
            ]
        );
    }
}
