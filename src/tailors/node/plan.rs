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

/// A locked URL parsed the way the fetcher parses it, so the check here and
/// the download there read one URL: `https:///u:p@host` has credentials to
/// both. `None` when the fetcher could not request it at all.
fn fetcher_url(url: &str) -> Option<url::Url> {
    crate::kernel::fetch::request_url(url)
}

/// The refusal for a locked tarball URL, if any: tog never fetches from a
/// URL with userinfo, and fetches https only. Credentials are checked
/// first, so a credentialed http URL is refused without being echoed.
pub(crate) fn tarball_url_refusal(url: &str) -> Option<TarballUrlRefusal> {
    let Some(parsed) = fetcher_url(url) else {
        return Some(TarballUrlRefusal::NotHttps);
    };
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

/// `text` for a message, with any URL userinfo replaced by `***`. Text that
/// may carry credentials ([`url_credentials`]) but is not one URL the
/// fetcher can parse (an identity with a URL inside it, `https:u:p@host`) is
/// withheld whole, since where its credentials end cannot be told; other
/// text (a plain version) is returned as written.
pub(crate) fn redact_url_userinfo(text: &str) -> String {
    let withheld = |withhold: bool| match withhold {
        true => "<URL withheld: it may carry credentials>".to_string(),
        false => text.to_string(),
    };
    let Some(parsed) = fetcher_url(text) else {
        let embedded = text
            .split_once("://")
            .is_some_and(|(_, rest)| rest.contains('@'));
        return withheld(embedded || url_credentials(text));
    };
    let mut url = parsed;
    if url.username().is_empty() && url.password().is_none() {
        return withheld(url_credentials(text));
    }
    // Only the userinfo is redacted, so a second URL in the path, query or
    // fragment (`?next=https://u:p@h`, or one after a space the parser
    // escaped) would be shown as written: such text is withheld whole. An
    // escape (`%20`) reads as a space, so the URL after it still starts one.
    let tail = format!(
        "{}?{}#{}",
        url.path(),
        url.query().unwrap_or_default(),
        url.fragment().unwrap_or_default()
    );
    if url_credentials(&unescaped_for_scan(&tail)) {
        return withheld(true);
    }
    let _ = url.set_username("***");
    if url.password().is_some() {
        let _ = url.set_password(Some("***"));
    }
    url.to_string()
}

/// `text` with every `%XX` escape replaced by a space, for
/// [`url_credentials`] only: what the escape stood for does not matter,
/// only that a scheme after it is not glued to the text before it.
fn unescaped_for_scan(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let escape = after
            .get(..2)
            .filter(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
        out.push(if escape.is_some() { ' ' } else { '%' });
        rest = &after[escape.map_or(0, str::len)..];
    }
    out.push_str(rest);
    out
}

/// The refusal for a lockfile or manifest string that carries URL
/// credentials: the file named, the string redacted.
pub(crate) fn url_credentials_refusal(source: &str, text: &str) -> io::Error {
    url_credentials_refusal_at(source, "", text)
}

/// [`url_credentials_refusal`] naming where in the file the string sits
/// (`dependencies.b`, `packages["node_modules/a"].resolved`), when `path`
/// is not empty.
fn url_credentials_refusal_at(source: &str, path: &str, text: &str) -> io::Error {
    let at = match path {
        "" => String::new(),
        path => format!("{path}: "),
    };
    err(format!(
        "{source}: {at}{} carries URL credentials (user:pass@ before its host); tog will not \
         read a file that holds them",
        redact_url_userinfo(text)
    ))
}

/// Refuse `value`, a parsed `source`, if any string in it (a key or a
/// value, at any depth) carries URL credentials. Every importer runs this
/// on what it read before anything else, so no URL with credentials reaches
/// a plan, a closure, the store's metadata or an error message.
pub(crate) fn refuse_json_url_credentials(
    source: &str,
    value: &serde_json::Value,
) -> io::Result<()> {
    refuse_json_url_credentials_at(source, &mut String::new(), value)
}

/// The fields of a package.json that become dependencies, fetches or tog
/// settings. Only these are held to [`url_credentials`]: a `scripts` entry
/// naming `https://$TOKEN@host` or a username-only `repository` clone URL
/// holds no secret and never reaches a plan.
const PACKAGE_JSON_PLANNED_FIELDS: [&str; 8] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "resolutions",
    "overrides",
    "workspaces",
    "tog",
];

/// [`refuse_json_url_credentials`] for a package.json `source` (the
/// project's, a workspace member's or a linked directory's), over the
/// fields that feed the plan only.
pub(crate) fn refuse_package_json_url_credentials(
    source: &str,
    package: &serde_json::Value,
) -> io::Result<()> {
    PACKAGE_JSON_PLANNED_FIELDS.iter().try_for_each(|field| {
        let Some(value) = package.get(field) else {
            return Ok(());
        };
        refuse_json_url_credentials_at(source, &mut field.to_string(), value)
    })
}

/// [`refuse_json_url_credentials`] for `value`, found at `path` in the file.
fn refuse_json_url_credentials_at(
    source: &str,
    path: &mut String,
    value: &serde_json::Value,
) -> io::Result<()> {
    // Descend into `segment` for `walk`, then restore `path`.
    fn within(
        path: &mut String,
        segment: String,
        walk: impl FnOnce(&mut String) -> io::Result<()>,
    ) -> io::Result<()> {
        let len = path.len();
        path.push_str(&segment);
        let result = walk(path);
        path.truncate(len);
        result
    }
    match value {
        serde_json::Value::String(text) if url_credentials(text) => {
            Err(url_credentials_refusal_at(source, path, text))
        }
        serde_json::Value::Array(items) => items.iter().enumerate().try_for_each(|(at, item)| {
            within(path, format!("[{at}]"), |path| {
                refuse_json_url_credentials_at(source, path, item)
            })
        }),
        serde_json::Value::Object(map) => map.iter().try_for_each(|(key, item)| {
            if url_credentials(key) {
                return Err(url_credentials_refusal_at(source, path, key));
            }
            // A key that reads as a name is joined with a dot; any other is
            // quoted, so `node_modules/a` cannot be read as two segments.
            let plain = !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '$'));
            let segment = match (plain, path.is_empty()) {
                (true, true) => key.clone(),
                (true, false) => format!(".{key}"),
                (false, _) => format!("[{key:?}]"),
            };
            within(path, segment, |path| {
                refuse_json_url_credentials_at(source, path, item)
            })
        }),
        _ => Ok(()),
    }
}

/// Whether `text` holds a URL with credentials anywhere in it: a version, an
/// identity (`a@https://u:p@host/a.tgz`) or a selector as much as a URL.
/// An http(s) URL (`git+` or not) with any userinfo counts, read the way
/// Node's URL parser reads one: slashes and backslashes after the scheme
/// are skipped, so `https:u:p@host` and `https:\\u:p@host` name a host with
/// credentials. Any other `scheme://` counts only with a password, so the
/// `git@` of `git+ssh://git@github.com/o/r.git` is an ssh user, not one.
/// Tab, CR and LF are dropped first, as both parsers drop them anywhere in
/// a URL, so `ht\ttps://to\tken@host` is `https://token@host`.
pub(crate) fn url_credentials(text: &str) -> bool {
    let lower: String = text
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect::<String>()
        .to_ascii_lowercase();
    let authority = |rest: &str| -> String {
        rest.chars()
            .take_while(|c| !matches!(c, '/' | '\\' | '?' | '#') && !c.is_whitespace())
            .collect()
    };
    for (at, _) in lower.match_indices("http") {
        let tail = &lower[at..];
        let Some(rest) = tail
            .strip_prefix("https:")
            .or_else(|| tail.strip_prefix("http:"))
        else {
            continue;
        };
        // A scheme starts the text or follows what cannot end one: `xhttps:`
        // is another scheme, `git+https:` and `a@https:` are not.
        if lower[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            continue;
        }
        if authority(rest.trim_start_matches(['/', '\\'])).contains('@') {
            return true;
        }
    }
    lower.match_indices("://").any(|(at, _)| {
        let host = authority(&lower[at + 3..]);
        host.split_once('@')
            .is_some_and(|(userinfo, _)| userinfo.contains(':'))
    })
}

/// Why a git dependency that is not pinned to a full commit cannot be
/// realized. The wording is persisted verbatim, down to its trailing tag: it
/// is recorded as `git-dependency` exception detail in closures and store
/// object metadata, and a cache hit compares exceptions exactly, so rewording
/// it would make existing store objects refuse with "published concurrently
/// with different exceptions". `tools/hitrate.py` also matches it.
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

/// The first of a lock entry's `libc`, `os` and `cpu` restriction lists that
/// excludes `platform`, by field name; `None` when the host is supported.
/// An absent list is an empty one, which excludes nothing.
///
/// This is the one platform filter: package-lock.json, pnpm-lock.yaml and
/// both hosts read restrictions through it, with npm's list semantics, which
/// pnpm shares. `libc` is judged on Linux only: tog's Linux is glibc, and
/// on macOS the field is ignored (npm itself refuses any `libc` list there,
/// a case no lock for a macOS package has been seen to carry).
pub(super) fn unsupported_restriction(
    platform: Platform,
    os: &[&str],
    cpu: &[&str],
    libc: &[&str],
) -> Option<&'static str> {
    if !platform.is_macos() && !npm_list_compatible(libc, LINUX_LIBC) {
        return Some("libc");
    }
    if !npm_list_compatible(os, platform.npm_os()) {
        return Some("os");
    }
    if !npm_list_compatible(cpu, platform.npm_cpu()) {
        return Some("cpu");
    }
    None
}

/// Whether Node, resolving `name` from the package directory `path`, first
/// meets a workspace link: each enclosing `node_modules`, nearest first.
/// `placed` answers for one project-relative path: `Some(true)` for a link,
/// `Some(false)` for anything else that is really there, `None` for nothing.
pub(super) fn resolves_to_workspace_link(
    placed: &impl Fn(&str) -> Option<bool>,
    path: &str,
    name: &str,
) -> bool {
    let mut dir = path;
    loop {
        // Node never looks inside a directory named node_modules for
        // another node_modules.
        if dir != "node_modules" && !dir.ends_with("/node_modules") {
            let candidate = if dir.is_empty() {
                format!("node_modules/{name}")
            } else {
                format!("{dir}/node_modules/{name}")
            };
            if let Some(link) = placed(&candidate) {
                return link;
            }
        }
        if dir.is_empty() {
            return false;
        }
        dir = dir.rsplit_once('/').map_or("", |(parent, _)| parent);
    }
}

/// The names a manifest or lock entry may resolve at run time.
pub(super) fn dependency_names(entry: &serde_json::Value) -> impl Iterator<Item = &String> {
    ["dependencies", "optionalDependencies", "peerDependencies"]
        .iter()
        .filter_map(|field| entry[*field].as_object())
        .flat_map(|names| names.keys())
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
/// `Ok(false)` means; incompatible required deps are an error, as they are
/// for npm itself (`EBADPLATFORM`).
fn entry_platform_compatible(
    platform: Platform,
    entry: &serde_json::Value,
    path: &str,
) -> io::Result<bool> {
    let values = |field: &str| restriction_values(entry, field).unwrap_or_default();
    let Some(field) =
        unsupported_restriction(platform, &values("os"), &values("cpu"), &values("libc"))
    else {
        return Ok(true);
    };
    if entry["optional"].as_bool() == Some(true) {
        return Ok(false);
    }
    let restriction = if field == "libc" {
        format!(
            "libc restriction {} is incompatible with host {LINUX_LIBC}",
            entry["libc"]
        )
    } else {
        format!("{field} restriction {} is incompatible", entry[field])
    };
    Err(err(format!(
        "{path}: required dependency does not support host {} ({}; npm {}/{}); npm refuses this lock here too (EBADPLATFORM), so make the dependency optional or drop it",
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
    // npm writes a list when a package was published with several hashes:
    // every hash of the strongest algorithm is kept, and the tarball may
    // match any of them.
    let integrity =
        crate::kernel::digest::strongest_sri(integrity).unwrap_or_else(|| integrity.to_string());
    let digests = crate::kernel::digest::sri_candidates(&integrity)?; // validate early
    if digests[0].algo() == "sha1" {
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
    Ok(integrity)
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
        foreign_platform: false,
        needs_workspace: false,
    }
}

/// Mark each package one of whose dependencies is a workspace package. A
/// package-lock names no edges between placements, so the walk Node makes
/// decides, over what this plan really places: a lock entry left out for
/// this platform is not there to stop the walk.
fn mark_workspace_dependents(
    lock: &serde_json::Map<String, serde_json::Value>,
    packages: &mut [NpmPackage],
    links: &[NpmLink],
    bundled: &[&str],
) {
    let mut placed: std::collections::BTreeMap<&str, bool> = links
        .iter()
        .map(|link| (link.path.as_str(), true))
        .collect();
    placed.extend(bundled.iter().map(|path| (*path, false)));
    let paths: Vec<String> = packages.iter().map(|p| p.path.clone()).collect();
    placed.extend(paths.iter().map(|path| (path.as_str(), false)));
    let placed = |path: &str| placed.get(path).copied();
    for package in packages {
        package.needs_workspace = dependency_names(&lock[package.path.as_str()])
            .any(|name| resolves_to_workspace_link(&placed, &package.path, name));
    }
}

impl NpmPackage {
    /// What this package adds to its environment-identity input for its
    /// install scripts. A foreign-platform package's are not run, which
    /// changes the tree a package with scripts leaves behind; the marker is
    /// added only for such a package, so every other identity stands.
    pub(super) fn scripts_identity(&self) -> &'static str {
        if self.foreign_platform {
            ":scripts[not-run]"
        } else {
            ""
        }
    }
}

/// The packages whose install scripts may run, in the order they run:
/// deepest first, so nested deps build before their dependents. A package
/// this host cannot run is files only, because its scripts would build or
/// download for a platform that is not this one.
pub(super) fn lifecycle_candidates(plan: &NpmPlan) -> Vec<&NpmPackage> {
    let mut pkgs: Vec<&NpmPackage> = plan
        .packages
        .iter()
        .filter(|p| !p.foreign_platform)
        .collect();
    pkgs.sort_by_key(|p| std::cmp::Reverse(p.path.matches("node_modules/").count()));
    pkgs
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
    refuse_json_url_credentials("package-lock.json", &v)?;
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
    mark_workspace_dependents(packages, &mut out, &links, &bundled);
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

    /// A list of hashes plans with its strongest entry, whatever the order.
    #[test]
    fn an_integrity_list_plans_with_its_strongest_entry() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        for list in [
            format!("{SHA1_SRI} {TEST_SRI}"),
            format!("{TEST_SRI} {SHA1_SRI}"),
        ] {
            let plan = plan_npm(
                Platform::X86_64UnknownLinuxGnu,
                &entry("node_modules/a", "https://r/a.tgz", &list),
            )
            .unwrap();
            assert_eq!(plan.packages[0].integrity, TEST_SRI);
        }
    }

    /// Two hashes of the strongest algorithm both plan, in one order
    /// whatever the lock's, so the identity does not depend on it (#508).
    #[test]
    fn an_integrity_list_keeps_every_strongest_entry_in_one_order() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let other = format!("sha512-{}", crate::kernel::base64::encode(&[1; 64]));
        let mut both = [TEST_SRI, other.as_str()];
        both.sort_unstable();
        for list in [
            format!("{TEST_SRI} {SHA1_SRI} {other}"),
            format!("{other} {TEST_SRI}"),
        ] {
            let plan = plan_npm(
                Platform::X86_64UnknownLinuxGnu,
                &entry("node_modules/a", "https://r/a.tgz", &list),
            )
            .unwrap();
            assert_eq!(plan.packages[0].integrity, both.join(" "));
        }
        // A malformed entry of the strongest algorithm refuses the list.
        let bad = format!("{TEST_SRI} sha512-!!!");
        assert!(plan_npm(
            Platform::X86_64UnknownLinuxGnu,
            &entry("node_modules/a", "https://r/a.tgz", &bad),
        )
        .is_err());
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
            let message = error.to_string();
            assert!(
                message.starts_with("package-lock.json: ")
                    && message.ends_with(
                        " carries URL credentials (user:pass@ before its host); tog will not \
                         read a file that holds them"
                    ),
                "{resolved}: {message}"
            );
            assert!(
                !message.contains("secret") && !message.contains("token"),
                "{message}"
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

    /// A URL the fetcher cannot parse is still refused for its credentials,
    /// and shown withheld.
    #[test]
    fn an_unparseable_credentialed_url_is_withheld() {
        let error = refused(&entry("node_modules/a", "http://user:secret@", TEST_SRI));
        assert_eq!(
            error.to_string(),
            "package-lock.json: packages[\"node_modules/a\"].resolved: <URL withheld: it may \
             carry credentials> carries URL credentials (user:pass@ before its host); tog will \
             not read a file that holds them"
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    /// Every http(s) userinfo counts, in the spellings Node's parser accepts
    /// (no slashes, extra slashes, backslashes); another scheme counts only
    /// with a password, so `git+ssh://git@host` is a plain git URL.
    #[test]
    fn url_credentials_are_found_in_every_spelling() {
        for text in [
            "https://user:secret@r/a.tgz",
            "https://secret@r/a.tgz",
            "HTTP://u:secret@r",
            "https:user:secret@r/a.tgz",
            "https:\\\\user:secret@r/a.tgz",
            "https:///user:secret@r/a.tgz",
            "git+https://user:secret@github.com/o/r.git#abc",
            "a@https://user:secret@r/a.tgz",
            "git+ssh://user:secret@github.com/o/r.git",
            "see https://u:secret@r here",
            // Both parsers drop tab, CR and LF anywhere in a URL.
            "https://to\tken@r/x",
            "ht\ttps://token@r/x",
            "https://to\r\nken@r/x",
            "https:\n//token@r/x",
        ] {
            assert!(url_credentials(text), "{text}");
        }
        for text in [
            "https://r/a.tgz",
            "https://r/@s/a.tgz",
            "https://r?by=a@b",
            "https://r#a@b",
            "git+ssh://git@github.com/o/r.git",
            "ssh://git@github.com/o/r.git",
            "xhttps://u@r",
            "user@example.com",
            "^1.2.3",
        ] {
            assert!(!url_credentials(text), "{text}");
        }
    }

    /// A lockfile is refused for credentials anywhere in it, not only in a
    /// tarball URL: a git dependency, a key, a dependency spec, and the
    /// spellings Node's parser accepts. The secret is never echoed.
    #[test]
    fn credentials_anywhere_in_package_lock_are_refused_without_the_secret() {
        for packages in [
            r#""node_modules/a":{"version":"1.0.0","resolved":"git+https://user:secret@github.com/o/a.git#0123456789012345678901234567890123456789"}"#,
            r#""node_modules/a":{"version":"1.0.0","resolved":"https:user:secret@r/a.tgz"}"#,
            r#""node_modules/a":{"version":"1.0.0","resolved":"https:\\user:secret@r/a.tgz"}"#,
            r#""node_modules/a":{"version":"1.0.0","dependencies":{"b":"https://user:secret@r/b.tgz"}}"#,
            r#""node_modules/https://user:secret@r":{"version":"1.0.0"}"#,
        ] {
            let error = refused(&lock(packages));
            let message = error.to_string();
            assert!(message.starts_with("package-lock.json: "), "{message}");
            assert!(message.contains(" carries URL credentials "), "{message}");
            assert!(!message.contains("secret"), "{message}");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
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

    /// Redacting the userinfo leaves the rest of a URL as written, so a
    /// second credentialed URL after the host (in the query, the fragment,
    /// or after a space) withholds the whole text.
    #[test]
    fn a_second_credentialed_url_after_the_host_is_withheld() {
        for text in [
            "https://tok@r/a.tgz?next=https://u:secret@h",
            "https://tok@r/a.tgz#https://secret@h",
            "https://u:p@r/a.tgz https://x:secret@y",
            "https://u:p@r/a.tgz https://secret@y",
            "https://u:p@r/a.tgz%20https://secret@y",
            "https://u:p@r/a/https://secret@y",
        ] {
            let shown = redact_url_userinfo(text);
            assert_eq!(shown, "<URL withheld: it may carry credentials>", "{text}");
            let message = url_credentials_refusal("package-lock.json", text).to_string();
            assert!(!message.contains("secret"), "{message}");
        }
        // A scoped path or a plain query is still shown, redacted.
        for (text, shown) in [
            ("https://u:p@r/@s/a.tgz", "https://***:***@r/@s/a.tgz"),
            ("https://u@r/a.tgz?x=1%20y", "https://***@r/a.tgz?x=1%20y"),
        ] {
            assert_eq!(redact_url_userinfo(text), shown, "{text}");
        }
    }

    /// A refusal names the JSON path of the string, keys quoted when they
    /// are not plain names, without the secret.
    #[test]
    fn a_credentials_refusal_names_where_the_string_sits() {
        let error = refused(&lock(
            r#""node_modules/a":{"version":"1.0.0","dependencies":{"b":"https://user:secret@r/b.tgz"}}"#,
        ));
        assert!(
            error.to_string().starts_with(
                "package-lock.json: packages[\"node_modules/a\"].dependencies.b: \
                 https://***:***@r/b.tgz carries URL credentials"
            ),
            "{error}"
        );
        let package: serde_json::Value =
            serde_json::from_str(r#"{"workspaces":["a","https://u:secret@r"]}"#).unwrap();
        let error = refuse_package_json_url_credentials("package.json", &package).unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("package.json: workspaces[1]: https://***:***@r/ carries"),
            "{error}"
        );
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
