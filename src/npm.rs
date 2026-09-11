//! The npm tailor: package-lock.json importer (no solver).
//!
//! npm's lockfile v2/v3 already encodes the complete node_modules tree —
//! every key in "packages" is a literal filesystem path — so planning is
//! pure parsing (no network, no resolution). Realization materializes
//! exactly that tree as an immutable store object; projection is one
//! node_modules symlink.
//!
//! v0 limits: registry tarballs only for installed packages; git sources are
//! classified for NEXT.md item 4, while local/workspace links are projected
//! back into the project. Lifecycle scripts run in the sandbox; failures are
//! retained as exceptions by default.
//!
//! Trust model: the lockfile is a TRUSTED input. Integrity pins every
//! tarball's bytes, but `resolved` URLs choose where the GET goes, so a
//! hostile lockfile is a network capability. A registry allowlist is the
//! M5 control for that.

use crate::fetch::{download_verified_digest_held, download_verified_held, Digest};
use crate::platform::{no_pin, Platform};
use crate::store::Store;
use crate::types::Identity;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn wrap_ensure_node_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("ensure node: {error}"))
}

/// Read the string-valued scripts from a package.json.
pub fn package_scripts(package_json: &str) -> io::Result<BTreeMap<String, String>> {
    let package: serde_json::Value = serde_json::from_str(package_json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("package.json: {e}")))?;
    Ok(package["scripts"]
        .as_object()
        .into_iter()
        .flat_map(|scripts| scripts.iter())
        .filter_map(|(name, command)| {
            command
                .as_str()
                .map(|command| (name.clone(), command.to_string()))
        })
        .collect())
}

/// Resolve one requested package script, rejecting only that script when its
/// package.json value is not a string.
pub fn script_commands_from_package(
    package_json: &str,
    name: &str,
    args: &[String],
) -> io::Result<Option<Vec<(String, String)>>> {
    let package: serde_json::Value = serde_json::from_str(package_json)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("package.json: {e}")))?;
    let Some(scripts) = package["scripts"].as_object() else {
        return Ok(None);
    };
    let Some(command) = scripts.get(name) else {
        return Ok(None);
    };
    if command.as_str().is_none() {
        return Err(err(format!(
            "package.json script {name:?} must be a string"
        )));
    }
    let scripts = scripts
        .iter()
        .filter_map(|(name, command)| {
            command
                .as_str()
                .map(|command| (name.clone(), command.to_string()))
        })
        .collect();
    Ok(script_commands(&scripts, name, args))
}

/// Build npm's pre/name/post script order, appending quoted arguments only
/// to the requested script. Returns None when the requested name is absent.
pub fn script_commands(
    scripts: &BTreeMap<String, String>,
    name: &str,
    args: &[String],
) -> Option<Vec<(String, String)>> {
    let script = scripts.get(name)?;
    let mut commands = Vec::new();
    if let Some(command) = scripts.get(&format!("pre{name}")) {
        commands.push((format!("pre{name}"), command.clone()));
    }
    let mut command = script.clone();
    if !args.is_empty() {
        command.push(' ');
        command.push_str(
            &args
                .iter()
                .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    commands.push((name.to_string(), command));
    if let Some(command) = scripts.get(&format!("post{name}")) {
        commands.push((format!("post{name}"), command.clone()));
    }
    Some(commands)
}

/// Pinned Node.js toolchain (nodejs.org, checksum from SHASUMS256.txt).
pub struct PinnedNode {
    pub platform: Platform,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const NODE_PINS: &[PinnedNode] = &[
    PinnedNode {
        platform: Platform::Aarch64AppleDarwin,
        version: "24.20.0",
        url: "https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz",
        sha256: "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
    },
    PinnedNode {
        platform: Platform::X86_64UnknownLinuxGnu,
        version: "24.20.0",
        url: "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz",
        sha256: "855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec",
    },
];

pub fn node_pin(platform: Platform) -> io::Result<&'static PinnedNode> {
    NODE_PINS
        .iter()
        .find(|pin| pin.platform == platform)
        .ok_or_else(|| no_pin("nodejs", platform, "stage 2"))
}

pub fn preflight(platform: Platform) -> io::Result<()> {
    crate::platform::require_host(platform, "Node.js", "stage 2")?;
    node_pin(platform).map(|_| ())
}

fn node_identity(node: &PinnedNode) -> Identity {
    Identity {
        kind: "nodejs".into(),
        name: "nodejs".into(),
        version: node.version.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), node.sha256.to_string()),
            ("platform".to_string(), node.platform.triple().to_string()),
        ]),
    }
}

fn validate_node_layout(root: &Path) -> io::Result<()> {
    for relative in [
        "bin/node",
        "include/node/node.h",
        "lib/node_modules/npm/bin/npm-cli.js",
        "lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js",
    ] {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Node archive is missing required layout entry {relative}"),
            ));
        }
    }
    Ok(())
}

/// Ensure Node.js is realized in the store (interpreter at <obj>/bin/node).
pub fn ensure_node(store: &Store) -> io::Result<PathBuf> {
    ensure_node_for(store, Platform::host()?)
}

pub fn ensure_node_for(store: &Store, platform: Platform) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "Node.js", "stage 2")?;
    let node = node_pin(platform)?;
    let identity = node_identity(node);
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        validate_node_layout(&store.object_path(&id))?;
        return Ok(store.object_path(&id));
    }
    let tarball = download_verified_held(store, node.url, node.sha256)?;
    let staged = store
        .stage()
        .map_err(|e| io::Error::new(e.kind(), format!("stage: {e}")))?;
    let mut command = Command::new("/usr/bin/tar");
    command
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::supervise::status_owned(&mut command, store)
        .map_err(|e| io::Error::new(e.kind(), format!("spawn tar: {e}")))?;
    if !status.success() {
        return Err(err("node tarball extraction failed"));
    }
    validate_node_layout(&staged)?;
    store
        .commit(&identity, &staged, &[])
        .map(|(path, _)| path)
        .map_err(|e| io::Error::new(e.kind(), format!("commit node object: {e}")))
}

#[derive(Debug, Clone)]
pub struct NpmPackage {
    /// Project-relative lockfile path, e.g. "node_modules/a/node_modules/@s/b"
    /// or "packages/foo/node_modules/a" for a package-local importer.
    pub path: String,
    pub name: String,
    pub version: String,
    pub url: String,
    pub integrity: String, // SRI string
    pub bin: Vec<(String, String)>,
    /// Verified pnpm patch applied to this package after extraction.
    pub patch: Option<NpmPatch>,
    /// A git dependency pinned to a commit (NEXT.md item 4). When set, the
    /// package content comes from the realized git object, not a tarball, and
    /// `integrity` carries `git:<commit>` rather than an SRI.
    pub git: Option<crate::gitsrc::GitSource>,
    /// Install-script failures are kept by default; strict policy makes them
    /// fatal for both optional and required packages.
    pub optional: bool,
}

#[derive(Debug, Clone)]
pub struct NpmPatch {
    /// Canonical absolute path to the patch file in the source project.
    pub path: String,
    /// The lockfile's verified patch hash, included in the environment id.
    pub hash: String,
}

/// A workspace link: `node_modules/<name>` resolving to a source directory
/// inside the project (npm workspaces). Projection-time only — the target
/// is the user's own source, never store content.
#[derive(Debug, Clone)]
pub struct NpmLink {
    /// Lockfile path, e.g. "node_modules/@mono/lib".
    pub path: String,
    /// Project-relative target, e.g. "packages/lib".
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct NpmPlan {
    pub node_version: String,
    pub packages: Vec<NpmPackage>,
    pub links: Vec<NpmLink>,
    /// Actual workspace importer paths. This must not be inferred from every
    /// package placement because local file links can live below node_modules.
    pub workspaces: Vec<String>,
    pub lock_source: String,
}

fn add_node_env_layout_input(inputs: &mut BTreeMap<String, String>, packages: &[NpmPackage]) {
    if packages.is_empty() {
        inputs.insert("layout".into(), "empty-node_modules".into());
    }
}

/// Validate a lockfile "packages" key as a safe, well-formed npm path. A
/// workspace importer is a safe project-relative prefix followed by the same
/// repeated `node_modules/<name>` units used by the root importer.
pub(crate) fn validate_lock_path(path: &str) -> io::Result<()> {
    let bad = || err(format!("malformed lockfile package path: {path}"));
    let ok_name = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s != "node_modules"
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
    };
    let mut comps = path.split('/').peekable();
    // package-lock v2/v3 records workspace packages as
    // `packages/foo/node_modules/bar`. Keep the importer prefix in the plan;
    // realization maps it to the immutable workspace subtree.
    if !path.starts_with("node_modules/") {
        let Some(index) = path.find("/node_modules/") else {
            return Err(bad());
        };
        let prefix = &path[..index];
        let workspace_name = |component: &str| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component != "node_modules"
                && !component.starts_with('.')
                && component.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'@' | b'-' | b'_' | b'.' | b'+')
                })
        };
        if prefix.is_empty()
            || prefix
                .split('/')
                .any(|component| !workspace_name(component))
        {
            return Err(bad());
        }
        comps = path[index + 1..].split('/').peekable();
    }
    while comps.peek().is_some() {
        if comps.next() != Some("node_modules") {
            return Err(bad());
        }
        match comps.next() {
            Some(scope) if scope.starts_with('@') => {
                if !ok_name(&scope[1..]) {
                    return Err(bad());
                }
                match comps.next() {
                    Some(name) if ok_name(name) => {}
                    _ => return Err(bad()),
                }
            }
            Some(name) if ok_name(name) => {}
            _ => return Err(bad()),
        }
    }
    Ok(())
}

/// Return the workspace importer and its importer-relative node_modules path.
/// Root-importer paths return `None`.
fn workspace_path(path: &str) -> Option<(&str, &str)> {
    if path.starts_with("node_modules/") {
        None
    } else {
        let index = path.find("/node_modules/")?;
        Some((&path[..index], &path[index + 1..]))
    }
}

fn encode_workspace_path(workspace: &str) -> String {
    workspace.replace('%', "%25").replace('/', "%2F")
}

/// Map a project-relative package path into the immutable env object's
/// layout. This is also used by lifecycle scripts, which run before the
/// project symlinks are projected.
pub(crate) fn env_package_path(staged: &Path, path: &str) -> PathBuf {
    match workspace_path(path) {
        Some((workspace, relative)) => staged
            .join("workspaces")
            .join(encode_workspace_path(workspace))
            .join(relative),
        None => staged.join(path),
    }
}

fn env_node_modules_path(staged: &Path, path: &str) -> PathBuf {
    match workspace_path(path) {
        Some((workspace, _)) => staged
            .join("workspaces")
            .join(encode_workspace_path(workspace))
            .join("node_modules"),
        None => staged.join("node_modules"),
    }
}

fn importer_relative_path(path: &str) -> &str {
    workspace_path(path)
        .map(|(_, relative)| relative)
        .unwrap_or(path)
}

fn is_importer_top_level(path: &str) -> bool {
    importer_relative_path(path)
        .matches("node_modules/")
        .count()
        == 1
}

fn normalized_bin_path(path: &str) -> io::Result<PathBuf> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(err(format!("unsafe bin target {path:?}")));
    }
    let mut normalized = PathBuf::new();
    for component in path.split('/') {
        if component.is_empty() {
            return Err(err(format!("unsafe bin target {path:?}")));
        }
        if component == ".." {
            return Err(err(format!("unsafe bin target {path:?}")));
        }
        if component != "." {
            normalized.push(component);
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(err(format!("unsafe bin target {path:?}")));
    }
    Ok(normalized)
}

/// Read npm's normalized bin forms from an extracted package. Lockfile bin
/// metadata remains authoritative; realization calls this only when the lock
/// did not provide a mapping (pnpm/yarn normally omit it).
pub(crate) fn discover_package_bins(
    package_json: &str,
    package_name: &str,
    package_dir: &Path,
) -> io::Result<Vec<(String, String)>> {
    let package: serde_json::Value = serde_json::from_str(package_json)
        .map_err(|e| err(format!("{}: package.json: {e}", package_dir.display())))?;
    let mut bins = Vec::new();
    match package.get("bin") {
        Some(value) if value.is_string() => {
            let name = package_name.rsplit('/').next().unwrap_or(package_name);
            bins.push((name.to_string(), value.as_str().unwrap().to_string()));
        }
        Some(value) if value.is_object() => {
            for (name, path) in value.as_object().unwrap() {
                if let Some(path) = path.as_str() {
                    bins.push((name.clone(), path.to_string()));
                }
            }
        }
        Some(_) => {}
        None => {
            let Some(directory) = package["directories"]["bin"].as_str() else {
                return Ok(bins);
            };
            let directory = normalized_bin_path(directory)?;
            let bin_dir = package_dir.join(&directory);
            let entries = match fs::read_dir(&bin_dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(bins),
                Err(error) => return Err(error),
            };
            let mut names = Vec::new();
            for entry in entries {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    names.push((name, directory.join(entry.file_name())));
                }
            }
            names.sort_by(|a, b| a.0.cmp(&b.0));
            bins.extend(
                names
                    .into_iter()
                    .map(|(name, path)| (name, path.to_string_lossy().replace('\\', "/"))),
            );
        }
    }
    bins.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(bins)
}

fn bin_link_target(path: &str, bin: &str) -> PathBuf {
    Path::new("..").join(
        Path::new(importer_relative_path(path))
            .strip_prefix("node_modules/")
            .unwrap_or_else(|_| Path::new(importer_relative_path(path)))
            .join(bin),
    )
}

fn workspace_set(plan: &NpmPlan) -> Vec<String> {
    if !plan.workspaces.is_empty() {
        return plan.workspaces.clone();
    }
    let mut workspaces = BTreeMap::<String, ()>::new();
    for path in plan
        .packages
        .iter()
        .map(|package| package.path.as_str())
        .chain(plan.links.iter().map(|link| link.path.as_str()))
    {
        if let Some((workspace, _)) = workspace_path(path) {
            workspaces.insert(workspace.to_string(), ());
        }
    }
    workspaces.into_keys().collect()
}

fn previous_workspace_set(project_dir: &Path) -> Vec<String> {
    let path = project_dir.join(".blanket/closures/node.json");
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    value["body"]["workspaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|workspace| workspace.as_str().map(str::to_string))
        .collect()
}

fn safe_workspace_path(workspace: &str) -> bool {
    !workspace.is_empty()
        && !workspace.starts_with('/')
        && Path::new(workspace)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn canonical_workspace_parent(path: &Path) -> io::Result<PathBuf> {
    let mut candidate = path.to_path_buf();
    loop {
        match candidate.canonicalize() {
            Ok(path) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                candidate = candidate
                    .parent()
                    .ok_or_else(|| err("workspace path has no existing parent"))?
                    .to_path_buf();
            }
            Err(error) => return Err(error),
        }
    }
}

fn validate_workspace_parents(
    project_dir: &Path,
    previous: &[String],
    current: &[String],
) -> io::Result<()> {
    let project_root = project_dir.canonicalize()?;
    for workspace in previous {
        if !safe_workspace_path(workspace) {
            continue;
        }
        let path = project_dir.join(workspace);
        let canonical = canonical_workspace_parent(&path)?;
        if !canonical.starts_with(&project_root) {
            return Err(err(format!(
                "workspace path {workspace:?} resolves outside the project"
            )));
        }
    }
    for workspace in current {
        if !safe_workspace_path(workspace) {
            return Err(err(format!(
                "workspace path {workspace:?} is not a safe project-relative path"
            )));
        }
        let path = project_dir.join(workspace);
        let canonical = canonical_workspace_parent(&path)?;
        if !canonical.starts_with(&project_root) {
            return Err(err(format!(
                "workspace path {workspace:?} resolves outside the project"
            )));
        }
    }
    Ok(())
}

fn managed_projection_symlink(path: &Path, project_dir: &Path, home: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_symlink() {
        return false;
    }
    let Ok(target) = fs::read_link(path) else {
        return false;
    };
    let target = if target.is_absolute() {
        target
    } else {
        path.parent().unwrap_or(project_dir).join(target)
    };
    // The link itself may have been created through a symlinked TMPDIR
    // (`/tmp` -> `/private/tmp` on macOS). Canonicalize the ownership roots
    // too, otherwise a real target never matches its logical root spelling.
    let target = target.canonicalize().unwrap_or(target);
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    target.starts_with(home.join("forests"))
        || target.starts_with(home.join("store"))
        || target.starts_with(project_dir.join(".blanket/nm"))
}

/// A git source cannot be represented by a registry tarball integrity: GitHub
/// codeload and archive endpoints can change their generated bytes. Keep the
/// diagnostic in one place so all npm lockfile importers classify it equally.
/// A git dependency URL pinned to a full commit, in any of the spellings npm,
/// pnpm and yarn write (NEXT.md item 4). An unpinned ref returns None: the
/// caller reports it rather than guessing which commit was meant.
pub(crate) fn git_source_from_url(url: &str) -> Option<crate::gitsrc::GitSource> {
    let (repo, commit) = git_repo_and_commit(url)?;
    if !crate::gitsrc::is_full_commit(&commit) {
        return None;
    }
    let source = crate::gitsrc::GitSource {
        url: crate::gitsrc::normalize_url(&repo),
        commit: commit.to_ascii_lowercase(),
        subdirectory: None,
    };
    crate::gitsrc::validate_source(&source).ok()?;
    Some(source)
}

/// A dependency that must be realized from git: the lockfile names the git
/// protocol outright. A GitHub archive/codeload tarball is deliberately NOT
/// included — when the lock carries an SRI for it, those bytes are what the
/// lock attests, and a checkout of the same commit can legitimately differ
/// (`.gitattributes` export-ignore/export-subst). Such an entry only falls
/// back to git when the lock gives no integrity to verify.
pub(crate) fn explicit_git_source(url: &str) -> Option<crate::gitsrc::GitSource> {
    url.starts_with("git+")
        .then(|| git_source_from_url(url))
        .flatten()
}

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
fn name_from_path(path: &str) -> String {
    match path.rfind("node_modules/") {
        Some(i) => path[i + "node_modules/".len()..].to_string(),
        None => path.to_string(),
    }
}

/// The Linux host's libc, as npm's `os`/`cpu`/`libc` lists name it. The port
/// targets glibc only (LINUX_PORT.md); musl is a foreign value here.
const LINUX_LIBC: &str = "glibc";

/// A lock entry's `os`/`cpu`/`libc` restriction as npm accepts it: an array
/// of strings, or a bare string standing for a one-element list.
fn restriction_values<'a>(entry: &'a serde_json::Value, field: &str) -> Option<Vec<&'a str>> {
    if let Some(list) = entry[field].as_array() {
        return Some(list.iter().filter_map(|value| value.as_str()).collect());
    }
    entry[field].as_str().map(|value| vec![value])
}

/// npm's `checkList` (npm-install-checks): a sole `any` accepts everything;
/// otherwise a matching `!value` denies, then a matching positive is
/// required if any positives exist, and an all-negated list accepts what
/// it does not exclude.
fn npm_list_compatible(values: &[&str], ours: &str) -> bool {
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

/// Stage 1 Darwin semantics, kept byte-for-byte for this port: only array
/// restrictions count, and any negated entry makes positives irrelevant.
/// (A shared correction to npm's semantics is a separate decision.)
fn darwin_list_compatible(entry: &serde_json::Value, field: &str, ours: &str) -> bool {
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

fn platform_list_compatible(
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
fn libc_compatible(platform: Platform, entry: &serde_json::Value) -> bool {
    if platform.is_macos() {
        return true;
    }
    restriction_values(entry, "libc")
        .map(|values| npm_list_compatible(&values, LINUX_LIBC))
        .unwrap_or(true)
}

/// Parse package-lock.json (lockfileVersion 2 or 3) into a plan.
/// Pure parsing: no network. Deterministic (sorted by path).
pub fn plan_npm(platform: Platform, lock_json: &str) -> io::Result<NpmPlan> {
    let node = node_pin(platform)?;
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
    // node_modules/ (e.g. "packages/lib"). They are the user's own source,
    // not installed content.
    let workspace_dirs: Vec<&str> = packages
        .keys()
        .filter(|p| !p.is_empty() && !p.starts_with("node_modules/"))
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
            let target = entry["resolved"].as_str().unwrap_or_default();
            let ok = !target.is_empty()
                && !target.starts_with('/')
                && target
                    .split('/')
                    .all(|c| !c.is_empty() && c != "." && c != "..");
            if !ok {
                return Err(err(format!("{path}: unsafe link target {target:?}")));
            }
            links.push(NpmLink {
                path: path.clone(),
                target: target.to_string(),
            });
            continue;
        }
        // Bundled deps ship inside the parent tarball (covered by the
        // parent's integrity hash) and carry no resolved/integrity of
        // their own; extraction of the parent materializes them.
        if entry["inBundle"].as_bool() == Some(true) {
            continue;
        }
        // Platform filtering: lock entries carry os/cpu/libc restrictions.
        // Incompatible optional deps are skipped (npm does the same);
        // incompatible required deps are an error. Linux uses npm's list
        // semantics (deny a matching exclusion, then require a matching
        // positive when positives exist), while Darwin keeps its established
        // Stage 1 behavior.
        let os_ok = platform_list_compatible(platform, entry, "os", platform.npm_os());
        let cpu_ok = platform_list_compatible(platform, entry, "cpu", platform.npm_cpu());
        let libc_ok = libc_compatible(platform, entry);
        let compatible = os_ok && cpu_ok && libc_ok;
        if !compatible {
            if entry["optional"].as_bool() == Some(true) {
                skipped.push(format!("{path}/"));
                continue;
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
            return Err(err(format!(
                "{path}: required dependency does not support host {} ({}; npm {}/{})",
                platform.triple(),
                restriction,
                platform.npm_os(),
                platform.npm_cpu()
            )));
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
        // A git dependency pinned to a full commit is realizable (item 4);
        // anything else (a branch, a tag, a bare repo URL) is not, because the
        // bytes it names can change.
        // An explicit git+ URL is always realized from git. Anything else
        // (a codeload/archive tarball) is only realized from git when the lock
        // has no integrity to verify it with.
        let pinned_git = explicit_git_source(resolved).or_else(|| {
            entry["integrity"]
                .as_str()
                .is_none()
                .then(|| git_source_from_url(resolved))
                .flatten()
        });
        if pinned_git.is_none() {
            if let Some(detail) = git_dependency_detail(&name, resolved) {
                if entry["optional"].as_bool() == Some(true) {
                    crate::policy::record(crate::policy::GIT_DEPENDENCY, path, &detail)?;
                    skipped.push(format!("{path}/"));
                    continue;
                }
                return Err(err(format!("{path}: {detail}")));
            }
        }
        if pinned_git.is_none() && !resolved.starts_with("https://") {
            return Err(err(format!(
                "{path}: only https registry tarballs supported (v0), got {resolved}"
            )));
        }
        // A git package's content is verified by the commit hash, so the
        // lockfile carries no SRI for it.
        let integrity = match &pinned_git {
            Some(_) => String::new(),
            None => {
                let integrity = entry["integrity"].as_str().ok_or_else(|| {
                    err(format!(
                        "{path}: missing 'integrity' (regenerate the lockfile)"
                    ))
                })?;
                let digest = Digest::from_sri(integrity)?; // validate early
                if digest.algo() == "sha1" {
                    if let Err(policy_error) = crate::policy::record(
                        crate::policy::WEAK_INTEGRITY,
                        path,
                        "sha1 integrity accepted and verified, but is cryptographically weak",
                    ) {
                        return Err(err(format!(
                            "unsupported integrity algorithm: sha1 ({policy_error})"
                        )));
                    }
                }
                integrity.to_string()
            }
        };
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
        let git = pinned_git;
        out.push(NpmPackage {
            path: path.clone(),
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
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    links.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(NpmPlan {
        node_version: node.version.to_string(),
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
                "package.json {field} disagree with package-lock.json;                  regenerate the lock (npm install --package-lock-only)"
            )));
        }
    }
    Ok(())
}

fn tarball_has_binding_gyp(store: &Store, path: &Path) -> io::Result<bool> {
    let mut command = Command::new("/usr/bin/tar");
    command.args(["-tzf"]).arg(path);
    let output = crate::supervise::output_owned(&mut command, store).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("list npm tarball {}: {e}", path.display()),
        )
    })?;
    if !output.status.success() {
        return Err(err(format!(
            "list npm tarball {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|entry| entry.trim_end_matches('/'))
        .any(|entry| entry == "binding.gyp" || entry.ends_with("/binding.gyp")))
}

const ARCHIVE_CLASSIFICATION_SCHEMA: &str = "npm-archive-classification/1";

fn archive_classification_path(store: &Store, digest: &Digest) -> PathBuf {
    store.cache_path(
        "npm-archive-classification",
        &format!("{}-{}.json", digest.algo(), digest.hex()),
    )
}

/// Read the verified archive inspection result without requiring the archive
/// itself to remain in the download cache. The digest and schema are checked
/// because this file participates in derivation planning.
fn read_archive_classification(store: &Store, digest: &Digest) -> io::Result<Option<bool>> {
    let path = archive_classification_path(store, digest);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "read npm archive classification {}: {error}",
                    path.display()
                ),
            ))
        }
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "parse npm archive classification {}: {error}",
                path.display()
            ),
        )
    })?;
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some(ARCHIVE_CLASSIFICATION_SCHEMA)
        || value.get("digest").and_then(serde_json::Value::as_str)
            != Some(&format!("{}:{}", digest.algo(), digest.hex()))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "npm archive classification {} has the wrong identity",
                path.display()
            ),
        ));
    }
    value
        .get("binding_gyp")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "npm archive classification {} has no binding_gyp result",
                    path.display()
                ),
            )
        })
        .map(Some)
}

fn write_archive_classification(
    store: &Store,
    digest: &Digest,
    binding_gyp: bool,
) -> io::Result<()> {
    if let Some(existing) = read_archive_classification(store, digest)? {
        if existing != binding_gyp {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "npm archive classification changed for {}:{}",
                    digest.algo(),
                    digest.hex()
                ),
            ));
        }
        return Ok(());
    }

    let destination = archive_classification_path(store, digest);
    fs::create_dir_all(destination.parent().expect("classification cache parent"))?;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let temporary = store.root.join("tmp").join(format!(
        "npm-archive-classification-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let value = serde_json::json!({
        "schema": ARCHIVE_CLASSIFICATION_SCHEMA,
        "digest": format!("{}:{}", digest.algo(), digest.hex()),
        "binding_gyp": binding_gyp,
    });
    fs::write(&temporary, serde_json::to_vec(&value)?)?;
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
    }
    match fs::rename(&temporary, &destination) {
        Ok(()) => Ok(()),
        Err(_) if destination.is_file() => {
            let _ = fs::remove_file(&temporary);
            match read_archive_classification(store, digest)? {
                Some(existing) if existing == binding_gyp => Ok(()),
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "npm archive classification changed for {}:{}",
                        digest.algo(),
                        digest.hex()
                    ),
                )),
                None => Err(io::Error::other(
                    "npm archive classification disappeared during publication",
                )),
            }
        }
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "publish npm archive classification {}: {error}",
                destination.display()
            ),
        )),
    }
}

fn persisted_archive_classification(
    store: &Store,
    packages: &[NpmPackage],
) -> io::Result<Option<bool>> {
    let mut has_native = false;
    for package in packages {
        // A git package is realized from its commit, not a tarball: its
        // binding.gyp is visible in the object once realized, and until then
        // the classification is unknown.
        if let Some(source) = &package.git {
            let object = store.object_path(&crate::gitsrc::object_id(source));
            if !object.is_dir() {
                return Ok(None);
            }
            has_native |= object.join("binding.gyp").is_file();
            continue;
        }
        let digest = Digest::from_sri(&package.integrity)?;
        let Some(binding_gyp) = read_archive_classification(store, &digest)? else {
            return Ok(None);
        };
        has_native |= binding_gyp;
    }
    Ok(Some(has_native))
}

fn classify_downloaded_archives(
    store: &Store,
    tarballs: &[(&NpmPackage, crate::fetch::CacheLease)],
) -> io::Result<bool> {
    let mut has_native = false;
    for (package, tarball) in tarballs {
        let digest = Digest::from_sri(&package.integrity)?;
        // The tarball was returned by download_verified_digest, so inspect the
        // verified bytes and persist the result before planning the identity.
        let binding_gyp = tarball_has_binding_gyp(store, tarball)?;
        write_archive_classification(store, &digest, binding_gyp)?;
        has_native |= binding_gyp;
    }
    Ok(has_native)
}

fn fetch_npm_tarballs<'a>(
    store: &Store,
    packages: &'a [NpmPackage],
) -> io::Result<Vec<(&'a NpmPackage, crate::fetch::CacheLease)>> {
    packages
        .iter()
        .filter(|p| p.git.is_none())
        .map(|p| {
            let digest = Digest::from_sri(&p.integrity)?;
            let tarball = download_verified_digest_held(store, &p.url, &digest).map_err(|e| {
                io::Error::new(e.kind(), format!("{}: fetch {}: {e}", p.path, p.url))
            })?;
            Ok((p, tarball))
        })
        .collect()
}

fn native_libs_identity_id(
    store: &Store,
    platform: Platform,
    has_native: bool,
) -> io::Result<Option<String>> {
    if has_native && matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        Ok(Some(crate::nativelibs::object_id_for(store, platform)?))
    } else {
        Ok(None)
    }
}

/// Realize the node_modules tree as an immutable store object.
/// Object content root contains exactly `node_modules/`.
pub fn realize_node_env(
    store: &Store,
    platform: Platform,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
) -> io::Result<PathBuf> {
    crate::platform::require_host(platform, "node environment", "stage 2")?;
    let node_obj = ensure_node_for(store, platform).map_err(wrap_ensure_node_error)?;
    realize_node_env_with_node_object(store, platform, plan, artifacts, &node_obj)
}

fn node_env_identity(
    store: &Store,
    platform: Platform,
    node_obj: &Path,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    native_libs_id: Option<&str>,
) -> io::Result<Identity> {
    let mut inputs = BTreeMap::new();
    // /3: install scripts run sandboxed; name@version joined the per-pkg
    // identity (they reach scripts as npm_package_* env). Remaining known
    // impurity, documented: host Xcode/SDK version is not fingerprinted
    // (same standing as python sdist builds).
    inputs.insert("schema".to_string(), "node-env/3".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert(
        "nodejs".to_string(),
        node_obj.file_name().unwrap().to_string_lossy().into_owned(),
    );
    add_node_env_layout_input(&mut inputs, &plan.packages);
    let workspaces = workspace_set(plan);
    inputs.insert("workspaces".into(), workspaces.join("|"));
    for p in &plan.packages {
        // A git package has no registry tarball: its content is the realized
        // commit, so the git object id takes the digest's place.
        let content = match &p.git {
            Some(source) => format!("git:{}", crate::gitsrc::object_id(source)),
            None => {
                let digest = Digest::from_sri(&p.integrity)?;
                format!("{}:{}", digest.algo(), digest.hex())
            }
        };
        // bin mappings change the realized tree, so they are identity inputs.
        let mut bins: Vec<String> = p.bin.iter().map(|(k, v)| format!("{k}={v}")).collect();
        bins.sort();
        if inputs
            .insert(
                format!("pkg:{}", p.path),
                format!(
                    "{}:{}@{}:patch[{}]:bin[{}]",
                    content,
                    p.name,
                    p.version,
                    p.patch
                        .as_ref()
                        .map(|patch| patch.hash.as_str())
                        .unwrap_or(""),
                    bins.join(",")
                ),
            )
            .is_some()
        {
            return Err(err(format!("duplicate lockfile path: {}", p.path)));
        }
    }
    // A provisioned artifact is a build input too: a GitHub release asset can
    // be replaced, so the package version alone does not determine the bytes
    // that reach the install script.
    for p in &plan.packages {
        if let Some(input) =
            crate::artifacts::provisioned_identity_input(store, platform, &p.name, &p.version)?
        {
            inputs.insert(format!("provisioned:{}", p.path), input);
        }
    }
    // Declared artifacts are build inputs: they change what install
    // scripts produce, so they are part of the identity.
    for a in artifacts {
        if inputs
            .insert(format!("artifact:{}", a.path), a.sha256.clone())
            .is_some()
        {
            return Err(err(format!("duplicate artifact path: {}", a.path)));
        }
    }
    if let Some(native_libs_id) = native_libs_id {
        inputs.insert("native_libs".into(), native_libs_id.into());
    }
    Ok(Identity {
        kind: "node-env".into(),
        name: "env".into(),
        version: plan.node_version.clone(),
        inputs,
    })
}

fn realize_node_env_with_node_object(
    store: &Store,
    platform: Platform,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    node_obj: &Path,
) -> io::Result<PathBuf> {
    // Linux needs archive inspection to decide whether node-gyp will mount the
    // native library set. The inspection result is persisted by archive
    // digest, so a warm environment can be identified before its tarballs are
    // fetched. Darwin deliberately does not mount this Linux-only set.
    let mut classification_tarballs: Vec<(&NpmPackage, crate::fetch::CacheLease)> = Vec::new();
    let native_libs_id = if platform.is_macos() {
        None
    } else {
        let has_native = match persisted_archive_classification(store, &plan.packages)? {
            Some(has_native) => has_native,
            None => {
                classification_tarballs = fetch_npm_tarballs(store, &plan.packages)?;
                classify_downloaded_archives(store, &classification_tarballs)?
            }
        };
        native_libs_identity_id(store, platform, has_native)?
    };
    let identity = node_env_identity(
        store,
        platform,
        node_obj,
        plan,
        artifacts,
        native_libs_id.as_deref(),
    )?;
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    let workspaces = workspace_set(plan);
    // A warm sync returned at the cache lookup above, so reaching here means a
    // cold realization. Take a lease on every tarball so gc cannot collect the
    // cached bytes mid-extraction; peer snapshots are separate graph nodes that
    // normally share one registry tarball, so deduplicate the byte fetch while
    // keeping extraction and placement per physical lockfile path.
    drop(classification_tarballs);
    let mut leases: Vec<crate::fetch::CacheLease> = Vec::new();
    let mut tarballs: Vec<(NpmPackage, PathBuf)> = Vec::new();
    let mut git_objects: Vec<(NpmPackage, PathBuf)> = Vec::new();
    let mut downloaded = BTreeMap::<(String, String), PathBuf>::new();
    for p in &plan.packages {
        // Git dependencies are realized as their own store objects; the loop
        // below extracts tarballs, so they are collected separately.
        if let Some(source) = &p.git {
            let object = crate::gitsrc::ensure_git_source(store, source).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: git source {}: {e}", p.path, source.url),
                )
            })?;
            crate::policy::record(
                crate::policy::GIT_DEPENDENCY,
                &format!("{}@{}", p.name, p.version),
                &format!("{} at {}", source.url, source.commit),
            )?;
            git_objects.push((p.clone(), object));
            continue;
        }
        let digest = Digest::from_sri(&p.integrity)?;
        let cache_key = (p.url.clone(), p.integrity.clone());
        let t = if let Some(t) = downloaded.get(&cache_key) {
            t.clone()
        } else {
            let lease = download_verified_digest_held(store, &p.url, &digest).map_err(|e| {
                io::Error::new(e.kind(), format!("{}: fetch {}: {e}", p.path, p.url))
            })?;
            let path = lease.to_path_buf();
            leases.push(lease);
            downloaded.insert(cache_key, path.clone());
            path
        };
        tarballs.push((p.clone(), t));
    }

    let native_libs = if native_libs_id.is_some() {
        Some(crate::nativelibs::ensure_native_libs(store, platform)?)
    } else {
        None
    };

    let staged = store.stage()?;
    fs::create_dir_all(staged.join("node_modules"))?;
    for workspace in &workspaces {
        fs::create_dir_all(
            staged
                .join("workspaces")
                .join(encode_workspace_path(workspace))
                .join("node_modules"),
        )?;
    }
    // Parents before children (path depth = lexicographic prefix ordering
    // already holds after sort, since "a/node_modules/b" sorts after "a").
    for (p, tarball) in &mut tarballs {
        let dest = env_package_path(&staged, &p.path);
        fs::create_dir_all(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: create dir: {e}", p.path)))?;
        let mut tar = Command::new("/usr/bin/tar");
        tar.arg("-xzf")
            .arg(tarball)
            .arg("-C")
            .arg(&dest)
            .args(["--strip-components", "1"]);
        if !platform.is_macos() {
            // Registry tarballs are packed by arbitrary publishers; some
            // (pngjs, eta 1.x) carry directories with mode 0666. bsdtar
            // (macOS) descends into them anyway; GNU tar creates the
            // directory 0666 and then cannot open its children unless
            // directory modes are applied after extraction. normalize_modes
            // below rewrites every mode afterwards, so the store content is
            // identical either way (LINUX_PORT.md, stage 5 follow-up).
            tar.arg("--delay-directory-restore");
        }
        let status = crate::supervise::status_owned(&mut tar, store)?;
        if !status.success() {
            return Err(err(format!("{}: tarball extraction failed", p.path)));
        }
        normalize_modes(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: normalize modes: {e}", p.path)))?;
        if let Some(patch) = &p.patch {
            let patch_path = Path::new(&patch.path);
            let patch_bytes = fs::read(patch_path).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: read verified patch {}: {e}", p.path, patch.path),
                )
            })?;
            use sha2::Digest as _;
            let actual = hex::encode(sha2::Sha256::digest(&patch_bytes));
            let expected = patch.hash.strip_prefix("sha256-").unwrap_or(&patch.hash);
            if expected.len() != 64 || !expected.eq_ignore_ascii_case(&actual) {
                return Err(err(format!(
                    "{}: patch {} changed after lock verification (expected {}, got {})",
                    p.path, patch.path, patch.hash, actual
                )));
            }
            let file = fs::File::open(patch_path)?;
            let mut command = Command::new("/usr/bin/patch");
            command
                .args(["-p1", "--batch", "--forward"])
                .current_dir(&dest)
                .stdin(file);
            let status = crate::supervise::status_owned(&mut command, store).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: spawn /usr/bin/patch for {}: {e}", p.path, patch.path),
                )
            })?;
            if !status.success() {
                return Err(err(format!(
                    "{}: applying patch {} failed",
                    p.path, patch.path
                )));
            }
            normalize_modes(&dest).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("{}: normalize patched modes: {e}", p.path),
                )
            })?;
        }
        if p.bin.is_empty() {
            if let Ok(manifest) = fs::read_to_string(dest.join("package.json")) {
                p.bin = discover_package_bins(&manifest, &p.name, &dest)?;
            }
        }
        // ponytail: post-extraction size cap (1 GiB/package) — catches
        // decompression bombs after the fact; a streaming extractor with
        // preflight limits is the M5 upgrade. Lockfiles are trusted inputs.
        if dir_size(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: size walk: {e}", p.path)))?
            > 1 << 30
        {
            return Err(err(format!(
                "{}: package expands past 1 GiB; refusing",
                p.path
            )));
        }
    }

    // Git packages: the realized commit IS the package content. npm would run
    // the package's `prepare` script here (git deps are installed from source);
    // blanket does not, because that script is unsandboxed build logic with its
    // own dependency needs — the exception says so rather than pretending.
    for (p, object) in &mut git_objects {
        let dest = env_package_path(&staged, &p.path);
        let source_root = match &p.git.as_ref().and_then(|g| g.subdirectory.clone()) {
            Some(subdir) => {
                crate::npm::validate_lock_path(subdir).map_err(|e| {
                    io::Error::new(e.kind(), format!("{}: subdirectory {subdir}: {e}", p.path))
                })?;
                object.join(subdir)
            }
            None => object.clone(),
        };
        if !source_root.is_dir() {
            return Err(err(format!(
                "{}: {} is not a directory in the git source",
                p.path,
                source_root.display()
            )));
        }
        // `cp -a src dest` copies INTO dest when dest already exists, which it
        // does whenever this package has nested dependencies (their directories
        // are created first). Copy into a fresh sibling and move it into place.
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&dest)?;
        let staging = dest.with_file_name(format!(
            ".blanket-git-{}",
            dest.file_name().and_then(|n| n.to_str()).unwrap_or("pkg")
        ));
        let _ = crate::store::remove_tree(&staging);
        crate::project::clone_tree_for_store(store, &source_root, &staging, platform)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: copy git source: {e}", p.path)))?;
        for entry in fs::read_dir(&staging)? {
            let entry = entry?;
            fs::rename(entry.path(), dest.join(entry.file_name()))?;
        }
        let _ = crate::store::remove_tree(&staging);
        normalize_modes(&dest)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: normalize modes: {e}", p.path)))?;
        let manifest = fs::read_to_string(dest.join("package.json")).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("{}: git source has no package.json: {e}", p.path),
            )
        })?;
        if serde_json::from_str::<serde_json::Value>(&manifest)
            .ok()
            .and_then(|value| value["scripts"]["prepare"].as_str().map(str::to_string))
            .is_some()
        {
            crate::policy::record(
                crate::policy::GIT_DEPENDENCY,
                &format!("{}@{}", p.name, p.version),
                "package has a `prepare` script; blanket does not run it for git sources",
            )?;
        }
        if p.bin.is_empty() {
            p.bin = discover_package_bins(&manifest, &p.name, &dest)?;
        }
    }
    let mut tarballs = tarballs;
    tarballs.append(&mut git_objects);

    // .bin launchers for physically top-level (hoisted) packages, which is
    // what node_modules/.bin holds in npm's own layout.
    for (p, _) in &tarballs {
        if !is_importer_top_level(&p.path) || p.bin.is_empty() {
            continue;
        }
        let bin_dir = env_node_modules_path(&staged, &p.path).join(".bin");
        fs::create_dir_all(&bin_dir)?;
        for (bin_name, rel) in &p.bin {
            // bin metadata comes from the lockfile (attacker-editable), so
            // it is validated hard: single normal name component, relative
            // target with only normal components, canonical target inside
            // the package directory, not a symlink.
            let name_ok = !bin_name.is_empty()
                && !bin_name.starts_with('.')
                && !bin_name.contains('/')
                && !bin_name.contains('\\');
            let rel_path = normalized_bin_path(rel);
            if !name_ok || rel_path.is_err() {
                return Err(err(format!(
                    "{}: unsafe bin entry {bin_name:?} -> {rel:?}",
                    p.path
                )));
            }
            let rel_path = rel_path.unwrap();
            let pkg_dir = env_package_path(&staged, &p.path);
            let target_file = pkg_dir.join(&rel_path);
            let md = match fs::symlink_metadata(&target_file) {
                Ok(md) => md,
                Err(_) => continue, // bin target genuinely absent: npm tolerates this
            };
            if !md.is_file() {
                return Err(err(format!(
                    "{}: bin target {rel} is not a regular file",
                    p.path
                )));
            }
            let canon = target_file.canonicalize()?;
            if !canon.starts_with(pkg_dir.canonicalize()?) {
                return Err(err(format!(
                    "{}: bin target {rel} escapes the package directory",
                    p.path
                )));
            }
            // Relative link: node_modules/.bin/x -> ../<name>/<rel>
            // Relative link: <importer>/node_modules/.bin/x -> ../<name>/<rel>.
            let link_target = bin_link_target(&p.path, &rel_path.to_string_lossy());
            let link = bin_dir.join(bin_name);
            if link.symlink_metadata().is_ok() {
                // Real graphs collide (playwright + @playwright/test both
                // declare `playwright`). npm keeps the first hoisted claim;
                // plan order is sorted, so first-wins is deterministic.
                eprintln!(
                    "blanket: warning: bin {bin_name:?} already claimed; \
                     skipping the one from {}",
                    p.path
                );
                continue;
            }
            std::os::unix::fs::symlink(&link_target, &link)?;
            use std::os::unix::fs::PermissionsExt;
            let mut perms = md.permissions();
            perms.set_mode(perms.mode() | 0o755);
            fs::set_permissions(&target_file, perms)?;
        }
    }

    // Lifecycle setup may fetch declared artifacts and a pinned Python for
    // node-gyp; the package tarballs have already been fully extracted.
    drop(tarballs);
    run_install_scripts(
        store,
        platform,
        &staged,
        &node_obj,
        plan,
        artifacts,
        native_libs.as_ref().map(|set| set.path.as_path()),
    )?;

    let candidate = crate::policy::object_exceptions();
    let (object, applied) = store
        .commit(&identity, &staged, &candidate)
        .map_err(|e| io::Error::new(e.kind(), format!("commit env: {e}")))?;
    for exception in applied {
        if !candidate.contains(&exception) {
            crate::policy::record(&exception.kind, &exception.subject, &exception.detail)?;
        }
    }
    Ok(object)
}

/// npm lifecycle install scripts, run hermetically: network denied, writes
/// confined to the package's own directory and a scratch dir, reads limited
/// to the staged tree + node toolchain + system. This is what makes native
/// addons (better-sqlite3, bcrypt) work: prebuilt-binary downloads fail
/// closed and the node-gyp source fallback compiles offline against the
/// store's node headers.
///
/// npm semantics mirrored: preinstall/install/postinstall in that order;
/// packages with a binding.gyp and no install script get the default
/// `node-gyp rebuild`. A failure is an exception by default, while strict
/// policy preserves the fail-closed behavior. Isolation per package: a fresh
/// scratch HOME each, tool shims in a directory scripts cannot write,
/// declared artifacts planted per consuming HOME.
enum LifecycleFailure {
    SandboxUnavailable(io::Error),
    Script(io::Error),
}

fn classify_lifecycle_result(result: io::Result<()>) -> Result<(), LifecycleFailure> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::Unsupported => {
            Err(LifecycleFailure::SandboxUnavailable(error))
        }
        Err(error) => Err(LifecycleFailure::Script(error)),
    }
}

fn run_install_scripts(
    store: &Store,
    platform: Platform,
    staged: &Path,
    node_obj: &Path,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    native_libs: Option<&Path>,
) -> io::Result<()> {
    // Scratch stage dirs (tool shims, per-package HOMEs, snapshots) are
    // removed on every exit, including the fatal Unsupported paths (missing
    // Linux pin, unavailable sandbox backend) that return early.
    let mut cleanup: Vec<PathBuf> = Vec::new();
    let result = run_install_scripts_staged(
        store,
        platform,
        staged,
        node_obj,
        plan,
        artifacts,
        native_libs,
        &mut cleanup,
    );
    for t in cleanup {
        let _ = crate::store::remove_tree(&t);
    }
    result
}

fn run_install_scripts_staged(
    store: &Store,
    platform: Platform,
    staged: &Path,
    node_obj: &Path,
    plan: &NpmPlan,
    artifacts: &[DeclaredArtifact],
    native_libs: Option<&Path>,
    cleanup: &mut Vec<PathBuf>,
) -> io::Result<()> {
    let activity = store.activity(crate::activity::ActivityMode::Shared)?;
    // Deepest first: nested deps build before their dependents.
    let mut pkgs: Vec<&NpmPackage> = plan.packages.iter().collect();
    pkgs.sort_by_key(|p| std::cmp::Reverse(p.path.matches("node_modules/").count()));

    // Tools live in their own stage dir which is NOT in the sandbox write
    // list — a script can execute the node-gyp shim but never replace it.
    let mut tools: Option<PathBuf> = None;
    // node-gyp needs a Python; the store's pinned CPython keeps builds off
    // the system toolchain drift. Realized lazily, only when needed.
    let mut python_obj: Option<PathBuf> = None;
    for p in &pkgs {
        let pkg_dir = env_package_path(staged, &p.path);
        let manifest = match fs::read_to_string(pkg_dir.join("package.json")) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let manifest: serde_json::Value = match serde_json::from_str(&manifest) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let scripts = &manifest["scripts"];
        let has = |k: &str| scripts[k].as_str().is_some();
        let default_gyp =
            !has("install") && !has("preinstall") && pkg_dir.join("binding.gyp").exists();
        if !has("preinstall") && !has("install") && !has("postinstall") && !default_gyp {
            continue;
        }

        let tools_dir = match &tools {
            Some(t) => t.clone(),
            None => {
                // A store stage dir: collision-proof and already canonical
                // (Seatbelt matches real paths).
                let t = store.stage()?;
                // node-gyp shim: npm normally injects this into PATH.
                let bin = t.join("bin");
                fs::create_dir_all(&bin)?;
                let gyp_js =
                    node_obj.join("lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js");
                fs::write(
                    bin.join("node-gyp"),
                    format!(
                        "#!/bin/sh\nexec \"{}\" \"{}\" \"$@\"\n",
                        node_obj.join("bin/node").display(),
                        gyp_js.display()
                    ),
                )?;
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(bin.join("node-gyp"), fs::Permissions::from_mode(0o755))?;
                cleanup.push(t.clone());
                tools.insert(t).clone()
            }
        };
        // Fresh scratch HOME per package: no shared writable state between
        // one package's scripts and the next.
        let tmp = store.stage()?;
        cleanup.push(tmp.clone());
        // Plant declared artifacts where this package's installer looks
        // (paths are HOME-relative; HOME is this scratch dir).
        for a in artifacts {
            let src = download_verified_held(store, &a.url, &a.sha256).map_err(|e| {
                io::Error::new(e.kind(), format!("declared artifact {}: {e}", a.url))
            })?;
            let dest = tmp.join(&a.path);
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::copy(&src, &dest).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("placing declared artifact {}: {e}", a.path),
                )
            })?;
        }

        let phases: Vec<(&str, String)> = ["preinstall", "install", "postinstall"]
            .iter()
            .filter_map(|ph| match scripts[*ph].as_str() {
                Some(s) => Some((*ph, s.to_string())),
                None if *ph == "install" && default_gyp => {
                    Some((*ph, "node-gyp rebuild".to_string()))
                }
                None => None,
            })
            .collect();

        // Snapshot lives in its own stage dir: neither readable nor writable
        // inside the sandbox, so a failing script cannot tamper with what
        // gets restored (Sol, item 3 round 2).
        let snapshot_root = store.stage()?;
        cleanup.push(snapshot_root.clone());
        let snapshot = snapshot_root.join("package");
        crate::project::clone_tree_for_store(store, &pkg_dir, &snapshot, platform)?;

        let python = match &python_obj {
            Some(p) => p.clone(),
            None => {
                let pin = crate::python::lookup(platform, "3.12")
                    .ok_or_else(|| crate::platform::no_pin("cpython 3.12", platform, "stage 2"))?;
                let p = crate::python::ensure_python_for(store, pin, platform).map_err(|e| {
                    io::Error::new(e.kind(), format!("ensure python for node-gyp: {e}"))
                })?;
                python_obj.insert(p).clone()
            }
        };
        let python_bin = python.join("bin/python3");

        let nearest_bin = env_node_modules_path(staged, &p.path).join(".bin");
        let root_bin = staged.join("node_modules/.bin");
        let mut path_entries = vec![
            tools_dir.join("bin").display().to_string(),
            node_obj.join("bin").display().to_string(),
            nearest_bin.display().to_string(),
        ];
        if nearest_bin != root_bin {
            path_entries.push(root_bin.display().to_string());
        }
        path_entries.extend([
            "/usr/bin".into(),
            "/bin".into(),
            "/usr/sbin".into(),
            "/sbin".into(),
        ]);
        let path_env = path_entries.join(":");
        let mut envs: Vec<(String, String)> = vec![
            ("PYTHON".into(), python_bin.display().to_string()),
            ("npm_config_python".into(), python_bin.display().to_string()),
            ("npm_config_nodedir".into(), node_obj.display().to_string()),
            (
                "npm_config_node_gyp".into(),
                node_obj
                    .join("lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js")
                    .display()
                    .to_string(),
            ),
            // NOTE: npm_config_build_from_source is not set globally here: it
            // would make packages like sharp skip their local-cache lookup
            // (where declared artifacts land). It is set per package, below,
            // only for prebuilt-binary downloaders with no declared artifacts
            // (NEXT.md item 5).
            // Deterministic npm cache location inside the scratch HOME —
            // also where declared artifacts under .npm/ land.
            (
                "npm_config_cache".into(),
                tmp.join(".npm").display().to_string(),
            ),
            ("npm_package_name".into(), p.name.clone()),
            ("npm_package_version".into(), p.version.clone()),
        ];
        if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
            // python-build-standalone's sysconfig may name clang even though
            // Linux node-gyp is intentionally built with the host toolchain.
            // The sandbox cleared the inherited environment, so these are the
            // only compiler selections visible to the lifecycle process.
            envs.push(("CC".into(), "gcc".into()));
            envs.push(("CXX".into(), "g++".into()));
        }
        // NEXT.md item 5: packages whose installers download at install time.
        // A documented skip switch turns a doomed fetch into a recorded
        // exception naming what the user runs later; a prebuilt-binary
        // downloader is told to compile instead, which is the path it would
        // have fallen back to anyway once the network denied it.
        let script_text = phases
            .iter()
            .map(|(_, script)| script.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        // Only artifacts planted for THIS package suppress the source build:
        // one declared artifact anywhere must not silently change how every
        // other package installs.
        let declared_here = artifacts.iter().any(|a| {
            a.path.split('/').any(|segment| segment == p.name)
                || a.url.contains(&format!("/{}/", p.name))
        });
        // Provisioning comes first: if blanket can supply the artifact, the
        // package is really installed rather than skipped.
        match crate::artifacts::provision(store, platform, &p.name, &p.version, &tmp) {
            Ok(Some(provisioning)) => {
                envs.extend(provisioning.envs);
                for (subject, detail) in &provisioning.records {
                    crate::policy::record(crate::policy::ARTIFACT_PROVISIONED, subject, detail)?;
                }
            }
            Ok(None) => {}
            Err(error) => {
                // A provisioning failure is not fatal: the install script still
                // runs and fails loudly on its own if it needs the artifact.
                eprintln!(
                    "blanket: {}: could not provision its artifact: {error}",
                    p.name
                );
                crate::policy::record(
                    crate::policy::ARTIFACT_NOT_PROVISIONED,
                    &format!("{}@{}", p.name, p.version),
                    &format!("provisioning failed: {error}"),
                )?;
            }
        }
        if let Some(skip) = crate::artifacts::skip_download_for(&p.name) {
            for (key, value) in skip.envs {
                envs.push(((*key).to_string(), (*value).to_string()));
            }
            crate::policy::record(
                crate::policy::ARTIFACT_NOT_PROVISIONED,
                &format!("{}@{}", p.name, p.version),
                &format!("install-time download skipped; run: {}", skip.hint),
            )?;
        } else if crate::artifacts::wants_source_build(&script_text, declared_here) {
            envs.extend(crate::artifacts::source_build_envs());
            crate::policy::record(
                crate::policy::BUILT_FROM_SOURCE,
                &format!("{}@{}", p.name, p.version),
                "prebuilt binary not downloaded; compiled from source in the sandbox",
            )?;
        }
        envs.push(("PATH".into(), path_env.clone()));
        if let Some(native_libs) = native_libs {
            envs = crate::nativelibs::compose_env(native_libs, &envs);
        }
        let path_env = envs
            .iter()
            .find(|(key, _)| key == "PATH")
            .map(|(_, value)| value.as_str())
            .unwrap_or("/usr/bin:/bin");
        // Tools dir is readable+executable but NOT writable in-sandbox.
        let sandbox = crate::sandbox::Sandbox {
            read: vec![staged, node_obj, &python, &tools_dir]
                .into_iter()
                .chain(native_libs)
                .collect(),
            write: vec![&pkg_dir, &tmp],
        };
        for (phase, script) in &phases {
            eprintln!("blanket: {} {}: {phase} (sandboxed)", p.name, p.version);
            let envs_phase: Vec<(String, String)> = envs
                .iter()
                .cloned()
                .chain([("npm_lifecycle_event".to_string(), phase.to_string())])
                .collect();
            let result = sandbox.run_in_on_with_activity(
                platform,
                &["/bin/sh", "-c", script],
                &path_env,
                &tmp,
                &pkg_dir,
                &envs_phase,
                &activity,
            );
            // A missing sandbox backend is never a script failure: it must
            // not become a permissive install-script-failed exception.
            let e = match classify_lifecycle_result(result) {
                Ok(()) => continue,
                Err(LifecycleFailure::SandboxUnavailable(e)) => return Err(e),
                Err(LifecycleFailure::Script(e)) => e,
            };
            let hint = "If this package downloads files at install time, declare them as verified inputs in package.json — \
                        \"blanket\": {\"artifacts\": [{\"url\", \"sha256\", \"path\"}]} — \
                        placed where the package's downloader caches them (see README).";
            let error = e.to_string();
            let detail = format!(
                "{phase}: {}. {hint}",
                error.chars().take(300).collect::<String>()
            );
            if let Err(policy_error) =
                crate::policy::record(crate::policy::INSTALL_SCRIPT_FAILED, &p.path, &detail)
            {
                return Err(err(format!(
                    "{}: {phase} script failed under the network-denied build \
                     sandbox: {e}. {hint} ({policy_error})",
                    p.path
                )));
            }
            crate::store::remove_tree(&pkg_dir)?;
            fs::rename(&snapshot, &pkg_dir)?;
            remove_dangling_bin_links(staged, plan)?;
            break;
        }
    }
    Ok(())
}

fn remove_dangling_bin_links(staged: &Path, plan: &NpmPlan) -> io::Result<()> {
    let mut bin_dirs = vec![staged.join("node_modules/.bin")];
    bin_dirs.extend(workspace_set(plan).into_iter().map(|workspace| {
        staged
            .join("workspaces")
            .join(encode_workspace_path(&workspace))
            .join("node_modules/.bin")
    }));
    for bin_dir in bin_dirs {
        let entries = match fs::read_dir(&bin_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in entries {
            let path = entry?.path();
            if fs::symlink_metadata(&path)?.file_type().is_symlink() && !path.exists() {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

/// A project-declared build input: a URL + sha256 that blanket prefetches
/// into the verified artifact cache and plants at `path` (relative to the
/// sandbox HOME) before install scripts run. This is how packages that
/// "download prebuilt binaries at install time" (old sharp, etc.) build
/// hermetically: their downloader finds the file already cached, the
/// network stays denied, and the hash is a declared, verified input.
#[derive(Debug, Clone)]
pub struct DeclaredArtifact {
    pub url: String,
    pub sha256: String,
    /// Where the file must appear, relative to the sandbox HOME
    /// (e.g. ".npm/_libvips/libvips-8.14.5-darwin-arm64v8.tar.br"; LINUX_PORT.md stage 1).
    pub path: String,
}

#[derive(Debug, Clone, Default)]
pub struct BlanketConfig {
    pub mutable_packages: Vec<String>,
    pub artifacts: Vec<DeclaredArtifact>,
}

/// Strictly parse the optional `"blanket"` config field of package.json.
/// Unknown keys and malformed values are hard errors: this config weakens
/// or extends the trust boundary, so typos must not be silently ignored.
pub fn parse_blanket_config(pkg_json: &str) -> io::Result<BlanketConfig> {
    let v: serde_json::Value =
        serde_json::from_str(pkg_json).map_err(|e| err(format!("package.json: {e}")))?;
    let cfg = match v.get("blanket") {
        None => return Ok(BlanketConfig::default()),
        Some(c) => c
            .as_object()
            .ok_or_else(|| err("package.json: \"blanket\" must be an object"))?,
    };
    for key in cfg.keys() {
        if key != "mutablePackages" && key != "artifacts" {
            return Err(err(format!("package.json: unknown blanket key {key:?}")));
        }
    }
    let mut out = BlanketConfig::default();
    if let Some(list) = cfg.get("mutablePackages") {
        let arr = list
            .as_array()
            .ok_or_else(|| err("blanket.mutablePackages must be an array"))?;
        for item in arr {
            let name = item
                .as_str()
                .ok_or_else(|| err("blanket.mutablePackages entries must be strings"))?;
            let bare = name.strip_prefix('@').unwrap_or(name);
            let ok = !name.is_empty()
                && name.matches('/').count() == if name.starts_with('@') { 1 } else { 0 }
                && bare
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c));
            if !ok {
                return Err(err(format!("blanket.mutablePackages: bad name {name:?}")));
            }
            out.mutable_packages.push(name.to_string());
        }
    }
    if let Some(list) = cfg.get("artifacts") {
        let arr = list
            .as_array()
            .ok_or_else(|| err("blanket.artifacts must be an array"))?;
        for item in arr {
            let url = item["url"].as_str().unwrap_or_default();
            let sha256 = item["sha256"].as_str().unwrap_or_default();
            let path = item["path"].as_str().unwrap_or_default();
            if !url.starts_with("https://") {
                return Err(err(format!(
                    "blanket.artifacts: url must be https ({url:?})"
                )));
            }
            if sha256.len() != 64
                || !sha256
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(err(
                    "blanket.artifacts: sha256 must be 64 lowercase hex chars",
                ));
            }
            let path_ok = !path.is_empty()
                && !path.starts_with('/')
                && path
                    .split('/')
                    .all(|c| !c.is_empty() && c != "." && c != "..");
            if !path_ok {
                return Err(err(format!("blanket.artifacts: unsafe path {path:?}")));
            }
            out.artifacts.push(DeclaredArtifact {
                url: url.into(),
                sha256: sha256.into(),
                path: path.into(),
            });
        }
    }
    out.mutable_packages.sort();
    out.mutable_packages.dedup();
    out.artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn relative_path(from: &Path, to: &Path) -> io::Result<PathBuf> {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    if common == 0 {
        return Err(err(format!(
            "cannot make relative link from {} to {}",
            from.iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
            to.iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
        )));
    }
    let mut result = PathBuf::new();
    for _ in common..from.len() {
        result.push("..");
    }
    for component in &to[common..] {
        result.push(component.as_os_str());
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    Ok(result)
}

fn replace_with_symlink(path: &Path, target: &Path, label: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| err(format!("{label} has no parent")))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.blanket-swap.{}.{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::os::unix::fs::symlink(target, &tmp)?;
    fs::rename(&tmp, path)
}

/// Project the env into the project as a "forest": the root and every
/// package-local importer node_modules is a symlink to a WRITABLE per-project
/// directory under the forest projection, holding one symlink per top-level
/// entry into the immutable store object. Tools that treat node_modules' top
/// level as scratch space (vite's .vite dep cache, prisma's .prisma client)
/// get real writable directories, while package contents stay read-only in
/// the store — pnpm's proven layout.
///
/// If mutable packages are declared, the whole tree is instead cloned
/// (APFS copy-on-write) so runtime writes inside those packages succeed and
/// realpath stays coherent; the closure records them as unattested.
pub fn project_node_env(
    project_dir: &Path,
    env_obj: &Path,
    platform: Platform,
    plan: &NpmPlan,
    mutable: &[String],
    fresh: bool,
) -> io::Result<()> {
    project_node_env_recorded(project_dir, env_obj, platform, plan, mutable, fresh, &[])
}

/// `project_node_env` plus the input files recorded for `blanket status`
/// (package.json and the lockfile the plan came from).
pub fn project_node_env_recorded(
    project_dir: &Path,
    env_obj: &Path,
    platform: Platform,
    plan: &NpmPlan,
    mutable: &[String],
    fresh: bool,
    inputs: &[crate::project::InputRecord],
) -> io::Result<()> {
    if !mutable.is_empty() {
        crate::policy::record(
            crate::policy::UNATTESTED_MUTABLE_STATE,
            &mutable.join(", "),
            "mutable package projection is unattested",
        )?;
    }
    let nm = project_dir.join("node_modules");
    let workspaces = workspace_set(plan);
    let previous_workspaces = previous_workspace_set(project_dir);
    // Resolve every old and new workspace parent before any policy, backup,
    // removal, or projection mutation. A lexical `packages/lib` can be an
    // external symlink after the previous closure was written.
    validate_workspace_parents(project_dir, &previous_workspaces, &workspaces)?;
    let home = env_obj
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| err("cannot locate blanket home for forests"))?;
    // A workspace can disappear from the imported lockfile (or stop having
    // package-local dependencies) while its old managed projection remains
    // in the source tree. Reconcile the previous closure before projecting
    // the new set. Real directories are user state and retain backup_real_dir
    // semantics; only symlinks proven to target blanket-owned roots are
    // removed automatically.
    for workspace in previous_workspaces {
        if workspaces.contains(&workspace) || !safe_workspace_path(&workspace) {
            continue;
        }
        let workspace_nm = project_dir.join(&workspace).join("node_modules");
        if managed_projection_symlink(&workspace_nm, project_dir, &home) {
            fs::remove_file(&workspace_nm)?;
        } else {
            crate::project::backup_real_dir(&workspace_nm, env_obj)?;
        }
    }
    // A real (npm-made) node_modules is moved aside automatically so
    // pointing blanket at an existing project is one command. Workspace
    // importers get the same treatment in their source directories.
    crate::project::backup_real_dir(&nm, env_obj)?;
    for workspace in &workspaces {
        crate::project::backup_real_dir(
            &project_dir.join(workspace).join("node_modules"),
            env_obj,
        )?;
    }

    // Projection id: env object + mutable declarations + layout schema.
    use sha2::{Digest as _, Sha256};
    let env_name = env_obj.file_name().unwrap().to_string_lossy().into_owned();
    let link_key: String = plan
        .links
        .iter()
        .map(|l| format!("{}={};", l.path, l.target))
        .collect();
    let workspace_key = workspaces.join(",");
    let proj_id = hex::encode(Sha256::digest(
        format!(
            "node-forest/2\x00{env_name}\x00{}\x00{workspace_key}\x00{link_key}",
            mutable.join(",")
        )
        .as_bytes(),
    ))[..32]
        .to_string();

    // Forests live OUTSIDE the project (under the blanket home, keyed by
    // project path): anything inside the project gets crawled by test
    // runners and type checkers, and the forest links into store packages
    // whose own test files must never be picked up.
    let project_key = &hex::encode(Sha256::digest(
        project_dir.canonicalize()?.to_string_lossy().as_bytes(),
    ))[..32];
    let nm_root = home.join("forests").join(project_key);
    let proj_dir = nm_root.join(&proj_id);
    // The projected tree must itself be NAMED node_modules: Node's module
    // resolution only treats a directory as a package root when its
    // basename is node_modules, and cloned packages realpath to this tree.
    let forest = proj_dir.join("node_modules");
    if fresh && proj_dir.exists() {
        crate::store::remove_tree(&proj_dir)?;
    }
    let workspace_forests_ready = workspaces.iter().all(|workspace| {
        proj_dir
            .join("workspaces")
            .join(encode_workspace_path(workspace))
            .join("node_modules")
            .is_dir()
    });
    if !forest.exists() || !workspace_forests_ready {
        fs::create_dir_all(&nm_root)?;
        let tmp = nm_root.join(format!(".{proj_id}.tmp.{}", std::process::id()));
        if tmp.exists() {
            crate::store::remove_tree(&tmp)?;
        }
        fs::create_dir_all(&tmp)?;
        let src = env_obj.join("node_modules");
        if mutable.is_empty() {
            build_forest(&src, &tmp.join("node_modules"))?;
        } else {
            crate::project::clone_tree_for(&src, &tmp.join("node_modules"), platform)?;
        }
        for workspace in &workspaces {
            let src = env_obj
                .join("workspaces")
                .join(encode_workspace_path(workspace))
                .join("node_modules");
            let dest = tmp
                .join("workspaces")
                .join(encode_workspace_path(workspace))
                .join("node_modules");
            if mutable.is_empty() {
                build_forest(&src, &dest)?;
            } else {
                crate::project::clone_tree_for(&src, &dest, platform)?;
            }
        }
        fs::rename(&tmp, &proj_dir)?;
    }
    // Workspace links: symlinks into the project's own source dirs. The
    // targets are user-owned and writable by nature. Idempotent — the
    // projection id covers the link set, so a changed set is a new forest.
    for l in &plan.links {
        let link_root = workspace_path(&l.path)
            .map(|(workspace, _)| {
                proj_dir
                    .join("workspaces")
                    .join(encode_workspace_path(workspace))
                    .join("node_modules")
            })
            .unwrap_or_else(|| forest.clone());
        let rel = importer_relative_path(&l.path).trim_start_matches("node_modules/");
        let link = link_root.join(rel);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        if link.symlink_metadata().is_err() {
            let target = relative_path(
                link.parent()
                    .ok_or_else(|| err("workspace link has no parent"))?,
                &project_dir.join(&l.target),
            )?;
            std::os::unix::fs::symlink(target, &link)?;
        }
    }
    // Old forests are deliberately NOT pruned here (Sol review 3): a dev
    // server may still be running from one, and pruning would break it
    // mid-session. They are cheap symlink trees; explicit `blanket gc`
    // with liveness checks is the collection path (M5).

    // iCloud/Drive-synced folders resurrect each replaced symlink as a
    // "node_modules 2"-style duplicate. Ones that are symlinks into
    // blanket-owned paths are ours from earlier projections: remove them
    // (test runners crawl through them otherwise). Anything else is only
    // warned about — never delete what we didn't create.
    if let Ok(entries) = fs::read_dir(project_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with("node_modules ") {
                continue;
            }
            let p = e.path();
            // Only targets under blanket-owned roots count as ours — never
            // delete a user's own symlink on a loose match.
            let is_ours = fs::read_link(&p)
                .map(|t| {
                    t.starts_with(home.join("forests"))
                        || t.starts_with(home.join("store"))
                        || t.starts_with(project_dir.join(".blanket/nm"))
                })
                .unwrap_or(false);
            if is_ours {
                let _ = fs::remove_file(&p);
                eprintln!("blanket: removed stale sync-duplicate symlink {name:?}");
            } else {
                eprintln!(
                    "blanket: warning: {name:?} looks like a cloud-sync duplicate \
                     of node_modules; consider removing it"
                );
            }
        }
    }

    replace_with_symlink(&nm, &forest, "node_modules")?;
    for workspace in &workspaces {
        let workspace_dir = project_dir.join(workspace);
        fs::create_dir_all(&workspace_dir)?;
        let workspace_nm = workspace_dir.join("node_modules");
        let workspace_forest = proj_dir
            .join("workspaces")
            .join(encode_workspace_path(workspace))
            .join("node_modules");
        replace_with_symlink(&workspace_nm, &workspace_forest, "workspace-node_modules")?;
    }

    // Mutable declarations expand to every matching physical lockfile path.
    let mutable_paths: Vec<&str> = plan
        .packages
        .iter()
        .filter(|p| mutable.iter().any(|m| *m == p.name))
        .map(|p| p.path.as_str())
        .collect();
    let native_reference = crate::nativelibs::env_reference(env_obj)?;

    let meta_dir = project_dir.join(".blanket");
    fs::create_dir_all(&meta_dir)?;
    let body = serde_json::json!({
        "env_object": env_obj,
        "native_libs": native_reference,
        "projection_schema": "node-forest/2",
        "projection_id": proj_id,
        "node_version": plan.node_version,
        "workspaces": workspaces,
        "mutable_packages": mutable,
        "mutable_paths": mutable_paths,
        "mutable_state": if mutable.is_empty() { "none" } else { "unattested" },
        // Honest scope: clone mode makes the WHOLE projected tree writable
        // (path coherence requires it); mutable_paths lists only where
        // writes are expected, not where they are possible.
        "mutable_scope": if mutable.is_empty() { "none" } else { "whole-tree-clone" },
        "workspace_links": plan.links.iter().map(|l| {
            serde_json::json!({"path": l.path, "target": l.target})
        }).collect::<Vec<_>>(),
        "lock_source": plan.lock_source,
        "inputs": inputs,
        "packages": plan.packages.iter().map(|p| {
            serde_json::json!({"path": p.path, "version": p.version, "integrity": p.integrity})
        }).collect::<Vec<_>>(),
    });
    crate::project::write_closure(project_dir, "node", body)
}

/// One symlink per top-level entry of the object's node_modules; scoped
/// packages get a real @scope dir with per-package symlinks so new scoped
/// siblings can be written at runtime.
fn build_forest(src: &Path, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('@') {
            let scope_dir = dest.join(&name);
            fs::create_dir(&scope_dir)?;
            for sub in fs::read_dir(entry.path())? {
                let sub = sub?;
                std::os::unix::fs::symlink(sub.path(), scope_dir.join(sub.file_name()))?;
            }
        } else {
            std::os::unix::fs::symlink(entry.path(), dest.join(&name))?;
        }
    }
    Ok(())
}

// clone_tree moved to project::clone_tree (kernel: elixir needs the same
// writable copy-on-write projection for source deps).

/// npm-compatible mode normalization: tarballs in the wild carry broken
/// permission bits (e.g. pngjs ships directories without the execute bit,
/// making them untraversable). npm's extractor ORs minimum modes onto every
/// entry (0o777-under-umask for dirs, 0o666 for files, exec bits preserved);
/// we do the same after extraction. Top-down so unreadable dirs get fixed
/// before we descend into them.
fn normalize_modes(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    let ft = md.file_type();
    if ft.is_symlink() {
        return Ok(());
    }
    let mode = md.permissions().mode();
    if ft.is_dir() {
        if mode & 0o755 != 0o755 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o755))?;
        }
        for entry in fs::read_dir(path)? {
            normalize_modes(&entry?.path())?;
        }
    } else if mode & 0o644 != 0o644 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o644))?;
    }
    Ok(())
}

fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let md = entry.metadata()?;
        total += if md.is_dir() {
            dir_size(&entry.path())?
        } else {
            md.len()
        };
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

    #[test]
    fn node_pins_cover_each_supported_platform() {
        assert_eq!(NODE_PINS.len(), Platform::ALL.len());
        let mut identities = std::collections::BTreeSet::new();
        for platform in Platform::ALL {
            let pin = node_pin(*platform).expect("one Node pin per supported platform");
            assert!(identities.insert((platform.triple(), pin.version)));
        }
        assert_eq!(identities.len(), NODE_PINS.len());

        let linux = node_pin(Platform::X86_64UnknownLinuxGnu).unwrap();
        assert_eq!(linux.version, "24.20.0");
        assert_eq!(
            linux.url,
            "https://nodejs.org/dist/v24.20.0/node-v24.20.0-linux-x64.tar.gz"
        );
        assert_eq!(
            linux.sha256,
            "855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec"
        );
    }

    #[test]
    fn darwin_identity_unchanged() {
        let node = node_pin(Platform::Aarch64AppleDarwin).unwrap();
        let identity = node_identity(node);
        assert_eq!(
            identity.object_id(),
            "174e755a9fcb532c2addfefb93562ba28874abdc-nodejs-24.20.0"
        );
    }

    #[test]
    fn darwin_binding_gyp_keeps_legacy_identity_inputs() {
        let store = Store {
            root: PathBuf::from("/nonexistent/blanket-test-store"),
        };
        assert_eq!(
            native_libs_identity_id(&store, Platform::Aarch64AppleDarwin, true).unwrap(),
            None
        );
    }

    #[test]
    fn darwin_warm_sync_does_not_fetch_package_tarballs() {
        let root =
            std::env::temp_dir().join(format!("blanket-npm-darwin-warm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for subdir in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let node_obj = store.object_path("node-cache");
        std::fs::create_dir_all(&node_obj).unwrap();
        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![NpmPackage {
                path: "node_modules/unreachable".into(),
                name: "unreachable".into(),
                version: "1.0.0".into(),
                url: "https://127.0.0.1:9/never-requested.tgz".into(),
                integrity: TEST_SRI.into(),
                bin: Vec::new(),
                optional: false,
                patch: None,
                git: None,
            }],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let identity = node_env_identity(
            &store,
            Platform::host().unwrap(),
            &node_obj,
            &plan,
            &[],
            None,
        )
        .unwrap();
        let staged = store.stage().unwrap();
        std::fs::create_dir_all(staged.join("node_modules")).unwrap();
        let (expected, _) = store.commit(&identity, &staged, &[]).unwrap();

        let realized = realize_node_env_with_node_object(
            &store,
            Platform::Aarch64AppleDarwin,
            &plan,
            &[],
            &node_obj,
        )
        .unwrap();
        assert_eq!(realized, expected);
        assert_eq!(
            std::fs::read_dir(store.root.join("cache/sha256"))
                .unwrap()
                .count(),
            0
        );
        crate::store::remove_tree(&root).unwrap();
    }

    #[test]
    fn linux_warm_sync_uses_persisted_archive_classification() {
        let root =
            std::env::temp_dir().join(format!("blanket-npm-linux-warm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for subdir in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let node_obj = store.object_path("node-cache");
        std::fs::create_dir_all(&node_obj).unwrap();
        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![NpmPackage {
                path: "node_modules/pure-js".into(),
                name: "pure-js".into(),
                version: "1.0.0".into(),
                url: "https://127.0.0.1:9/never-requested.tgz".into(),
                integrity: TEST_SRI.into(),
                bin: Vec::new(),
                optional: false,
                patch: None,
                git: None,
            }],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let digest = Digest::from_sri(TEST_SRI).unwrap();
        write_archive_classification(&store, &digest, false).unwrap();
        let identity = node_env_identity(
            &store,
            Platform::host().unwrap(),
            &node_obj,
            &plan,
            &[],
            None,
        )
        .unwrap();
        let staged = store.stage().unwrap();
        std::fs::create_dir_all(staged.join("node_modules")).unwrap();
        let (expected, _) = store.commit(&identity, &staged, &[]).unwrap();

        // Simulate the user clearing all downloaded package archives. The
        // persisted inspection result is the only input available to the
        // Linux warm lookup below.
        let realized = realize_node_env_with_node_object(
            &store,
            Platform::X86_64UnknownLinuxGnu,
            &plan,
            &[],
            &node_obj,
        )
        .unwrap();
        assert_eq!(realized, expected);
        assert_eq!(
            std::fs::read_dir(store.root.join("cache/sha256"))
                .unwrap()
                .count(),
            0
        );
        crate::store::remove_tree(&root).unwrap();
    }

    #[test]
    fn node_identity_is_platform_specific() {
        let darwin = node_identity(node_pin(Platform::Aarch64AppleDarwin).unwrap());
        let linux = node_identity(node_pin(Platform::X86_64UnknownLinuxGnu).unwrap());
        assert_ne!(darwin.object_id(), linux.object_id());
        assert_eq!(
            darwin.inputs.get("platform").map(String::as_str),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(
            linux.inputs.get("platform").map(String::as_str),
            Some("x86_64-unknown-linux-gnu")
        );
    }

    #[test]
    fn realize_node_env_preserves_unsupported_kind() {
        let error = wrap_ensure_node_error(io::Error::new(
            io::ErrorKind::Unsupported,
            "injected sandbox boundary failure",
        ));
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("ensure node"));
    }

    #[test]
    fn realize_node_env_rejects_foreign_platform_before_store_access() {
        let store = Store {
            root: PathBuf::from("/nonexistent/blanket-test-store"),
        };
        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: Vec::new(),
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let host = Platform::host().unwrap();
        let foreign = *Platform::ALL
            .iter()
            .find(|platform| **platform != host)
            .unwrap();
        let error = realize_node_env(&store, foreign, &plan, &[]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains(foreign.triple()));
    }

    fn lock(packages: &str) -> String {
        format!(r#"{{"name":"x","lockfileVersion":3,"packages":{{"":{{"name":"x"}},{packages}}}}}"#)
    }

    #[test]
    fn parses_nested_and_scoped() {
        let l = lock(
            r#""node_modules/@s/a":{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="},
               "node_modules/b/node_modules/c":{"version":"2.0.0","resolved":"https://r/c.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}"#,
        );
        let plan = plan_npm(Platform::Aarch64AppleDarwin, &l).unwrap();
        assert_eq!(plan.packages.len(), 2);
        assert_eq!(plan.packages[0].name, "@s/a");
        assert_eq!(plan.packages[1].name, "c");
        assert_eq!(plan.packages[1].path, "node_modules/b/node_modules/c");
        // deterministic order
        assert!(plan.packages[0].path < plan.packages[1].path);
    }

    #[test]
    fn discovers_string_object_and_legacy_directory_bins() {
        let dir = std::env::temp_dir().join(format!("blanket-npm-bin-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("cli")).unwrap();
        fs::write(dir.join("cli/a"), "a").unwrap();
        fs::write(dir.join("cli/b"), "b").unwrap();

        assert_eq!(
            discover_package_bins(r#"{"bin":"./cli.js"}"#, "@scope/tool", &dir).unwrap(),
            vec![("tool".into(), "./cli.js".into())]
        );
        assert_eq!(
            discover_package_bins(
                r#"{"bin":{"tool":"bin/tool.js","other":"bin/other.js"}}"#,
                "tool",
                &dir,
            )
            .unwrap(),
            vec![
                ("other".into(), "bin/other.js".into()),
                ("tool".into(), "bin/tool.js".into()),
            ]
        );
        assert_eq!(
            discover_package_bins(r#"{"directories":{"bin":"cli"}}"#, "tool", &dir).unwrap(),
            vec![("a".into(), "cli/a".into()), ("b".into(), "cli/b".into())]
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn workspace_paths_and_forest_keys_are_distinct() {
        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![NpmPackage {
                path: "packages/lib/node_modules/a".into(),
                name: "a".into(),
                version: "1".into(),
                url: "https://example.invalid/a.tgz".into(),
                integrity: TEST_SRI.into(),
                bin: Vec::new(),
                patch: None,
                git: None,
                optional: false,
            }],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "pnpm-lock.yaml".into(),
        };
        assert_eq!(workspace_set(&plan), vec!["packages/lib"]);
        assert_eq!(encode_workspace_path("packages/lib"), "packages%2Flib");
        assert_eq!(
            env_package_path(Path::new("/env"), "packages/lib/node_modules/a"),
            PathBuf::from("/env/workspaces/packages%2Flib/node_modules/a")
        );
    }

    #[test]
    fn stale_workspace_projection_is_removed_when_dependency_aligns() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("blanket-npm-stale-workspace-{nonce}"));
        let project = root.join("project");
        let env = root.join("home/store/objects/env");
        fs::create_dir_all(project.join("packages/lib")).unwrap();
        fs::create_dir_all(env.join("node_modules/c")).unwrap();
        fs::create_dir_all(env.join("workspaces/packages%2Flib/node_modules/c")).unwrap();
        fs::write(env.join("node_modules/c/package.json"), "{}").unwrap();
        fs::write(
            env.join("workspaces/packages%2Flib/node_modules/c/package.json"),
            "{}",
        )
        .unwrap();

        let package = |path: &str, version: &str| NpmPackage {
            path: path.into(),
            name: "c".into(),
            version: version.into(),
            url: "https://example.invalid/c.tgz".into(),
            integrity: TEST_SRI.into(),
            bin: Vec::new(),
            patch: None,
            git: None,
            optional: false,
        };
        let first = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![
                package("node_modules/c", "1.0.0"),
                package("packages/lib/node_modules/c", "2.0.0"),
            ],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "pnpm-lock.yaml".into(),
        };
        project_node_env(
            &project,
            &env,
            Platform::host().unwrap(),
            &first,
            &[],
            false,
        )
        .unwrap();
        let workspace_nm = project.join("packages/lib/node_modules");
        assert!(fs::symlink_metadata(&workspace_nm)
            .unwrap()
            .file_type()
            .is_symlink());

        // The second plan aligns the workspace dependency with the root, so
        // the planner no longer needs a workspace-local forest.
        let second = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![package("node_modules/c", "1.0.0")],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "pnpm-lock.yaml".into(),
        };
        project_node_env(
            &project,
            &env,
            Platform::host().unwrap(),
            &second,
            &[],
            false,
        )
        .unwrap();
        assert!(fs::symlink_metadata(&workspace_nm).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_workspace_ownership_canonicalizes_symlinked_temp_roots() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("blanket-npm-symlinked-tmp-{nonce}"));
        let real = root.join("real");
        let alias = root.join("alias");
        let home = alias.join("home");
        let project = alias.join("project");
        let target = real.join("home/store/objects/env");
        fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        fs::create_dir_all(&project).unwrap();
        let workspace_nm = project.join("packages/lib/node_modules");
        fs::create_dir_all(workspace_nm.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &workspace_nm).unwrap();

        assert!(managed_projection_symlink(&workspace_nm, &project, &home));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_parent_preflight_rejects_external_stale_workspace() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("blanket-npm-external-workspace-{nonce}"));
        let project = root.join("project");
        let external = root.join("external");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&external).unwrap();
        std::os::unix::fs::symlink(&external, project.join("packages")).unwrap();
        let marker = external.join("must-remain");
        fs::write(&marker, "user data").unwrap();

        let error =
            validate_workspace_parents(&project, &["packages/lib".to_string()], &[]).unwrap_err();
        assert!(error.to_string().contains("outside the project"), "{error}");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "user data");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_parent_preflight_rejects_unsafe_current_workspace() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("blanket-npm-unsafe-workspace-{nonce}"));
        let project = root.join("project");
        let external = root.join("external");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&external).unwrap();
        let marker = external.join("must-remain");
        fs::write(&marker, "user data").unwrap();

        let error =
            validate_workspace_parents(&project, &[], &["../external".to_string()]).unwrap_err();
        assert!(
            error.to_string().contains("safe project-relative"),
            "{error}"
        );
        assert_eq!(fs::read_to_string(&marker).unwrap(), "user data");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn git_dependency_urls_are_classified_with_repo_and_commit() {
        let cases = [
            (
                "https://codeload.github.com/acme/tool/tar.gz/0123456789abcdef",
                "acme/tool",
                "0123456789abcdef",
            ),
            (
                "https://github.com/acme/tool/archive/0123456789abcdef.tar.gz",
                "acme/tool",
                "0123456789abcdef",
            ),
            (
                "git+https://github.com/acme/tool.git#0123456789abcdef",
                "github.com/acme/tool",
                "0123456789abcdef",
            ),
            (
                "https://github.com/acme/tool#0123456789abcdef",
                "github.com/acme/tool",
                "0123456789abcdef",
            ),
        ];
        for (url, repo, commit) in cases {
            let detail = git_dependency_detail("tool", url).unwrap();
            assert!(detail.starts_with("npm_git_dep:"), "{detail}");
            assert!(detail.contains(repo), "{detail}");
            assert!(detail.contains(commit), "{detail}");
            assert!(detail.contains("NEXT.md item 4"), "{detail}");
        }
    }

    #[test]
    fn local_git_file_urls_preserve_the_git_suffix() {
        let source = git_source_from_url(
            "git+file:///tmp/fixture-repo.git#0123456789abcdef0123456789abcdef01234567",
        )
        .expect("pinned local git source");
        assert_eq!(source.url, "file:///tmp/fixture-repo.git");
    }

    #[test]
    fn explicit_platform_selects_the_matching_esbuild_variant() {
        let l = lock(&format!(
            r#""node_modules/@esbuild/linux-x64":{{"name":"@esbuild/linux-x64","version":"0.25.9","optional":true,"os":["linux"],"cpu":["x64"],"resolved":"https://r/linux.tgz","integrity":"{TEST_SRI}"}},
               "node_modules/@esbuild/darwin-arm64":{{"name":"@esbuild/darwin-arm64","version":"0.25.9","optional":true,"os":["darwin"],"cpu":["arm64"],"resolved":"https://r/darwin.tgz","integrity":"{TEST_SRI}"}}"#
        ));
        let linux = plan_npm(Platform::X86_64UnknownLinuxGnu, &l).unwrap();
        assert_eq!(
            linux
                .packages
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            vec!["@esbuild/linux-x64"]
        );
        let darwin = plan_npm(Platform::Aarch64AppleDarwin, &l).unwrap();
        assert_eq!(
            darwin
                .packages
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            vec!["@esbuild/darwin-arm64"]
        );
    }

    #[test]
    fn linux_optional_platform_subtrees_are_pruned_but_siblings_remain() {
        let l = lock(&format!(
            r#""node_modules/optional-parent":{{"version":"1","optional":true,"os":["darwin"],"resolved":"https://r/parent.tgz","integrity":"{TEST_SRI}"}},
               "node_modules/optional-parent/node_modules/child":{{"version":"1"}},
               "node_modules/optional-parent-sibling":{{"version":"1","resolved":"https://r/sibling.tgz","integrity":"{TEST_SRI}"}}"#
        ));
        let plan = plan_npm(Platform::X86_64UnknownLinuxGnu, &l).unwrap();
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(
            plan.packages[0].path,
            "node_modules/optional-parent-sibling"
        );
    }

    #[test]
    fn required_platform_and_libc_restrictions_have_host_diagnostics() {
        let cases = [
            (r#""os":["darwin"]"#, "os restriction"),
            (r#""cpu":["arm64"]"#, "cpu restriction"),
            (r#""libc":["musl"]"#, "libc restriction"),
        ];
        for (restriction, reason) in cases {
            let l = lock(&format!(
                r#""node_modules/required":{{"version":"1",{restriction},"resolved":"https://r/required.tgz","integrity":"{TEST_SRI}"}}"#
            ));
            let error = plan_npm(Platform::X86_64UnknownLinuxGnu, &l).unwrap_err();
            let text = error.to_string();
            assert!(text.contains("node_modules/required"), "{text}");
            assert!(text.contains("x86_64-unknown-linux-gnu"), "{text}");
            assert!(text.contains(reason), "{text}");
        }

        let l = lock(&format!(
            r#""node_modules/required":{{"version":"1","libc":["!glibc"],"resolved":"https://r/required.tgz","integrity":"{TEST_SRI}"}}"#
        ));
        let error = plan_npm(Platform::X86_64UnknownLinuxGnu, &l).unwrap_err();
        assert!(error.to_string().contains("!glibc"));
    }

    #[test]
    fn linux_restriction_lists_follow_npm_semantics() {
        // Mirrors npm-install-checks' checkList, exercised end to end
        // through plan_npm on the Linux platform.
        let cases = [
            // unrestricted / allow-list
            (r#"[]"#, true),
            (r#"["linux"]"#, true),
            (r#"["darwin","linux"]"#, true),
            (r#"["darwin"]"#, false),
            (r#""linux""#, true), // bare string form
            (r#""darwin""#, false),
            // deny-list
            (r#"["!darwin"]"#, true),
            (r#"["!darwin","!win32"]"#, true),
            (r#"["!linux"]"#, false),
            (r#""!linux""#, false),
            // mixed: a matching negation always denies; otherwise a
            // positive must match when any positive exists
            (r#"["linux","!darwin"]"#, true),
            (r#"["linux","!linux"]"#, false),
            (r#"["darwin","!win32"]"#, false),
            // `any` is a wildcard only as the sole entry
            (r#"["any"]"#, true),
            (r#"["any","!darwin"]"#, false),
            (r#"["any","linux"]"#, true),
        ];
        for (restriction, compatible) in cases {
            let l = lock(&format!(
                r#""node_modules/restricted":{{"version":"1","os":{restriction},"resolved":"https://r/restricted.tgz","integrity":"{TEST_SRI}"}}"#
            ));
            let result = plan_npm(Platform::X86_64UnknownLinuxGnu, &l);
            assert_eq!(result.is_ok(), compatible, "os restriction {restriction}");
        }
        for (restriction, compatible) in [(r#"["x64"]"#, true), (r#"["!x64"]"#, false)] {
            let l = lock(&format!(
                r#""node_modules/restricted":{{"version":"1","cpu":{restriction},"resolved":"https://r/restricted.tgz","integrity":"{TEST_SRI}"}}"#
            ));
            let result = plan_npm(Platform::X86_64UnknownLinuxGnu, &l);
            assert_eq!(result.is_ok(), compatible, "cpu restriction {restriction}");
        }

        for libc in [r#"["glibc"]"#, r#"["!musl"]"#, r#"["any"]"#, r#""glibc""#] {
            let l = lock(&format!(
                r#""node_modules/restricted":{{"version":"1","libc":{libc},"resolved":"https://r/restricted.tgz","integrity":"{TEST_SRI}"}}"#
            ));
            assert!(
                plan_npm(Platform::X86_64UnknownLinuxGnu, &l).is_ok(),
                "libc {libc}"
            );
        }
        for libc in [r#"["musl"]"#, r#"["!glibc"]"#, r#""musl""#] {
            let l = lock(&format!(
                r#""node_modules/restricted":{{"version":"1","libc":{libc},"resolved":"https://r/restricted.tgz","integrity":"{TEST_SRI}"}}"#
            ));
            assert!(
                plan_npm(Platform::X86_64UnknownLinuxGnu, &l).is_err(),
                "libc {libc}"
            );
        }
    }

    #[test]
    fn darwin_restriction_semantics_are_unchanged_by_the_linux_selector() {
        // Stage 1 Darwin behavior, preserved verbatim: array-only, and any
        // negated entry makes positives irrelevant.
        let cases = [
            (r#"["darwin"]"#, true),
            (r#"["linux"]"#, false),
            (r#"["!linux"]"#, true),
            (r#"["!darwin"]"#, false),
            (r#"["linux","!win32"]"#, true), // negation present: positives ignored
            (r#"["any","!darwin"]"#, false),
            (r#""linux""#, true), // string form is not an array: ignored
        ];
        for (restriction, compatible) in cases {
            let l = lock(&format!(
                r#""node_modules/restricted":{{"version":"1","os":{restriction},"resolved":"https://r/restricted.tgz","integrity":"{TEST_SRI}"}}"#
            ));
            let result = plan_npm(Platform::Aarch64AppleDarwin, &l);
            assert_eq!(
                result.is_ok(),
                compatible,
                "darwin os restriction {restriction}"
            );
        }
        // Darwin ignores libc entirely.
        let l = lock(&format!(
            r#""node_modules/restricted":{{"version":"1","libc":["musl"],"resolved":"https://r/restricted.tgz","integrity":"{TEST_SRI}"}}"#
        ));
        assert!(plan_npm(Platform::Aarch64AppleDarwin, &l).is_ok());
    }

    #[test]
    fn rejections() {
        // v1 lockfile
        assert!(plan_npm(
            Platform::Aarch64AppleDarwin,
            r#"{"lockfileVersion":1,"packages":{}}"#
        )
        .is_err());
        // link entry
        let l = lock(r#""node_modules/a":{"link":true,"resolved":"https://r/a.tgz"}"#);
        assert!(plan_npm(Platform::Aarch64AppleDarwin, &l).is_err());
        // missing integrity
        let l = lock(r#""node_modules/a":{"version":"1.0.0","resolved":"https://r/a.tgz"}"#);
        assert!(plan_npm(Platform::Aarch64AppleDarwin, &l).is_err());
        // path traversal
        let l = lock(
            r#""node_modules/../evil":{"version":"1","resolved":"https://r/a.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}"#,
        );
        assert!(plan_npm(Platform::Aarch64AppleDarwin, &l).is_err());
        // git URL
        let l = lock(
            r#""node_modules/a":{"version":"1","resolved":"git+ssh://git@x/a.git","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}"#,
        );
        assert!(plan_npm(Platform::Aarch64AppleDarwin, &l).is_err());
    }

    #[test]
    fn bundled_and_platform_skipped_subtrees() {
        // inBundle entries are provided by the parent tarball: skipped.
        let l = lock(
            r#""node_modules/a":{"version":"1","resolved":"https://r/a.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="},
               "node_modules/a/node_modules/b":{"version":"1","inBundle":true}"#,
        );
        assert_eq!(
            plan_npm(Platform::Aarch64AppleDarwin, &l)
                .unwrap()
                .packages
                .len(),
            1
        );
        // descendants of a platform-skipped optional package are dropped
        // even without their own os/cpu/resolved fields.
        let l = lock(
            r#""node_modules/w":{"version":"1","optional":true,"cpu":["wasm32"],"resolved":"https://r/w.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="},
               "node_modules/w/node_modules/c":{"version":"1"}"#,
        );
        assert_eq!(
            plan_npm(Platform::Aarch64AppleDarwin, &l)
                .unwrap()
                .packages
                .len(),
            0
        );
    }

    #[test]
    fn blanket_config_parsing() {
        let empty = parse_blanket_config(r#"{"name":"x"}"#).unwrap();
        assert!(empty.mutable_packages.is_empty() && empty.artifacts.is_empty());
        let ok =
            parse_blanket_config(r#"{"blanket":{"mutablePackages":["b","@prisma/engines","b"]}}"#)
                .unwrap();
        assert_eq!(
            ok.mutable_packages,
            vec!["@prisma/engines".to_string(), "b".to_string()]
        );
        // unknown key, bad names, wrong types: hard errors
        assert!(parse_blanket_config(r#"{"blanket":{"mutable":["a"]}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":{"mutablePackages":["../x"]}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":{"mutablePackages":"a"}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":{"mutablePackages":[""]}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":[]}"#).is_err());
        // artifacts: happy path + validation
        let a = parse_blanket_config(
            r#"{"blanket":{"artifacts":[{"url":"https://x/y.tar","sha256":"0000000000000000000000000000000000000000000000000000000000000000","path":".npm/_libvips/y.tar"}]}}"#,
        )
        .unwrap();
        assert_eq!(a.artifacts.len(), 1);
        assert!(parse_blanket_config(
            r#"{"blanket":{"artifacts":[{"url":"http://x/y","sha256":"00","path":"p"}]}}"#
        )
        .is_err());
        assert!(parse_blanket_config(
            r#"{"blanket":{"artifacts":[{"url":"https://x/y","sha256":"0000000000000000000000000000000000000000000000000000000000000000","path":"../evil"}]}}"#
        )
        .is_err());
    }

    #[test]
    fn package_scripts_and_command_order() {
        let scripts = package_scripts(
            r#"{"scripts":{"build":"echo build","pretest":"echo pre","test":"echo test","posttest":"echo post"}}"#,
        )
        .unwrap();
        assert_eq!(
            script_commands(&scripts, "build", &[]),
            Some(vec![("build".into(), "echo build".into())])
        );
        assert_eq!(
            script_commands(&scripts, "test", &["a'b".into(), "two words".into()]),
            Some(vec![
                ("pretest".into(), "echo pre".into()),
                ("test".into(), "echo test 'a'\\''b' 'two words'".into()),
                ("posttest".into(), "echo post".into()),
            ])
        );
        assert_eq!(script_commands(&scripts, "missing", &[]), None);
        assert!(package_scripts("{").is_err());
    }

    #[test]
    fn non_string_script_is_rejected() {
        let error =
            script_commands_from_package(r#"{"scripts":{"test":1}}"#, "test", &[]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("test"));
    }

    #[test]
    fn script_arguments_are_shell_quoted_literally() {
        let scripts = package_scripts(r#"{"scripts":{"test":"echo test"}}"#).unwrap();
        let args = vec!["$HOME".into(), "`whoami`".into(), "line\nbreak".into()];
        assert_eq!(
            script_commands(&scripts, "test", &args),
            Some(vec![(
                "test".into(),
                "echo test '$HOME' '`whoami`' 'line\nbreak'".into()
            )])
        );
    }

    #[test]
    fn empty_node_env_layout_changes_identity() {
        let mut with_layout = BTreeMap::new();
        let empty: &[NpmPackage] = &[];
        add_node_env_layout_input(&mut with_layout, empty);
        assert_eq!(
            with_layout.get("layout").map(String::as_str),
            Some("empty-node_modules")
        );
        let identity = |inputs| Identity {
            kind: "node-env".into(),
            name: "env".into(),
            version: node_pin(Platform::Aarch64AppleDarwin)
                .unwrap()
                .version
                .into(),
            inputs,
        };
        assert_ne!(
            identity(with_layout).object_id(),
            identity(BTreeMap::new()).object_id()
        );
    }

    #[test]
    fn lifecycle_sandbox_failure_is_fatal_before_policy_handling() {
        let failure = classify_lifecycle_result(Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "injected sandbox unavailable",
        )))
        .unwrap_err();
        match failure {
            LifecycleFailure::SandboxUnavailable(error) => {
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            }
            LifecycleFailure::Script(_) => panic!("sandbox failure was downgraded"),
        }
    }

    #[test]
    fn lifecycle_script_failure_is_separate_from_sandbox_failure() {
        let failure =
            classify_lifecycle_result(Err(io::Error::other("script exited 1"))).unwrap_err();
        assert!(
            matches!(failure, LifecycleFailure::Script(error) if error.kind() == io::ErrorKind::Other)
        );
    }
}

#[cfg(test)]
mod git_url_tests {
    #[test]
    fn pinned_git_urls_are_recognized_in_every_lockfile_spelling() {
        let commit = "8bf567b9e2230cdd02f9b8c9774fb8eb0d71af1e";
        for url in [
            &format!("https://codeload.github.com/o/r/tar.gz/{commit}"),
            &format!("https://github.com/o/r/archive/{commit}.tar.gz"),
            &format!("git+https://github.com/o/r.git#{commit}"),
            &format!("git+ssh://git@github.com/o/r.git#{commit}"),
        ] {
            let source =
                super::git_source_from_url(url).unwrap_or_else(|| panic!("not recognized: {url}"));
            assert_eq!(source.commit, commit, "{url}");
            assert!(
                source.url.starts_with("https://") || source.url.starts_with("ssh://"),
                "{url} produced a fetchable URL? got {}",
                source.url
            );
        }
        assert!(super::git_source_from_url("https://registry.npmjs.org/a/-/a-1.0.0.tgz").is_none());
    }
}
