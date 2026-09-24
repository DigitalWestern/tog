//! The npm tailor: package-lock.json importer (no solver).
//!
//! npm's lockfile v2/v3 already encodes the complete node_modules tree —
//! every key in "packages" is a literal filesystem path — so planning is
//! pure parsing (no network, no resolution). Realization materializes
//! exactly that tree as an immutable store object; projection is one
//! node_modules symlink per importer.
//!
//! Installed packages come from registry tarballs or from git sources pinned
//! to a full commit; an unpinned git source is refused (or skipped with a
//! `git-dependency` exception when optional). Local/workspace links are
//! projected back into the project. Lifecycle scripts run in the sandbox; failures are
//! retained as exceptions by default.
//!
//! Trust model: the lockfile is a TRUSTED input. Integrity pins every
//! tarball's bytes, but `resolved` URLs choose where the GET goes, so a
//! hostile lockfile is a network capability. There is no registry
//! allowlist yet.

pub mod inputs;
pub mod lock_import;
pub mod objects;
pub mod registry_tool;
pub mod run_refusal;
pub mod tailor;

mod plan;
mod project;
mod realize;

pub use plan::*;
pub use project::*;
pub use realize::*;

use crate::kernel::activity::StoreActivity;
use crate::kernel::fetch::{download_verified_digest_held, download_verified_held, Digest};
use crate::kernel::platform::{no_pin, Platform};
use crate::kernel::store::Store;
use crate::kernel::toolchain::document::Shipped;
use crate::kernel::toolchain::{ArtifactSpec, Catalog, LegacyEvidence, Selected};
use crate::kernel::types::Identity;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

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

/// The shipped Node catalog: every release of the Node lines nodejs.org
/// still supports, with its default, generated and verified by
/// `tools/catalog.py node`. Each digest comes from that release's
/// SHASUMS256.txt, whose detached signature the generator checks against
/// the nodejs/release-keys keyring.
static CATALOG: Shipped = Shipped::new(include_str!("catalog.toml"));

/// One platform's nodejs.org tarball for one Node release, as the shipped
/// catalog lists it.
#[derive(Debug)]
pub struct PinnedNode {
    pub platform: Platform,
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

/// Every shipped Node tarball: one row per release and supported platform.
pub fn node_pins() -> io::Result<&'static [PinnedNode]> {
    static PINS: OnceLock<Vec<PinnedNode>> = OnceLock::new();
    let document = CATALOG.document()?;
    Ok(PINS.get_or_init(|| {
        document
            .bundles
            .iter()
            .flat_map(|bundle| {
                let version = bundle
                    .component("node")
                    .map(|c| c.version.as_str())
                    .unwrap_or_default();
                bundle
                    .artifacts
                    .iter()
                    .filter(|row| row.component == "node")
                    .map(move |row| PinnedNode {
                        platform: row.platform,
                        version,
                        url: row.url.as_str(),
                        sha256: row.digest.hex(),
                    })
            })
            .collect()
    }))
}

/// The shipped default Node for a platform: the catalog's named default,
/// the same release `shipped_selection` picks. A newer release in the
/// catalog does not move it.
pub fn node_pin(platform: Platform) -> io::Result<&'static PinnedNode> {
    let default = &CATALOG.document()?.default;
    node_pins()?
        .iter()
        .find(|pin| pin.platform == platform && format!("node-{}", pin.version) == *default)
        .ok_or_else(|| no_pin("nodejs", platform))
}

/// The shipped Node catalog: one release bundle per nodejs.org release.
/// npm and node-gyp ship inside the Node artifact; the catalog records no
/// version for them, so they are not listed as components here.
pub fn toolchain_catalog() -> io::Result<Catalog> {
    CATALOG.catalog()
}

/// A pre-lock Node closure records its runtime under `node_version`, and
/// its environment object under `env_object`, whose `nodejs` input is the
/// runtime object: the artifact that object was built from is the proof.
pub fn legacy_toolchain_evidence(
    platform: Option<Platform>,
    body: &serde_json::Value,
    store: Option<&crate::kernel::store::Store>,
) -> LegacyEvidence {
    use crate::comforter::toolchain::{self as project_toolchain, LegacyRuntime};
    let mut evidence =
        crate::comforter::legacy_toolchain_evidence(platform, body, &[("node", "/node_version")]);
    project_toolchain::prove_legacy_runtime(
        &mut evidence,
        store,
        body,
        LegacyRuntime {
            pointer: "/env_object",
            via: &[("node-env", "nodejs")],
            kind: "nodejs",
        },
        |identity, evidence| {
            project_toolchain::expect_legacy_version(
                identity,
                evidence,
                "node",
                &identity.version,
            )?;
            // A Node identity carries no schema: its layout is the one the
            // catalog names `nodejs/legacy`.
            Ok(vec![project_toolchain::proved_from_identity(
                identity,
                "node",
                "artifact_sha256",
                "sha256",
                NODE_RECIPE,
            )?])
        },
    );
    evidence
}

/// The objects a pre-lock Node sync from `selected` left for legacy seeding
/// to read: the runtime the producer builds and an environment naming it,
/// and the body field that names the environment.
#[cfg(test)]
pub(crate) fn legacy_runtime_for_test(
    platform: Platform,
    selected: &Selected,
    store: &Store,
) -> (serde_json::Value, Vec<Identity>) {
    let node = node_identity_of(&node_row(selected, platform).unwrap(), platform);
    let env = Identity {
        kind: "node-env".into(),
        name: "env".into(),
        version: node.version.clone(),
        inputs: BTreeMap::from([
            ("schema".to_string(), "node-env/4".to_string()),
            ("nodejs".to_string(), node.object_id()),
        ]),
    };
    let body = serde_json::json!({"env_object": store.object_path(&env.object_id())});
    (body, vec![node, env])
}

pub fn preflight(platform: Platform) -> io::Result<()> {
    crate::kernel::platform::require_host(platform, "Node.js")?;
    node_pin(platform).map(|_| ())
}

/// The recipe id this tailor knows how to lay out. A lock row naming
/// anything else was written by a tog that extracts or relocates the Node
/// archive differently.
const NODE_RECIPE: &str = "nodejs/legacy";

/// The Node row from the selection, checked against the layout this tailor
/// implements.
fn node_row(selected: &Selected, platform: Platform) -> io::Result<ArtifactSpec> {
    if selected.ecosystem != "node" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("node: asked to realize a {} toolchain", selected.ecosystem),
        ));
    }
    let spec = selected.artifact(platform, "node")?;
    if spec.recipe != NODE_RECIPE {
        return Err(err(format!(
            "node: recipe {} in tog-toolchain.toml is not known to this tog; upgrade tog",
            spec.recipe
        )));
    }
    if spec.digest.algo() != "sha256" {
        return Err(err(format!(
            "node {}: tog realizes Node from a sha256 digest, not {}",
            spec.version,
            spec.digest.algo()
        )));
    }
    Ok(spec)
}

/// The shipped catalog's default Node release, for work with no project
/// selection to honor.
pub fn shipped_selection() -> io::Result<Selected> {
    crate::kernel::toolchain::shipped(&toolchain_catalog()?)
}

/// The CPython node-gyp runs on when the project's toolchain lock names no
/// Python: the newest shipped 3.12. It is not a component of the Node
/// release bundle, so a Node-only project takes it from the shipped Python
/// catalog; a project that also locks Python builds its addons on that one.
pub fn shipped_gyp_python() -> io::Result<Selected> {
    crate::kernel::provider::cpython::shipped_selection(GYP_PYTHON_LINE)
}

/// The CPython line [`shipped_gyp_python`] takes the newest release of.
const GYP_PYTHON_LINE: &str = "3.12";

/// The store object id of the Node a selection names, from the selection's
/// own row and without realizing it: the same id `realize_runtime` commits.
pub fn runtime_object_id(platform: Platform, selected: &Selected) -> io::Result<String> {
    let spec = node_row(selected, platform)?;
    Ok(node_identity_of(&spec, platform).object_id())
}

/// The Node object identity, from the row the selection names. It is
/// byte-identical to the one the pin table produced: the row carries the
/// same version and the same artifact digest.
fn node_identity_of(spec: &ArtifactSpec, platform: Platform) -> Identity {
    Identity {
        kind: "nodejs".into(),
        name: "nodejs".into(),
        version: spec.version.clone(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), spec.digest.hex().to_string()),
            ("platform".to_string(), platform.triple().to_string()),
        ]),
    }
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

/// A node environment does not repeat the platform input. Its `nodejs`
/// reference is the producer's platform anchor, so conditional contracts can
/// still distinguish the Linux-only native-library shape without changing the
/// established node-env identity bytes.
pub(crate) fn platform_of_node_object(id: &str) -> Option<Platform> {
    node_pins()
        .ok()?
        .iter()
        .find(|pin| node_identity(pin).object_id() == id)
        .map(|pin| pin.platform)
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

/// Realize the shipped Node, for work with no project selection to honor
/// (`x` outside a project, `add`/`update`'s delegated npm, tests).
pub fn ensure_node_for(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
) -> io::Result<PathBuf> {
    realize_runtime(store, activity, platform, &shipped_selection()?)
}

/// Realize the Node this selection names (interpreter at <obj>/bin/node).
///
/// npm and node-gyp ship inside this archive, so this one row is the whole
/// independently fetched set: the lock's digest covers all three.
pub fn realize_runtime(
    store: &Store,
    activity: &StoreActivity,
    platform: Platform,
    selected: &Selected,
) -> io::Result<PathBuf> {
    crate::tailors::install_kinds();
    crate::kernel::platform::require_host(platform, "Node.js")?;
    let spec = node_row(selected, platform)?;
    let identity = node_identity_of(&spec, platform);
    let id = identity.object_id();
    if store.has_with_activity(activity, &id)? {
        crate::kernel::policy::check_cached_with_activity(store, activity, &id)?;
        validate_node_layout(&store.object_path(&id))?;
        return Ok(store.object_path(&id));
    }
    let sha256 = spec.digest.hex();
    let tarball = download_verified_held(store, activity, &spec.url, sha256)?;
    let staged = store
        .stage_with_activity(activity)
        .map_err(|e| io::Error::new(e.kind(), format!("stage: {e}")))?;
    let mut command = Command::new("/usr/bin/tar");
    command
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&staged)
        .args(["--strip-components", "1"]);
    let status = crate::kernel::supervise::status(&mut command, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("spawn tar: {e}")))?;
    if !status.success() {
        return Err(err("node tarball extraction failed"));
    }
    validate_node_layout(&staged)?;
    store
        .commit_with_activity_and_deps(activity, &identity, &staged, &[], &{
            let mut deps = crate::kernel::store::ObjectDeps::new();
            deps.cache_digest(Digest::sha256(sha256)?);
            deps
        })
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
    /// A git dependency pinned to a commit. When set, the
    /// package content comes from the realized git object, not a tarball, and
    /// `integrity` carries `git:<commit>` rather than an SRI.
    pub git: Option<crate::kernel::gitsrc::GitSource>,
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
    /// Raw-byte SHA-256 when the lockfile hash matched pnpm's normalized/lossy
    /// patch text. A raw match is `None` so existing SHA-256 patch identities
    /// remain byte-identical.
    pub content_sha256: Option<String>,
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

/// A project-declared build input: a URL + sha256 that tog prefetches
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
    /// (e.g. ".npm/_libvips/libvips-8.14.5-darwin-arm64v8.tar.br").
    pub path: String,
}

#[derive(Debug, Clone, Default)]
pub struct TogConfig {
    pub mutable_packages: Vec<String>,
    pub artifacts: Vec<DeclaredArtifact>,
}

/// Strictly parse the optional `"tog"` config field of package.json.
/// Unknown keys and malformed values are hard errors: this config weakens
/// or extends the trust boundary, so typos must not be silently ignored.
pub fn parse_tog_config(pkg_json: &str) -> io::Result<TogConfig> {
    let v: serde_json::Value =
        serde_json::from_str(pkg_json).map_err(|e| err(format!("package.json: {e}")))?;
    let cfg = match v.get("tog") {
        None => return Ok(TogConfig::default()),
        Some(c) => c
            .as_object()
            .ok_or_else(|| err("package.json: \"tog\" must be an object"))?,
    };
    for key in cfg.keys() {
        if key != "mutablePackages" && key != "artifacts" {
            return Err(err(format!("package.json: unknown tog key {key:?}")));
        }
    }
    let mut out = TogConfig::default();
    if let Some(list) = cfg.get("mutablePackages") {
        let arr = list
            .as_array()
            .ok_or_else(|| err("tog.mutablePackages must be an array"))?;
        for item in arr {
            let name = item
                .as_str()
                .ok_or_else(|| err("tog.mutablePackages entries must be strings"))?;
            let bare = name.strip_prefix('@').unwrap_or(name);
            let ok = !name.is_empty()
                && name.matches('/').count() == if name.starts_with('@') { 1 } else { 0 }
                && bare
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c));
            if !ok {
                return Err(err(format!("tog.mutablePackages: bad name {name:?}")));
            }
            out.mutable_packages.push(name.to_string());
        }
    }
    if let Some(list) = cfg.get("artifacts") {
        let arr = list
            .as_array()
            .ok_or_else(|| err("tog.artifacts must be an array"))?;
        for item in arr {
            let url = item["url"].as_str().unwrap_or_default();
            let sha256 = item["sha256"].as_str().unwrap_or_default();
            let path = item["path"].as_str().unwrap_or_default();
            if !url.starts_with("https://") {
                return Err(err(format!("tog.artifacts: url must be https ({url:?})")));
            }
            if sha256.len() != 64
                || !sha256
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(err("tog.artifacts: sha256 must be 64 lowercase hex chars"));
            }
            let path_ok = !path.is_empty()
                && !path.starts_with('/')
                && path
                    .split('/')
                    .all(|c| !c.is_empty() && c != "." && c != "..");
            if !path_ok {
                return Err(err(format!("tog.artifacts: unsafe path {path:?}")));
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

/// The Python node-gyp runs on in tests: the shipped default, the one a
/// Node-only project gets.
#[cfg(test)]
pub(crate) fn test_gyp_python() -> Selected {
    shipped_gyp_python().expect("shipped CPython for node-gyp")
}

/// [`test_gyp_python`]'s object id on `platform`, the `gyp_python` input a
/// Node-only project's environment carries.
#[cfg(test)]
pub(crate) fn test_gyp_python_id(platform: Platform) -> String {
    crate::kernel::provider::cpython::cpython_object_id(&test_gyp_python(), platform)
        .expect("CPython object id for node-gyp")
}

#[cfg(test)]
pub(crate) fn live_identity_cases(platform: Platform) -> Vec<Identity> {
    const SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";
    let node = node_identity(node_pin(platform).expect("pinned Node for test platform"));
    let node_object = PathBuf::from(node.object_id());
    // `store_root` is a real `node-env` identity input, so the fixture store
    // path enters every case. Pin it per process and platform (not per
    // call) so two builds of the matrix yield identical identities; the
    // contents written below are idempotent, and the tree is left for the
    // OS temp cleanup rather than removed under a concurrent caller.
    let root = std::env::temp_dir().join(format!(
        "tog-node-identity-fixture-{}-{}",
        std::process::id(),
        platform.triple()
    ));
    for sub in [
        "objects",
        "meta",
        "cache/sha256",
        "cache/electron-shasums",
        "tmp",
    ] {
        fs::create_dir_all(root.join(sub)).expect("Node identity fixture store");
    }
    let store = Store {
        root: root
            .canonicalize()
            .expect("canonical Node identity fixture store"),
    };
    let empty_plan = NpmPlan {
        node_version: node.version.clone(),
        packages: Vec::new(),
        links: Vec::new(),
        workspaces: Vec::new(),
        lock_source: "fixture".into(),
    };
    let package = NpmPackage {
        path: "node_modules/example".into(),
        name: "example".into(),
        version: "1.0.0".into(),
        url: "https://registry.example.invalid/example.tgz".into(),
        integrity: SRI.into(),
        bin: Vec::new(),
        patch: None,
        git: None,
        optional: false,
    };
    let package_plan = NpmPlan {
        packages: vec![package.clone()],
        ..empty_plan.clone()
    };
    let second_package = NpmPackage {
        path: "node_modules/second-example".into(),
        name: "second-example".into(),
        version: "2.0.0".into(),
        url: "https://registry.example.invalid/second-example.tgz".into(),
        integrity: SRI.into(),
        bin: Vec::new(),
        patch: None,
        git: None,
        optional: false,
    };
    let multi_package_plan = NpmPlan {
        packages: vec![package, second_package],
        ..empty_plan.clone()
    };
    let artifact = DeclaredArtifact {
        url: "https://artifacts.example.invalid/tool.tar.gz".into(),
        sha256: "a".repeat(64),
        path: ".npm/tool.tar.gz".into(),
    };
    let empty = realize::node_env_identity(
        &store,
        platform,
        &node_object,
        &empty_plan,
        &[],
        None,
        &test_gyp_python_id(platform),
    )
    .expect("empty Node environment identity");
    let packages = realize::node_env_identity(
        &store,
        platform,
        &node_object,
        &package_plan,
        &[],
        None,
        &test_gyp_python_id(platform),
    )
    .expect("Node package environment identity");
    let multi_package = realize::node_env_identity(
        &store,
        platform,
        &node_object,
        &multi_package_plan,
        &[],
        None,
        &test_gyp_python_id(platform),
    )
    .expect("Node multi-package environment identity");
    let declared = realize::node_env_identity(
        &store,
        platform,
        &node_object,
        &empty_plan,
        &[artifact],
        None,
        &test_gyp_python_id(platform),
    )
    .expect("Node declared-artifact environment identity");
    let electron_version = "39.0.0";
    let release_url =
        format!("https://github.com/electron/electron/releases/download/v{electron_version}");
    use sha2::Digest as _;
    let electron_cache_directory = hex::encode(sha2::Sha256::digest(release_url.as_bytes()));
    let electron_cache = store
        .root
        .join("cache/electron-shasums")
        .join(electron_cache_directory);
    fs::create_dir_all(&electron_cache).expect("Electron checksum fixture directory");
    let electron_sha = "b".repeat(64);
    // Write-then-rename: a concurrent matrix builder in this process must
    // never observe a truncated manifest.
    static MANIFEST_WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let manifest_tmp = electron_cache.join(format!(
        ".SHASUMS256.txt.{}",
        MANIFEST_WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::write(
        &manifest_tmp,
        format!(
            "{electron_sha} electron-v{electron_version}-{}-{}.zip\n",
            platform.npm_os(),
            platform.npm_cpu()
        ),
    )
    .expect("Electron checksum fixture manifest");
    fs::rename(&manifest_tmp, electron_cache.join("SHASUMS256.txt"))
        .expect("publish Electron checksum fixture manifest");
    let electron = NpmPackage {
        path: "node_modules/electron".into(),
        name: "electron".into(),
        version: electron_version.into(),
        url: format!("{release_url}/electron-v{electron_version}.zip"),
        integrity: SRI.into(),
        bin: Vec::new(),
        patch: None,
        git: None,
        optional: false,
    };
    let electron_plan = NpmPlan {
        packages: vec![electron],
        ..empty_plan.clone()
    };
    let provisioned = realize::node_env_identity(
        &store,
        platform,
        &node_object,
        &electron_plan,
        &[],
        None,
        &test_gyp_python_id(platform),
    )
    .expect("Node Electron provisioned identity");
    let native_id =
        native_libs_identity_id(&store, platform, true).expect("Node native library conditional");
    let native = native_id.as_deref().map(|id| {
        realize::node_env_identity(
            &store,
            platform,
            &node_object,
            &package_plan,
            &[],
            Some(id),
            &test_gyp_python_id(platform),
        )
        .expect("Node native environment identity")
    });
    let mut cases = vec![node, empty, packages, multi_package, declared, provisioned];
    if let Some(native) = native {
        cases.push(native);
    }
    cases
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity matrix is reproducible: two builds in the same process
    /// yield the same kinds and the same inputs, case for case, on both
    /// platforms.
    #[test]
    fn live_identity_cases_are_reproducible() {
        for platform in Platform::ALL {
            let first = live_identity_cases(*platform);
            let second = live_identity_cases(*platform);
            assert_eq!(first.len(), second.len(), "{}", platform.triple());
            for (a, b) in first.iter().zip(&second) {
                assert_eq!(a.kind, b.kind, "{}", platform.triple());
                assert_eq!(a.version, b.version, "{}: {}", platform.triple(), a.kind);
                assert_eq!(a.inputs, b.inputs, "{}: {}", platform.triple(), a.kind);
            }
        }
    }

    /// Drift check: the legacy adapter must reconstruct exactly what this
    /// producer supplies at commit, or a migrated record stops matching what
    /// a re-sync publishes and every later cache hit becomes a hard error.
    #[test]
    fn legacy_adapter_recovers_the_pinned_node_artifact() {
        for platform in Platform::ALL {
            let pin = node_pin(*platform).unwrap();
            assert_eq!(
                recovered_cache(node_identity(pin)),
                vec![format!("sha256:{}", pin.sha256)]
            );
        }
    }

    fn recovered_cache(identity: crate::kernel::types::Identity) -> Vec<String> {
        match crate::kernel::objmeta::adapt_identity_for_test(identity, Vec::new()) {
            crate::kernel::objmeta::Adaptation::Proven(deps) => {
                assert!(
                    deps.objects.is_empty(),
                    "a pinned artifact has no object deps"
                );
                deps.cache
                    .iter()
                    .map(|digest| format!("{}:{}", digest.algo(), digest.hex()))
                    .collect()
            }
            crate::kernel::objmeta::Adaptation::Unresolved(reason) => panic!("{reason}"),
        }
    }

    const TEST_SRI: &str =
        "sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw==";

    #[test]
    fn node_pins_cover_each_supported_platform() {
        // Every pinned version has exactly one well-formed row per platform.
        let mut rows = std::collections::BTreeSet::new();
        let mut versions = std::collections::BTreeSet::new();
        let pins = node_pins().unwrap();
        for pin in pins {
            assert!(rows.insert((pin.platform.triple(), pin.version)));
            versions.insert(pin.version);
            let arch = match pin.platform {
                Platform::Aarch64AppleDarwin => "darwin-arm64",
                Platform::X86_64UnknownLinuxGnu => "linux-x64",
            };
            assert_eq!(
                pin.url,
                format!(
                    "https://nodejs.org/dist/v{0}/node-v{0}-{arch}.tar.gz",
                    pin.version
                )
            );
            assert!(
                pin.sha256.len() == 64 && pin.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "{}",
                pin.url
            );
        }
        assert_eq!(rows.len(), versions.len() * Platform::ALL.len());
        let digests: std::collections::BTreeSet<_> = pins.iter().map(|p| p.sha256).collect();
        assert_eq!(digests.len(), pins.len(), "a digest repeats");

        // The shipped default is the named one, on every platform, though
        // the catalog holds newer releases (the 24 line past it, and 26).
        assert!(versions
            .iter()
            .any(|v| crate::kernel::toolchain::Version::parse(v).unwrap()
                > crate::kernel::toolchain::Version::parse("24.20.0").unwrap()));
        for platform in Platform::ALL {
            assert_eq!(node_pin(*platform).unwrap().version, "24.20.0");
        }
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

    /// A pinned older LTS release is selectable exactly, a range the default
    /// satisfies keeps the default, one it does not takes the newest it
    /// admits, and the shipped default does not move.
    #[test]
    fn the_catalog_selects_a_pinned_lts_release_exactly() {
        use crate::kernel::toolchain::input::InputRow;
        use crate::kernel::toolchain::select_for;
        let catalog = toolchain_catalog().unwrap();
        let row = |path: &str, field: &str, value: &str| InputRow {
            path: PathBuf::from(path),
            field: field.into(),
            value: Some(value.into()),
            absent: false,
            sha256: Some("a".repeat(64)),
        };
        let pinned = select_for(
            &catalog,
            "node",
            &[row(".node-version", "version", "24.16.0")],
        )
        .unwrap();
        assert_eq!(pinned.release, "node-24.16.0");
        let darwin = pinned
            .artifacts
            .iter()
            .find(|a| a.platform == Platform::Aarch64AppleDarwin)
            .unwrap();
        assert_eq!(
            darwin.url,
            "https://nodejs.org/dist/v24.16.0/node-v24.16.0-darwin-arm64.tar.gz"
        );

        let vite = select_for(
            &catalog,
            "node",
            &[row("package.json", "engines.node", "^20.19.0 || >=22.12.0")],
        )
        .unwrap();
        assert_eq!(vite.release, "node-24.20.0");
        let maintenance = select_for(
            &catalog,
            "node",
            &[row("package.json", "engines.node", "^22.12.0")],
        )
        .unwrap();
        // No default on the 22 line: the newest release it admits.
        assert_eq!(maintenance.release, "node-22.23.3");
        assert_eq!(shipped_selection().unwrap().bundle.release, "node-24.20.0");

        // A non-default release's object still names its platform.
        let old = node_pins()
            .unwrap()
            .iter()
            .find(|p| p.version == "24.16.0" && p.platform == Platform::X86_64UnknownLinuxGnu)
            .unwrap();
        assert_eq!(
            platform_of_node_object(&node_identity(old).object_id()),
            Some(Platform::X86_64UnknownLinuxGnu)
        );
    }

    /// `node-env/5` goldens, on both platforms, from fixed inputs: a fixed
    /// store root (a real identity input), two packages, one declared
    /// artifact and the shipped node-gyp Python. The identity constructor is
    /// a pure function of its platform argument, so the Darwin value is
    /// computed here and the macOS gate only confirms it.
    ///
    /// `/5` is `/4` plus `gyp_python`: taking that input away and spelling
    /// the schema `/4` gives back the `/4` goldens byte for byte, so nothing
    /// else moved. The `/3` spelling is a different object id again, and the
    /// two drifts `/3` could not see — one package or the declared artifact
    /// dropped — stay contract errors.
    #[test]
    fn node_env_identity_goldens_and_dropped_plan_entries() {
        crate::tailors::install_kinds();
        let store = Store {
            root: PathBuf::from("/fixture/tog-store"),
        };
        let package = |path: &str, name: &str, version: &str| NpmPackage {
            path: path.into(),
            name: name.into(),
            version: version.into(),
            url: format!("https://registry.example.invalid/{name}.tgz"),
            integrity: TEST_SRI.into(),
            bin: Vec::new(),
            patch: None,
            git: None,
            optional: false,
        };
        let artifact = DeclaredArtifact {
            url: "https://artifacts.example.invalid/tool.tar.gz".into(),
            sha256: "a".repeat(64),
            path: ".npm/tool.tar.gz".into(),
        };
        for (platform, golden, golden_v4) in [
            (
                Platform::X86_64UnknownLinuxGnu,
                "3999dd6a1940ed182bcfffefd41dedcfed9fb429-env-24.20.0",
                "26333746f02786ed4d81de465ca6ee4c43e07000-env-24.20.0",
            ),
            (
                Platform::Aarch64AppleDarwin,
                "a0aaa1a6f2b11c672252154e50b87ceba0c0eb37-env-24.20.0",
                "aa486e4a07068ad33e42126fc5b58b042200b055-env-24.20.0",
            ),
        ] {
            let node = node_identity(node_pin(platform).unwrap());
            let node_object = PathBuf::from(node.object_id());
            let plan = NpmPlan {
                node_version: node.version.clone(),
                packages: vec![
                    package("node_modules/example", "example", "1.0.0"),
                    package("node_modules/second-example", "second-example", "2.0.0"),
                ],
                links: Vec::new(),
                workspaces: Vec::new(),
                lock_source: "fixture".into(),
            };
            let identity = realize::node_env_identity(
                &store,
                platform,
                &node_object,
                &plan,
                std::slice::from_ref(&artifact),
                None,
                &test_gyp_python_id(platform),
            )
            .unwrap();
            assert_eq!(identity.inputs["schema"], "node-env/5");
            assert_eq!(identity.inputs["native"], realize::NATIVE_NONE);
            assert_eq!(
                identity.inputs["gyp_python"],
                test_gyp_python_id(platform),
                "{}",
                platform.triple()
            );
            assert_eq!(identity.object_id(), golden, "{}", platform.triple());
            assert_eq!(
                crate::kernel::objmeta::check_identity_grammar(&identity),
                Ok(())
            );

            // Without the node-gyp Python, the `/4` identity is unchanged.
            let mut v4 = identity.clone();
            v4.inputs.insert("schema".into(), "node-env/4".into());
            v4.inputs.remove("gyp_python");
            assert_eq!(v4.object_id(), golden_v4, "{}", platform.triple());

            // The `/3` spelling of the same plan: a different object id,
            // which is the store-wide rebuild that bump accepted.
            let mut old = v4.clone();
            old.inputs.insert("schema".into(), "node-env/3".into());
            old.inputs.remove("plan_digest");
            old.inputs.remove("native");
            assert_ne!(old.object_id(), v4.object_id());

            // `gyp_python` must name a CPython object.
            let mut foreign = identity.clone();
            foreign.inputs.insert("gyp_python".into(), node.object_id());
            let reason = crate::kernel::objmeta::check_identity_grammar(&foreign).unwrap_err();
            assert!(reason.contains("Node gyp python"), "{reason}");
            let mut missing = identity.clone();
            missing.inputs.remove("gyp_python");
            assert!(crate::kernel::objmeta::check_identity_grammar(&missing).is_err());

            // The two drifts `/3` could not see.
            for key in ["pkg:node_modules/example", "artifact:.npm/tool.tar.gz"] {
                let mut dropped = identity.clone();
                dropped.inputs.remove(key);
                let reason = crate::kernel::objmeta::check_identity_grammar(&dropped).unwrap_err();
                assert!(reason.contains("Node plan digest"), "{key}: {reason}");
            }
        }
    }

    /// The real shape of the drift, not a mutated finished identity: a
    /// producer whose input loops never write one planned package or one
    /// declared artifact. The plan digest comes from the lockfile plan and
    /// the artifact list, so it still covers what the identity is missing
    /// and the contract refuses the commit.
    ///
    /// Building the digest from the input map instead would move it along
    /// with the drift, and each of these would be a legitimate smaller
    /// plan's identity — the `node-env/3` gap the bump exists to close.
    #[test]
    fn a_producer_that_skips_a_plan_input_is_refused() {
        crate::tailors::install_kinds();
        let store = Store {
            root: PathBuf::from("/fixture/tog-store"),
        };
        let package = |path: &str, name: &str, version: &str| NpmPackage {
            path: path.into(),
            name: name.into(),
            version: version.into(),
            url: format!("https://registry.example.invalid/{name}.tgz"),
            integrity: TEST_SRI.into(),
            bin: Vec::new(),
            patch: None,
            git: None,
            optional: false,
        };
        let artifact = DeclaredArtifact {
            url: "https://artifacts.example.invalid/tool.tar.gz".into(),
            sha256: "a".repeat(64),
            path: ".npm/tool.tar.gz".into(),
        };
        for platform in Platform::ALL.iter().copied() {
            let node = node_identity(node_pin(platform).unwrap());
            let node_object = PathBuf::from(node.object_id());
            let plan = NpmPlan {
                node_version: node.version.clone(),
                packages: vec![
                    package("node_modules/example", "example", "1.0.0"),
                    package("node_modules/second-example", "second-example", "2.0.0"),
                ],
                links: Vec::new(),
                workspaces: Vec::new(),
                lock_source: "fixture".into(),
            };
            let artifacts = std::slice::from_ref(&artifact);
            let honest = realize::node_env_identity(
                &store,
                platform,
                &node_object,
                &plan,
                artifacts,
                None,
                &test_gyp_python_id(platform),
            )
            .unwrap();

            for skipped in [
                "pkg:node_modules/second-example",
                "artifact:.npm/tool.tar.gz",
            ] {
                let drifted = realize::node_env_identity_skipping_input(
                    &store,
                    platform,
                    &node_object,
                    &plan,
                    artifacts,
                    None,
                    &test_gyp_python_id(platform),
                    skipped,
                )
                .unwrap();
                assert!(!drifted.inputs.contains_key(skipped));
                let reason = crate::kernel::objmeta::check_identity_grammar(&drifted).unwrap_err();
                assert!(
                    reason.contains("Node plan digest"),
                    "{} {skipped}: {reason}",
                    platform.triple()
                );
                assert_ne!(drifted.object_id(), honest.object_id());

                // The legitimate smaller plan the drift used to impersonate
                // is a different identity, and it commits cleanly.
                let smaller = match skipped.strip_prefix("pkg:") {
                    Some(path) => {
                        let mut smaller = plan.clone();
                        smaller.packages.retain(|p| p.path != path);
                        realize::node_env_identity(
                            &store,
                            platform,
                            &node_object,
                            &smaller,
                            artifacts,
                            None,
                            &test_gyp_python_id(platform),
                        )
                    }
                    None => realize::node_env_identity(
                        &store,
                        platform,
                        &node_object,
                        &plan,
                        &[],
                        None,
                        &test_gyp_python_id(platform),
                    ),
                }
                .unwrap();
                assert_eq!(
                    crate::kernel::objmeta::check_identity_grammar(&smaller),
                    Ok(())
                );
                assert_ne!(drifted.object_id(), smaller.object_id());
            }
        }
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
    fn patch_identity_spelling_binds_pnpm_9_content_by_sha256() {
        let store = Store {
            root: PathBuf::from("/nonexistent/tog-test-store"),
        };
        let node_obj = PathBuf::from("/nonexistent/nodejs");
        let identity_for = |patch: NpmPatch| {
            let plan = NpmPlan {
                node_version: "24.20.0".into(),
                packages: vec![NpmPackage {
                    path: "node_modules/foo".into(),
                    name: "foo".into(),
                    version: "1.0.0".into(),
                    url: "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz".into(),
                    integrity: TEST_SRI.into(),
                    bin: Vec::new(),
                    patch: Some(patch),
                    git: None,
                    optional: false,
                }],
                links: Vec::new(),
                workspaces: Vec::new(),
                lock_source: "pnpm-lock.yaml".into(),
            };
            node_env_identity(
                &store,
                Platform::Aarch64AppleDarwin,
                &node_obj,
                &plan,
                &[],
                None,
                &test_gyp_python_id(Platform::Aarch64AppleDarwin),
            )
            .unwrap()
        };
        let sha256_declared = identity_for(NpmPatch {
            path: "/project/patches/foo.patch".into(),
            hash: "sha256-2692094a267de7e28825147fd6cb2ebde098a4e68c25dfa3976ac806f4a1a784".into(),
            content_sha256: None,
        });
        let pnpm_9_declared = identity_for(NpmPatch {
            path: "/project/patches/foo.patch".into(),
            hash: "kpncbvlbnwqxywzzahw2g7pnwq".into(),
            content_sha256: Some(
                "e4688624e5f1ad0629505e6768e3bb36244f2f3e33e751215afa820334a76ed3".into(),
            ),
        });
        let key = "pkg:node_modules/foo";
        assert_eq!(
            sha256_declared.inputs[key].split_once(":patch").unwrap().1,
            "[sha256-2692094a267de7e28825147fd6cb2ebde098a4e68c25dfa3976ac806f4a1a784]:bin[]"
        );
        assert_eq!(
            pnpm_9_declared.inputs[key]
                .split_once(":patch")
                .unwrap()
                .1,
            "[kpncbvlbnwqxywzzahw2g7pnwq;sha256:e4688624e5f1ad0629505e6768e3bb36244f2f3e33e751215afa820334a76ed3]:bin[]"
        );
    }

    #[test]
    fn darwin_binding_gyp_keeps_legacy_identity_inputs() {
        let store = Store {
            root: PathBuf::from("/nonexistent/tog-test-store"),
        };
        assert_eq!(
            native_libs_identity_id(&store, Platform::Aarch64AppleDarwin, true).unwrap(),
            None
        );
    }

    /// Minimal base64 for building an SRI out of raw digest bytes; the
    /// kernel's encoder is private to the store module.
    fn sri_base64(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// Characterization of the COLD realization path, offline: the tarball is
    /// seeded into the download cache by digest, so the fetch is a cache hit
    /// and no network is touched. Pins extraction, bin-link creation, the
    /// committed object id, and the fact that a second call is a cache hit.
    #[test]
    fn realize_node_env_cold_path_extracts_and_links_bins() {
        // Extraction runs `tar` through the supervisor, which owns
        // process-wide signal dispositions: one supervised child at a time.
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("tog-npm-cold-{}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for subdir in ["objects", "meta", "cache/sha512", "tmp"] {
            fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();

        // A real store object stands in for the node toolchain: the env
        // records it as a dependency, so it has to be complete.
        let node_staged = store.stage().unwrap();
        fs::create_dir_all(node_staged.join("bin")).unwrap();
        let (node_obj, _) = store
            .commit_with_deps(
                &crate::kernel::types::Identity {
                    kind: "nodejs".into(),
                    name: "nodejs".into(),
                    version: "24.20.0".into(),
                    // `node_identity`'s real input shape; the commit-time
                    // grammar check refuses anything else.
                    inputs: BTreeMap::from([
                        ("artifact_sha256".to_string(), "b".repeat(64)),
                        (
                            "platform".to_string(),
                            crate::kernel::platform::Platform::host()
                                .unwrap()
                                .triple()
                                .to_string(),
                        ),
                    ]),
                },
                &node_staged,
                &[],
                &crate::kernel::store::ObjectDeps::new(),
            )
            .unwrap();

        // A real registry tarball, seeded into the download cache by digest.
        let src = root.join("src");
        fs::create_dir_all(src.join("package/bin")).unwrap();
        fs::write(
            src.join("package/package.json"),
            r#"{"name":"a","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(src.join("package/bin/a.js"), "#!/usr/bin/env node\n").unwrap();
        let tarball = root.join("a.tgz");
        assert!(std::process::Command::new("/usr/bin/tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&src)
            .arg("package")
            .status()
            .unwrap()
            .success());
        let bytes = fs::read(&tarball).unwrap();
        use sha2::Digest as _;
        let raw = sha2::Sha512::digest(&bytes);
        let sri = format!("sha512-{}", sri_base64(&raw));
        fs::write(store.cache_path("sha512", &hex::encode(raw)), &bytes).unwrap();

        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![NpmPackage {
                path: "node_modules/a".into(),
                name: "a".into(),
                version: "1.0.0".into(),
                url: "https://127.0.0.1:9/a.tgz".into(),
                integrity: sri.clone(),
                bin: vec![("a".into(), "bin/a.js".into())],
                patch: None,
                git: None,
                optional: false,
            }],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let platform = Platform::Aarch64AppleDarwin;
        let env = realize_node_env_with_node_object(
            &store,
            activity,
            platform,
            &plan,
            &[],
            &node_obj,
            &test_gyp_python(),
        )
        .expect("cold realization");

        let expected = node_env_identity(
            &store,
            platform,
            &node_obj,
            &plan,
            &[],
            None,
            &test_gyp_python_id(platform),
        )
        .unwrap()
        .object_id();
        assert_eq!(env.file_name().unwrap().to_string_lossy(), expected);
        assert_eq!(
            fs::read_to_string(env.join("node_modules/a/package.json")).unwrap(),
            r#"{"name":"a","version":"1.0.0"}"#,
            "the tarball is extracted with its leading component stripped"
        );
        let link = env.join("node_modules/.bin/a");
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("../a/bin/a.js")
        );

        // A second call is a cache hit and returns the same object.
        let again = realize_node_env_with_node_object(
            &store,
            activity,
            platform,
            &plan,
            &[],
            &node_obj,
            &test_gyp_python(),
        )
        .expect("warm realization");
        assert_eq!(again, env);
        crate::kernel::store::remove_tree(&root).unwrap();
    }

    /// Characterization of the skip decision in `run_install_scripts_staged`:
    /// a package with no install hooks and no binding.gyp gets no scratch
    /// stage dir, no tool shim, and no cleanup entry. Packages that DO have
    /// hooks need the build sandbox and are covered by the `#[ignore]` gates
    /// in tests/npm_scripts.rs (benign_install_script_runs_and_output_is_captured,
    /// permissive_install_script_is_cached_but_rejected_strict,
    /// network_access_during_install_script_fails).
    #[test]
    fn install_scripts_skip_packages_without_lifecycle_hooks() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("tog-npm-lifecycle-{}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for subdir in ["objects", "meta", "cache/sha256", "tmp"] {
            fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let node_obj = store.object_path("node-cache");
        fs::create_dir_all(&node_obj).unwrap();
        let staged = store.stage().unwrap();
        // "no hooks", "unreadable manifest" and "unparsable manifest" are the
        // three ways the loop declines a package.
        for (path, manifest) in [
            (
                "plain",
                Some(r#"{"name":"plain","scripts":{"test":"echo"}}"#),
            ),
            ("broken", Some("{not json")),
            ("missing", None),
        ] {
            let dir = staged.join("node_modules").join(path);
            fs::create_dir_all(&dir).unwrap();
            if let Some(manifest) = manifest {
                fs::write(dir.join("package.json"), manifest).unwrap();
            }
        }
        let package = |name: &str| NpmPackage {
            path: format!("node_modules/{name}"),
            name: name.into(),
            version: "1.0.0".into(),
            url: "https://127.0.0.1:9/never-requested.tgz".into(),
            integrity: TEST_SRI.into(),
            bin: Vec::new(),
            patch: None,
            git: None,
            optional: false,
        };
        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![package("plain"), package("broken"), package("missing")],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let mut cleanup: Vec<PathBuf> = Vec::new();
        let mut consumed = crate::kernel::store::ObjectDeps::new();
        run_install_scripts_staged(
            &store,
            activity,
            Platform::host().unwrap(),
            &staged,
            &node_obj,
            &plan,
            &[],
            None,
            &test_gyp_python(),
            &mut consumed,
            &mut cleanup,
        )
        .expect("no lifecycle work to do");
        assert_eq!(
            consumed,
            crate::kernel::store::ObjectDeps::new(),
            "no lifecycle ran, so no cache entry was consumed"
        );
        assert!(
            cleanup.is_empty(),
            "no scratch stage dirs were taken: {cleanup:?}"
        );
        assert_eq!(
            fs::read_to_string(staged.join("node_modules/plain/package.json")).unwrap(),
            r#"{"name":"plain","scripts":{"test":"echo"}}"#,
            "the package tree is untouched"
        );
        crate::kernel::store::remove_tree(&root).unwrap();
    }

    #[test]
    fn darwin_warm_sync_does_not_fetch_package_tarballs() {
        let root = std::env::temp_dir().join(format!("tog-npm-darwin-warm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for subdir in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
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
            // The realization below is for Darwin, so is its node-gyp Python.
            &test_gyp_python_id(Platform::Aarch64AppleDarwin),
        )
        .unwrap();
        let staged = store.stage().unwrap();
        std::fs::create_dir_all(staged.join("node_modules")).unwrap();
        // Warm-path fixture: the realization below returns at the cache
        // lookup, so the cold dependency capture never runs. Publishing with
        // an empty set keeps the fixture from asserting evidence the
        // producer would not have supplied here.
        let (expected, _) = store
            .commit_with_deps(
                &identity,
                &staged,
                &[],
                &crate::kernel::store::ObjectDeps::new(),
            )
            .unwrap();

        let realized = realize_node_env_with_node_object(
            &store,
            activity,
            Platform::Aarch64AppleDarwin,
            &plan,
            &[],
            &node_obj,
            &test_gyp_python(),
        )
        .unwrap();
        assert_eq!(realized, expected);
        assert_eq!(
            std::fs::read_dir(store.root.join("cache/sha256"))
                .unwrap()
                .count(),
            0
        );
        crate::kernel::store::remove_tree(&root).unwrap();
    }

    /// The Python node-gyp runs on is the one the environment names: a
    /// project that locks Python 3.13 gets an environment keyed on that
    /// interpreter, a Node-only project one keyed on the shipped default, and
    /// the two never share an object. Offline: the warm path returns at the
    /// cache lookup, before any interpreter is realized.
    #[test]
    fn the_environment_is_keyed_on_the_python_node_gyp_runs_on() {
        crate::tailors::install_kinds();
        let root = std::env::temp_dir().join(format!("tog-npm-gyp-python-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for subdir in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let platform = Platform::Aarch64AppleDarwin;
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
        let locked = crate::kernel::provider::cpython::shipped_selection("3.13").unwrap();
        assert_eq!(locked.version("cpython").unwrap(), "3.13.15");
        let default = test_gyp_python();
        assert_eq!(default.version("cpython").unwrap(), "3.12.14");

        let mut published = Vec::new();
        for python in [&locked, &default] {
            let python_id =
                crate::kernel::provider::cpython::cpython_object_id(python, platform).unwrap();
            let identity =
                node_env_identity(&store, platform, &node_obj, &plan, &[], None, &python_id)
                    .unwrap();
            assert_eq!(identity.inputs["gyp_python"], python_id);
            let staged = store.stage().unwrap();
            std::fs::create_dir_all(staged.join("node_modules")).unwrap();
            let (expected, _) = store
                .commit_with_deps(
                    &identity,
                    &staged,
                    &[],
                    &crate::kernel::store::ObjectDeps::new(),
                )
                .unwrap();
            let realized = realize_node_env_with_node_object(
                &store,
                activity,
                platform,
                &plan,
                &[],
                &node_obj,
                python,
            )
            .unwrap();
            assert_eq!(realized, expected, "{}", python.describe());
            published.push(realized);
        }
        assert_ne!(published[0], published[1]);
        crate::kernel::store::remove_tree(&root).unwrap();
    }

    #[test]
    fn linux_warm_sync_uses_persisted_archive_classification() {
        let root = std::env::temp_dir().join(format!("tog-npm-linux-warm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for subdir in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(subdir)).unwrap();
        }
        let store = Store {
            root: root.canonicalize().unwrap(),
        };
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
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
            &test_gyp_python_id(Platform::host().unwrap()),
        )
        .unwrap();
        let staged = store.stage().unwrap();
        std::fs::create_dir_all(staged.join("node_modules")).unwrap();
        // Warm-path fixture: the realization below returns at the cache
        // lookup, so the cold dependency capture never runs. Publishing with
        // an empty set keeps the fixture from asserting evidence the
        // producer would not have supplied here.
        let (expected, _) = store
            .commit_with_deps(
                &identity,
                &staged,
                &[],
                &crate::kernel::store::ObjectDeps::new(),
            )
            .unwrap();

        // Simulate the user clearing all downloaded package archives. The
        // persisted inspection result is the only input available to the
        // Linux warm lookup below.
        let realized = realize_node_env_with_node_object(
            &store,
            activity,
            Platform::X86_64UnknownLinuxGnu,
            &plan,
            &[],
            &node_obj,
            &test_gyp_python(),
        )
        .unwrap();
        assert_eq!(realized, expected);
        assert_eq!(
            std::fs::read_dir(store.root.join("cache/sha256"))
                .unwrap()
                .count(),
            0
        );
        crate::kernel::store::remove_tree(&root).unwrap();
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
            root: PathBuf::from("/nonexistent/tog-test-store"),
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
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
        let error = realize_node_env(&store, activity, foreign, &plan, &[]).unwrap_err();
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

    /// Characterization: one lockfile that exercises every branch of
    /// `plan_npm` at once — a registry package with bins, a workspace source
    /// dir, a link entry, a pinned git dependency, a bundled entry and an
    /// optional platform-incompatible subtree — pinned field by field so a
    /// refactor of the loop cannot silently move a value.
    #[test]
    fn plan_npm_characterization_covers_every_entry_kind() {
        let l = format!(
            r#"{{"name":"x","lockfileVersion":3,"packages":{{
                 "":{{"name":"x","workspaces":["packages/lib"]}},
                 "packages/lib":{{"name":"@mono/lib","version":"0.1.0"}},
                 "node_modules/@mono/lib":{{"resolved":"packages/lib","link":true}},
                 "node_modules/a":{{"version":"1.2.3","resolved":"https://r/a.tgz","integrity":"{TEST_SRI}","bin":{{"a":"cli.js","a2":"bin/a2.js"}}}},
                 "node_modules/a/node_modules/bundled":{{"version":"9","inBundle":true}},
                 "node_modules/g":{{"version":"2.0.0","resolved":"git+https://github.com/o/g.git#1234567890abcdef1234567890abcdef12345678"}},
                 "node_modules/w":{{"version":"1","optional":true,"cpu":["wasm32"],"resolved":"https://r/w.tgz","integrity":"{TEST_SRI}"}},
                 "node_modules/w/node_modules/x":{{"version":"1"}}
               }}}}"#
        );
        let plan = plan_npm(Platform::Aarch64AppleDarwin, &l).unwrap();
        assert_eq!(plan.lock_source, "package-lock.json");
        assert_eq!(plan.workspaces, vec!["packages/lib".to_string()]);
        assert_eq!(plan.links.len(), 1);
        assert_eq!(plan.links[0].path, "node_modules/@mono/lib");
        assert_eq!(plan.links[0].target, "packages/lib");
        // bundled, the optional wasm32 package and its descendant are gone.
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(paths, vec!["node_modules/a", "node_modules/g"]);
        let a = &plan.packages[0];
        assert_eq!(a.name, "a");
        assert_eq!(a.version, "1.2.3");
        assert_eq!(a.url, "https://r/a.tgz");
        assert_eq!(a.integrity, TEST_SRI);
        assert_eq!(
            a.bin,
            vec![
                ("a".to_string(), "cli.js".to_string()),
                ("a2".to_string(), "bin/a2.js".to_string()),
            ]
        );
        assert!(a.patch.is_none());
        assert!(a.git.is_none());
        assert!(!a.optional);
        let g = &plan.packages[1];
        let source = g.git.as_ref().expect("pinned git source");
        assert_eq!(source.commit, "1234567890abcdef1234567890abcdef12345678");
        assert_eq!(g.integrity, "git:1234567890abcdef1234567890abcdef12345678");
        assert_eq!(g.name, "g");
    }

    #[test]
    fn workspace_local_packages_are_packages_not_workspaces() {
        // package-lock v3 monorepo: "packages/lib" is a workspace source dir;
        // "packages/lib/node_modules/c" is c@2 installed inside that
        // workspace because the root hoists c@1. The nested entry is a
        // package to realize, not a second workspace.
        // "tools/node_modules-shim" is a workspace whose directory name merely
        // contains the word: only a "/node_modules/" segment marks installed
        // content, so it must stay a workspace.
        let l = lock(&format!(
            r#""node_modules/c":{{"version":"1.0.0","resolved":"https://r/c1.tgz","integrity":"{TEST_SRI}"}},
               "node_modules/lib":{{"resolved":"packages/lib","link":true}},
               "packages/lib":{{"name":"lib","version":"0.0.0"}},
               "packages/lib/node_modules/c":{{"version":"2.0.0","resolved":"https://r/c2.tgz","integrity":"{TEST_SRI}"}},
               "tools/node_modules-shim":{{"name":"shim","version":"0.0.0"}},
               "tools/node_modules-shim/node_modules/c":{{"version":"3.0.0","resolved":"https://r/c3.tgz","integrity":"{TEST_SRI}"}}"#
        ));
        let plan = plan_npm(Platform::X86_64UnknownLinuxGnu, &l).unwrap();
        assert_eq!(
            plan.workspaces,
            vec![
                "packages/lib".to_string(),
                "tools/node_modules-shim".to_string()
            ]
        );
        let paths: Vec<&str> = plan.packages.iter().map(|p| p.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "node_modules/c",
                "packages/lib/node_modules/c",
                "tools/node_modules-shim/node_modules/c"
            ]
        );
        assert_eq!(plan.packages[1].name, "c");
        assert_eq!(plan.packages[1].version, "2.0.0");
        assert_eq!(plan.packages[2].version, "3.0.0");
        assert_eq!(plan.links.len(), 1);
        assert_eq!(plan.links[0].target, "packages/lib");
    }

    #[test]
    fn previous_workspace_set_drops_workspace_local_package_entries() {
        let dir = std::env::temp_dir().join(format!("tog-prev-ws-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        fs::write(
            dir.join(".tog/closures/node.json"),
            r#"{"body":{"workspaces":["packages/lib","packages/lib/node_modules/c","tools/node_modules-shim"]}}"#,
        )
        .unwrap();
        assert_eq!(
            previous_workspace_set(&crate::kernel::fsroot::ProjectRoot::open(&dir).unwrap()),
            vec![
                "packages/lib".to_string(),
                "tools/node_modules-shim".to_string()
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovers_string_object_and_legacy_directory_bins() {
        let dir = std::env::temp_dir().join(format!("tog-npm-bin-{}", std::process::id()));
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

    /// Characterization: one projection with a package, a workspace-local
    /// package, a workspace link and a recorded input, pinning both the
    /// symlink layout and every field of the closure record so a refactor of
    /// the projection cannot quietly move a value or reorder a step.
    #[test]
    fn project_node_env_recorded_characterization_pins_the_closure() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tog-npm-projection-{nonce}"));
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
        let plan = NpmPlan {
            node_version: "24.20.0".into(),
            packages: vec![
                package("node_modules/c", "1.0.0"),
                package("packages/lib/node_modules/c", "2.0.0"),
            ],
            links: vec![NpmLink {
                path: "node_modules/lib".into(),
                target: "packages/lib".into(),
            }],
            workspaces: Vec::new(),
            lock_source: "pnpm-lock.yaml".into(),
        };
        let inputs = vec![crate::comforter::InputRecord {
            path: "package.json".into(),
            sha256: "abc".into(),
        }];
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        project_node_env_recorded(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &env,
            Platform::host().unwrap(),
            &plan,
            &[],
            false,
            &inputs,
            None,
            &serde_json::Value::Null,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        // Both node_modules entries are symlinks into a forest outside the
        // project, and the workspace link points back at the source dir.
        for nm in [
            project.join("node_modules"),
            project.join("packages/lib/node_modules"),
        ] {
            assert!(
                fs::symlink_metadata(&nm).unwrap().file_type().is_symlink(),
                "{} is not a symlink",
                nm.display()
            );
        }
        let forest = fs::read_link(project.join("node_modules")).unwrap();
        assert_eq!(forest.file_name().unwrap(), "node_modules");
        assert!(fs::symlink_metadata(forest.join("lib"))
            .unwrap()
            .file_type()
            .is_symlink());

        let envelope: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(project.join(".tog/closures/node.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(envelope["schema"], "closure/1");
        assert_eq!(envelope["ecosystem"], "node");
        let closure = &envelope["body"];
        assert_eq!(closure["projection_schema"], "node-forest/2");
        assert_eq!(closure["node_version"], "24.20.0");
        assert_eq!(closure["lock_source"], "pnpm-lock.yaml");
        assert_eq!(closure["mutable_state"], "none");
        assert_eq!(closure["mutable_scope"], "none");
        assert_eq!(closure["mutable_packages"], serde_json::json!([]));
        assert_eq!(closure["mutable_paths"], serde_json::json!([]));
        assert_eq!(closure["backup_paths"], serde_json::json!([]));
        assert_eq!(
            closure["workspaces"],
            serde_json::json!(["packages/lib"]),
            "the workspace is inferred from the package-local placement"
        );
        assert_eq!(
            closure["workspace_links"],
            serde_json::json!([{"path": "node_modules/lib", "target": "packages/lib"}])
        );
        assert_eq!(
            closure["packages"],
            serde_json::json!([
                {"path": "node_modules/c", "version": "1.0.0", "integrity": TEST_SRI},
                {"path": "packages/lib/node_modules/c", "version": "2.0.0", "integrity": TEST_SRI},
            ])
        );
        assert_eq!(
            closure["inputs"],
            serde_json::json!([{"path": "package.json", "sha256": "abc"}])
        );
        assert_eq!(
            closure["env_object"],
            env.canonicalize().unwrap().to_string_lossy().into_owned()
        );
        assert!(closure["native_libs"].is_null());
        assert_eq!(
            closure["forest_path"].as_str().unwrap(),
            forest.to_string_lossy()
        );
        let _ = fs::remove_dir_all(root);
    }

    /// What sync records beside the projection: the bundle it planned from
    /// and the Node object it realized, so a later run resolves the same
    /// bytes and a catalog refresh cannot reach this project.
    #[test]
    fn project_node_env_recorded_writes_the_toolchain_record() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tog-npm-toolchain-record-{nonce}"));
        let project = root.join("project");
        let env = root.join("home/store/objects/env");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(env.join("node_modules")).unwrap();

        let selected = shipped_selection().unwrap();
        let runtime = root.join("home/store/objects/node-object");
        let plan = NpmPlan {
            node_version: selected.version("node").unwrap().to_string(),
            packages: Vec::new(),
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        project_node_env_recorded(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &env,
            Platform::host().unwrap(),
            &plan,
            &[],
            false,
            &[],
            Some((&selected, runtime.as_path())),
            &serde_json::Value::Null,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let envelope: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(project.join(".tog/closures/node.json")).unwrap(),
        )
        .unwrap();
        let closure = &envelope["body"];
        assert_eq!(closure["toolchain"]["ecosystem"], "node");
        assert_eq!(closure["toolchain"]["bundle_id"], selected.bundle_id());
        assert_eq!(
            closure["toolchain"]["versions"]["node"],
            plan.node_version.as_str()
        );
        assert_eq!(closure["runtime_object"]["id"], "node-object");
        assert_eq!(
            closure["runtime_object"]["path"],
            runtime.to_string_lossy().into_owned()
        );
        // The keys ls, status and sbom already read are untouched.
        assert_eq!(closure["node_version"], plan.node_version.as_str());
        assert_eq!(closure["projection_schema"], "node-forest/2");
        let _ = fs::remove_dir_all(root);
    }

    /// With complete object ids the strict path runs, and the durable
    /// root/2 record `project_node_env_recorded` publishes names exactly the
    /// environment object, the Node runtime object, the native library
    /// object the environment was built against, the forest it projected
    /// and the backup of the user's real `node_modules`: nothing inferred
    /// from the closure JSON, nothing missing.
    #[test]
    fn closure_refs_name_every_object_this_producer_created() {
        use std::os::unix::fs::PermissionsExt;
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tog-npm-closure-refs-{nonce}"));
        let store_root = root.join("home/store");
        for sub in [
            "objects",
            "meta",
            "cache/sha256",
            "tmp",
            "roots",
            "forests",
            "backups",
        ] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store {
            root: store_root.canonicalize().unwrap(),
        };
        let lease = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let activity = &lease;
        let selected = shipped_selection().unwrap();
        let env_id = format!("{}-npm-env-0", "1".repeat(40));
        let runtime_id = format!("{}-node-0", "2".repeat(40));
        let native_id = format!("{}-native-libs-0", "3".repeat(40));
        fs::create_dir_all(store.object_path(&env_id).join("node_modules/c")).unwrap();
        fs::write(
            store
                .object_path(&env_id)
                .join("node_modules/c/package.json"),
            "{}",
        )
        .unwrap();
        for (id, inputs) in [
            (&env_id, serde_json::json!({ "native_libs": native_id })),
            (&runtime_id, serde_json::json!({})),
            (&native_id, serde_json::json!({})),
        ] {
            let object = store.object_path(id);
            fs::create_dir_all(&object).unwrap();
            let mut permissions = fs::metadata(&object).unwrap().permissions();
            permissions.set_mode(permissions.mode() & !0o222);
            fs::set_permissions(&object, permissions).unwrap();
            fs::write(
                store.root.join("meta").join(format!("{id}.json")),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "id": id,
                    "identity": {"kind": "test", "name": id, "version": "0", "inputs": inputs},
                }))
                .unwrap(),
            )
            .unwrap();
        }
        // A real node_modules the user made: it is moved into a store backup.
        let project = root.join("project");
        fs::create_dir_all(project.join("node_modules/left-pad")).unwrap();
        let plan = NpmPlan {
            node_version: selected.version("node").unwrap().to_string(),
            packages: vec![NpmPackage {
                path: "node_modules/c".into(),
                name: "c".into(),
                version: "1.0.0".into(),
                url: "https://example.invalid/c.tgz".into(),
                integrity: TEST_SRI.into(),
                bin: Vec::new(),
                patch: None,
                git: None,
                optional: false,
            }],
            links: Vec::new(),
            workspaces: Vec::new(),
            lock_source: "package-lock.json".into(),
        };
        let runtime = store.object_path(&runtime_id);
        project_node_env_recorded(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &store.object_path(&env_id),
            Platform::host().unwrap(),
            &plan,
            &[],
            false,
            &[],
            Some((&selected, runtime.as_path())),
            &serde_json::Value::Null,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();

        let forest = fs::read_link(project.join("node_modules")).unwrap();
        let backups: Vec<PathBuf> = fs::read_dir(store.root.join("backups"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(backups.len(), 1, "{backups:?}");
        let roots = store.roots().unwrap();
        assert_eq!(roots.len(), 1, "no durable root record was published");
        let record = roots[0].record.as_ref().expect("root/2 record");
        assert_eq!(
            record.objects,
            std::collections::BTreeSet::from([env_id, runtime_id, native_id])
        );
        assert_eq!(
            record.projections,
            std::collections::BTreeSet::from([
                store
                    .projection_ref(crate::kernel::store::ProjectionBase::Forests, &forest)
                    .unwrap(),
                store
                    .projection_ref(crate::kernel::store::ProjectionBase::Backups, &backups[0])
                    .unwrap(),
            ])
        );

        // `gc --register` rebuilds the same record from this closure alone,
        // plus one reference the publisher never makes: the importer also
        // follows the `projection_id` route that `node-forest/1` closures
        // needed, and adds the forest's spelling in the legacy sibling
        // namespace. That namespace is never swept, so the extra reference
        // retains nothing; it is pinned here so a change to it is seen.
        drop(lease);
        let reimported = crate::kernel::store::reimport_root_for_test(&store, &project).unwrap();
        assert_eq!(reimported.objects, record.objects);
        let mut expected = record.projections.clone();
        let proj_id = forest.parent().unwrap();
        expected.insert(
            crate::kernel::store::ProjectionRef::new(
                crate::kernel::store::ProjectionBase::LegacyForests,
                vec![
                    proj_id.parent().unwrap().file_name().unwrap().into(),
                    proj_id.file_name().unwrap().into(),
                ],
            )
            .unwrap(),
        );
        assert_eq!(reimported.projections, expected);
        let _ = crate::kernel::store::remove_tree(&root);
    }

    #[test]
    fn stale_workspace_projection_is_removed_when_dependency_aligns() {
        let _attribution_lock = crate::kernel::policy::attribution_test_lock();
        let mut attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tog-npm-stale-workspace-{nonce}"));
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
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        project_node_env(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &env,
            Platform::host().unwrap(),
            &first,
            &[],
            false,
            &mut attribution,
        )
        .unwrap();
        attribution.finish(true).unwrap();
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
        let mut attribution = crate::kernel::policy::Attribution::open("node").unwrap();
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        project_node_env(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(&project).unwrap(),
            &env,
            Platform::host().unwrap(),
            &second,
            &[],
            false,
            &mut attribution,
        )
        .unwrap();
        assert!(fs::symlink_metadata(&workspace_nm).is_err());
        attribution.finish(true).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_workspace_ownership_canonicalizes_symlinked_temp_roots() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("tog-npm-symlinked-tmp-{nonce}"));
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
        let root = std::env::temp_dir().join(format!("tog-npm-external-workspace-{nonce}"));
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
        let root = std::env::temp_dir().join(format!("tog-npm-unsafe-workspace-{nonce}"));
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
        // Darwin behavior predating the Linux selector, preserved verbatim:
        // array-only, and any negated entry makes positives irrelevant.
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
    fn tog_config_parsing() {
        let empty = parse_tog_config(r#"{"name":"x"}"#).unwrap();
        assert!(empty.mutable_packages.is_empty() && empty.artifacts.is_empty());
        let ok =
            parse_tog_config(r#"{"tog":{"mutablePackages":["b","@prisma/engines","b"]}}"#).unwrap();
        assert_eq!(
            ok.mutable_packages,
            vec!["@prisma/engines".to_string(), "b".to_string()]
        );
        // unknown key, bad names, wrong types: hard errors
        assert!(parse_tog_config(r#"{"tog":{"mutable":["a"]}}"#).is_err());
        assert!(parse_tog_config(r#"{"tog":{"mutablePackages":["../x"]}}"#).is_err());
        assert!(parse_tog_config(r#"{"tog":{"mutablePackages":"a"}}"#).is_err());
        assert!(parse_tog_config(r#"{"tog":{"mutablePackages":[""]}}"#).is_err());
        assert!(parse_tog_config(r#"{"tog":[]}"#).is_err());
        // artifacts: happy path + validation
        let a = parse_tog_config(
            r#"{"tog":{"artifacts":[{"url":"https://x/y.tar","sha256":"0000000000000000000000000000000000000000000000000000000000000000","path":".npm/_libvips/y.tar"}]}}"#,
        )
        .unwrap();
        assert_eq!(a.artifacts.len(), 1);
        assert!(parse_tog_config(
            r#"{"tog":{"artifacts":[{"url":"http://x/y","sha256":"00","path":"p"}]}}"#
        )
        .is_err());
        assert!(parse_tog_config(
            r#"{"tog":{"artifacts":[{"url":"https://x/y","sha256":"0000000000000000000000000000000000000000000000000000000000000000","path":"../evil"}]}}"#
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
        // The bare repository URL carries its commit in the fragment.
        let source = super::git_source_from_url(&format!("https://github.com/o/r#{commit}"))
            .expect("repository URL");
        assert_eq!(source.commit, commit);
        // A release asset is a plain tarball; its fragment is Yarn's sha1 of
        // the bytes and names no commit.
        let sha1 = "abf2e9a850201e3571b8d36830f77bc52af3de9b";
        assert!(super::git_source_from_url(&format!(
            "https://github.com/o/r/releases/download/v1/r-1.0.0.tgz#{sha1}"
        ))
        .is_none());
        // An archive URL downloads the commit in its path, whatever the
        // fragment says.
        for url in [
            format!("https://codeload.github.com/o/r/tar.gz/{commit}#{sha1}"),
            format!("https://github.com/o/r/archive/{commit}.tar.gz#{sha1}"),
        ] {
            assert_eq!(super::git_source_from_url(&url).unwrap().commit, commit);
        }
    }
}

#[cfg(test)]
mod toolchain_tests {
    use super::*;

    /// A selection whose Node row names a layout this tog does not
    /// implement: the bytes it locked are not the bytes this code would
    /// produce, so realization refuses instead of guessing.
    fn with_recipe(platform: Platform, recipe: &str) -> Selected {
        let mut selected = shipped_selection().expect("shipped Node release");
        for row in &mut selected.bundle.artifacts {
            if row.platform == platform {
                row.recipe = recipe.to_string();
            }
        }
        selected
    }

    #[test]
    fn realization_refuses_an_unknown_recipe_and_another_ecosystem() {
        let store = Store {
            root: std::env::temp_dir().join("tog-node-recipe-refusal"),
        };
        let lease = crate::kernel::testutil::detached_lease();
        let activity = &lease.1;
        // The row check is per platform; realization can only run for the
        // host, which `require_host` refuses first for the other one.
        for platform in Platform::ALL {
            let error = node_row(&with_recipe(*platform, "nodejs/2"), *platform)
                .unwrap_err()
                .to_string();
            assert!(error.contains("recipe nodejs/2"), "{error}");
            assert!(error.contains("upgrade tog"), "{error}");
        }
        let platform = Platform::host().unwrap();
        let error = realize_runtime(
            &store,
            activity,
            platform,
            &with_recipe(platform, "nodejs/2"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("recipe nodejs/2"), "{error}");

        let mut python = shipped_selection().unwrap();
        python.ecosystem = "python".into();
        let error = realize_runtime(&store, activity, platform, &python)
            .unwrap_err()
            .to_string();
        assert!(error.contains("a python toolchain"), "{error}");
        assert!(!store.root.exists(), "a refusal touched the store");
    }

    /// The row and the pin describe the same bytes, so the object a locked
    /// project realizes is the object every existing store already holds.
    #[test]
    fn an_identity_from_a_selected_row_equals_the_identity_from_the_pin() {
        let selected = shipped_selection().unwrap();
        for platform in Platform::ALL {
            let pin = node_pin(*platform).unwrap();
            let spec = node_row(&selected, *platform).unwrap();
            assert_eq!(spec.version, pin.version);
            assert_eq!(
                node_identity_of(&spec, *platform).object_id(),
                node_identity(pin).object_id(),
                "node on {}",
                platform.triple()
            );
        }
    }
}
