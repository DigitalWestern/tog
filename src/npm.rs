//! The npm tailor: package-lock.json importer (no solver).
//!
//! npm's lockfile v2/v3 already encodes the complete node_modules tree —
//! every key in "packages" is a literal filesystem path — so planning is
//! pure parsing (no network, no resolution). Realization materializes
//! exactly that tree as an immutable store object; projection is one
//! node_modules symlink.
//!
//! v0 limits: registry tarballs only (no git/file/workspace links). Lifecycle
//! scripts run in the sandbox; failures are retained as exceptions by default.
//!
//! Trust model: the lockfile is a TRUSTED input. Integrity pins every
//! tarball's bytes, but `resolved` URLs choose where the GET goes, so a
//! hostile lockfile is a network capability. A registry allowlist is the
//! M5 control for that.

use crate::fetch::{download_verified_digest, Digest};
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
    let tarball = crate::fetch::download_verified(store, node.url, node.sha256)?;
    let staged = store
        .stage()
        .map_err(|e| io::Error::new(e.kind(), format!("stage: {e}")))?;
    let status = Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&staged)
        .args(["--strip-components", "1"])
        .status()
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
    /// Literal lockfile path, e.g. "node_modules/a/node_modules/@s/b".
    pub path: String,
    pub name: String,
    pub version: String,
    pub url: String,
    pub integrity: String, // SRI string
    pub bin: Vec<(String, String)>,
    /// Install-script failures are kept by default; strict policy makes them
    /// fatal for both optional and required packages.
    pub optional: bool,
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
    pub lock_source: String,
}

fn add_node_env_layout_input(inputs: &mut BTreeMap<String, String>, packages: &[NpmPackage]) {
    if packages.is_empty() {
        inputs.insert("layout".into(), "empty-node_modules".into());
    }
}

/// Validate a lockfile "packages" key as a safe, well-formed npm path:
/// repeated `node_modules/<name>` or `node_modules/@scope/<name>` units.
fn validate_lock_path(path: &str) -> io::Result<()> {
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
        if let Some(ws) = workspace_dirs
            .iter()
            .find(|w| path.starts_with(&format!("{w}/node_modules/")))
        {
            return Err(err(format!(
                "{path}: dependencies nested inside workspace {ws:?} are \
                 unsupported yet; hoist by aligning versions or dedupe"
            )));
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
        if !resolved.starts_with("https://") {
            return Err(err(format!(
                "{path}: only https registry tarballs supported (v0), got {resolved}"
            )));
        }
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
        out.push(NpmPackage {
            path: path.clone(),
            name,
            version,
            url: resolved.to_string(),
            integrity: integrity.to_string(),
            bin,
            optional: entry["optional"].as_bool() == Some(true),
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    links.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(NpmPlan {
        node_version: node.version.to_string(),
        packages: out,
        links,
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
    for p in &plan.packages {
        let digest = Digest::from_sri(&p.integrity)?;
        // bin mappings change the realized tree, so they are identity inputs.
        let mut bins: Vec<String> = p.bin.iter().map(|(k, v)| format!("{k}={v}")).collect();
        bins.sort();
        if inputs
            .insert(
                format!("pkg:{}", p.path),
                format!(
                    "{}:{}:{}@{}:bin[{}]",
                    digest.algo(),
                    digest.hex(),
                    p.name,
                    p.version,
                    bins.join(",")
                ),
            )
            .is_some()
        {
            return Err(err(format!("duplicate lockfile path: {}", p.path)));
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
    let identity = Identity {
        kind: "node-env".into(),
        name: "env".into(),
        version: plan.node_version.clone(),
        inputs,
    };
    let id = identity.object_id();
    if store.has(&id) {
        crate::policy::check_cached(store, &id)?;
        return Ok(store.object_path(&id));
    }

    // Fetch everything first.
    let mut tarballs: Vec<(&NpmPackage, PathBuf)> = Vec::new();
    for p in &plan.packages {
        let digest = Digest::from_sri(&p.integrity)?;
        let t = download_verified_digest(store, &p.url, &digest).map_err(|e| {
            io::Error::new(e.kind(), format!("{}: fetch {}: {e}", p.path, p.url))
        })?;
        tarballs.push((p, t));
    }

    let staged = store.stage()?;
    fs::create_dir_all(staged.join("node_modules"))?;
    // Parents before children (path depth = lexicographic prefix ordering
    // already holds after sort, since "a/node_modules/b" sorts after "a").
    for (p, tarball) in &tarballs {
        let dest = staged.join(&p.path);
        fs::create_dir_all(&dest).map_err(|e| {
            io::Error::new(e.kind(), format!("{}: create dir: {e}", p.path))
        })?;
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
        let status = tar.status()?;
        if !status.success() {
            return Err(err(format!("{}: tarball extraction failed", p.path)));
        }
        normalize_modes(&dest).map_err(|e| {
            io::Error::new(e.kind(), format!("{}: normalize modes: {e}", p.path))
        })?;
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

    // .bin launchers for physically top-level (hoisted) packages, which is
    // what node_modules/.bin holds in npm's own layout.
    let bin_dir = staged.join("node_modules/.bin");
    for (p, _) in &tarballs {
        if p.path.matches("node_modules/").count() != 1 || p.bin.is_empty() {
            continue;
        }
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
            let rel_ok = !rel.is_empty()
                && !rel.starts_with('/')
                && rel
                    .split('/')
                    .all(|c| !c.is_empty() && c != "." && c != "..");
            if !name_ok || !rel_ok {
                return Err(err(format!(
                    "{}: unsafe bin entry {bin_name:?} -> {rel:?}",
                    p.path
                )));
            }
            let pkg_dir = staged.join(&p.path);
            let target_file = pkg_dir.join(rel);
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
            let link_target = Path::new("..")
                .join(p.path.trim_start_matches("node_modules/"))
                .join(rel);
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

    run_install_scripts(store, platform, &staged, &node_obj, plan, artifacts)?;

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
    cleanup: &mut Vec<PathBuf>,
) -> io::Result<()> {
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
        let pkg_dir = staged.join(&p.path);
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
            let src = crate::fetch::download_verified(store, &a.url, &a.sha256)
                .map_err(|e| io::Error::new(e.kind(), format!("declared artifact {}: {e}", a.url)))?;
            let dest = tmp.join(&a.path);
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::copy(&src, &dest)
                .map_err(|e| io::Error::new(e.kind(), format!("placing declared artifact {}: {e}", a.path)))?;
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
        crate::project::clone_tree_for(&pkg_dir, &snapshot, platform)?;

        let python = match &python_obj {
            Some(p) => p.clone(),
            None => {
                let pin = crate::python::lookup(platform, "3.12").ok_or_else(|| {
                    crate::platform::no_pin("cpython 3.12", platform, "stage 2")
                })?;
                let p = crate::python::ensure_python_for(store, pin, platform)
                    .map_err(|e| {
                        io::Error::new(e.kind(), format!("ensure python for node-gyp: {e}"))
                    })?;
                python_obj.insert(p).clone()
            }
        };
        let python_bin = python.join("bin/python3");

        let path_env = format!(
            "{}:{}:{}:/usr/bin:/bin:/usr/sbin:/sbin",
            tools_dir.join("bin").display(),
            node_obj.join("bin").display(),
            staged.join("node_modules/.bin").display(),
        );
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
            // NOTE: npm_config_build_from_source is deliberately NOT set:
            // it would make packages like sharp skip their local-cache
            // lookup (where declared artifacts land). Downloaders fail
            // fast against the denied network and fall through to their
            // source-build path on their own.
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
        // Tools dir is readable+executable but NOT writable in-sandbox.
        let sandbox = crate::sandbox::Sandbox {
            read: vec![staged, node_obj, &python, &tools_dir],
            write: vec![&pkg_dir, &tmp],
        };
        for (phase, script) in &phases {
            eprintln!("blanket: {} {}: {phase} (sandboxed)", p.name, p.version);
            let envs_phase: Vec<(String, String)> = envs
                .iter()
                .cloned()
                .chain([("npm_lifecycle_event".to_string(), phase.to_string())])
                .collect();
            let result = sandbox.run_in_on(
                platform,
                &["/bin/sh", "-c", script],
                &path_env,
                &tmp,
                &pkg_dir,
                &envs_phase,
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
            remove_dangling_bin_links(staged)?;
            break;
        }
    }
    Ok(())
}

fn remove_dangling_bin_links(staged: &Path) -> io::Result<()> {
    let bin_dir = staged.join("node_modules/.bin");
    let entries = match fs::read_dir(&bin_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let path = entry?.path();
        if fs::symlink_metadata(&path)?.file_type().is_symlink() && !path.exists() {
            fs::remove_file(path)?;
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

/// Project the env into the project as a "forest": node_modules is a symlink
/// to a WRITABLE per-project dir under .blanket/nm/<projection-id>, holding
/// one symlink per top-level entry into the immutable store object. Tools
/// that treat node_modules' top level as scratch space (vite's .vite dep
/// cache, prisma's .prisma client) get real writable directories, while
/// package contents stay read-only in the store — pnpm's proven layout.
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
    if !mutable.is_empty() {
        crate::policy::record(
            crate::policy::UNATTESTED_MUTABLE_STATE,
            &mutable.join(", "),
            "mutable package projection is unattested",
        )?;
    }
    let nm = project_dir.join("node_modules");
    // A real (npm-made) node_modules is moved aside automatically so
    // pointing blanket at an existing project is one command.
    crate::project::backup_real_dir(&nm, env_obj)?;

    // Projection id: env object + mutable declarations + layout schema.
    use sha2::{Digest as _, Sha256};
    let env_name = env_obj.file_name().unwrap().to_string_lossy().into_owned();
    let link_key: String = plan
        .links
        .iter()
        .map(|l| format!("{}={};", l.path, l.target))
        .collect();
    let proj_id = hex::encode(Sha256::digest(
        format!(
            "node-forest/1\x00{env_name}\x00{}\x00{link_key}",
            mutable.join(",")
        )
        .as_bytes(),
    ))[..32]
        .to_string();

    // Forests live OUTSIDE the project (under the blanket home, keyed by
    // project path): anything inside the project gets crawled by test
    // runners and type checkers, and the forest links into store packages
    // whose own test files must never be picked up.
    let home = env_obj
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| err("cannot locate blanket home for forests"))?;
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
    if !forest.exists() {
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
        fs::rename(&tmp, &proj_dir)?;
    }
    // Workspace links: symlinks into the project's own source dirs. The
    // targets are user-owned and writable by nature. Idempotent — the
    // projection id covers the link set, so a changed set is a new forest.
    for l in &plan.links {
        let rel = l.path.trim_start_matches("node_modules/");
        let link = forest.join(rel);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        if link.symlink_metadata().is_err() {
            std::os::unix::fs::symlink(project_dir.join(&l.target), &link)?;
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

    let tmp_link = project_dir.join(format!(
        ".node_modules.blanket-swap.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::os::unix::fs::symlink(&forest, &tmp_link)?;
    fs::rename(&tmp_link, &nm)?;

    // Mutable declarations expand to every matching physical lockfile path.
    let mutable_paths: Vec<&str> = plan
        .packages
        .iter()
        .filter(|p| mutable.iter().any(|m| *m == p.name))
        .map(|p| p.path.as_str())
        .collect();

    let meta_dir = project_dir.join(".blanket");
    fs::create_dir_all(&meta_dir)?;
    let body = serde_json::json!({
        "env_object": env_obj,
        "projection_schema": "node-forest/1",
        "projection_id": proj_id,
        "node_version": plan.node_version,
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
            lock_source: "package-lock.json".into(),
        };
        let host = Platform::host().unwrap();
        let foreign = *Platform::ALL.iter().find(|platform| **platform != host).unwrap();
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
    fn explicit_platform_selects_the_matching_esbuild_variant() {
        let l = lock(&format!(
            r#""node_modules/@esbuild/linux-x64":{{"name":"@esbuild/linux-x64","version":"0.25.9","optional":true,"os":["linux"],"cpu":["x64"],"resolved":"https://r/linux.tgz","integrity":"{TEST_SRI}"}},
               "node_modules/@esbuild/darwin-arm64":{{"name":"@esbuild/darwin-arm64","version":"0.25.9","optional":true,"os":["darwin"],"cpu":["arm64"],"resolved":"https://r/darwin.tgz","integrity":"{TEST_SRI}"}}"#
        ));
        let linux = plan_npm(Platform::X86_64UnknownLinuxGnu, &l).unwrap();
        assert_eq!(
            linux.packages.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["@esbuild/linux-x64"]
        );
        let darwin = plan_npm(Platform::Aarch64AppleDarwin, &l).unwrap();
        assert_eq!(
            darwin.packages.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
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
        assert_eq!(plan.packages[0].path, "node_modules/optional-parent-sibling");
    }

    #[test]
    fn required_platform_and_libc_restrictions_have_host_diagnostics() {
        let cases = [
            (
                r#""os":["darwin"]"#,
                "os restriction",
            ),
            (
                r#""cpu":["arm64"]"#,
                "cpu restriction",
            ),
            (
                r#""libc":["musl"]"#,
                "libc restriction",
            ),
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
            assert!(plan_npm(Platform::X86_64UnknownLinuxGnu, &l).is_ok(), "libc {libc}");
        }
        for libc in [r#"["musl"]"#, r#"["!glibc"]"#, r#""musl""#] {
            let l = lock(&format!(
                r#""node_modules/restricted":{{"version":"1","libc":{libc},"resolved":"https://r/restricted.tgz","integrity":"{TEST_SRI}"}}"#
            ));
            assert!(plan_npm(Platform::X86_64UnknownLinuxGnu, &l).is_err(), "libc {libc}");
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
            assert_eq!(result.is_ok(), compatible, "darwin os restriction {restriction}");
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
        assert!(plan_npm(Platform::Aarch64AppleDarwin, r#"{"lockfileVersion":1,"packages":{}}"#).is_err());
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
        assert_eq!(plan_npm(Platform::Aarch64AppleDarwin, &l).unwrap().packages.len(), 1);
        // descendants of a platform-skipped optional package are dropped
        // even without their own os/cpu/resolved fields.
        let l = lock(
            r#""node_modules/w":{"version":"1","optional":true,"cpu":["wasm32"],"resolved":"https://r/w.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="},
               "node_modules/w/node_modules/c":{"version":"1"}"#,
        );
        assert_eq!(plan_npm(Platform::Aarch64AppleDarwin, &l).unwrap().packages.len(), 0);
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
            version: node_pin(Platform::Aarch64AppleDarwin).unwrap()
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
        let failure = classify_lifecycle_result(Err(io::Error::other("script exited 1")))
            .unwrap_err();
        assert!(matches!(failure, LifecycleFailure::Script(error) if error.kind() == io::ErrorKind::Other));
    }
}
