//! The npm tailor: package-lock.json importer (no solver).
//!
//! npm's lockfile v2/v3 already encodes the complete node_modules tree —
//! every key in "packages" is a literal filesystem path — so planning is
//! pure parsing (no network, no resolution). Realization materializes
//! exactly that tree as an immutable store object; projection is one
//! node_modules symlink.
//!
//! v0 limits: registry tarballs only (no git/file/workspace links), and
//! lifecycle scripts are NOT run — packages requiring postinstall (native
//! addons) will not work until the sandboxed-build story extends to npm.
//!
//! Trust model: the lockfile is a TRUSTED input. Integrity pins every
//! tarball's bytes, but `resolved` URLs choose where the GET goes, so a
//! hostile lockfile is a network capability. A registry allowlist is the
//! M5 control for that.

use crate::fetch::{download_verified_digest, Digest};
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

/// Pinned Node.js toolchain (nodejs.org, checksum from SHASUMS256.txt).
pub struct PinnedNode {
    pub version: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
}

pub const NODE: PinnedNode = PinnedNode {
    version: "24.20.0",
    url: "https://nodejs.org/dist/v24.20.0/node-v24.20.0-darwin-arm64.tar.gz",
    sha256: "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
};

/// Ensure Node.js is realized in the store (interpreter at <obj>/bin/node).
pub fn ensure_node(store: &Store) -> io::Result<PathBuf> {
    let identity = Identity {
        kind: "nodejs".into(),
        name: "nodejs".into(),
        version: NODE.version.into(),
        inputs: BTreeMap::from([
            ("artifact_sha256".to_string(), NODE.sha256.to_string()),
            ("platform".to_string(), "aarch64-apple-darwin".to_string()),
        ]),
    };
    let id = identity.object_id();
    if store.has(&id) {
        return Ok(store.object_path(&id));
    }
    let tarball = crate::fetch::download_verified(store, NODE.url, NODE.sha256)?;
    let staged = store.stage()?;
    let status = Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&staged)
        .args(["--strip-components", "1"])
        .status()?;
    if !status.success() {
        return Err(err("node tarball extraction failed"));
    }
    store.commit(&identity, &staged)
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
            && s.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+')
            })
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

/// Parse package-lock.json (lockfileVersion 2 or 3) into a plan.
/// Pure parsing: no network. Deterministic (sorted by path).
pub fn plan_npm(lock_json: &str) -> io::Result<NpmPlan> {
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
        // Platform filtering: lock entries carry os/cpu arrays. Incompatible
        // optional deps are skipped (npm does the same); incompatible
        // required deps are an error.
        let platform_ok = |field: &str, ours: &str| -> bool {
            match entry[field].as_array() {
                None => true,
                Some(list) => {
                    let allowed: Vec<&str> =
                        list.iter().filter_map(|v| v.as_str()).collect();
                    let negated: Vec<&str> = allowed
                        .iter()
                        .filter_map(|s| s.strip_prefix('!'))
                        .collect();
                    if !negated.is_empty() {
                        !negated.contains(&ours)
                    } else {
                        allowed.is_empty() || allowed.contains(&ours)
                    }
                }
            }
        };
        let compatible = platform_ok("os", "darwin") && platform_ok("cpu", "arm64");
        if !compatible {
            if entry["optional"].as_bool() == Some(true) {
                skipped.push(format!("{path}/"));
                continue;
            }
            return Err(err(format!(
                "{path}: required dependency does not support darwin/arm64"
            )));
        }
        let resolved = entry["resolved"].as_str().ok_or_else(|| {
            err(format!("{path}: missing 'resolved' URL (regenerate the lockfile)"))
        })?;
        if !resolved.starts_with("https://") {
            return Err(err(format!(
                "{path}: only https registry tarballs supported (v0), got {resolved}"
            )));
        }
        let integrity = entry["integrity"].as_str().ok_or_else(|| {
            err(format!("{path}: missing 'integrity' (regenerate the lockfile)"))
        })?;
        Digest::from_sri(integrity)?; // validate early
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
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    links.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(NpmPlan {
        node_version: NODE.version.to_string(),
        packages: out,
        links,
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
pub fn realize_node_env(store: &Store, plan: &NpmPlan) -> io::Result<PathBuf> {
    let node_obj = ensure_node(store)?;

    let mut inputs = BTreeMap::new();
    inputs.insert("schema".to_string(), "node-env/1".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert(
        "nodejs".to_string(),
        node_obj.file_name().unwrap().to_string_lossy().into_owned(),
    );
    for p in &plan.packages {
        let digest = Digest::from_sri(&p.integrity)?;
        // bin mappings change the realized tree, so they are identity inputs.
        let mut bins: Vec<String> =
            p.bin.iter().map(|(k, v)| format!("{k}={v}")).collect();
        bins.sort();
        if inputs
            .insert(
                format!("pkg:{}", p.path),
                format!("{}:{}:bin[{}]", digest.algo(), digest.hex(), bins.join(",")),
            )
            .is_some()
        {
            return Err(err(format!("duplicate lockfile path: {}", p.path)));
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
        return Ok(store.object_path(&id));
    }

    // Fetch everything first.
    let mut tarballs: Vec<(&NpmPackage, PathBuf)> = Vec::new();
    for p in &plan.packages {
        let digest = Digest::from_sri(&p.integrity)?;
        tarballs.push((p, download_verified_digest(store, &p.url, &digest)?));
    }

    let staged = store.stage()?;
    // Parents before children (path depth = lexicographic prefix ordering
    // already holds after sort, since "a/node_modules/b" sorts after "a").
    for (p, tarball) in &tarballs {
        let dest = staged.join(&p.path);
        fs::create_dir_all(&dest)
            .map_err(|e| err(format!("{}: create dir: {e}", p.path)))?;
        let status = Command::new("/usr/bin/tar")
            .arg("-xzf")
            .arg(tarball)
            .arg("-C")
            .arg(&dest)
            .args(["--strip-components", "1"])
            .status()?;
        if !status.success() {
            return Err(err(format!("{}: tarball extraction failed", p.path)));
        }
        normalize_modes(&dest)
            .map_err(|e| err(format!("{}: normalize modes: {e}", p.path)))?;
        // ponytail: post-extraction size cap (1 GiB/package) — catches
        // decompression bombs after the fact; a streaming extractor with
        // preflight limits is the M5 upgrade. Lockfiles are trusted inputs.
        if dir_size(&dest).map_err(|e| err(format!("{}: size walk: {e}", p.path)))? > 1 << 30 {
            return Err(err(format!("{}: package expands past 1 GiB; refusing", p.path)));
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

    store.commit(&identity, &staged)
}

/// Strictly parse the optional `"blanket"` config field of package.json.
/// Returns the sorted, deduplicated mutable-package list. Unknown keys and
/// malformed names are hard errors: this list weakens provenance, so typos
/// must not be silently ignored.
pub fn parse_blanket_config(pkg_json: &str) -> io::Result<Vec<String>> {
    let v: serde_json::Value = serde_json::from_str(pkg_json)
        .map_err(|e| err(format!("package.json: {e}")))?;
    let cfg = match v.get("blanket") {
        None => return Ok(Vec::new()),
        Some(c) => c
            .as_object()
            .ok_or_else(|| err("package.json: \"blanket\" must be an object"))?,
    };
    for key in cfg.keys() {
        if key != "mutablePackages" {
            return Err(err(format!("package.json: unknown blanket key {key:?}")));
        }
    }
    let mut names: Vec<String> = Vec::new();
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
            names.push(name.to_string());
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
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
    plan: &NpmPlan,
    mutable: &[String],
    fresh: bool,
) -> io::Result<()> {
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
        format!("node-forest/1\x00{env_name}\x00{}\x00{link_key}", mutable.join(",")).as_bytes(),
    ))[..16]
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
    ))[..16];
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
            clone_tree(&src, &tmp.join("node_modules"))?;
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
    // Prune forests for other projections (regenerable; only caches lost).
    if let Ok(entries) = fs::read_dir(&nm_root) {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy() != proj_id.as_str() {
                let _ = crate::store::remove_tree(&e.path());
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
    let closure = serde_json::json!({
        "env_object": env_obj,
        "projection_schema": "node-forest/1",
        "projection_id": proj_id,
        "node_version": plan.node_version,
        "mutable_packages": mutable,
        "mutable_paths": mutable_paths,
        "mutable_state": if mutable.is_empty() { "none" } else { "unattested" },
        "workspace_links": plan.links.iter().map(|l| {
            serde_json::json!({"path": l.path, "target": l.target})
        }).collect::<Vec<_>>(),
        "packages": plan.packages.iter().map(|p| {
            serde_json::json!({"path": p.path, "version": p.version, "integrity": p.integrity})
        }).collect::<Vec<_>>(),
    });
    fs::write(
        meta_dir.join("node-closure.json"),
        serde_json::to_vec_pretty(&closure)?,
    )
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

/// Copy-on-write clone of the whole tree (cp -c uses APFS clonefile; falls
/// back to a plain copy elsewhere), then restore user-write bits, which the
/// clone inherits as read-only from the store.
fn clone_tree(src: &Path, dest: &Path) -> io::Result<()> {
    let clone = Command::new("/bin/cp").args(["-Rc"]).arg(src).arg(dest).status()?;
    if !clone.success() {
        if dest.exists() {
            crate::store::remove_tree(dest)?;
        }
        let plain = Command::new("/bin/cp").arg("-R").arg(src).arg(dest).status()?;
        if !plain.success() {
            return Err(err("cloning node_modules tree failed"));
        }
    }
    restore_write_bits(dest)
}

fn restore_write_bits(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Ok(());
    }
    let mode = md.permissions().mode();
    if mode & 0o200 == 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o200))?;
    }
    if md.is_dir() {
        for entry in fs::read_dir(path)? {
            restore_write_bits(&entry?.path())?;
        }
    }
    Ok(())
}

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

    fn lock(packages: &str) -> String {
        format!(
            r#"{{"name":"x","lockfileVersion":3,"packages":{{"":{{"name":"x"}},{packages}}}}}"#
        )
    }

    #[test]
    fn parses_nested_and_scoped() {
        let l = lock(
            r#""node_modules/@s/a":{"version":"1.0.0","resolved":"https://r/a.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="},
               "node_modules/b/node_modules/c":{"version":"2.0.0","resolved":"https://r/c.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}"#,
        );
        let plan = plan_npm(&l).unwrap();
        assert_eq!(plan.packages.len(), 2);
        assert_eq!(plan.packages[0].name, "@s/a");
        assert_eq!(plan.packages[1].name, "c");
        assert_eq!(plan.packages[1].path, "node_modules/b/node_modules/c");
        // deterministic order
        assert!(plan.packages[0].path < plan.packages[1].path);
    }

    #[test]
    fn rejections() {
        // v1 lockfile
        assert!(plan_npm(r#"{"lockfileVersion":1,"packages":{}}"#).is_err());
        // link entry
        let l = lock(r#""node_modules/a":{"link":true,"resolved":"https://r/a.tgz"}"#);
        assert!(plan_npm(&l).is_err());
        // missing integrity
        let l = lock(r#""node_modules/a":{"version":"1.0.0","resolved":"https://r/a.tgz"}"#);
        assert!(plan_npm(&l).is_err());
        // path traversal
        let l = lock(
            r#""node_modules/../evil":{"version":"1","resolved":"https://r/a.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}"#,
        );
        assert!(plan_npm(&l).is_err());
        // git URL
        let l = lock(
            r#""node_modules/a":{"version":"1","resolved":"git+ssh://git@x/a.git","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}"#,
        );
        assert!(plan_npm(&l).is_err());
    }

    #[test]
    fn bundled_and_platform_skipped_subtrees() {
        // inBundle entries are provided by the parent tarball: skipped.
        let l = lock(
            r#""node_modules/a":{"version":"1","resolved":"https://r/a.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="},
               "node_modules/a/node_modules/b":{"version":"1","inBundle":true}"#,
        );
        assert_eq!(plan_npm(&l).unwrap().packages.len(), 1);
        // descendants of a platform-skipped optional package are dropped
        // even without their own os/cpu/resolved fields.
        let l = lock(
            r#""node_modules/w":{"version":"1","optional":true,"cpu":["wasm32"],"resolved":"https://r/w.tgz","integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="},
               "node_modules/w/node_modules/c":{"version":"1"}"#,
        );
        assert_eq!(plan_npm(&l).unwrap().packages.len(), 0);
    }

    #[test]
    fn blanket_config_parsing() {
        assert!(parse_blanket_config(r#"{"name":"x"}"#).unwrap().is_empty());
        let ok = parse_blanket_config(
            r#"{"blanket":{"mutablePackages":["b","@prisma/engines","b"]}}"#,
        )
        .unwrap();
        assert_eq!(ok, vec!["@prisma/engines".to_string(), "b".to_string()]);
        // unknown key, bad names, wrong types: hard errors
        assert!(parse_blanket_config(r#"{"blanket":{"mutable":["a"]}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":{"mutablePackages":["../x"]}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":{"mutablePackages":"a"}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":{"mutablePackages":[""]}}"#).is_err());
        assert!(parse_blanket_config(r#"{"blanket":[]}"#).is_err());
    }
}
