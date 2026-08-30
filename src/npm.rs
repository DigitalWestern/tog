//! npm ecosystem adapter: package-lock.json importer (no solver).
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

#[derive(Debug, Clone)]
pub struct NpmPlan {
    pub node_version: String,
    pub packages: Vec<NpmPackage>,
}

/// Validate a lockfile "packages" key as a safe relative node_modules path.
fn validate_lock_path(path: &str) -> io::Result<()> {
    if !path.starts_with("node_modules/") {
        return Err(err(format!("unexpected lockfile package path: {path}")));
    }
    for comp in path.split('/') {
        if comp.is_empty() || comp == ".." || comp == "." {
            return Err(err(format!("unsafe lockfile package path: {path}")));
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
    for (path, entry) in packages {
        if path.is_empty() {
            continue; // root project entry
        }
        validate_lock_path(path)?;
        if entry["link"].as_bool() == Some(true) {
            return Err(err(format!("{path}: workspaces/links unsupported (v0)")));
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
    Ok(NpmPlan {
        node_version: NODE.version.to_string(),
        packages: out,
    })
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
        if inputs
            .insert(format!("pkg:{}", p.path), format!("{}:{}", digest.algo(), digest.hex()))
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
        fs::create_dir_all(&dest)?;
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
    }

    // .bin launchers for direct dependencies.
    let bin_dir = staged.join("node_modules/.bin");
    for (p, _) in &tarballs {
        if p.path.matches("node_modules/").count() != 1 || p.bin.is_empty() {
            continue;
        }
        fs::create_dir_all(&bin_dir)?;
        for (bin_name, rel) in &p.bin {
            if bin_name.contains('/') || rel.contains("..") {
                continue; // refuse weird names silently-but-safely (v0)
            }
            let target_file = staged.join(&p.path).join(rel);
            if !target_file.is_file() {
                continue;
            }
            // Relative link: node_modules/.bin/x -> ../<name>/<rel>
            let link_target = Path::new("..")
                .join(p.path.trim_start_matches("node_modules/"))
                .join(rel);
            let link = bin_dir.join(bin_name);
            if link.symlink_metadata().is_ok() {
                return Err(err(format!("bin collision: {bin_name}")));
            }
            std::os::unix::fs::symlink(&link_target, &link)?;
            // ensure exec bit on the target
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&target_file)?.permissions();
            perms.set_mode(perms.mode() | 0o755);
            fs::set_permissions(&target_file, perms)?;
        }
    }

    store.commit(&identity, &staged)
}

/// Project: atomic node_modules symlink + provenance.
pub fn project_node_env(project_dir: &Path, env_obj: &Path, plan: &NpmPlan) -> io::Result<()> {
    let nm = project_dir.join("node_modules");
    match fs::symlink_metadata(&nm) {
        Ok(md) if !md.file_type().is_symlink() => {
            return Err(err(
                "node_modules exists and is a real directory; remove it first \
                 (blanket projects node_modules as a symlink)",
            ));
        }
        _ => {}
    }
    let tmp = project_dir.join(format!(
        ".node_modules.blanket-swap.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::os::unix::fs::symlink(env_obj.join("node_modules"), &tmp)?;
    fs::rename(&tmp, &nm)?;

    let meta_dir = project_dir.join(".blanket");
    fs::create_dir_all(&meta_dir)?;
    let closure = serde_json::json!({
        "env_object": env_obj,
        "node_version": plan.node_version,
        "packages": plan.packages.iter().map(|p| {
            serde_json::json!({"path": p.path, "version": p.version, "integrity": p.integrity})
        }).collect::<Vec<_>>(),
    });
    fs::write(
        meta_dir.join("node-closure.json"),
        serde_json::to_vec_pretty(&closure)?,
    )
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
}
