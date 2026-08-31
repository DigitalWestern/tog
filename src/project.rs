//! Environment (comforter) realization + projection.
//!
//! An environment is itself a store object (venv-shaped, immutable) whose
//! identity is the python object id plus every locked artifact hash. Two
//! projects with identical locks share one env object; different locks get
//! different objects and coexist. Projection into a project is one symlink.

use crate::fetch::download_verified;
use crate::store::Store;
use crate::types::{ArtifactKind, Identity, Plan};
use crate::{python, wheel};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// Common closure envelope (Sol review 4): every tailor's provenance lands
/// at .blanket/closures/<ecosystem>.json with a shared outer shape; the
/// `body` stays tailor-owned. Written atomically.
pub fn write_closure(
    project_dir: &Path,
    ecosystem: &str,
    body: serde_json::Value,
) -> io::Result<()> {
    let project_dir = project_dir.canonicalize()?;
    let dir = project_dir.join(".blanket/closures");
    fs::create_dir_all(&dir)?;
    // A symlinked closures dir would carry provenance writes outside the
    // project (same class as the cargo-home/bin escape).
    let dir = dir.canonicalize()?;
    if !dir.starts_with(&project_dir) {
        return Err(io::Error::other(format!(
            "{} escapes the project; refusing to write closures there",
            dir.display()
        )));
    }
    let envelope = serde_json::json!({
        "schema": "closure/1",
        "ecosystem": ecosystem,
        "projected_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        "body": body,
    });
    let dest = dir.join(format!("{ecosystem}.json"));
    let tmp = dir.join(format!(
        ".{ecosystem}.json.tmp.{}",
        std::process::id()
    ));
    fs::write(&tmp, serde_json::to_vec_pretty(&envelope)?)?;
    fs::rename(&tmp, &dest)
}

/// Read a tailor's closure body back (for `blanket run` and friends).
pub fn read_closure(project_dir: &Path, ecosystem: &str) -> io::Result<serde_json::Value> {
    let path = project_dir.join(format!(".blanket/closures/{ecosystem}.json"));
    let text = fs::read_to_string(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("read {}: {e}; run `blanket sync` first", path.display()),
        )
    })?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse {}: {e}; run `blanket sync` first", path.display()),
        )
    })?;
    if v["schema"] != "closure/1" || v["ecosystem"] != ecosystem {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: unknown closure schema/ecosystem; re-run `blanket sync`",
                path.display()
            ),
        ));
    }
    Ok(v["body"].clone())
}

/// Copy-on-write clone of a whole tree (cp -c uses APFS clonefile; plain
/// copy fallback), then restore user-write bits, which the clone inherits
/// as read-only from the store. Used for writable projections of immutable
/// objects (npm mutablePackages, elixir deps trees).
pub fn clone_tree(src: &Path, dest: &Path) -> io::Result<()> {
    use std::process::Command;
    let clone = Command::new("/bin/cp").args(["-Rc"]).arg(src).arg(dest).status()?;
    if !clone.success() {
        if dest.exists() {
            crate::store::remove_tree(dest)?;
        }
        let plain = Command::new("/bin/cp").arg("-R").arg(src).arg(dest).status()?;
        if !plain.success() {
            return Err(io::Error::other("cloning projected tree failed"));
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

/// Resolve an object reference from a closure body, CONTAINED to the
/// active store: the recorded id must exist in the store and the recorded
/// path must be exactly the store's path for that id. A project-editable
/// closure must never inject arbitrary executable paths into `blanket run`
/// (Sol review 5, reproduced against the ruby closure).
pub fn closure_object(
    store: &crate::store::Store,
    closure: &serde_json::Value,
    key: &str,
    probe: &str,
) -> io::Result<PathBuf> {
    let bad = |msg: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("closure {key}: {msg}; run `blanket sync` first"),
        )
    };
    let id = closure[key]["id"].as_str().ok_or_else(|| bad("missing id"))?;
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(bad("malformed id"));
    }
    if !store.has(id) {
        return Err(bad("object not in the store"));
    }
    let path = store.object_path(id);
    if closure[key]["path"].as_str().map(Path::new) != Some(path.as_path()) {
        return Err(bad("recorded path disagrees with the store"));
    }
    if !probe.is_empty() && !path.join(probe).exists() {
        return Err(bad("object is missing its expected content"));
    }
    Ok(path)
}

/// Realize the environment object for `plan`. Downloads/validates all
/// artifacts, assembles the venv shape in a staging dir, commits atomically.
/// Cache hit if the identical env already exists.
pub fn realize_env(store: &Store, plan: &Plan) -> io::Result<PathBuf> {
    let pin = python::lookup(&plan.python_version).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no pinned CPython {} (available: {})",
                plan.python_version,
                python::PYTHONS
                    .iter()
                    .map(|p| p.version)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
    })?;
    let python_obj = python::ensure_python(store, pin)?;

    // Canonical package order + duplicate rejection: identity must commit
    // to exactly one artifact per name, installed in a deterministic order.
    let mut packages: Vec<&crate::types::LockedPackage> = plan.packages.iter().collect();
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    for w in packages.windows(2) {
        if w[0].name == w[1].name {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate package in plan: {}", w[0].name),
            ));
        }
    }

    let mut inputs = BTreeMap::new();
    inputs.insert("schema".to_string(), "python-env/2".to_string());
    inputs.insert(
        "store_root".to_string(),
        store.root.to_string_lossy().into_owned(),
    );
    inputs.insert(
        "cpython".to_string(),
        python_obj.file_name().unwrap().to_string_lossy().into_owned(),
    );
    for p in &packages {
        let value = match p.kind {
            ArtifactKind::Wheel => format!("Wheel:{}", p.sha256),
            // The built wheel is a derivation of the sdist + build
            // toolchain; both must be committed to, or a toolchain upgrade
            // would leave stale envs under an unchanged id.
            ArtifactKind::Sdist => format!(
                "Sdist:{}:{}",
                p.sha256,
                crate::build::derivation_fingerprint()
            ),
        };
        inputs.insert(format!("pkg:{}", p.name), value);
    }
    let identity = Identity {
        kind: "python-env".into(),
        name: "env".into(),
        version: plan.python_version.clone(),
        inputs,
    };
    let id = identity.object_id();
    if store.has(&id) {
        return Ok(store.object_path(&id));
    }

    // Fetch everything first (all-or-nothing before assembly starts).
    let mut artifacts: Vec<(&crate::types::LockedPackage, PathBuf)> = Vec::new();
    for &p in &packages {
        let wheel_file = match p.kind {
            ArtifactKind::Wheel => download_verified(store, &p.url, &p.sha256)?,
            // sdist -> wheel via sandboxed derivation (network denied).
            ArtifactKind::Sdist => crate::build::build_sdist_wheel(store, p, &pin.version)?,
        };
        artifacts.push((p, wheel_file));
    }

    let minor = pin
        .version
        .split('.')
        .take(2)
        .collect::<Vec<_>>()
        .join(".");
    let staged = store.stage()?;
    let bin = staged.join("bin");
    let site = staged.join(format!("lib/python{minor}/site-packages"));
    fs::create_dir_all(&bin)?;
    fs::create_dir_all(&site)?;

    // Standard venv shape: symlinked interpreter + pyvenv.cfg. CPython finds
    // pyvenv.cfg next to the symlink, so store-side python resolves this env.
    let py_target = python_obj.join("bin/python3");
    symlink(&py_target, bin.join("python"))?;
    symlink("python", bin.join("python3"))?;
    symlink("python", bin.join(format!("python{minor}")))?;
    fs::write(
        staged.join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\nversion = {}\n",
            python_obj.join("bin").display(),
            pin.version
        ),
    )?;

    // The env's python path — as it will exist after commit — for shebangs.
    let final_python = store.object_path(&id).join("bin/python");
    for (_p, wheel_file) in &artifacts {
        wheel::install_wheel(wheel_file, &site, &bin, &final_python)?;
    }

    store.commit(&identity, &staged)
}

/// If `path` is a real directory (a pre-blanket install), move it out of the
/// project into `<blanket-home>/backups/` so no tool (tsc, vitest, eslint)
/// ever crawls it again. blanket-home is derived from the env object's store
/// (`<store>/objects/<id>` -> store parent), so tests with temp stores back
/// up into the temp dir, never the real one. Returns the backup location.
pub fn backup_real_dir(path: &Path, env_obj: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(md) if !md.file_type().is_symlink() && md.is_dir() => {}
        _ => return Ok(None),
    }
    let home = env_obj
        .parent() // objects/
        .and_then(|p| p.parent()) // store root
        .and_then(|p| p.parent()) // blanket home
        .ok_or_else(|| io::Error::other("cannot locate blanket home for backup"))?;
    let backups = home.join("backups");
    fs::create_dir_all(&backups)?;
    let project = path
        .parent()
        .and_then(|p| p.file_name())
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "project".into());
    let dirname = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dir".into());
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dest = backups.join(format!("{project}-{dirname}-{secs}"));
    fs::rename(path, &dest).map_err(|e| {
        io::Error::other(format!(
            "could not move existing {} aside to {}: {e}",
            path.display(),
            dest.display()
        ))
    })?;
    eprintln!(
        "blanket: moved existing {} to {} (delete it once you're happy)",
        path.display(),
        dest.display()
    );
    Ok(Some(dest))
}

/// Project an env into a project directory: `.venv` symlink (atomic swap)
/// plus closure-envelope provenance (.blanket/closures/python.json).
pub fn project_env(project_dir: &Path, env_obj: &Path, plan: &Plan) -> io::Result<()> {
    let venv = project_dir.join(".venv");
    backup_real_dir(&venv, env_obj)?;
    let tmp = project_dir.join(format!(
        ".venv.blanket-swap.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    symlink(env_obj, &tmp)?;
    fs::rename(&tmp, &venv)?; // atomic replace, including over an old symlink

    let meta_dir = project_dir.join(".blanket");
    fs::create_dir_all(&meta_dir)?;
    write_closure(
        project_dir,
        "python",
        serde_json::json!({
            "env_object": env_obj,
            "plan": plan,
        }),
    )
}
