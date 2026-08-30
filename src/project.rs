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

/// Project an env into a project directory: `.venv` symlink (atomic swap)
/// plus `.blanket/closure.json` provenance.
pub fn project_env(project_dir: &Path, env_obj: &Path, plan: &Plan) -> io::Result<()> {
    let venv = project_dir.join(".venv");
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
    let closure = serde_json::json!({
        "env_object": env_obj,
        "plan": plan,
        "projected_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    });
    fs::write(
        meta_dir.join("closure.json"),
        serde_json::to_vec_pretty(&closure)?,
    )
}
