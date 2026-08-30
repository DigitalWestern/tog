//! Environment realization + projection.
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

    let mut inputs = BTreeMap::new();
    inputs.insert(
        "cpython".to_string(),
        python_obj.file_name().unwrap().to_string_lossy().into_owned(),
    );
    for p in &plan.packages {
        inputs.insert(format!("pkg:{}", p.name), p.sha256.clone());
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
    for p in &plan.packages {
        if p.kind == ArtifactKind::Sdist {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "{}=={} resolves to an sdist ({}); sdist builds land in M3",
                    p.name, p.version, p.filename
                ),
            ));
        }
        artifacts.push((p, download_verified(store, &p.url, &p.sha256)?));
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
    let tmp = project_dir.join(".venv.blanket-swap");
    let _ = fs::remove_file(&tmp);
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
