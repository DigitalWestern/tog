//! The Python tailor's `RegistryTool`: how `tog x` resolves one PyPI
//! package with the store uv, realizes it as an ordinary env object, and
//! projects it as `.venv` in the command's cache directory.

use crate::comforter::status::canonical_symlink_target;
use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::python::{self, env, pypi, pyselect};
use crate::tailors::{RegistryTool, ToolEnv};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct PythonTool;

impl RegistryTool for PythonTool {
    fn cache_prefix(&self) -> &'static str {
        "py"
    }

    fn runtime_object_id(&self, platform: Platform, toolchain: &Selected) -> io::Result<String> {
        python::runtime_object_id(platform, toolchain)
    }

    /// The Rust a Rust-extension sdist builds on: inside a project that
    /// locks Rust, the locked one, so its object is part of the key
    /// (`x/4`). Outside one, the sdist's own toolchain file decides and the
    /// key stays `x/3`.
    fn helpers(&self) -> &'static [&'static str] {
        &["rust"]
    }

    fn helper_cache_key(
        &self,
        platform: Platform,
        helper: &str,
        selected: &Selected,
    ) -> io::Result<String> {
        match helper {
            "rust" => Ok(format!(
                "{};selection:{}",
                crate::kernel::provider::rust::runtime_object_id(platform, selected)?,
                selected.bundle_id()
            )),
            other => Err(io::Error::other(format!(
                "PyPI tools have no {other} helper"
            ))),
        }
    }

    fn spelling(&self) -> &'static str {
        "py"
    }

    fn registry_name(&self) -> &'static str {
        "PyPI"
    }

    fn project_label(&self) -> &'static str {
        "Python"
    }

    fn detection_reason(&self) -> &'static str {
        "Python, because this project has a Python manifest"
    }

    fn bin_dir(&self, root: &Path) -> PathBuf {
        root.join(".venv").join("bin")
    }

    fn projection_points_at(
        &self,
        _store: &Store,
        root: &Path,
        _closure: &Value,
        env_path: &Path,
    ) -> io::Result<bool> {
        Ok(canonical_symlink_target(&root.join(".venv")).as_deref() == Some(env_path))
    }

    fn realize(
        &self,
        door: &mut ResolutionDoor<'_>,
        root: &Path,
        package: &str,
        version: Option<&str>,
        toolchain: &Selected,
        helpers: &std::collections::BTreeMap<String, Selected>,
    ) -> io::Result<()> {
        let (activity, platform) = (door.lease(), door.platform());
        fs::create_dir_all(root)?;
        // The environment runs on the runtime the caller resolved, not on
        // the global default: inside a project with a lock that is the
        // locked CPython, and the projection has to match the key the
        // directory was named for.
        let selection = pyselect::select_python_for_version(
            platform,
            &pyselect::PythonInputs::default(),
            toolchain.version("cpython")?,
        )?;
        let pin = selection.pin;
        let spec = match version {
            Some(version) => format!("{package}=={version}\n"),
            None => format!("{package}\n"),
        };
        let input = root.join("requirements.in");
        let output = root.join("requirements.txt");
        fs::write(&input, &spec)?;
        ui::note(&format!("resolving {} with the store uv...", spec.trim()));
        // The bundle names the uv build this environment resolves with. It
        // runs confined through this `x` door, detached: the cache root is
        // the lock root and takes the accepted lock back, and the ledger is
        // rooted under it, so GC keeps it with the root.
        let uv = python::door::Uv::for_door(door, toolchain)?;
        let report = python::door::run_uv(
            door,
            python::door::UvRun {
                uv: &uv,
                lock_root: root,
                cwd: None,
                args: python::resolve::compile_args(
                    "requirements.in",
                    "requirements.txt",
                    pin.version,
                ),
                index: python::door::Index::PipCompile,
                outputs: vec![PathBuf::from("requirements.txt")],
                target: python::door::UvTarget::Detached,
                builds: python::door::Builds::Probe,
                capture: !ui::verbose(),
                policy: None,
            },
        )?;
        if !report.status.success() {
            return Err(python::uv_failure(
                &format!("could not resolve '{}' from PyPI", spec.trim()),
                report.status,
                &report.stderr,
            ));
        }
        python::door::root_ledger(door, root, &report)?;
        let text = fs::read_to_string(&output)?;
        let plan = pypi::plan_python(platform, &text, pin.version)?;
        let env = env::realize_env_with(door, &plan, toolchain, helpers.get("rust"))?;
        env::project_env_with_selection(
            activity,
            &crate::kernel::fsroot::ProjectRoot::open(root)?,
            &env,
            &plan,
            &selection,
            door.attribution(),
        )?;
        ui::synced(&format!("x {package}"), &env);
        Ok(())
    }

    fn launch_env(
        &self,
        _store: &Store,
        _activity: &StoreActivity,
        _platform: Platform,
        root: &Path,
        _toolchain: &Selected,
    ) -> io::Result<ToolEnv> {
        let venv = root.join(".venv");
        Ok(ToolEnv {
            path: vec![venv.join("bin")],
            vars: vec![
                ("VIRTUAL_ENV", venv.into_os_string()),
                ("PYTHONDONTWRITEBYTECODE", "1".into()),
            ],
        })
    }
}
