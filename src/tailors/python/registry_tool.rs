//! The Python tailor's `RegistryTool`: how `tog x` resolves one PyPI
//! package with the store uv, realizes it as an ordinary env object, and
//! projects it as `.venv` in the command's cache directory.

use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::policy::Attribution;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::python::{self, env, pypi, pyselect};
use crate::tailors::{RegistryTool, ToolEnv};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct PythonTool;

impl RegistryTool for PythonTool {
    fn cache_prefix(&self) -> &'static str {
        "py"
    }

    fn runtime_object_id(&self, platform: Platform, toolchain: &Selected) -> io::Result<String> {
        python::runtime_object_id(platform, toolchain)
    }

    fn bin_dir(&self, root: &Path) -> PathBuf {
        root.join(".venv").join("bin")
    }

    fn realize(
        &self,
        store: &Store,
        activity: &StoreActivity,
        platform: Platform,
        root: &Path,
        package: &str,
        version: Option<&str>,
        toolchain: &Selected,
        attribution: &mut Attribution,
    ) -> io::Result<()> {
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
        // The bundle names the uv build this environment resolves with.
        let uv = python::realize_uv(store, platform, toolchain)?.join("uv");
        let mut command = Command::new(uv);
        command
            .args(["pip", "compile"])
            .arg(&input)
            .arg("--generate-hashes");
        if !ui::verbose() {
            command.arg("--quiet");
        }
        command
            .args(["--python-version", pin.version])
            .args(["--index-url", "https://pypi.org/simple"])
            .arg("-o")
            .arg(&output)
            .current_dir(root)
            .env_remove("UV_INDEX_URL")
            .env_remove("UV_DEFAULT_INDEX")
            .env_remove("UV_EXTRA_INDEX_URL")
            .env_remove("PIP_INDEX_URL")
            .env_remove("PIP_EXTRA_INDEX_URL")
            .env_remove("PIP_TRUSTED_HOST")
            .env_remove("PIP_FIND_LINKS");
        ui::trace_command(&command);
        let status = crate::kernel::supervise::status(&mut command, activity)?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "could not resolve '{}' from PyPI (uv pip compile exit {status})",
                spec.trim()
            )));
        }
        let text = fs::read_to_string(&output)?;
        let plan = pypi::plan_python(platform, &text, pin.version)?;
        let env = env::realize_env_for(store, platform, &plan, toolchain)?;
        env::project_env_with_selection(root, &env, &plan, &selection, attribution)?;
        ui::synced(&format!("x {package}"), &env);
        Ok(())
    }

    fn launch_env(
        &self,
        _store: &Store,
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
