//! The Node tailor's `RegistryTool`: how `tog x` resolves one npm package
//! with the store npm, realizes it as an ordinary node env object, and
//! projects it as `node_modules` in the command's cache directory.

use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::policy::Attribution;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::node;
use crate::tailors::{RegistryTool, ToolEnv};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct NodeTool;

impl RegistryTool for NodeTool {
    fn cache_prefix(&self) -> &'static str {
        "npm"
    }

    fn runtime_object_id(&self, platform: Platform, toolchain: &Selected) -> io::Result<String> {
        node::runtime_object_id(platform, toolchain)
    }

    fn bin_dir(&self, root: &Path) -> PathBuf {
        root.join("node_modules").join(".bin")
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
        let manifest = serde_json::json!({
            "name": "tog-x",
            "private": true,
            "dependencies": { package: version.unwrap_or("latest") },
        });
        fs::write(
            root.join("package.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        let lock = root.join("package-lock.json");
        if lock.exists() {
            fs::remove_file(&lock)?;
        }
        ui::note(&format!(
            "resolving {package}@{} with the store npm...",
            version.unwrap_or("latest")
        ));
        let node_obj = node::realize_runtime(store, platform, toolchain)?;
        let mut command = Command::new(node_obj.join("bin/npm"));
        command.args(["install", "--package-lock-only", "--ignore-scripts"]);
        if !ui::verbose() {
            command.arg("--silent");
        }
        command.current_dir(root).env(
            "PATH",
            format!(
                "{}:{}",
                node_obj.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        ui::trace_command(&command);
        let status = crate::kernel::supervise::status(&mut command, activity)?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "could not resolve '{package}' from npm (npm exit {status})"
            )));
        }
        let plan = node::plan_npm(platform, &fs::read_to_string(&lock)?)?;
        let env = node::realize_node_env_for(store, platform, &plan, &[], toolchain)?;
        node::project_node_env(root, &env, platform, &plan, &[], false, attribution)?;
        ui::synced(&format!("x {package}"), &env);
        Ok(())
    }

    /// The package's executables first, then the runtime they run on.
    fn launch_env(
        &self,
        store: &Store,
        platform: Platform,
        root: &Path,
        toolchain: &Selected,
    ) -> io::Result<ToolEnv> {
        let node_obj = node::realize_runtime(store, platform, toolchain)?;
        Ok(ToolEnv {
            path: vec![self.bin_dir(root), node_obj.join("bin")],
            vars: Vec::new(),
        })
    }
}
