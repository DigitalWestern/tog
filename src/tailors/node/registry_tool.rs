//! The Node tailor's `RegistryTool`: how `tog x` resolves one npm package
//! with the store npm, realizes it as an ordinary node env object, and
//! projects it as `node_modules` in the command's cache directory.

use crate::comforter::status::canonical_symlink_target;
use crate::kernel::activity::StoreActivity;
use crate::kernel::platform::Platform;
use crate::kernel::policy::Attribution;
use crate::kernel::store::Store;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::node;
use crate::tailors::node::tailor::encoded_workspace;
use crate::tailors::{LegacyPackage, RegistryTool, ToolEnv};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
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

    fn spelling(&self) -> &'static str {
        "npm"
    }

    fn registry_name(&self) -> &'static str {
        "npm"
    }

    fn project_label(&self) -> &'static str {
        "Node"
    }

    fn detection_reason(&self) -> &'static str {
        "npm, because this project has a package.json"
    }

    fn scoped_packages(&self) -> bool {
        true
    }

    fn bin_dir(&self, root: &Path) -> PathBuf {
        root.join("node_modules").join(".bin")
    }

    /// A `node-forest/2` projection: `root/node_modules` (and each recorded
    /// workspace's) links into the store's forest for this project key and
    /// projection id.
    fn projection_points_at(
        &self,
        store: &Store,
        root: &Path,
        closure: &Value,
        _env_path: &Path,
    ) -> io::Result<bool> {
        if closure["projection_schema"] != "node-forest/2" {
            return Ok(false);
        }
        let Some(projection_id) = closure["projection_id"].as_str() else {
            return Ok(false);
        };
        if projection_id.is_empty() || !projection_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(false);
        }
        let project_key = hex::encode(Sha256::digest(root.canonicalize()?.as_os_str().as_bytes()));
        // New projections are owned by the originating store. Keep a
        // read-only compatibility candidate for pre-root/2 x records, whose
        // forest lived beside the store under tog home.
        let mut forest_bases = vec![store.root.join("forests")];
        if let Some(home) = store.root.parent() {
            let legacy = home.join("forests");
            if legacy != forest_bases[0] {
                forest_bases.push(legacy);
            }
        }
        let workspaces = closure["workspaces"].as_array();
        Ok(forest_bases
            .into_iter()
            .map(|base| base.join(&project_key[..32]).join(projection_id))
            .any(|projection| {
                let Some(expected) = projection.join("node_modules").canonicalize().ok() else {
                    return false;
                };
                if canonical_symlink_target(&root.join("node_modules")) != Some(expected) {
                    return false;
                }
                workspaces.is_none_or(|workspaces| {
                    workspaces.iter().all(|workspace| {
                        let Some(source) = workspace.as_str() else {
                            return false;
                        };
                        let Some(encoded) = encoded_workspace(source) else {
                            return false;
                        };
                        let Some(expected) = projection
                            .join("workspaces")
                            .join(encoded)
                            .join("node_modules")
                            .canonicalize()
                            .ok()
                        else {
                            return false;
                        };
                        canonical_symlink_target(&root.join(source).join("node_modules"))
                            == Some(expected)
                    })
                })
            }))
    }

    /// The dependencies of the `package.json` an older `x` wrote.
    fn legacy_packages(&self, root: &Path) -> Option<Vec<LegacyPackage>> {
        let text = fs::read_to_string(root.join("package.json")).ok()?;
        let value: Value = serde_json::from_str(&text).ok()?;
        let dependencies = value.get("dependencies")?.as_object()?;
        let mut packages = Vec::with_capacity(dependencies.len());
        for (package, version) in dependencies {
            let version = version.as_str()?.to_string();
            packages.push(LegacyPackage {
                package: package.clone(),
                version: Some(version),
            });
        }
        Some(packages)
    }

    fn clean_note(&self) -> Option<&'static str> {
        Some("'tog gc --project' also reclaims the node_modules forest each removed node environment used")
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
