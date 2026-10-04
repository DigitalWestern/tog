//! The Node tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for an npm/pnpm/Yarn project.

use crate::comforter;
use crate::comforter::status::{canonical_symlink_target, recorded_inputs_state, string, State};
use crate::kernel::activity::StoreActivity;
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_property, required, toolchain_component, version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::node::{self as node, inputs};
use crate::tailors::{ClosureListing, PackageRow, RegistryTool, SyncRequest, Tailor};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const NODE_INPUTS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

pub struct Node;

/// The package.json `tog run` reads scripts from, as (canonical path,
/// text): only under a `node_modules` projection whose closure reads back,
/// and only when `dir` has a package.json.
pub fn projected_package_json(dir: &Path, cwd: &Path) -> io::Result<Option<(PathBuf, String)>> {
    let (node_projected, _) = projected_node_modules(dir, cwd);
    if !node_projected {
        return Ok(None);
    }
    comforter::read_closure(dir, "node")?;
    let path = dir.join("package.json");
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    Ok(Some((path.canonicalize()?, std::fs::read_to_string(path)?)))
}

/// Is `dir/node_modules` a tog projection, and which `node_modules`
/// between `cwd` and `dir` should lead PATH? `tog run` works from
/// workspace subdirectories like npm run does: the nearest projected
/// `node_modules` inside the same forest wins, falling back to the root's.
pub fn projected_node_modules(dir: &Path, cwd: &Path) -> (bool, PathBuf) {
    let nm = dir.join("node_modules");
    let node_projected = std::fs::symlink_metadata(&nm)
        .map(|md| md.file_type().is_symlink())
        .unwrap_or(false)
        && std::fs::symlink_metadata(dir.join(".tog/closures/node.json")).is_ok();
    let nearest_nm = if node_projected {
        let forest_root = nm
            .canonicalize()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        cwd.ancestors()
            .take_while(|path| path.starts_with(dir))
            .map(|path| path.join("node_modules"))
            .find(|path| {
                std::fs::symlink_metadata(path)
                    .map(|md| md.file_type().is_symlink())
                    .unwrap_or(false)
                    && forest_root
                        .as_ref()
                        .and_then(|root| {
                            path.canonicalize().ok().map(|path| path.starts_with(root))
                        })
                        .unwrap_or(false)
            })
            .unwrap_or_else(|| nm.clone())
    } else {
        nm.clone()
    };
    (node_projected, nearest_nm)
}

impl Tailor for Node {
    fn package_registry(&self) -> Option<crate::tailors::PackageRegistry> {
        Some(super::edit::REGISTRY)
    }

    fn registry_exists(&self, name: &str) -> io::Result<Option<String>> {
        super::edit::registry_exists(name)
    }

    fn claims_package_name(&self, name: &str) -> bool {
        super::edit::claims_package_name(name)
    }

    fn edit_root(&self, project: &Path) -> io::Result<std::path::PathBuf> {
        super::edit::edit_root(project)
    }

    fn edit_manifest(
        &self,
        _ctx: &crate::kernel::context::Context,
        edit: &crate::tailors::ManifestEdit<'_>,
        door: &mut crate::kernel::resolve::ResolutionDoor<'_>,
    ) -> io::Result<crate::tailors::EditOutcome> {
        super::edit::edit_manifest(edit, door)
    }

    fn id(&self) -> &'static str {
        "node"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(NODE_INPUTS
            .iter()
            .any(|name| project.is_input_file(Path::new(name))))
    }

    /// `tog x` resolves from the public registry and projects into its own
    /// cache directory (`registry_tool.rs`).
    fn registry_tool(&self) -> io::Result<&'static dyn RegistryTool> {
        Ok(&node::registry_tool::NodeTool)
    }

    /// node-gyp runs on a Python.
    fn helpers(&self) -> &'static [&'static str] {
        &["python"]
    }

    /// A project without Python gets the shipped 3.12 line for node-gyp.
    fn default_helper(&self, helper: &str) -> io::Result<Option<Selected>> {
        match helper {
            "python" => node::shipped_gyp_python().map(Some),
            _ => Ok(None),
        }
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        node::preflight(platform)
    }

    fn prepare(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        // A missing lock is generated by the npm bundled in the Node this
        // project's toolchain selection names.
        inputs::ensure_npm_lock(project, toolchain, door)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let Some(plan) = inputs::load_npm_plan(ctx.platform, project, toolchain)? else {
            inputs::require_lock(project)?;
            return Ok(None);
        };
        node::freshness::check_lock_freshness(project, &plan)?;
        let v: Vec<_> = plan
            .packages
            .iter()
            .map(|p| {
                json!({"path": p.path, "version": p.version,
                                   "url": p.url, "integrity": p.integrity})
            })
            .collect();
        Ok(Some(serde_json::to_string_pretty(&json!({
            "ecosystem": "node", "node_version": plan.node_version,
            "lock_source": plan.lock_source, "packages": v
        }))?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let activity = &ctx.activity;
        let fresh = request.fresh;

        let platform = ctx.platform;
        let store = &ctx.store;
        // The Node this sync plans with and realizes is the row the
        // project's toolchain selection names, not the pin table.
        let selected = request.toolchain;
        let Some(plan) = inputs::load_npm_plan(platform, project, selected)? else {
            inputs::require_lock(project)?;
            return Ok(false);
        };
        node::freshness::check_lock_freshness(project, &plan)?;
        // package.json is read through the held descriptor; a lock-only
        // project has no "tog" config to read.
        let config = match project.read_input_string(Path::new("package.json"))? {
            Some(pkg) => node::parse_tog_config(&pkg)?,
            None => node::TogConfig::default(),
        };
        let runtime = node::realize_runtime(store, activity, platform, selected)?;
        // node-gyp runs on the helper Python selection when the project has
        // one; a Node-only project gets the shipped default.
        let helpers = request.helpers(self)?;
        let gyp_python = match helpers.get("python") {
            Some(python) => python.clone(),
            None => node::shipped_gyp_python()?,
        };
        let env = node::realize_node_env_for(
            store,
            activity,
            platform,
            &plan,
            &config.artifacts,
            selected,
            &gyp_python,
        )?;
        let inputs = inputs::input_records(project, &["package.json", &plan.lock_source])?;
        node::project_node_env_recorded(
            activity,
            project,
            &env,
            platform,
            &plan,
            &config.mutable_packages,
            fresh,
            &inputs,
            Some((selected, runtime.as_path())),
            &crate::tailors::helper_record(self, &helpers),
            attribution,
        )?;
        ui::synced("node_modules", &env);
        Ok(true)
    }

    fn refused_command(&self, cmd: &[String]) -> Option<String> {
        super::run_refusal::refused_command(cmd)
    }

    fn run_env(
        &self,
        ctx: &Context,
        dir: &Path,
        cwd: &Path,
        _cmd: &[String],
        _command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        let nm = dir.join("node_modules");
        let (_, nearest_nm) = projected_node_modules(dir, cwd);
        if nm.exists() {
            prefix.push(nearest_nm.join(".bin").to_string_lossy().into_owned());
            if nearest_nm != nm {
                prefix.push(nm.join(".bin").to_string_lossy().into_owned());
            }
            // The Node this run uses is the object the closure recorded, so
            // a catalog refresh between sync and run cannot change it.
            let node = closure_runtime(&ctx.store, activity, dir)?;
            prefix.push(node.join("bin").to_string_lossy().into_owned());
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        node::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("node".into(), string(&body["node_version"])));
        for package in body["packages"].as_array().unwrap_or(&empty) {
            let path = string(&package["path"]);
            let name = path
                .rsplit_once("node_modules/")
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| path.clone());
            out.packages.push(PackageRow {
                name,
                version: string(&package["version"]),
                detail: path,
            });
        }
        out
    }

    fn closure_state(
        &self,
        _platform: Platform,
        dir: &Path,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        let projection = node_projection_state(dir, body);
        Ok(
            if matches!(&projection, State::Synced | State::Unchecked(_)) {
                match recorded_inputs_state(dir, body)? {
                    State::Synced if matches!(projection, State::Unchecked(_)) => projection,
                    State::Synced => State::Synced,
                    other => other,
                }
            } else {
                projection
            },
        )
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "packages")? {
            let path = required(eco, &p, "path")?;
            let name = npm_name_from_path(&path).to_string();
            let ver = required(eco, &p, "version")?;
            // Scoped names: '@scope/x' -> '%40scope/x' per the purl spec.
            let purl_name = match name.strip_prefix('@') {
                Some(rest) => match rest.split_once('/') {
                    Some((scope, n)) => {
                        format!("%40{}/{}", purl_encode(scope), purl_encode(n))
                    }
                    None => purl_encode(&name),
                },
                None => purl_encode(&name),
            };
            let mut c = component(
                &name,
                &ver,
                format!("pkg:npm/{}@{}", purl_name, purl_encode(&ver)),
                eco,
            );
            // integrity is an SRI string (base64), not a hex digest;
            // recorded as a property rather than a malformed hash entry.
            push_property(&mut c, "tog:integrity", &required(eco, &p, "integrity")?);
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "env_object",
            "node-env",
            &version_of(eco, body, "node_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["nodejs"]
    }
}

/// The Node object this project's closure recorded. A closure written
/// before the toolchain lock has no such reference: it names no bytes to
/// resolve, so the run stops rather than silently picking today's default.
fn closure_runtime(
    store: &crate::kernel::store::Store,
    activity: &StoreActivity,
    dir: &Path,
) -> io::Result<PathBuf> {
    let closure = comforter::read_closure(dir, "node")?;
    if closure["runtime_object"]["id"].as_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "node closure predates runtime recording; run `tog`",
        ));
    }
    comforter::toolchain::runtime_object(store, activity, &closure, "bin/node")
}

/// npm lockfile path ("node_modules/a/node_modules/@s/b") -> package name.
fn npm_name_from_path(path: &str) -> &str {
    match path.rfind("node_modules/") {
        Some(i) => &path[i + "node_modules/".len()..],
        None => path,
    }
}

fn store_home_from_object(path: &Path) -> Option<PathBuf> {
    let objects = path.parent()?;
    if objects.file_name()?.to_str()? != "objects" {
        return None;
    }
    Some(objects.parent()?.parent()?.to_path_buf())
}

pub(super) fn encoded_workspace(workspace: &str) -> Option<String> {
    if workspace.is_empty()
        || workspace
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(workspace.replace('%', "%25").replace('/', "%2F"))
}

/// A `node_modules` that exists but is not a symlink. tog only ever
/// projects a symlink, so a real directory here means an install tool
/// (`npm install`, `yarn`, `pnpm`) ran and replaced the projection — the
/// single most common way a synced project silently stops being synced.
/// Named as its own detail so `tog status` says what happened rather than
/// the generic "not the synced projection".
fn replaced_by_a_real_directory(node_modules: &Path) -> bool {
    std::fs::symlink_metadata(node_modules)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

/// The `State` detail for that case. Reads as one sentence inside the
/// status line's "{what} is not the synced projection; run 'tog'".
pub(crate) fn replaced_projection_detail(name: &str) -> String {
    format!("{name} (a real directory an install tool wrote over the projection)")
}

fn node_projection_state(dir: &Path, body: &Value) -> State {
    let node_modules = dir.join("node_modules");
    if replaced_by_a_real_directory(&node_modules) {
        return State::ProjectionMissing(replaced_projection_detail("node_modules"));
    }
    let Some(env_text) = body["env_object"].as_str() else {
        return if canonical_symlink_target(&node_modules).is_some() && node_modules.is_dir() {
            State::Unchecked("node projection provenance was not recorded".into())
        } else {
            State::ProjectionMissing("node_modules".into())
        };
    };
    let Some(projection_id) = body["projection_id"].as_str() else {
        return State::ProjectionMissing("node_modules".into());
    };
    let expected_root = if let Some(path) = body["forest_path"].as_str() {
        let path = PathBuf::from(path);
        if path.file_name().and_then(|name| name.to_str()) != Some("node_modules") {
            return State::ProjectionMissing("node_modules".into());
        }
        let Some(root) = path.parent().map(Path::to_path_buf) else {
            return State::ProjectionMissing("node_modules".into());
        };
        root
    } else {
        let Some(home) = store_home_from_object(Path::new(env_text)) else {
            return State::ProjectionMissing("node_modules".into());
        };
        let Ok(project_key) = dir
            .canonicalize()
            .map(|path| hex::encode(Sha256::digest(path.as_os_str().as_bytes()))[..32].to_string())
        else {
            return State::ProjectionMissing("node_modules".into());
        };
        home.join("forests").join(project_key).join(projection_id)
    };
    let Some(expected) = expected_root.join("node_modules").canonicalize().ok() else {
        return State::ProjectionMissing("node_modules".into());
    };
    if canonical_symlink_target(&node_modules) != Some(expected) {
        return State::ProjectionMissing("node_modules".into());
    }
    if !Path::new(env_text).is_dir() {
        return State::ProjectionMissing("env object".into());
    }
    if let Some(workspaces) = body["workspaces"].as_array() {
        for workspace in workspaces {
            let Some(workspace) = workspace.as_str() else {
                return State::ProjectionMissing("workspace node_modules".into());
            };
            let Some(encoded) = encoded_workspace(workspace) else {
                return State::ProjectionMissing("workspace node_modules".into());
            };
            // A member whose node_modules git tracks was left unprojected
            // on purpose (#174): its own directory is what belongs there.
            if body["unprojected_workspaces"]
                .as_array()
                .is_some_and(|kept| kept.iter().any(|kept| kept == workspace))
            {
                if replaced_by_a_real_directory(&dir.join(workspace).join("node_modules")) {
                    continue;
                }
                return State::ProjectionMissing("workspace node_modules".into());
            }
            let Some(expected) = expected_root
                .join("workspaces")
                .join(encoded)
                .join("node_modules")
                .canonicalize()
                .ok()
            else {
                return State::ProjectionMissing("workspace node_modules".into());
            };
            if canonical_symlink_target(&dir.join(workspace).join("node_modules")) != Some(expected)
            {
                return State::ProjectionMissing("workspace node_modules".into());
            }
        }
    }
    State::Synced
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::store::Store;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    struct StoreEnv(Option<std::ffi::OsString>);

    impl Drop for StoreEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("TOG_STORE", value),
                None => std::env::remove_var("TOG_STORE"),
            }
        }
    }

    fn write_closure(dir: &Path, body: Value) {
        let closures = dir.join(".tog/closures");
        fs::create_dir_all(&closures).unwrap();
        fs::write(
            closures.join("node.json"),
            serde_json::to_string(&json!({
                "schema": "closure/1",
                "ecosystem": "node",
                "platform": Platform::host().unwrap().triple(),
                "body": body,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// A member whose node_modules git tracks keeps its own directory
    /// (#174). `status` takes that directory as the member's projection,
    /// and still reports the member missing once the directory is gone.
    #[test]
    fn an_unprojected_member_keeps_its_own_directory_and_is_synced() {
        let temp = TempDir::new();
        let dir = temp.0.join("project");
        let root = temp.0.join("forest");
        let env = temp.0.join("env");
        for path in [
            root.join("node_modules"),
            root.join("workspaces/packages%2Fbuilt/node_modules"),
            dir.join("packages/fixture/node_modules"),
            dir.join("packages/built"),
            env.clone(),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        std::os::unix::fs::symlink(root.join("node_modules"), dir.join("node_modules")).unwrap();
        std::os::unix::fs::symlink(
            root.join("workspaces/packages%2Fbuilt/node_modules"),
            dir.join("packages/built/node_modules"),
        )
        .unwrap();
        let body = |kept: Value| {
            json!({
                "env_object": env,
                "projection_id": "p",
                "forest_path": root.join("node_modules"),
                "workspaces": ["packages/built", "packages/fixture"],
                "unprojected_workspaces": kept,
            })
        };
        assert_eq!(
            node_projection_state(&dir, &body(json!(["packages/fixture"]))),
            State::Synced
        );
        let outside = temp.0.join("outside");
        fs::create_dir_all(outside.join("node_modules")).unwrap();
        for workspace in [
            "../outside".to_string(),
            outside.to_string_lossy().into_owned(),
        ] {
            let mut invalid = body(json!([workspace]));
            invalid["workspaces"] = json!([workspace]);
            assert!(matches!(
                node_projection_state(&dir, &invalid),
                State::ProjectionMissing(_)
            ));
        }
        assert!(matches!(
            node_projection_state(&dir, &body(Value::Null)),
            State::ProjectionMissing(_)
        ));
        fs::remove_dir(dir.join("packages/fixture/node_modules")).unwrap();
        assert!(matches!(
            node_projection_state(&dir, &body(json!(["packages/fixture"]))),
            State::ProjectionMissing(_)
        ));
    }

    /// A sync holds the project open: once the directory is renamed and a
    /// different project put at its old path, the plan and the recorded
    /// inputs still come from the original directory's lock.
    #[test]
    fn plan_reads_the_held_project_after_it_is_renamed_and_replaced() {
        let lock = |name: &str| {
            format!(
                r#"{{"name":"x","lockfileVersion":3,"packages":{{"":{{"name":"x"}},
                   "node_modules/{name}":{{"version":"1.0.0","resolved":"https://r/{name}.tgz",
                   "integrity":"sha512-m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRXMui/CET1IEDrHK6nHYbdEaGL/uhPMbuF3AGkGxXTVpn3ETw=="}}}}}}"#
            )
        };
        let temp = TempDir::new();
        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("package.json"), r#"{"name":"x"}"#).unwrap();
        fs::write(dir.join("package-lock.json"), lock("original")).unwrap();
        let project = ProjectRoot::open(&dir).unwrap();

        fs::rename(&dir, temp.0.join("moved")).unwrap();
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("package.json"), r#"{"name":"replacement"}"#).unwrap();
        fs::write(dir.join("package-lock.json"), lock("replacement")).unwrap();

        assert!(Node.detect(&project).unwrap());
        let selected = node::shipped_selection().unwrap();
        let plan = inputs::load_npm_plan(Platform::host().unwrap(), &project, &selected)
            .unwrap()
            .unwrap();
        let names: Vec<&str> = plan.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["original"]);
        let records =
            inputs::input_records(&project, &["package.json", "package-lock.json"]).unwrap();
        assert_eq!(
            records[1].sha256,
            hex::encode(Sha256::digest(lock("original").as_bytes()))
        );
    }

    /// A run takes its Node from the object the closure named, and a closure
    /// written before that reference existed stops the run instead of
    /// falling back to whatever the catalog would pick today.
    #[test]
    fn run_resolves_node_through_the_closure() {
        let _store_lock = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let temp = TempDir::new();
        let old_store = std::env::var_os("TOG_STORE");
        std::env::set_var("TOG_STORE", temp.0.join("store"));
        let _store_env = StoreEnv(old_store);
        let store = Store::open().unwrap();
        let activity = &store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();

        let id = format!("{}-node-24.20.0", "b".repeat(40));
        let object = store.object_path(&id);
        fs::create_dir_all(object.join("bin")).unwrap();
        fs::write(object.join("bin/node"), b"#!/bin/sh\n").unwrap();
        // A published object is a read-only directory with a metadata file;
        // anything less reads as a crashed publication.
        fs::write(store.root.join(format!("meta/{id}.json")), "{}").unwrap();
        let mut mode = fs::metadata(&object).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o555);
        fs::set_permissions(&object, mode).unwrap();

        let dir = temp.0.join("project");
        fs::create_dir_all(&dir).unwrap();
        write_closure(
            &dir,
            json!({
                "node_version": "24.20.0",
                "runtime_object": {"id": id, "path": object},
            }),
        );
        assert_eq!(closure_runtime(&store, activity, &dir).unwrap(), object);

        write_closure(&dir, json!({"node_version": "24.20.0"}));
        let error = closure_runtime(&store, activity, &dir).unwrap_err();
        assert_eq!(
            error.to_string(),
            "node closure predates runtime recording; run `tog`"
        );

        // Leave the fixture removable.
        let mut mode = fs::metadata(&object).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
        fs::set_permissions(&object, mode).unwrap();
    }
}
