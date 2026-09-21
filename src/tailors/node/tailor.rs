//! The Node tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for an npm/pnpm/Yarn project.

use crate::comforter;
use crate::comforter::status::{canonical_symlink_target, recorded_inputs_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_property, required, toolchain_component, version_of,
};
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::toolchain::{Catalog, LegacyEvidence};
use crate::kernel::ui;
use crate::tailors::node::{self as node, inputs};
use crate::tailors::{ClosureListing, PackageRow, Tailor};
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
    fn id(&self) -> &'static str {
        "node"
    }

    fn detect(&self, dir: &Path) -> io::Result<bool> {
        Ok(NODE_INPUTS.iter().any(|name| dir.join(name).is_file()))
    }

    fn preflight(&self, platform: Platform, _dir: &Path) -> io::Result<()> {
        node::preflight(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        dir: &Path,
        _attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        inputs::ensure_npm_lock(ctx.platform, dir, &ctx.store)
    }

    fn plan(&self, ctx: &Context, dir: &Path) -> io::Result<Option<String>> {
        let Some(plan) = inputs::load_npm_plan(ctx.platform, dir)? else {
            return Ok(None);
        };
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
        dir: &Path,
        fresh: bool,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let platform = ctx.platform;
        let store = &ctx.store;
        let Some(plan) = inputs::load_npm_plan(platform, dir)? else {
            return Ok(false);
        };
        let mut config = node::TogConfig::default();
        if plan.lock_source == "package-lock.json" {
            let lock = std::fs::read_to_string(dir.join("package-lock.json"))?;
            if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
                node::check_lock_freshness(&pkg, &lock)?;
                config = node::parse_tog_config(&pkg)?;
            }
        } else if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
            config = node::parse_tog_config(&pkg)?;
        }
        let env = node::realize_node_env(store, platform, &plan, &config.artifacts)?;
        let inputs = comforter::input_records(
            dir,
            &[dir.join("package.json"), dir.join(&plan.lock_source)],
        )?;
        node::project_node_env_recorded(
            dir,
            &env,
            platform,
            &plan,
            &config.mutable_packages,
            fresh,
            &inputs,
            attribution,
        )?;
        ui::synced("node_modules", &env);
        Ok(true)
    }

    fn run_env(
        &self,
        ctx: &Context,
        dir: &Path,
        cwd: &Path,
        _cmd: &[String],
        _command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let mut prefix = Vec::new();
        let nm = dir.join("node_modules");
        let (_, nearest_nm) = projected_node_modules(dir, cwd);
        if nm.exists() {
            prefix.push(nearest_nm.join(".bin").to_string_lossy().into_owned());
            if nearest_nm != nm {
                prefix.push(nm.join(".bin").to_string_lossy().into_owned());
            }
            // Node toolchain from the store (cache hit after sync).
            let node = node::ensure_node_for(&ctx.store, ctx.platform)?;
            prefix.push(node.join("bin").to_string_lossy().into_owned());
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        node::toolchain_catalog()
    }

    fn legacy_toolchain_evidence(
        &self,
        _ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
    ) -> LegacyEvidence {
        node::legacy_toolchain_evidence(platform, body)
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

    fn object_kinds(&self) -> &'static [KindAdapter] {
        super::objects::KINDS
    }
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

fn encoded_workspace(workspace: &str) -> Option<String> {
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
/// status line's "{what} is not the synced projection; run 'tog sync'".
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
