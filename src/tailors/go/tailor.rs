//! The Go tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, `doctor`, and `sbom` do for a Go module.

use crate::comforter;
use crate::comforter::status::{lock_state, object_liveness_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, purl_encode_path, push_hash, push_property, required,
    toolchain_component, version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::toolchain::{Catalog, LegacyEvidence, Selected};
use crate::kernel::ui;
use crate::tailors::go::{self as go, inputs};
use crate::tailors::{ClosureListing, DoctorCheck, PackageRow, SyncRequest, Tailor};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Go;

impl Tailor for Go {
    fn id(&self) -> &'static str {
        "go"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(project.is_input_file(Path::new("go.mod")))
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        go::preflight_platform(platform)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
    ) -> io::Result<Option<String>> {
        let inputs =
            inputs::load_go_inputs(ctx.platform, project, &ctx.store, &ctx.activity, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&inputs.plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let activity = &ctx.activity;
        let toolchain = request.toolchain;
        let platform = ctx.platform;
        let store = &ctx.store;
        let inputs = inputs::load_go_inputs(platform, project, store, &ctx.activity, toolchain)?;
        let modcache = go::realize_modcache(
            store,
            &ctx.activity,
            platform,
            toolchain,
            &inputs.plan,
            &inputs.go_obj,
        )?;
        // The closure is published through the descriptor this sync holds.
        go::project_go_env(
            activity,
            project,
            &inputs.go_obj,
            &modcache,
            &inputs.plan,
            &inputs.gosum_sha256,
            toolchain,
            attribution,
        )?;
        ui::synced("go modcache", &modcache);
        Ok(true)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        Ok(cwd.ancestors().any(|d| d.join("go.mod").is_file()))
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd
            .ancestors()
            .find(|dir| dir.join("go.mod").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no go.mod found from here upward")
            })?
            .to_path_buf())
    }

    fn build(
        &self,
        ctx: &Context,
        root: &Path,
        _cwd: &Path,
        args: &[String],
        toolchain: &Selected,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        let activity = &ctx.activity;
        let platform = ctx.platform;
        let store = &ctx.store;
        let project = ProjectRoot::open(root)?;
        let inputs = inputs::load_go_inputs(platform, &project, store, &ctx.activity, toolchain)?;
        let modcache = go::realize_modcache(
            store,
            &ctx.activity,
            platform,
            toolchain,
            &inputs.plan,
            &inputs.go_obj,
        )?;
        go::project_go_env(
            activity,
            &project,
            &inputs.go_obj,
            &modcache,
            &inputs.plan,
            &inputs.gosum_sha256,
            toolchain,
            attribution,
        )?;
        go::build_sandboxed(
            platform,
            &ctx.activity,
            root,
            &inputs.go_obj,
            &modcache,
            args,
        )
    }

    fn run_env(
        &self,
        ctx: &Context,
        dir: &Path,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        if dir.join(".tog/closures/go.json").exists() {
            let closure = comforter::read_closure(dir, "go")?;
            let go_obj =
                comforter::closure_object(&ctx.store, activity, &closure, "go_object", "bin/go")?;
            let modcache =
                comforter::closure_object(&ctx.store, activity, &closure, "modcache_object", "")?;
            prefix.push(go_obj.join("bin").to_string_lossy().into_owned());
            for (k, v) in go::go_env(&go_obj, &modcache, true) {
                if v.is_empty() {
                    command.env_remove(&k);
                } else {
                    command.env(&k, &v);
                }
            }
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        go::toolchain_catalog()
    }

    fn legacy_toolchain_evidence(
        &self,
        _ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
        store: Option<&crate::kernel::store::Store>,
    ) -> LegacyEvidence {
        go::legacy_toolchain_evidence(platform, body, store)
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("go".into(), string(&plan["go_version"])));
        for package in plan["modules"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["path"]),
                version: string(&package["version"]),
                detail: String::new(),
            });
        }
        out
    }

    fn closure_state(
        &self,
        platform: Platform,
        dir: &Path,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        go_status(platform, dir, body)
    }

    fn doctor(&self, platform: Platform, dir: &Path) -> Vec<DoctorCheck> {
        let mut checks = Vec::new();
        if dir.join("go.mod").is_file() {
            match ProjectRoot::open(dir).and_then(|root| go::project_go_version(platform, &root)) {
                Ok(version) => checks.push(DoctorCheck {
                    name: "go-toolchain",
                    ok: true,
                    detail: format!("{version} selected for this project"),
                }),
                Err(error) => checks.push(DoctorCheck {
                    name: "go-toolchain",
                    ok: false,
                    detail: format!("cannot select a realizable Go toolchain: {error}"),
                }),
            }
        }
        checks
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "modules")? {
            let (path, ver) = (required(eco, &p, "path")?, required(eco, &p, "version")?);
            let mut c = component(
                &path,
                &ver,
                format!(
                    "pkg:golang/{}@{}",
                    purl_encode_path(&path),
                    purl_encode(&ver)
                ),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "zip_sha256")?);
            push_property(&mut c, "tog:go:h1", &required(eco, &p, "h1")?);
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "go_object",
            "go",
            &version_of(eco, plan, "go_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [KindAdapter] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["go"]
    }
}

/// Compare the selected Go version in go.mod with the one recorded in the
/// closure. This is read-only: status must never realize a toolchain or touch
/// the network just to detect a stale selection.
fn go_status(platform: Platform, dir: &Path, body: &Value) -> io::Result<State> {
    if let Some(state) = object_liveness_state(body, &["go_object", "modcache_object"]) {
        return Ok(state);
    }

    let mut changed = Vec::new();
    let recorded_version = string(&body["plan"]["go_version"]);
    if !recorded_version.is_empty() {
        match fs::metadata(dir.join("go.mod")) {
            Ok(_) => match ProjectRoot::open(dir)
                .and_then(|root| go::project_go_version(platform, &root))
            {
                Ok(selected) if selected == recorded_version => {}
                Ok(_) => changed.push("go.mod".to_string()),
                Err(_) => changed.push("go.mod (Go toolchain selection unavailable)".to_string()),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                changed.push("go.mod (removed)".to_string())
            }
            Err(error) => return Err(error),
        }
    }

    let lock_state = lock_state(dir, "go.sum", &string(&body["go_sum_sha256"]))?;
    match lock_state {
        State::Changed(files) => changed.extend(files),
        State::Unchecked(reason) if changed.is_empty() => {
            if recorded_version.is_empty() {
                return Ok(State::Unchecked(format!(
                    "{reason}; recorded Go version is missing; run 'tog' once to record the selected toolchain"
                )));
            }
            return Ok(State::Unchecked(reason));
        }
        State::Synced | State::Unchecked(_) => {}
        _ => unreachable!("go.sum lock_state has no projection or platform state"),
    }
    if !changed.is_empty() {
        return Ok(State::Changed(changed));
    }
    if recorded_version.is_empty() {
        return Ok(State::Unchecked(
            "recorded Go version is missing; run 'tog' once to record the selected toolchain"
                .into(),
        ));
    }
    Ok(State::Synced)
}
