//! The Ruby tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for a Bundler project.

use crate::comforter;
use crate::comforter::status::{lock_state, object_liveness_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, required, toolchain_component, version_of,
};
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::sandbox;
use crate::kernel::toolchain::{Catalog, LegacyEvidence, Selected};
use crate::kernel::ui;
use crate::tailors::ruby;
use crate::tailors::{ClosureListing, PackageRow, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::Path;
use std::process::Command;

pub struct Ruby;

impl Tailor for Ruby {
    fn id(&self) -> &'static str {
        "ruby"
    }

    fn detect(&self, dir: &Path) -> io::Result<bool> {
        Ok(dir.join("Gemfile").is_file())
    }

    fn preflight(&self, platform: Platform, _dir: &Path) -> io::Result<()> {
        ruby::preflight_platform(platform)
    }

    fn plan(&self, ctx: &Context, dir: &Path, toolchain: &Selected) -> io::Result<Option<String>> {
        let activity = &ctx.activity;
        let ruby_obj = ruby::realize_runtime(&ctx.store, activity, ctx.platform, toolchain)?;
        let (plan, _) = ruby::plan_ruby(&ctx.store, &ctx.activity, dir, &ruby_obj, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        dir: &Path,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let activity = &ctx.activity;
        let toolchain = request.toolchain;
        let platform = ctx.platform;
        let store = &ctx.store;
        let ruby_obj = ruby::realize_runtime(store, activity, platform, toolchain)?;
        let (plan, lock_sha256) = ruby::plan_ruby(store, &ctx.activity, dir, &ruby_obj, toolchain)?;
        let gems = ruby::realize_gems(store, &ctx.activity, platform, &plan, &ruby_obj, toolchain)?;
        ruby::project_ruby_env(
            activity,
            dir,
            &ruby_obj,
            &gems,
            &plan,
            &lock_sha256,
            toolchain,
            attribution,
        )?;
        ui::synced("gems", &gems);
        Ok(true)
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
        if dir.join(".tog/closures/ruby.json").exists() {
            let closure = comforter::read_closure(dir, "ruby")?;
            let ruby_obj = comforter::closure_object(
                &ctx.store,
                activity,
                &closure,
                "ruby_object",
                "bin/ruby",
            )?;
            let gems_obj =
                comforter::closure_object(&ctx.store, activity, &closure, "gems_object", "")?;
            // Ruby FIRST, then gem binstubs (a gem exe must never shadow ruby).
            prefix.push(ruby_obj.join("bin").to_string_lossy().into_owned());
            prefix.push(gems_obj.join("bin").to_string_lossy().into_owned());
            let (prefixes, remove, set) = ruby::run_env(dir, &gems_obj);
            sandbox::force_env(command, &prefixes, &remove, &set);
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        ruby::toolchain_catalog()
    }

    fn legacy_toolchain_evidence(
        &self,
        _ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
        store: Option<&crate::kernel::store::Store>,
    ) -> LegacyEvidence {
        ruby::legacy_toolchain_evidence(platform, body, store)
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("ruby".into(), string(&plan["ruby_version"])));
        out.toolchain
            .push(("bundler".into(), string(&plan["bundler_version"])));
        for package in plan["gems"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["name"]),
                version: string(&package["version"]),
                detail: string(&package["full_name"]),
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
        Ok(
            object_liveness_state(body, &["ruby_object", "gems_object"]).unwrap_or(lock_state(
                dir,
                "Gemfile.lock",
                &string(&body["gemfile_lock_sha256"]),
            )?),
        )
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "gems")? {
            let (name, ver, platform) = (
                required(eco, &p, "name")?,
                required(eco, &p, "version")?,
                required(eco, &p, "platform")?,
            );
            let qualifier = if platform.is_empty() || platform == "ruby" {
                String::new()
            } else {
                format!("?platform={}", purl_encode(&platform))
            };
            let mut c = component(
                &name,
                &ver,
                format!(
                    "pkg:gem/{}@{}{}",
                    purl_encode(&name),
                    purl_encode(&ver),
                    qualifier
                ),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "sha256")?);
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "ruby_object",
            "ruby",
            &version_of(eco, plan, "ruby_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [KindAdapter] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["ruby"]
    }
}
