//! The Ruby tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for a Bundler project.

use crate::comforter;
use crate::comforter::status::{standard_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, required, toolchain_component, version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::sandbox;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::ruby;
use crate::tailors::{ClosureListing, FileRunner, PackageRow, SourceFile, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::Path;
use std::process::Command;

pub struct Ruby;

impl Tailor for Ruby {
    fn package_registry(&self) -> Option<crate::tailors::PackageRegistry> {
        Some(super::edit::REGISTRY)
    }

    fn registry_exists(&self, name: &str) -> io::Result<Option<String>> {
        super::edit::registry_exists(name)
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
        "ruby"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(project.is_input_file(Path::new("Gemfile")))
    }

    fn input_files(&self) -> &'static str {
        "Gemfile"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        &[SourceFile {
            extension: "rb",
            runner: FileRunner::Command(&["ruby"]),
        }]
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        ruby::preflight_platform(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        if ruby::require_lock(project).is_ok() {
            return Ok(());
        }
        let ruby_obj = ruby::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        ruby::generate_lock(door, project, &ruby_obj)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let activity = &ctx.activity;
        ruby::require_lock(project)?;
        let ruby_obj = ruby::realize_runtime(&ctx.store, activity, ctx.platform, toolchain)?;
        let (plan, _) = ruby::plan_ruby(door, project, &ruby_obj, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
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
        ruby::require_lock(project)?;
        let ruby_obj = ruby::realize_runtime(store, activity, platform, toolchain)?;
        let (plan, lock_sha256) = ruby::plan_ruby(
            &mut ResolutionDoor::open(store, activity, platform, DoorKind::Planner, attribution)?,
            project,
            &ruby_obj,
            toolchain,
        )?;
        let gems = ruby::realize_gems(store, activity, platform, &plan, &ruby_obj, toolchain)?;
        ruby::project_ruby_env(
            activity,
            project,
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

    fn runtime_programs(&self) -> &'static [&'static str] {
        &["ruby"]
    }

    fn run_env(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let dir = project.path();
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        if let Some(closure) = comforter::read_closure_if_present(project, "ruby")? {
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
        project: &ProjectRoot,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        standard_state(
            project,
            body,
            &["ruby_object", "gems_object"],
            "Gemfile.lock",
            "gemfile_lock_sha256",
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

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["ruby"]
    }
}
