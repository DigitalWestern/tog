//! The Elixir tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a Mix project.

use crate::comforter;
use crate::comforter::status::{standard_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, push_property, required, toolchain_component,
    version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::sandbox;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::elixir;
use crate::tailors::{ClosureListing, FileRunner, PackageRow, SourceFile, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Elixir;

/// What `sync` and `build` share: realize the BEAM pair and the Hex deps,
/// then project them. Projection writes only the store forest and the
/// closure, which is published through the descriptor the command holds.
/// Returns the BEAM object and the projection.
fn realize_and_project(
    ctx: &Context,
    project: &ProjectRoot,
    toolchain: &Selected,
    fresh: bool,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<(PathBuf, PathBuf)> {
    let (activity, platform, store) = (&ctx.activity, ctx.platform, &ctx.store);
    let beam = elixir::realize_runtime(store, activity, platform, toolchain)?;
    let (plan, lock_sha256) = elixir::plan_elixir(
        &mut ResolutionDoor::open(store, activity, platform, DoorKind::Planner, attribution)?,
        project,
        &beam,
        toolchain,
    )?;
    let deps = elixir::realize_deps(store, activity, platform, &plan, &beam, toolchain)?;
    let projection = elixir::project_elixir_env(
        activity,
        platform,
        project,
        &beam,
        &deps,
        &plan,
        &lock_sha256,
        fresh,
        toolchain,
        attribution,
    )?;
    Ok((beam, projection))
}

impl Tailor for Elixir {
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
        "elixir"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(project.is_input_file(Path::new("mix.exs")))
    }

    fn input_files(&self) -> &'static str {
        "mix.exs"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        // .exs is a script; .ex is a compiled module of a Mix project and
        // has no meaning on its own. `mix run` rather than `elixir`: a bare
        // `elixir` loads none of the project's deps, and the projection
        // only reaches the script through Mix.
        &[SourceFile {
            extension: "exs",
            runner: FileRunner::Command(&["mix", "run"]),
        }]
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        elixir::preflight_platform(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        if elixir::require_lock(project).is_ok() {
            return Ok(());
        }
        let beam = elixir::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        elixir::generate_lock(door, project, &beam)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let activity = &ctx.activity;
        elixir::require_lock(project)?;
        let beam = elixir::realize_runtime(&ctx.store, activity, ctx.platform, toolchain)?;
        let (plan, _) = elixir::plan_elixir(door, project, &beam, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        elixir::require_lock(project)?;
        let (_, projection) =
            realize_and_project(ctx, project, request.toolchain, request.fresh, attribution)?;
        ui::synced("hex deps", &projection);
        Ok(true)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        Ok(cwd.ancestors().any(|d| d.join("mix.exs").is_file()))
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd
            .ancestors()
            .find(|dir| dir.join("mix.exs").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no mix.exs found from here upward")
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
        let project = ProjectRoot::open(root)?;
        let (beam, projection) = realize_and_project(ctx, &project, toolchain, false, attribution)?;
        elixir::build_sandboxed(
            ctx.platform,
            &ctx.activity,
            root,
            &beam,
            &projection,
            args,
            toolchain,
        )
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
        if let Some(closure) = comforter::read_closure_if_present(project, "elixir")? {
            let store = &ctx.store;
            let beam = comforter::closure_object(
                store,
                activity,
                &closure,
                "beam_object",
                "elixir/bin/mix",
            )?;
            // The deps projection is a writable clone OUTSIDE the store; verify
            // it lives under the tog home and matches the recorded deps id.
            let deps_obj = comforter::closure_object(store, activity, &closure, "deps_object", "")?;
            // Never trust the recorded projection path: reconstruct the ONE
            // expected forest path from canonical project + deps id and require
            // exact canonical equality — lexical checks admit foreign forests,
            // dot-dot tricks, and symlinked dirs.
            let projection = elixir::expected_projection(store, dir, &deps_obj)?;
            let recorded = closure["deps_projection"].as_str().map(PathBuf::from);
            if recorded.as_deref().and_then(|p| p.canonicalize().ok()) != Some(projection.clone())
                || !projection.is_dir()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "elixir closure projection is not the expected forest path; \
                     run `tog` first",
                ));
            }
            prefix.push(beam.join("elixir/bin").to_string_lossy().into_owned());
            prefix.push(beam.join("otp/bin").to_string_lossy().into_owned());
            // A private per-project home inside the store: a HOME under
            // the shared temp root lets another user plant `.erlang` or
            // `.iex.exs` that Erlang and Elixir run at startup as this
            // user, and a per-process one would make `tog env` print
            // different bytes on every call.
            let scratch = ctx.store.run_home(dir, "elixir")?;
            elixir::prepare_run_home(&scratch)?;
            // The build root belongs to the toolchain this closure was
            // synced with, not to whatever the catalog offers now.
            let fingerprint = closure["beam_fingerprint"].as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "elixir closure records no toolchain fingerprint; run `tog`",
                )
            })?;
            let (prefixes, remove, set) = elixir::run_env(
                &beam,
                &projection,
                &elixir::build_root_at(dir, fingerprint),
                &scratch,
            )?;
            sandbox::force_env(command, &prefixes, &remove, &set);
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        elixir::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("elixir".into(), string(&plan["elixir_version"])));
        out.toolchain
            .push(("otp".into(), string(&plan["otp_version"])));
        for package in plan["deps"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["package"]),
                version: string(&package["version"]),
                detail: string(&package["app"]),
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
            &["beam_object", "deps_object"],
            "mix.lock",
            "mix_lock_sha256",
        )
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "deps")? {
            let (name, ver) = (required(eco, &p, "package")?, required(eco, &p, "version")?);
            let mut c = component(
                &name,
                &ver,
                format!(
                    "pkg:hex/{}@{}",
                    purl_encode(&name.to_ascii_lowercase()),
                    purl_encode(&ver)
                ),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "outer_sha256")?);
            push_property(
                &mut c,
                "tog:hex:inner-checksum",
                &required(eco, &p, "inner_sha256")?,
            );
            out.push(c);
        }
        let beam_version = format!(
            "otp-{}-elixir-{}",
            version_of(eco, plan, "otp_version")?,
            version_of(eco, plan, "elixir_version")?,
        );
        out.push(toolchain_component(
            body,
            "beam_object",
            "beam",
            &beam_version,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["beam"]
    }
}
