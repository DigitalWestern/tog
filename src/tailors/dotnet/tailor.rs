//! The .NET tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a NuGet-locked project.

use crate::comforter;
use crate::comforter::status::{standard_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_property, required, toolchain_component, version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::sandbox;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::dotnet;
use crate::tailors::{ClosureListing, PackageRow, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Dotnet;

/// What `sync` and `build` share: realize the SDK and the restored
/// packages, then project the closure through the descriptor the command
/// holds. Returns the SDK object and the packages object.
fn realize_and_project(
    ctx: &Context,
    project: &ProjectRoot,
    toolchain: &Selected,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<(PathBuf, PathBuf)> {
    let (activity, platform, store) = (&ctx.activity, ctx.platform, &ctx.store);
    let sdk = dotnet::realize_runtime(store, activity, platform, toolchain)?;
    let (plan, lock_sha256) = dotnet::plan_dotnet(project, toolchain)?;
    let packages =
        dotnet::realize_packages(store, activity, platform, &plan, &sdk, project, toolchain)?;
    dotnet::project_dotnet_env(
        activity,
        project,
        &sdk,
        &packages,
        &plan,
        &lock_sha256,
        toolchain,
        attribution,
    )?;
    Ok((sdk, packages))
}

impl Tailor for Dotnet {
    fn package_registry(&self) -> Option<crate::tailors::PackageRegistry> {
        Some(super::edit::REGISTRY)
    }

    fn registry_exists(&self, name: &str) -> io::Result<Option<String>> {
        super::edit::registry_exists(name)
    }

    fn claims_package_name(&self, name: &str) -> bool {
        super::edit::claims_package_name(name)
    }

    fn edit_manifest(
        &self,
        _ctx: &crate::kernel::context::Context,
        edit: &crate::tailors::ManifestEdit<'_>,
        _door: &mut crate::kernel::resolve::ResolutionDoor<'_>,
    ) -> io::Result<crate::tailors::EditOutcome> {
        super::edit::edit_manifest(edit)
    }

    fn id(&self) -> &'static str {
        "dotnet"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        // A held root is a directory by construction.
        dotnet::has_marker(project)
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        dotnet::preflight_platform(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        if dotnet::require_lock(project).is_ok() {
            return Ok(());
        }
        let sdk = dotnet::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        dotnet::generate_lock(door, project, &sdk, toolchain)
    }

    fn plan(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        // The plan is read from the lock alone: no SDK is realized.
        let (plan, _) = dotnet::plan_dotnet(project, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let toolchain = request.toolchain;
        dotnet::preflight(project, toolchain.version("dotnet-sdk")?)?;
        dotnet::require_lock(project)?;
        let (_, packages) = realize_and_project(ctx, project, toolchain, attribution)?;
        ui::synced("nuget packages", &packages);
        Ok(true)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        dotnet::has_marker(&ProjectRoot::open(cwd)?)
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd.to_path_buf())
    }

    fn build(
        &self,
        ctx: &Context,
        _root: &Path,
        cwd: &Path,
        args: &[String],
        toolchain: &Selected,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        let project = ProjectRoot::open(cwd)?;
        let (sdk, packages) = realize_and_project(ctx, &project, toolchain, attribution)?;
        dotnet::build_sandboxed(
            ctx.platform,
            &ctx.activity,
            &project,
            &sdk,
            &packages,
            args,
            toolchain,
        )
    }

    fn refused_package_script(&self, dir: &Path) -> Option<String> {
        std::fs::symlink_metadata(dir.join(".tog/closures/dotnet.json"))
            .is_ok()
            .then(|| {
                "package.json scripts are not run under a .NET projection (MSBuild belongs in \
                 the sandbox: use `tog build dotnet`)"
                    .to_string()
            })
    }

    fn run_env(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        _cwd: &Path,
        cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let dir = project.path();
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        if comforter::has_closure(project, "dotnet")? {
            // This prevents accidental unsandboxed builds, not deliberate bypasses
            // through wrappers such as `sh -c`; during realization and build,
            // tog never evaluates project code outside its sandbox. Missing-lock
            // lock generation is the explicit host-side exception.
            if let Some(reason) = dotnet::refused_run_command(cmd) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, reason));
            }
            let closure = comforter::read_closure_in(project, "dotnet")?;
            let sdk =
                comforter::closure_object(&ctx.store, activity, &closure, "sdk_object", "dotnet")?;
            let packages =
                comforter::closure_object(&ctx.store, activity, &closure, "packages_object", "")?;
            prefix.push(sdk.to_string_lossy().into_owned());
            // A private per-project home inside the store, laid out like
            // the sync path's scratch: a home under the shared temp root
            // lets another user plant files the SDK reads as this user,
            // and a per-process one would make `tog env` print different
            // bytes on every call.
            let scratch = ctx.store.run_home(dir, "dotnet")?;
            dotnet::prepare_scratch(&scratch)?;
            let (prefixes, remove, set) = dotnet::run_env(&sdk, &packages, &scratch);
            sandbox::force_env(command, &prefixes, &remove, &set);
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        dotnet::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("dotnet-sdk".into(), string(&plan["sdk_version"])));
        for package in plan["packages"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["id"]),
                version: string(&package["version"]),
                detail: string(&package["content_hash"]),
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
            &["sdk_object", "packages_object"],
            "packages.lock.json",
            "packages_lock_sha256",
        )
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "packages")? {
            let (id, ver) = (required(eco, &p, "id")?, required(eco, &p, "version")?);
            let mut c = component(
                &id,
                &ver,
                format!("pkg:nuget/{}@{}", purl_encode(&id), purl_encode(&ver)),
                eco,
            );
            // contentHash is NuGet's semantic (signature-stripped)
            // sha512, base64 — not a raw file digest.
            push_property(
                &mut c,
                "tog:nuget:contentHash",
                &required(eco, &p, "content_hash")?,
            );
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "sdk_object",
            "dotnet-sdk",
            &version_of(eco, plan, "sdk_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["dotnet-sdk"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// The run guard is wired into the tailor's `tog run` environment: under
    /// a .NET projection a build verb is refused before any closure object
    /// is read; without one, the tailor adds nothing and refuses nothing.
    #[test]
    fn tog_run_under_a_dotnet_projection_refuses_build_verbs() {
        let _store_env = crate::kernel::store::STORE_ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let scratch = TempDir::named("dotnet-run-guard");
        let previous_store = std::env::var_os("TOG_STORE");
        std::env::set_var("TOG_STORE", scratch.0.join("store"));
        let ctx = Context::open(Platform::host().unwrap());
        match previous_store {
            Some(value) => std::env::set_var("TOG_STORE", value),
            None => std::env::remove_var("TOG_STORE"),
        }
        let ctx = ctx.unwrap();
        let project = scratch.0.join("project");
        std::fs::create_dir_all(project.join(".tog/closures")).unwrap();
        let cmd = |words: &[&str]| words.iter().map(|w| w.to_string()).collect::<Vec<_>>();
        let build = cmd(&["dotnet", "build"]);

        let prefix = Dotnet
            .run_env(
                &ctx,
                &ProjectRoot::open(&project).unwrap(),
                &project,
                &build,
                &mut Command::new("dotnet"),
            )
            .unwrap();
        assert!(prefix.is_empty());

        // A closure that names no objects: reaching it would fail on the
        // missing `sdk_object`, not with the guard's refusal.
        std::fs::write(project.join(".tog/closures/dotnet.json"), "{}").unwrap();
        let error = Dotnet
            .run_env(
                &ctx,
                &ProjectRoot::open(&project).unwrap(),
                &project,
                &build,
                &mut Command::new("dotnet"),
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{error}");
        assert_eq!(
            error.to_string(),
            dotnet::refused_run_command(&build).unwrap()
        );
        let error = Dotnet
            .run_env(
                &ctx,
                &ProjectRoot::open(&project).unwrap(),
                &project,
                &cmd(&["dotnet", "exec", "app.dll"]),
                &mut Command::new("dotnet"),
            )
            .unwrap_err();
        assert!(!error.to_string().contains("must run sandboxed"), "{error}");
    }
}
