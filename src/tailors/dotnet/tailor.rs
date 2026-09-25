//! The .NET tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a NuGet-locked project.

use crate::comforter;
use crate::comforter::status::{lock_state, object_liveness_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_property, required, toolchain_component, version_of,
};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::sandbox;
use crate::kernel::toolchain::{Catalog, LegacyEvidence, Selected};
use crate::kernel::ui;
use crate::tailors::dotnet;
use crate::tailors::{ClosureListing, PackageRow, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Dotnet;

impl Tailor for Dotnet {
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
        _attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        if dotnet::require_lock(project).is_ok() {
            return Ok(());
        }
        let sdk = dotnet::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        dotnet::generate_lock(&ctx.store, &ctx.activity, project, &sdk, toolchain)
    }

    fn plan(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
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
        let activity = &ctx.activity;
        let toolchain = request.toolchain;
        let platform = ctx.platform;
        let store = &ctx.store;
        dotnet::preflight(project, toolchain.version("dotnet-sdk")?)?;
        dotnet::require_lock(project)?;
        let sdk = dotnet::realize_runtime(store, activity, platform, toolchain)?;
        let (plan, lock_sha256) = dotnet::plan_dotnet(project, toolchain)?;
        let packages =
            dotnet::realize_packages(store, activity, platform, &plan, &sdk, project, toolchain)?;
        // The closure is published through the descriptor this sync holds.
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
        let activity = &ctx.activity;
        let platform = ctx.platform;
        let store = &ctx.store;
        let project = ProjectRoot::open(cwd)?;
        let sdk = dotnet::realize_runtime(store, activity, platform, toolchain)?;
        let (plan, lock_sha256) = dotnet::plan_dotnet(&project, toolchain)?;
        let packages =
            dotnet::realize_packages(store, activity, platform, &plan, &sdk, &project, toolchain)?;
        dotnet::project_dotnet_env(
            activity,
            &project,
            &sdk,
            &packages,
            &plan,
            &lock_sha256,
            toolchain,
            attribution,
        )?;
        dotnet::build_sandboxed(
            platform, activity, &project, &sdk, &packages, args, toolchain,
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
        dir: &Path,
        _cwd: &Path,
        cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
        if dir.join(".tog/closures/dotnet.json").exists() {
            // This prevents accidental unsandboxed builds, not deliberate bypasses
            // through wrappers such as `sh -c`; during realization and build,
            // tog never evaluates project code outside its sandbox. Missing-lock
            // lock generation is the explicit host-side exception.
            if let Some(reason) = dotnet::refused_run_command(cmd) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, reason));
            }
            let closure = comforter::read_closure(dir, "dotnet")?;
            let sdk =
                comforter::closure_object(&ctx.store, activity, &closure, "sdk_object", "dotnet")?;
            let packages =
                comforter::closure_object(&ctx.store, activity, &closure, "packages_object", "")?;
            prefix.push(sdk.to_string_lossy().into_owned());
            let scratch = std::env::temp_dir().join(format!("tog-dn-run-{}", std::process::id()));
            std::fs::create_dir_all(&scratch)?;
            let (prefixes, remove, set) = dotnet::run_env(&sdk, &packages, &scratch);
            sandbox::force_env(command, &prefixes, &remove, &set);
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        dotnet::toolchain_catalog()
    }

    fn legacy_toolchain_evidence(
        &self,
        _ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
        store: Option<&crate::kernel::store::Store>,
    ) -> LegacyEvidence {
        dotnet::legacy_toolchain_evidence(platform, body, store)
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
        dir: &Path,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        Ok(
            object_liveness_state(body, &["sdk_object", "packages_object"]).unwrap_or(lock_state(
                dir,
                "packages.lock.json",
                &string(&body["packages_lock_sha256"]),
            )?),
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

    fn object_kinds(&self) -> &'static [KindAdapter] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["dotnet-sdk"]
    }
}
