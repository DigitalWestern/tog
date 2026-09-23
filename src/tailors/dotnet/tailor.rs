//! The .NET tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a NuGet-locked project.

use crate::comforter;
use crate::comforter::status::{lock_state, object_liveness_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_property, required, toolchain_component, version_of,
};
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

    fn detect(&self, dir: &Path) -> io::Result<bool> {
        Ok(dir.is_dir() && dotnet::has_marker(dir)?)
    }

    fn preflight(&self, platform: Platform, _dir: &Path) -> io::Result<()> {
        dotnet::preflight_platform(platform)
    }

    fn plan(&self, ctx: &Context, dir: &Path, toolchain: &Selected) -> io::Result<Option<String>> {
        // Preflight before SDK realization: a broken layout should fail
        // loudly here, not after a toolchain download.
        dotnet::preflight(dir, toolchain.version("dotnet-sdk")?)?;
        let sdk = dotnet::realize_runtime(&ctx.store, ctx.platform, toolchain)?;
        let (plan, _) = dotnet::plan_dotnet(&ctx.store, dir, &sdk, toolchain)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        dir: &Path,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let toolchain = request.toolchain;
        let platform = ctx.platform;
        let store = &ctx.store;
        dotnet::preflight(dir, toolchain.version("dotnet-sdk")?)?;
        let sdk = dotnet::realize_runtime(store, platform, toolchain)?;
        let (plan, lock_sha256) = dotnet::plan_dotnet(store, dir, &sdk, toolchain)?;
        let packages = dotnet::realize_packages(store, platform, &plan, &sdk, dir, toolchain)?;
        dotnet::project_dotnet_env(
            dir,
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
        dotnet::has_marker(cwd)
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
        let platform = ctx.platform;
        let store = &ctx.store;
        let sdk = dotnet::realize_runtime(store, platform, toolchain)?;
        let (plan, lock_sha256) = dotnet::plan_dotnet(store, cwd, &sdk, toolchain)?;
        let packages = dotnet::realize_packages(store, platform, &plan, &sdk, cwd, toolchain)?;
        dotnet::project_dotnet_env(
            cwd,
            &sdk,
            &packages,
            &plan,
            &lock_sha256,
            toolchain,
            attribution,
        )?;
        dotnet::build_sandboxed(platform, cwd, &sdk, &packages, args, toolchain)
    }

    fn run_env(
        &self,
        ctx: &Context,
        dir: &Path,
        _cwd: &Path,
        cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
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
            let sdk = comforter::closure_object(&ctx.store, &closure, "sdk_object", "dotnet")?;
            let packages = comforter::closure_object(&ctx.store, &closure, "packages_object", "")?;
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
}
