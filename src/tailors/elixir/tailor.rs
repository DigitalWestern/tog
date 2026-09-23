//! The Elixir tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a Mix project.

use crate::comforter;
use crate::comforter::status::{lock_state, object_liveness_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, push_property, required, toolchain_component,
    version_of,
};
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::sandbox;
use crate::kernel::toolchain::{Catalog, LegacyEvidence, Selected};
use crate::kernel::ui;
use crate::tailors::elixir;
use crate::tailors::{ClosureListing, PackageRow, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Elixir;

impl Tailor for Elixir {
    fn id(&self) -> &'static str {
        "elixir"
    }

    fn detect(&self, dir: &Path) -> io::Result<bool> {
        Ok(dir.join("mix.exs").is_file())
    }

    fn preflight(&self, platform: Platform, _dir: &Path) -> io::Result<()> {
        elixir::preflight_platform(platform)
    }

    fn plan(&self, ctx: &Context, dir: &Path, toolchain: &Selected) -> io::Result<Option<String>> {
        let beam = elixir::realize_runtime(&ctx.store, ctx.platform, toolchain)?;
        let (plan, _) = elixir::plan_elixir(&ctx.store, dir, &beam, toolchain)?;
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
        let fresh = request.fresh;

        let platform = ctx.platform;
        let store = &ctx.store;
        let beam = elixir::realize_runtime(store, platform, toolchain)?;
        let (plan, lock_sha256) = elixir::plan_elixir(store, dir, &beam, toolchain)?;
        let deps = elixir::realize_deps(store, platform, &plan, &beam, toolchain)?;
        let projection = elixir::project_elixir_env(
            platform,
            dir,
            &beam,
            &deps,
            &plan,
            &lock_sha256,
            fresh,
            toolchain,
            attribution,
        )?;
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
        let platform = ctx.platform;
        let store = &ctx.store;
        let beam = elixir::realize_runtime(store, platform, toolchain)?;
        let (plan, lock_sha256) = elixir::plan_elixir(store, root, &beam, toolchain)?;
        let deps = elixir::realize_deps(store, platform, &plan, &beam, toolchain)?;
        let projection = elixir::project_elixir_env(
            platform,
            root,
            &beam,
            &deps,
            &plan,
            &lock_sha256,
            false,
            toolchain,
            attribution,
        )?;
        elixir::build_sandboxed(platform, root, &beam, &projection, args, toolchain)
    }

    fn run_env(
        &self,
        ctx: &Context,
        dir: &Path,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let mut prefix = Vec::new();
        if dir.join(".tog/closures/elixir.json").exists() {
            let store = &ctx.store;
            let closure = comforter::read_closure(dir, "elixir")?;
            let beam = comforter::closure_object(store, &closure, "beam_object", "elixir/bin/mix")?;
            // The deps projection is a writable clone OUTSIDE the store; verify
            // it lives under the tog home and matches the recorded deps id.
            let deps_obj = comforter::closure_object(store, &closure, "deps_object", "")?;
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
            let scratch = std::env::temp_dir().join(format!("tog-mix-run-{}", std::process::id()));
            std::fs::create_dir_all(&scratch)?;
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

    fn legacy_toolchain_evidence(
        &self,
        _ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
        store: Option<&crate::kernel::store::Store>,
    ) -> LegacyEvidence {
        elixir::legacy_toolchain_evidence(platform, body, store)
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
        dir: &Path,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        Ok(
            object_liveness_state(body, &["beam_object", "deps_object"]).unwrap_or(lock_state(
                dir,
                "mix.lock",
                &string(&body["mix_lock_sha256"]),
            )?),
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

    fn object_kinds(&self) -> &'static [KindAdapter] {
        super::objects::KINDS
    }
}
