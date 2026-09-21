//! The Python tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for a Python project.

use crate::comforter::status::{recorded_inputs_state, string, symlink_target, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, required, toolchain_component, version_of,
};
use crate::kernel::objmeta::KindAdapter;
use crate::kernel::platform::Platform;
use crate::kernel::toolchain::{Catalog, LegacyEvidence, Selected};
use crate::kernel::ui;
use crate::tailors::python::{self as python, inputs, manifest, pyselect};
use crate::tailors::{ClosureListing, PackageRow, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::Path;
use std::process::Command;

pub struct Python;

impl Tailor for Python {
    fn id(&self) -> &'static str {
        "python"
    }

    fn detect(&self, dir: &Path) -> io::Result<bool> {
        inputs::has_python_input(dir)
    }

    fn preflight(&self, platform: Platform, dir: &Path) -> io::Result<()> {
        let selection =
            pyselect::select_python_with_inputs(platform, &manifest::python_inputs(dir)?)?;
        python::preflight(platform, selection.pin.version)
    }

    fn plan(&self, ctx: &Context, dir: &Path, toolchain: &Selected) -> io::Result<Option<String>> {
        let _ = toolchain;
        let (plan, _selection, _inputs) = inputs::read_plan(ctx.platform, dir, &ctx.store)?;
        Ok(Some(serde_json::to_string_pretty(&plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        dir: &Path,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let _ = request.toolchain;

        let platform = ctx.platform;
        let store = &ctx.store;
        let (plan, selection, inputs) = inputs::read_plan(platform, dir, store)?;
        let env = super::env::realize_env(store, platform, &plan)?;
        super::env::project_env_with_inputs(dir, &env, &plan, &selection, &inputs, attribution)?;
        ui::synced(".venv", &env);
        Ok(true)
    }

    fn run_env(
        &self,
        _ctx: &Context,
        dir: &Path,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let mut prefix = Vec::new();
        let venv = dir.join(".venv");
        if venv.exists() {
            prefix.push(venv.join("bin").to_string_lossy().into_owned());
            command.env("VIRTUAL_ENV", &venv);
            command.env("PYTHONDONTWRITEBYTECODE", "1"); // site-packages is read-only
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        python::toolchain_catalog()
    }

    fn legacy_toolchain_evidence(
        &self,
        _ecosystem: &str,
        platform: Option<Platform>,
        body: &Value,
    ) -> LegacyEvidence {
        python::legacy_toolchain_evidence(platform, body)
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        let version = body["python"]["version"]
            .as_str()
            .or_else(|| plan["python_version"].as_str())
            .unwrap_or_default();
        out.toolchain.push(("cpython".into(), version.into()));
        for package in plan["packages"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["name"]),
                version: string(&package["version"]),
                detail: string(&package["filename"]),
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
        let venv = dir.join(".venv");
        let env_object = string(&body["env_object"]);
        let target = symlink_target(&venv);
        Ok(
            if target.as_deref() != Some(Path::new(&env_object)) || !venv.join("bin").is_dir() {
                State::ProjectionMissing(".venv".into())
            } else {
                recorded_inputs_state(dir, body)?
            },
        )
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "packages")? {
            let (name, ver) = (required(eco, &p, "name")?, required(eco, &p, "version")?);
            let norm = name.to_ascii_lowercase().replace('_', "-");
            let mut c = component(
                &name,
                &ver,
                format!("pkg:pypi/{}@{}", purl_encode(&norm), purl_encode(&ver)),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "sha256")?);
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "env_object",
            "python-env",
            &version_of(eco, plan, "python_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [KindAdapter] {
        super::objects::KINDS
    }
}
