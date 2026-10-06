//! The Python tailor's `Tailor` implementation: what `sync`, `plan`, `run`,
//! `ls`, `status`, and `sbom` do for a Python project.

use crate::comforter::status::{recorded_inputs_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, required, toolchain_component, version_of,
};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::python::{self as python, inputs, manifest, pyselect};
use crate::tailors::{
    ClosureListing, FileRunner, PackageRow, RegistryTool, SourceFile, SyncRequest, Tailor,
};
use serde_json::Value;
use std::io;
use std::path::Path;
use std::process::Command;

pub struct Python;

impl Tailor for Python {
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
        "python"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        inputs::has_python_input(project)
    }

    fn input_files(&self) -> &'static str {
        "requirements.lock.txt, requirements.txt, pyproject.toml ([project], [tool.poetry], [dependency-groups]), setup.cfg, setup.py, requirements/{common.txt,base.txt,requirements.in,cpu.txt,cuda.txt,rocm.txt,xpu.txt}"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        &[SourceFile {
            extension: "py",
            runner: FileRunner::Command(&["python"]),
        }]
    }

    /// An sdist with a Rust extension compiles with a Rust. With no locked
    /// Rust there is no single default: each sdist's own toolchain file
    /// picks among the shipped pins.
    fn helpers(&self) -> &'static [&'static str] {
        &["rust"]
    }

    /// An sdist with no toolchain file of its own (or one naming no
    /// channel, or `stable`) builds on the Rust the Python section pins: the
    /// catalog's default when the section is written. The wheel ids of a
    /// locked project then stay put when a newer tog ships a newer default.
    fn helper_pins(&self) -> io::Result<std::collections::BTreeMap<String, String>> {
        let rust = crate::kernel::toolchain::shipped(
            &crate::kernel::provider::rust::toolchain_catalog()?,
        )?;
        Ok(std::collections::BTreeMap::from([(
            "rust".to_string(),
            rust.version("rustc")?.to_string(),
        )]))
    }

    fn registry_tool(&self) -> io::Result<&'static dyn RegistryTool> {
        Ok(&python::registry_tool::PythonTool)
    }

    /// A `.python-version`, `requires-python`, or Poetry `python` that does
    /// not parse refuses here, on every command, before any lock is read
    /// or written from it.
    fn check_inputs(&self, project: &ProjectRoot) -> io::Result<()> {
        pyselect::check_project_inputs(project)
    }

    /// Host support and a pinned interpreter for the request this project
    /// states, before the store is opened. Selection proper happens in the
    /// kernel a moment later, from the same rows; this runs first so an
    /// unpinnable request is refused in Python's own words (which patch
    /// releases exist, and what to put in `.python-version`) rather than in
    /// the catalog's.
    fn preflight(&self, platform: Platform, project: &ProjectRoot) -> io::Result<()> {
        let selection =
            pyselect::select_python_with_inputs(platform, &manifest::python_inputs(project)?)?;
        python::preflight(platform, selection.pin.version)
    }

    fn plan(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        selected: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let (plan, _selection, _inputs) = inputs::read_plan(project, selected, door)?;
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
        let platform = ctx.platform;
        let store = &ctx.store;
        // The interpreter and the resolver this sync uses are the rows the
        // project's toolchain selection names, not the pin table.
        let selected = request.toolchain;
        // Planning and realization run their resolvers (a missing
        // requirements lock, an sdist's build requirements or Rust lock)
        // through one door on this sync's scope.
        let mut door =
            ResolutionDoor::open(store, activity, platform, DoorKind::Planner, attribution)?;
        let (plan, selection, inputs) = inputs::read_plan(project, selected, &mut door)?;
        let runtime = python::realize_runtime(store, activity, platform, selected)?;
        // An sdist with a Rust extension builds on the Rust this project's
        // lock names when the project has one, not on the shipped pin.
        let helpers = request.helpers(self)?;
        let env = super::env::realize_env_with(&mut door, &plan, selected, helpers.get("rust"))?;
        // An sdist's generated Cargo.lock ran through a Detached door with
        // no project at hand; its ledger is evidence of this sync's
        // planning, rooted here so GC keeps it.
        let ledgers = door.take_kept_ledgers();
        for objects in &ledgers {
            crate::kernel::resolve::ledger::root(store, activity, project, objects)?;
        }
        // The `.venv` projection and the closure are published through the
        // held project descriptor.
        super::env::project_env_with_inputs(
            activity,
            project,
            &env,
            &plan,
            &selection,
            &inputs,
            Some((selected, runtime.as_path())),
            &crate::tailors::helper_record(self, &helpers),
            &ledgers,
            attribution,
        )?;
        ui::synced(".venv", &env);
        Ok(true)
    }

    fn refused_command(&self, cmd: &[String]) -> Option<String> {
        python::run_refusal::refused_command(cmd)
    }

    fn run_env(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let dir = project.path();
        let mut prefix = Vec::new();
        let venv = dir.join(".venv");
        if project.input_entry(Path::new(".venv"))? != Entry::Absent {
            prefix.push(venv.join("bin").to_string_lossy().into_owned());
            command.env("VIRTUAL_ENV", &venv);
            command.env("PYTHONDONTWRITEBYTECODE", "1"); // site-packages is read-only
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        python::toolchain_catalog()
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
        project: &ProjectRoot,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        let env_object = string(&body["env_object"]);
        let target = project.read_link(Path::new(".venv")).ok().flatten();
        Ok(
            if target.as_deref() != Some(Path::new(&env_object))
                || !project.is_input_dir(Path::new(".venv/bin"))
            {
                State::ProjectionMissing(".venv".into())
            } else {
                match recorded_inputs_state(project, body)? {
                    // A kernel marker's answer is not in any project file.
                    State::Synced
                        if manifest::kernel_marker_record(project)?
                            .is_some_and(|kernel| kernel != body["host_kernel"]) =>
                    {
                        State::Changed(vec![
                            "host kernel (uv.lock reads platform_release or platform_version)"
                                .into(),
                        ])
                    }
                    state => state,
                }
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

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["cpython", "uv", "native-libs"]
    }
}
