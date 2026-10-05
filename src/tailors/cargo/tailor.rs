//! The Cargo tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, and `sbom` do for a Cargo workspace, and the
//! pinned formatter `tog fmt` runs.

use crate::comforter;
use crate::comforter::status::{lock_state, object_liveness_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, push_hash, required, toolchain_component, version_of,
};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::cargo::{self as cargo, inputs, rustfmt};
use crate::tailors::{ClosureListing, PackageRow, SyncRequest, Tailor};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Exit code for a finished child: its code, or 128 + signal.
fn child_status_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

pub struct Cargo;

/// What `sync` and `build` share: load the plan from `lock_root`'s lock,
/// realize the vendor object, and project the closure and cargo-home into
/// the workspace root, the held `project` or a directory resolved from it.
/// `fresh` clears cargo-home first. Returns the inputs and the vendor object.
fn realize_and_project(
    ctx: &Context,
    lock_root: &ProjectRoot,
    project: &ProjectRoot,
    toolchain: &Selected,
    fresh: bool,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<(inputs::CargoInputs, PathBuf)> {
    let (activity, store) = (&ctx.activity, &ctx.store);
    let inputs =
        inputs::load_cargo_inputs(ctx.platform, lock_root, project, store, activity, toolchain)?;
    let vendor_obj = cargo::realize_vendor(store, activity, &inputs.plan)?;
    let workspace = inputs::workspace_root(project, &inputs.root)?;
    if fresh {
        workspace.remove_dir_all(Path::new(".tog/cargo-home"))?;
    }
    cargo::project_cargo_env(
        activity,
        &workspace,
        &inputs.rust_obj,
        &vendor_obj,
        &inputs.plan,
        &inputs.lock_digest,
        &inputs.resolution_basis,
        toolchain,
        attribution,
    )?;
    Ok((inputs, vendor_obj))
}

impl Tailor for Cargo {
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

    fn resolution_outputs(&self, project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        super::resolve::resolution_outputs(project)
    }

    fn resolution_inputs(&self, project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        super::resolve::resolution_inputs(project)
    }

    /// `cargo metadata --locked` at the workspace root, on the Rust the
    /// selection names with its components and targets.
    fn attest_lock(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<(crate::kernel::resolve::record::ResolutionRecord, Vec<u8>)> {
        let root = inputs::locate_cargo_root(project.path())?;
        let extras = cargo::project_extras_in(project)?;
        let rust_obj =
            cargo::realize_toolchain(&ctx.store, &ctx.activity, ctx.platform, toolchain, &extras)?;
        super::resolve::attest_project(door, project, &rust_obj, &root, toolchain)
    }

    fn id(&self) -> &'static str {
        "cargo"
    }

    /// The lock names the language, not the package manager: a project's
    /// `rust-toolchain.toml` and the `[toolchain.rust]` section are the
    /// same statement.
    fn lock_ecosystem(&self) -> &'static str {
        "rust"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(inputs::is_cargo_here(project))
    }

    fn input_files(&self) -> &'static str {
        "Cargo.toml, Cargo.lock"
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        cargo::preflight_platform(platform)
    }

    fn prepare(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        inputs::ensure_lock(project, toolchain, door)
    }

    fn plan(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let inputs = inputs::load_cargo_inputs(
            ctx.platform,
            project,
            project,
            &ctx.store,
            &ctx.activity,
            toolchain,
        )?;
        Ok(Some(serde_json::to_string_pretty(&inputs.plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let (_, vendor_obj) = realize_and_project(
            ctx,
            project,
            project,
            request.toolchain,
            request.fresh,
            attribution,
        )?;
        ui::synced("cargo env", &vendor_obj);
        Ok(true)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        Ok(cwd
            .ancestors()
            .any(|dir| ProjectRoot::open(dir).is_ok_and(|project| inputs::is_cargo_here(&project))))
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd
            .ancestors()
            .find(|dir| dir.join("Cargo.toml").is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no Cargo.toml found from here upward",
                )
            })?
            .to_path_buf())
    }

    fn build(
        &self,
        ctx: &Context,
        root: &Path,
        cwd: &Path,
        args: &[String],
        toolchain: &Selected,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<()> {
        let lock_root = ProjectRoot::open(root)?;
        let project = ProjectRoot::open(cwd)?;
        let (inputs, vendor_obj) =
            realize_and_project(ctx, &lock_root, &project, toolchain, false, attribution)?;
        cargo::build_sandboxed(
            ctx.platform,
            &ctx.activity,
            &inputs.root,
            &inputs.rust_obj,
            &vendor_obj,
            args,
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
        let cargo_home = dir.join(".tog/cargo-home");
        if project.input_entry(Path::new(".tog/cargo-home"))? != Entry::Absent {
            let closure = comforter::read_closure_in(project, "cargo")?;
            // Store-contained resolution: a project-editable closure must never
            // inject arbitrary executable paths.
            let rust_obj = comforter::closure_object(
                &ctx.store,
                activity,
                &closure,
                "rust_object",
                "bin/rustc",
            )?;
            prefix.push(cargo_home.join("bin").to_string_lossy().into_owned());
            prefix.push(rust_obj.join("bin").to_string_lossy().into_owned());
            command.env("CARGO_HOME", cargo_home.canonicalize()?);
            command.env_remove("RUSTUP_HOME");
            command.env_remove("RUSTUP_TOOLCHAIN");
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        cargo::toolchain_catalog()
    }

    /// `[toolchain] path` in rust-toolchain.toml names a local tree.
    fn external_toolchain(&self) -> Option<crate::comforter::toolchain::ExternalToolchain> {
        Some(crate::kernel::provider::rust_path::select)
    }

    fn listing(&self, ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        if ecosystem == "cargo" {
            out.toolchain
                .push(("rust".into(), string(&plan["rust_version"])));
            for package in plan["crates"].as_array().unwrap_or(&empty) {
                out.packages.push(PackageRow {
                    name: string(&package["name"]),
                    version: string(&package["version"]),
                    detail: string(&package["sha256"]),
                });
            }
        }
        out
    }

    fn closure_state(
        &self,
        _platform: Platform,
        project: &ProjectRoot,
        ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        Ok(match ecosystem {
            // An object gc removed is checked before the projection that
            // points into it.
            "cargo" => match object_liveness_state(body, &["rust_object", "vendor_object"]) {
                Some(state) => state,
                None if !project.is_input_dir(Path::new(".tog/cargo-home")) => {
                    State::ProjectionMissing(".tog/cargo-home".into())
                }
                None => lock_state(project, "Cargo.lock", &string(&body["cargo_lock_sha256"]))?,
            },
            _ => State::Unchecked("unknown ecosystem".into()),
        })
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        if eco != "cargo" {
            return Ok(());
        }
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "crates")? {
            let (name, ver) = (required(eco, &p, "name")?, required(eco, &p, "version")?);
            let mut c = component(
                &name,
                &ver,
                format!("pkg:cargo/{}@{}", purl_encode(&name), purl_encode(&ver)),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "sha256")?);
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "rust_object",
            "rust",
            &version_of(eco, plan, "rust_version")?,
        )?);
        Ok(())
    }

    fn fmt_ecosystem(&self) -> Option<&'static str> {
        Some("rust")
    }

    fn fmt_preflight(&self, platform: Platform) -> io::Result<()> {
        // A platform with no pinned component is refused here, before
        // `Store::open` and before the Rust realization downloads ~105 MB of
        // toolchain.
        rustfmt::preflight_platform(platform)
    }

    fn fmt_check_project(&self, cwd: &Path) -> io::Result<()> {
        if !cwd
            .ancestors()
            .any(|dir| dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file())
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no Rust project here; run `tog fmt` from a Cargo project",
            ));
        }
        Ok(())
    }

    /// The Cargo workspace root, found by tog's own walk of the manifests
    /// (no cargo runs on the host).
    fn fmt_root(&self, _ctx: &Context, cwd: &Path, _toolchain: &Selected) -> io::Result<PathBuf> {
        inputs::locate_cargo_root(cwd)?.canonicalize()
    }

    /// Realize only the Rust toolchain and its paired rustfmt component, then
    /// format the Cargo workspace without resolving dependencies.
    fn fmt(
        &self,
        ctx: &Context,
        cwd: &Path,
        check: bool,
        args: &[String],
        toolchain: &Selected,
    ) -> io::Result<i32> {
        let platform = ctx.platform;
        let store = &ctx.store;
        let activity = &ctx.activity;
        // The formatter rides in the same release bundle as the compiler, so
        // one selection names both, and both are realized from its rows.
        let workspace_root = inputs::locate_cargo_root(cwd)?.canonicalize()?;
        // cargo fmt runs in the workspace itself (writable, the user's home
        // out of sight): a file there that is the signing key under another
        // name (a hard link) would be read as a manifest or a config and
        // quoted in cargo's parse error. The whole workspace is mounted,
        // `target` included (a config can be a symlink to `../target/key`),
        // so the whole of it is scanned. The formatter's output is relayed
        // with the key's secret replaced as well (`supervise::Relay`).
        crate::kernel::resolve::confine::refuse_key_links_under(
            &workspace_root,
            &crate::kernel::resolve::confine::signing_key_ids(),
            &[],
        )?;
        // The configuration cargo-fmt's cargo reads, from the invocation
        // directory up to the workspace root (nothing above it is mounted):
        // a file there (or one it includes) that is the key, or a symlink
        // out of the workspace, is refused by name before anything runs.
        {
            use crate::kernel::provider::cargo_door;
            let bound = cargo_door::Bound::new(&workspace_root)?;
            let invocation = cwd.canonicalize()?;
            for dir in invocation.ancestors() {
                if !dir.starts_with(&workspace_root) {
                    break;
                }
                cargo_door::config_files(dir, &bound)?;
            }
        }
        let rust_object = cargo::realize_runtime(store, activity, platform, toolchain)?;
        let rustfmt_object =
            rustfmt::ensure_rustfmt(store, activity, platform, toolchain, &rust_object)?;
        // An older `tog fmt` wrote a `rustfmt` closure here; nothing reads
        // one any more, so a formatting run removes it (unless it is the
        // only closure of a registered project: see
        // `remove_legacy_record`). `--check` changes
        // no file: a CI check must not leave the checkout dirty.
        if !check {
            let key =
                crate::kernel::store::Store::canonical_root_key(&workspace_root.canonicalize()?);
            rustfmt::remove_legacy_record(
                &ProjectRoot::open(&workspace_root)?,
                store.has_root_entry(&key)?,
            )?;
        }
        let invocation_dir = cwd.canonicalize()?;
        let status = rustfmt::run_sandboxed(
            platform,
            &invocation_dir,
            &workspace_root,
            &rust_object,
            &rustfmt_object,
            activity,
            check,
            args,
        )?;
        Ok(child_status_code(&status))
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["rust", "rustfmt"]
    }
}
