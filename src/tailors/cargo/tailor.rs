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
use crate::kernel::toolchain::input::{InputRow, Sources};
use crate::kernel::toolchain::Request;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::cargo::{self as cargo, inputs, rustfmt};
use crate::tailors::{
    ClosureListing, FileRunner, Formatter, PackageRow, SourceFile, SyncRequest, Tailor,
};
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
    let workspace = &inputs.workspace;
    workspace.check_still_named()?;
    if fresh {
        workspace.remove_dir_all(Path::new(".tog/cargo-home"))?;
    }
    cargo::project_cargo_env(
        activity,
        workspace,
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
        _host: &dyn crate::tailors::EditHost,
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

    fn toolchain_sources(&self) -> Sources {
        Sources {
            discover: toolchain_rows,
            request: toolchain_request,
        }
    }

    fn input_files(&self) -> &'static str {
        "Cargo.toml, Cargo.lock"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        &[SourceFile {
            extension: "rs",
            runner: FileRunner::Built(
                "a Rust source file is built as part of its crate: 'tog build' builds the \
                 crate in the sandbox, and 'tog run cargo run' builds and runs it",
            ),
        }]
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
            &inputs.workspace,
            &inputs.rust_obj,
            &vendor_obj,
            args,
        )
    }

    fn runtime_programs(&self) -> &'static [&'static str] {
        &["cargo", "rustc"]
    }

    fn run_env(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        _cwd: &Path,
        _cmd: &[String],
        command: &mut Command,
    ) -> io::Result<Vec<String>> {
        let activity = &ctx.activity;
        let mut prefix = Vec::new();
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
            let cargo_home = project
                .subdir(Path::new(".tog/cargo-home"))?
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "held Cargo home disappeared")
                })?
                .current_name()?;
            prefix.push(cargo_home.join("bin").to_string_lossy().into_owned());
            prefix.push(rust_obj.join("bin").to_string_lossy().into_owned());
            command.env("CARGO_HOME", &cargo_home);
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

    fn formatter(&self) -> Option<&'static dyn Formatter> {
        Some(&Rustfmt)
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["rust", "rustfmt"]
    }
}

/// `tog fmt` for Rust: the rustfmt component the toolchain lock pins.
pub struct Rustfmt;

impl Formatter for Rustfmt {
    fn word(&self) -> &'static str {
        "rust"
    }

    fn preflight(&self, platform: Platform) -> io::Result<()> {
        // A platform with no pinned component is refused here, before
        // `Store::open` and before the Rust realization downloads ~105 MB of
        // toolchain.
        rustfmt::preflight_platform(platform)
    }

    fn check_project(&self, cwd: &Path) -> io::Result<()> {
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
    fn root(&self, _ctx: &Context, cwd: &Path, _toolchain: &Selected) -> io::Result<PathBuf> {
        inputs::locate_cargo_root(cwd)?.canonicalize()
    }

    /// Realize only the Rust toolchain and its paired rustfmt component, then
    /// format the Cargo workspace without resolving dependencies.
    fn run(
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
        //
        // The invocation directory and the workspace root are held open for
        // the whole run, and the sandbox binds the workspace through its
        // descriptor and starts cargo-fmt in the invocation directory it
        // holds (#612): a project renamed or replaced after this point is
        // not what gets formatted. Every path below is the canonical one
        // each was opened at, never canonicalized again.
        let invocation = ProjectRoot::open(cwd)
            .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", cwd.display())))?;
        let (_, workspace) = inputs::locate_held_cargo_root(&invocation)?;
        let workspace_root = workspace.path().to_path_buf();
        fmt_preflight(
            &invocation,
            &workspace,
            &crate::kernel::resolve::confine::signing_key_paths(),
        )?;
        let rust_object = cargo::realize_runtime(store, activity, platform, toolchain)?;
        let rustfmt_object =
            rustfmt::ensure_rustfmt(store, activity, platform, toolchain, &rust_object)?;
        // An older `tog fmt` wrote a `rustfmt` closure here; nothing reads
        // one any more, so a formatting run removes it (unless it is the
        // only closure of a registered project: see
        // `remove_legacy_record`). `--check` changes
        // no file: a CI check must not leave the checkout dirty.
        if !check {
            let key = crate::kernel::store::Store::canonical_root_key(&workspace_root);
            rustfmt::remove_legacy_record(&workspace, store.has_root_entry(&key)?)?;
        }
        let status = rustfmt::run_sandboxed(
            platform,
            &invocation,
            &workspace,
            &rust_object,
            &rustfmt_object,
            activity,
            check,
            args,
        )?;
        Ok(child_status_code(&status))
    }
}

/// What `tog fmt` refuses before anything runs, checked in the directories
/// it holds, never at the paths they were opened at: a workspace renamed
/// or replaced since is not what the sandbox mounts, so it is not what is
/// checked either (#612).
///
/// cargo fmt runs in the workspace itself (writable, the user's home out
/// of sight): a file there that is the signing key under another name (a
/// hard link) would be read as a manifest or a config and quoted in
/// cargo's parse error. The whole workspace is mounted, `target` included
/// (a config can be a symlink to `../target/key`), so the whole of it is
/// scanned, from the held descriptor. The formatter's output is relayed
/// with the key's secret replaced as well (`supervise::Relay`).
///
/// Then the configuration cargo-fmt's cargo reads, from the invocation
/// directory up to the workspace root (nothing above it is mounted): a
/// file there (or one it includes) that is the key, or a symlink out of
/// the workspace, is refused by name. These are read at the names the two
/// held directories have now, each checked against its descriptor.
fn fmt_preflight(
    invocation: &ProjectRoot,
    workspace: &ProjectRoot,
    keys: &[PathBuf],
) -> io::Result<()> {
    use crate::kernel::provider::cargo_door;
    use crate::kernel::resolve::confine;
    confine::refuse_key_links_in(workspace, &confine::key_ids(keys), &[])?;
    let workspace_now = workspace.current_name()?;
    let invocation_now = invocation.current_name()?;
    if !invocation_now.starts_with(&workspace_now) {
        return Err(io::Error::other(format!(
            "{} is no longer inside the workspace {}; run 'tog fmt' again",
            invocation.path().display(),
            workspace.path().display()
        )));
    }
    let bound = cargo_door::Bound::with_keys(&workspace_now, keys)?;
    for dir in invocation_now.ancestors() {
        if !dir.starts_with(&workspace_now) {
            break;
        }
        cargo_door::config_files(dir, &bound)?;
    }
    Ok(())
}

/// The files this ecosystem's toolchain version is read from, in its own
/// tools' precedence order ([`Tailor::toolchain_sources`]).
fn toolchain_rows(root: &ProjectRoot) -> io::Result<Vec<InputRow>> {
    crate::kernel::toolchain::input::rust_rows(root)
}

/// The selection request [`toolchain_rows`] state.
fn toolchain_request(rows: &[InputRow]) -> io::Result<Request> {
    use crate::kernel::toolchain::input::{RUST_TOOLCHAIN_PATH, RUST_TOOLCHAIN_REQUESTS};
    use crate::kernel::toolchain::invalid;
    use crate::kernel::toolchain::resolve::{exact_or_prefix, value, UPDATE_HINT};
    use crate::kernel::toolchain::Version;
    let mut request = Request::newest();
    let legacy = value(rows, "rust-toolchain", "toolchain.channel");
    let modern = value(rows, "rust-toolchain.toml", "toolchain.channel");
    if let (Some(a), Some(b)) = (legacy, modern) {
        if a != b {
            return Err(invalid(format!(
                "rust-toolchain says {a} and rust-toolchain.toml says {b}; make them agree, then {UPDATE_HINT}"
            )));
        }
    }
    // The lists are not part of the version request, but both files are
    // read and recorded, so two that ask for different components or
    // targets, or name different local trees, are the same conflict as two
    // channels. A local tree states no version: the tailor's external
    // selection answers for it.
    let present = |path: &str| {
        rows.iter()
            .any(|row| row.path.as_os_str() == path && row.sha256.is_some())
    };
    if present("rust-toolchain") && present("rust-toolchain.toml") {
        for (key, field) in RUST_TOOLCHAIN_REQUESTS
            .into_iter()
            .chain([RUST_TOOLCHAIN_PATH])
        {
            let a = value(rows, "rust-toolchain", field);
            let b = value(rows, "rust-toolchain.toml", field);
            if a != b {
                return Err(invalid(format!(
                    "rust-toolchain asks for {key} {} and rust-toolchain.toml asks for {}; \
                     make them agree, then {UPDATE_HINT}",
                    a.unwrap_or("none"),
                    b.unwrap_or("none")
                )));
            }
        }
    }
    if let Some(channel) = legacy.or(modern) {
        if channel != "stable" {
            let version = Version::parse(channel).map_err(|_| {
                invalid(format!(
                    "rust channel {channel} is not supported; use an exact version or stable"
                ))
            })?;
            request = request.with("rustc", exact_or_prefix(version));
        }
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::fmt_preflight;
    use crate::kernel::fsroot::ProjectRoot;
    use crate::kernel::testutil::TempDir;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    /// A workspace with a member, held open, then renamed away and a clean
    /// copy put at its old path: what `fmt_preflight` checks must be the
    /// held original, the one the sandbox mounts (#612).
    fn held_then_replaced(temp: &TempDir) -> (ProjectRoot, ProjectRoot, PathBuf, PathBuf) {
        let original = temp.0.join("ws");
        fs::create_dir_all(original.join("member")).unwrap();
        fs::write(original.join("Cargo.toml"), "[workspace]\n").unwrap();
        let invocation = ProjectRoot::open(&original.join("member")).unwrap();
        let workspace = ProjectRoot::open(&original).unwrap();
        let moved = temp.0.join("moved");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir_all(original.join("member")).unwrap();
        fs::write(original.join("Cargo.toml"), "[workspace]\n").unwrap();
        (invocation, workspace, original, moved)
    }

    #[test]
    fn fmt_checks_the_held_workspace_not_its_replacement() {
        let temp = TempDir::named("fmt-preflight");
        let key = temp.0.join("signing.key");
        fs::write(&key, b"ed25519:secret").unwrap();
        let keys = [key.clone()];

        // The held original carries a hard link to the key; the
        // replacement at the old path is clean.
        let (invocation, workspace, original, moved) = held_then_replaced(&temp);
        fs::create_dir_all(moved.join("target")).unwrap();
        fs::hard_link(&key, moved.join("target/k")).unwrap();
        let error = fmt_preflight(&invocation, &workspace, &keys).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("is the signing key"), "{error}");
        assert!(
            error
                .to_string()
                .contains(&original.join("target/k").display().to_string()),
            "{error}"
        );
        fs::remove_file(moved.join("target/k")).unwrap();

        // A config in the held member that leads out of the workspace.
        let outside = temp.0.join("outside.toml");
        fs::write(&outside, "").unwrap();
        fs::create_dir_all(moved.join("member/.cargo")).unwrap();
        std::os::unix::fs::symlink(&outside, moved.join("member/.cargo/config.toml")).unwrap();
        let error = fmt_preflight(&invocation, &workspace, &keys).unwrap_err();
        assert!(error.to_string().contains("outside"), "{error}");
        fs::remove_file(moved.join("member/.cargo/config.toml")).unwrap();

        // The held tree is clean now, and what sits at the old path is not
        // looked at: a key link there does not refuse the run.
        fs::create_dir_all(original.join("target")).unwrap();
        fs::hard_link(&key, original.join("target/k")).unwrap();
        fmt_preflight(&invocation, &workspace, &keys).unwrap();
    }

    #[test]
    fn fmt_refuses_an_invocation_moved_out_of_its_workspace() {
        let temp = TempDir::named("fmt-preflight-out");
        let (invocation, workspace, _, moved) = held_then_replaced(&temp);
        fs::rename(moved.join("member"), temp.0.join("elsewhere")).unwrap();
        let error = fmt_preflight(&invocation, &workspace, &[]).unwrap_err();
        assert!(
            error.to_string().contains("no longer inside the workspace"),
            "{error}"
        );
        assert!(Path::new(&temp.0.join("elsewhere")).is_dir());
    }
}
