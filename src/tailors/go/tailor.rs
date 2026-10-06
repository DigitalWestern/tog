//! The Go tailor's `Tailor` implementation: what `sync`, `plan`, `build`,
//! `run`, `ls`, `status`, `doctor`, and `sbom` do for a Go module.

use crate::comforter;
use crate::comforter::status::{lock_state, object_liveness_state, string, State};
use crate::kernel::context::Context;
use crate::kernel::cyclonedx::{
    component, list, purl_encode, purl_encode_path, push_hash, push_property, required,
    toolchain_component, version_of,
};
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::objmeta::ObjectKind;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DoorKind, ResolutionDoor};
use crate::kernel::toolchain::input::{InputRow, Sources};
use crate::kernel::toolchain::Request;
use crate::kernel::toolchain::{Catalog, Selected};
use crate::kernel::ui;
use crate::tailors::go::{self as go, inputs};
use crate::tailors::{
    ClosureListing, DoctorCheck, FileRunner, LoneFile, PackageRow, SourceFile, SyncRequest, Tailor,
};
use serde_json::Value;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Go;

/// What `sync` and `build` share: plan the module, realize its modcache,
/// and project the closure through the descriptor the command holds.
/// Returns the Go runtime object and the modcache object.
fn realize_and_project(
    ctx: &Context,
    project: &ProjectRoot,
    toolchain: &Selected,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<(PathBuf, PathBuf)> {
    let (activity, platform, store) = (&ctx.activity, ctx.platform, &ctx.store);
    let inputs = inputs::load_go_inputs(
        project,
        toolchain,
        &mut ResolutionDoor::open(store, activity, platform, DoorKind::Planner, attribution)?,
    )?;
    let modcache = go::realize_modcache(
        store,
        activity,
        platform,
        toolchain,
        &inputs.plan,
        &inputs.go_obj,
    )?;
    go::project_go_env(
        activity,
        project,
        &inputs.go_obj,
        &modcache,
        &inputs.plan,
        &inputs.gosum_sha256,
        &inputs.resolution_basis,
        toolchain,
        &inputs.ledgers,
        attribution,
    )?;
    Ok((inputs.go_obj, modcache))
}

impl Tailor for Go {
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
        door: &mut crate::kernel::resolve::ResolutionDoor<'_>,
    ) -> io::Result<crate::tailors::EditOutcome> {
        super::edit::edit_manifest(edit, door)
    }

    fn id(&self) -> &'static str {
        "go"
    }

    fn detect(&self, project: &ProjectRoot) -> io::Result<bool> {
        Ok(project.is_input_file(Path::new("go.mod")))
    }

    fn toolchain_sources(&self) -> Sources {
        Sources {
            discover: toolchain_rows,
            request: toolchain_request,
        }
    }

    fn input_files(&self) -> &'static str {
        "go.mod"
    }

    fn source_files(&self) -> &'static [SourceFile] {
        &[SourceFile {
            extension: "go",
            runner: FileRunner::Command(&["go", "run"]),
        }]
    }

    fn preflight(&self, platform: Platform, _project: &ProjectRoot) -> io::Result<()> {
        go::preflight_platform(platform)
    }

    fn prepare(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<()> {
        let go_obj = go::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        go::tidy_project(door, project, &go_obj, go::go_tool(toolchain)?)
    }

    fn plan(
        &self,
        _ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<Option<String>> {
        let inputs = inputs::load_go_inputs(project, toolchain, door)?;
        Ok(Some(serde_json::to_string_pretty(&inputs.plan)?))
    }

    fn sync(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        request: &SyncRequest,
        attribution: &mut crate::kernel::policy::Attribution,
    ) -> io::Result<bool> {
        let (_, modcache) = realize_and_project(ctx, project, request.toolchain, attribution)?;
        ui::synced("go modcache", &modcache);
        Ok(true)
    }

    /// go.mod and go.sum: what `go mod tidy` and `go get` write. Go reads no
    /// other resolution input: `GOWORK=off` and `GOENV=off` are forced,
    /// workspaces and local replaces are refused, and module sources come
    /// only from the proxy.
    fn resolution_outputs(&self, _project: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
        Ok(vec![PathBuf::from("go.mod"), PathBuf::from("go.sum")])
    }

    fn attest_lock(
        &self,
        ctx: &Context,
        project: &ProjectRoot,
        toolchain: &Selected,
        _host: &dyn crate::tailors::EditHost,
        door: &mut ResolutionDoor<'_>,
    ) -> io::Result<(crate::kernel::resolve::record::ResolutionRecord, Vec<u8>)> {
        let go_obj = go::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        go::attest_project(door, project, &go_obj, go::go_tool(toolchain)?)
    }

    fn builds(&self) -> bool {
        true
    }

    fn build_present(&self, cwd: &Path) -> io::Result<bool> {
        Ok(cwd.ancestors().any(|d| d.join("go.mod").is_file()))
    }

    fn build_root(&self, cwd: &Path) -> io::Result<PathBuf> {
        Ok(cwd
            .ancestors()
            .find(|dir| dir.join("go.mod").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no go.mod found from here upward")
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
        let (go_obj, modcache) = realize_and_project(ctx, &project, toolchain, attribution)?;
        go::build_sandboxed(
            ctx.platform,
            &ctx.activity,
            &project,
            &go_obj,
            &modcache,
            args,
        )
    }

    /// `go run` on a lone file, outside any module: the standard library
    /// only, since nothing locks a module to download (`GOPROXY=off`), and
    /// never another toolchain (`GOTOOLCHAIN=local`).
    fn lone_file(
        &self,
        ctx: &Context,
        toolchain: &Selected,
        _extension: &str,
    ) -> io::Result<Option<LoneFile>> {
        let runtime = go::realize_runtime(&ctx.store, &ctx.activity, ctx.platform, toolchain)?;
        let mut lone = LoneFile::in_bin(&runtime, "go");
        lone.program.push("run".into());
        lone.env = vec![
            ("GOTOOLCHAIN", "local".into()),
            ("GOROOT", runtime.display().to_string()),
            ("GOENV", "off".into()),
            ("GOWORK", "off".into()),
            ("GOFLAGS", String::new()),
            ("GOPROXY", "off".into()),
            ("GOSUMDB", "off".into()),
        ];
        Ok(Some(lone))
    }

    fn runtime_programs(&self) -> &'static [&'static str] {
        &["go"]
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
        if let Some(closure) = comforter::read_closure_if_present(project, "go")? {
            let go_obj =
                comforter::closure_object(&ctx.store, activity, &closure, "go_object", "bin/go")?;
            let modcache =
                comforter::closure_object(&ctx.store, activity, &closure, "modcache_object", "")?;
            prefix.push(go_obj.join("bin").to_string_lossy().into_owned());
            for (k, v) in go::go_env(&go_obj, &modcache, true) {
                if v.is_empty() {
                    command.env_remove(&k);
                } else {
                    command.env(&k, &v);
                }
            }
        }
        Ok(prefix)
    }

    fn toolchain_catalog(&self) -> io::Result<Catalog> {
        go::toolchain_catalog()
    }

    fn listing(&self, _ecosystem: &str, body: &Value) -> ClosureListing {
        let plan = &body["plan"];
        let empty = Vec::new();
        let mut out = ClosureListing::default();
        out.toolchain
            .push(("go".into(), string(&plan["go_version"])));
        for package in plan["modules"].as_array().unwrap_or(&empty) {
            out.packages.push(PackageRow {
                name: string(&package["path"]),
                version: string(&package["version"]),
                detail: String::new(),
            });
        }
        out
    }

    fn closure_state(
        &self,
        platform: Platform,
        project: &ProjectRoot,
        _ecosystem: &str,
        body: &Value,
    ) -> io::Result<State> {
        go_status(platform, project, body)
    }

    fn doctor(&self, platform: Platform, project: &ProjectRoot) -> Vec<DoctorCheck> {
        let mut checks = Vec::new();
        if project.is_input_file(Path::new("go.mod")) {
            match go::project_go_version(platform, project) {
                Ok(version) => checks.push(DoctorCheck {
                    name: "go-toolchain",
                    ok: true,
                    detail: format!("{version} selected for this project"),
                }),
                Err(error) => checks.push(DoctorCheck {
                    name: "go-toolchain",
                    ok: false,
                    detail: format!("cannot select a realizable Go toolchain: {error}"),
                }),
            }
        }
        checks
    }

    fn sbom_components(&self, eco: &str, body: &Value, out: &mut Vec<Value>) -> io::Result<()> {
        let plan = body.get("plan").unwrap_or(body);
        for p in list(eco, plan, "modules")? {
            let (path, ver) = (required(eco, &p, "path")?, required(eco, &p, "version")?);
            let mut c = component(
                &path,
                &ver,
                format!(
                    "pkg:golang/{}@{}",
                    purl_encode_path(&path),
                    purl_encode(&ver)
                ),
                eco,
            );
            push_hash(&mut c, "SHA-256", &required(eco, &p, "zip_sha256")?);
            push_property(&mut c, "tog:go:h1", &required(eco, &p, "h1")?);
            out.push(c);
        }
        out.push(toolchain_component(
            body,
            "go_object",
            "go",
            &version_of(eco, plan, "go_version")?,
        )?);
        Ok(())
    }

    fn object_kinds(&self) -> &'static [ObjectKind] {
        super::objects::KINDS
    }

    fn toolchain_kinds(&self) -> &'static [&'static str] {
        &["go"]
    }
}

/// Compare the selected Go version in go.mod with the one recorded in the
/// closure. This is read-only: status must never realize a toolchain or touch
/// the network just to detect a stale selection.
fn go_status(platform: Platform, project: &ProjectRoot, body: &Value) -> io::Result<State> {
    if let Some(state) = object_liveness_state(body, &["go_object", "modcache_object"]) {
        return Ok(state);
    }

    let mut changed = Vec::new();
    let recorded_version = string(&body["plan"]["go_version"]);
    if !recorded_version.is_empty() {
        match project.input_entry(Path::new("go.mod"))? {
            Entry::Absent => changed.push("go.mod (removed)".to_string()),
            _ => match go::project_go_version(platform, project) {
                Ok(selected) if selected == recorded_version => {}
                Ok(_) => changed.push("go.mod".to_string()),
                Err(_) => changed.push("go.mod (Go toolchain selection unavailable)".to_string()),
            },
        }
    }

    let lock_state = lock_state(project, "go.sum", &string(&body["go_sum_sha256"]))?;
    match lock_state {
        State::Changed(files) => changed.extend(files),
        State::Unchecked(reason) if changed.is_empty() => {
            if recorded_version.is_empty() {
                return Ok(State::Unchecked(format!(
                    "{reason}; recorded Go version is missing; run 'tog' once to record the selected toolchain"
                )));
            }
            return Ok(State::Unchecked(reason));
        }
        State::Synced | State::Unchecked(_) => {}
        _ => unreachable!("go.sum lock_state has no projection or platform state"),
    }
    if !changed.is_empty() {
        return Ok(State::Changed(changed));
    }
    if recorded_version.is_empty() {
        return Ok(State::Unchecked(
            "recorded Go version is missing; run 'tog' once to record the selected toolchain"
                .into(),
        ));
    }
    Ok(State::Synced)
}

/// The files this ecosystem's toolchain version is read from, in its own
/// tools' precedence order ([`Tailor::toolchain_sources`]).
fn toolchain_rows(root: &ProjectRoot) -> io::Result<Vec<InputRow>> {
    use crate::kernel::toolchain::input::{read_go_mod, read_go_mod_toolchain, row_for};
    Ok(vec![
        row_for(root, "go.mod", "go", read_go_mod)?,
        row_for(root, "go.mod", "toolchain", read_go_mod_toolchain)?,
    ])
}

/// The selection request [`toolchain_rows`] state.
fn toolchain_request(rows: &[InputRow]) -> io::Result<Request> {
    use crate::kernel::toolchain::invalid;
    use crate::kernel::toolchain::resolve::{parse_version, value, UPDATE_HINT};
    use crate::kernel::toolchain::select::{Op, Specifier};
    use crate::kernel::toolchain::VersionRequest;
    let mut request = Request::newest();
    let minimum = match value(rows, "go.mod", "go") {
        Some(text) => Some(parse_version("go.mod go directive", text)?),
        None => None,
    };
    match value(rows, "go.mod", "toolchain") {
        Some(text) => {
            let exact = parse_version("go.mod toolchain directive", text)?;
            if let Some(minimum) = &minimum {
                if &exact < minimum {
                    return Err(invalid(format!(
                        "go.mod: toolchain go{exact} does not satisfy the go {minimum} minimum; {UPDATE_HINT}"
                    )));
                }
            }
            request = request.with("go", VersionRequest::Exact(exact));
        }
        None => {
            if let Some(minimum) = minimum {
                request = request.with(
                    "go",
                    VersionRequest::Specifiers(vec![Specifier::new(Op::Ge, minimum)
                        .map_err(|error| invalid(format!("go.mod: {error}")))?]),
                );
            }
        }
    }
    Ok(request)
}
