//! Helpers shared by two or more commands (REFACTOR.md §4 Stage 2 step
//! 2): project-directory resolution, per-ecosystem input loaders, and the
//! Python planning stack. Stage 3 turns most of these into tailor methods.

use crate::comforter;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::store;
use crate::kernel::supervise;
use crate::kernel::types;
use crate::kernel::ui;
use crate::tailors::cargo;
use crate::tailors::go;
use crate::tailors::node;
use crate::tailors::node::lock_import;
use crate::tailors::python;
use crate::tailors::python::manifest;
use crate::tailors::python::pypi;
use crate::tailors::python::pyselect;
use std::io;
use std::path::Path;
use std::path::PathBuf;

pub(crate) const PLANNER_SCHEMA: &str = "python-planner/3";

pub(crate) fn planner_input_hash(
    platform: Platform,
    python_version: &str,
    text: &str,
    glibc: pypi::Glibc,
) -> String {
    use sha2::{Digest, Sha256};
    let glibc_input = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        format!("\0{}.{}", glibc.0, glibc.1)
    } else {
        String::new()
    };
    hex::encode(Sha256::digest(
        format!(
            "{PLANNER_SCHEMA}\x00{python_version}\x00{text}\x00{}{glibc_input}",
            platform.triple(),
        )
        .as_bytes(),
    ))
}

pub(crate) fn project_dir() -> PathBuf {
    std::env::current_dir().expect("cwd")
}

/// Implicit detection for sync/plan: cargo joins the party only when the
/// invocation dir is itself a Cargo package (workspace members included).
/// Without this gate, running blanket in any project nested under an
/// unrelated Cargo workspace would silently project into that parent tree.
pub(crate) fn is_cargo_here(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file()
}

pub(crate) struct CargoInputs {
    pub(crate) root: PathBuf,
    pub(crate) rust_obj: PathBuf,
    pub(crate) plan: cargo::CargoPlan,
    pub(crate) lock_digest: String,
}

/// Workspace rooting is delegated to the pinned Cargo itself
/// (`locate-project --workspace`): an ancestor-walk for Cargo.lock picks an
/// unrelated outer lock when independent packages nest (Sol review, repro'd).
pub(crate) fn locate_cargo_root(
    rust_obj: &Path,
    cwd: &Path,
    store: &store::Store,
) -> io::Result<PathBuf> {
    let mut command = std::process::Command::new(rust_obj.join("bin/cargo"));
    command
        .args([
            "locate-project",
            "--workspace",
            "--message-format",
            "plain",
            "--offline",
        ])
        .current_dir(cwd)
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    ui::trace_command(&command);
    let out = supervise::output_owned(&mut command, store)
        .map_err(|e| io::Error::new(e.kind(), format!("run store cargo locate-project: {e}")))?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let manifest = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    manifest
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("cargo locate-project returned no manifest path"))
}

pub(crate) fn load_cargo_inputs(
    platform: Platform,
    cwd: &Path,
    store: &store::Store,
) -> io::Result<CargoInputs> {
    let rust_version = cargo::resolve_toolchain(platform, cwd)?;
    let rust_obj = cargo::ensure_rust_for(store, platform, rust_version)?;
    let root = locate_cargo_root(&rust_obj, cwd, store)?;
    // Cargo is the one tailor whose registered root is not the directory
    // sync was run in: a member of a workspace sends its closure and its
    // record to the workspace root. The preflight checked the invocation
    // directory, so check the root as soon as it is known — before a lock,
    // a vendor object or a cargo-home lands in a workspace that cannot be
    // registered and so cannot be protected (A-R3 residual class).
    store::Store::check_registrable(&root)?;
    if !root.join("Cargo.lock").is_file() {
        ensure_cargo_lock(&root, &rust_obj, store)?;
    }
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))?;
    let plan = cargo::plan_cargo(&lock, rust_version)?;
    Ok(CargoInputs {
        root,
        rust_obj,
        plan,
        lock_digest: cargo::lock_digest(&lock),
    })
}

pub(crate) fn ensure_cargo_lock(
    root: &Path,
    rust_obj: &Path,
    store: &store::Store,
) -> io::Result<()> {
    eprintln!(
        "blanket: no Cargo.lock; generating it with the store Rust toolchain \
         (network allowed, unsandboxed)..."
    );
    let mut command = std::process::Command::new(rust_obj.join("bin/cargo"));
    command
        .arg("generate-lockfile")
        .current_dir(root)
        .env("CARGO_NET_OFFLINE", "false")
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    ui::trace_command(&command);
    let status = supervise::status_owned(&mut command, store).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "could not run store Cargo to generate Cargo.lock: {e}; \
                     use `blanket sync` after fixing the project or network"
            ),
        )
    })?;
    if !status.success() {
        return Err(io::Error::other(
            "store Cargo generate-lockfile failed; check the project manifest and network",
        ));
    }
    Ok(())
}

/// Plan from project inputs. Planning hits PyPI, so successful plans are
/// cached in .blanket/plan.json keyed by a hash of the inputs; an unchanged
/// lock replans offline and instantly.
/// Plan from project inputs, returning the interpreter selection that was
/// used. The manifest layer may only learn the constraint after a sandboxed
/// `setup.py egg_info`, so the selection is made here and handed back to the
/// caller: planning, realization and the closure all use this one value.
/// The Python plan, the interpreter selection it was made with, and the
/// project files it was computed from (recorded in the closure for status).
pub(crate) type PythonPlan = (
    types::Plan,
    pyselect::PythonSelection,
    Vec<comforter::InputRecord>,
);

/// Candidate input files for the status record: the manifest that won, the
/// interpreter request, and every lock blanket reads or writes.
pub(crate) fn python_input_records(
    dir: &Path,
    manifest: &manifest::Manifest,
) -> io::Result<Vec<comforter::InputRecord>> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    match &manifest.source_path {
        Some(path) => candidates.push(path.clone()),
        None => candidates.push(dir.join(&manifest.input)),
    }
    for extra in [
        ".python-version",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "requirements.lock.txt",
        "uv.lock",
        "poetry.lock",
        "pdm.lock",
    ] {
        candidates.push(dir.join(extra));
    }
    comforter::input_records(dir, &candidates)
}

pub(crate) fn read_plan(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
) -> io::Result<PythonPlan> {
    let mut manifest = manifest::discover(platform, dir)?;
    let mut selection = pyselect::select_python_with_inputs(platform, &manifest.python)?;
    if manifest.requires_setup() {
        let dynamic_dependencies = manifest.dynamic_dependencies;
        const MAX_SETUP_PROBES: usize = 3;
        let mut selection_history = vec![selection.pin.version.to_string()];
        let mut stabilized = false;
        for _ in 0..MAX_SETUP_PROBES {
            let probed_version = selection.pin.version;
            if let Err(error) = manifest.prepare_setup(platform, dir, store, probed_version) {
                if !dynamic_dependencies {
                    return Err(error);
                }
                let Some(mut fallback) = manifest::dynamic_requirements_fallback(dir)? else {
                    return Err(error);
                };
                eprintln!(
                    "blanket: setup.py metadata probe failed; using the requirements directory convention: {error}"
                );
                fallback.python = manifest.python.clone();
                manifest = fallback;
                selection = pyselect::select_python_with_inputs(platform, &manifest.python)?;
                stabilized = true;
                break;
            }

            let next = pyselect::select_python_with_inputs(platform, &manifest.python)?;
            if next.pin.version == probed_version {
                selection = next;
                stabilized = true;
                break;
            }
            selection = next;
            selection_history.push(selection.pin.version.to_string());
        }
        if !stabilized {
            return Err(io::Error::other(format!(
                "setup.py metadata probe and Python selection did not stabilize after {MAX_SETUP_PROBES} probes (oscillation: {})",
                selection_history.join(" -> "),
            )));
        }
    }
    if manifest.is_empty() && !manifest.provenance.contains("empty manifest") {
        manifest.provenance.push_str(" (empty manifest)");
    }
    eprintln!("blanket: python inputs: {}", manifest.provenance);
    let input = manifest.input.clone();
    let source = manifest.requirements_text();
    let resolver_source = manifest.resolver_text();
    if !input.starts_with("requirements") {
        record_skippable_specs(&input, &source)?;
    }
    selection.emit_warnings();
    let pin = selection.pin;

    // A found manifest may intentionally declare no dependencies. Keep the
    // interpreter-only plan on the normal realization/projection path, but do
    // not ask uv to compile an empty setup.cfg or requirements file.
    let inputs = python_input_records(dir, &manifest)?;
    if manifest.is_empty() {
        return Ok((
            types::Plan {
                ecosystem: "python".into(),
                python_version: pin.version.into(),
                packages: Vec::new(),
            },
            selection,
            inputs,
        ));
    }

    if let Some(packages) = manifest.locked_packages {
        return Ok((
            types::Plan {
                ecosystem: "python".into(),
                python_version: pin.version.into(),
                packages,
            },
            selection,
            inputs,
        ));
    }

    let generated_input = if input.starts_with("requirements") && resolver_source == source {
        None
    } else if is_fully_pinned(&source) && resolver_source == source {
        None
    } else {
        let path = dir.join(".blanket/manifest-requirements.txt");
        std::fs::create_dir_all(dir.join(".blanket"))?;
        let mut text = if manifest.has_constraints() {
            let constraints = dir.join(".blanket/manifest-constraints.txt");
            std::fs::write(&constraints, manifest.constraints_text())?;
            format!(
                "{}-c {}\n",
                manifest.normalized_requirements_text(),
                constraints.display()
            )
        } else {
            resolver_source.clone()
        };
        if text.is_empty() {
            text.push('\n');
        }
        std::fs::write(&path, text)?;
        Some(path)
    };
    let compile_path = if generated_input.is_some() {
        generated_input.as_deref()
    } else {
        manifest.source_path.as_deref()
    };
    let text = if is_fully_pinned(&source) {
        match pypi::parse_requirements(&source) {
            Ok(_) => source,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(e),
            Err(e) => {
                eprintln!(
                    "blanket: requirements.txt is pinned but not directly \
                     consumable ({e}); re-locking for this platform with uv..."
                );
                locked_requirements(
                    platform,
                    dir,
                    store,
                    &input,
                    &resolver_source,
                    pin.version,
                    compile_path,
                )?
            }
        }
    } else {
        locked_requirements(
            platform,
            dir,
            store,
            &input,
            &resolver_source,
            pin.version,
            compile_path,
        )?
    };

    // These are project-local .blanket caches, not store identities; one
    // re-plan after moving a project between platforms is acceptable.
    let glibc = if matches!(platform, Platform::X86_64UnknownLinuxGnu) {
        pypi::host_glibc()?
    } else {
        pypi::Glibc(0, 0)
    };
    // The lock may have just been (re)written above: hash it now.
    let inputs = python_input_records(dir, &manifest)?;
    let input_hash = planner_input_hash(platform, pin.version, &text, glibc);
    let cache_path = dir.join(".blanket/plan.json");
    if let Ok(cached) = std::fs::read_to_string(&cache_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&cached) {
            if v["input_hash"] == input_hash.as_str() {
                if let Ok(plan) = serde_json::from_value::<types::Plan>(v["plan"].clone()) {
                    return Ok((plan, selection, inputs));
                }
            }
        }
    }

    let plan = pypi::plan_python(platform, &text, pin.version)?;
    std::fs::create_dir_all(dir.join(".blanket"))?;
    std::fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "input_hash": input_hash,
            "plan": plan,
        }))?,
    )?;
    Ok((plan, selection, inputs))
}

pub(crate) fn record_skippable_specs(input: &str, source: &str) -> io::Result<()> {
    record_skippable_specs_with(input, source, policy::record)
}

pub(crate) fn record_skippable_specs_with<F>(
    _input: &str,
    source: &str,
    mut record: F,
) -> io::Result<()>
where
    F: FnMut(&str, &str, &str) -> io::Result<()>,
{
    let specs: Vec<String> = pypi::skippable_specs(source);
    for spec in specs {
        record(
            policy::REQUIREMENT_SKIPPED,
            &spec,
            "project-local or direct reference is not a locked registry package",
        )?;
    }
    for option in pypi::unattested_index_options(source) {
        record(
            policy::UNATTESTED_INDEX,
            &option,
            "requirements index/find-links options are recorded but never followed",
        )?;
    }
    Ok(())
}

/// Every non-comment logical line (after backslash continuations) carries a
/// --hash= option. That is the shape `uv pip compile --generate-hashes`
/// emits and the only shape the planner accepts directly.
pub(crate) fn is_fully_pinned(text: &str) -> bool {
    let mut logical = String::new();
    let mut any = false;
    for raw in text.lines().chain(std::iter::once("")) {
        if let Some(stripped) = raw.strip_suffix('\\') {
            logical.push_str(stripped);
            continue;
        }
        logical.push_str(raw);
        let line = logical.trim();
        let line = match line.find(" #") {
            Some(i) => line[..i].trim(),
            None => line,
        };
        if !line.is_empty() && !line.starts_with('#') {
            any = true;
            let spec = line
                .split_whitespace()
                .filter(|token| !token.starts_with("--hash="))
                .collect::<Vec<_>>()
                .join(" ");
            if pypi::is_skippable_spec(&spec) {
                logical.clear();
                continue;
            }
            if !line.contains("--hash=") {
                return false;
            }
        }
        logical.clear();
    }
    any
}

/// Resolve ranged requirements to a hash-pinned lock via uv, cached in
/// requirements.lock.txt and regenerated when the source input changes.
pub(crate) fn locked_requirements(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
    input: &str,
    source: &str,
    pyver: &str,
    compile_path: Option<&Path>,
) -> io::Result<String> {
    let lock_path = dir.join("requirements.lock.txt");
    let stamp_path = dir.join(".blanket/lock-source.hash");
    let source_hash = if compile_path.is_some_and(|path| {
        !path
            .components()
            .any(|component| component.as_os_str() == ".blanket")
    }) {
        let path = compile_path.expect("checked above");
        let tree_hash = manifest::requirements_tree_hash(path)?;
        lock_source_hash(pyver, &format!("{source}\0{tree_hash}"))
    } else {
        lock_source_hash(pyver, source)
    };
    if let (Ok(stamp), Ok(lock)) = (
        std::fs::read_to_string(&stamp_path),
        std::fs::read_to_string(&lock_path),
    ) {
        if cached_lock_matches(&stamp, &lock, &source_hash) {
            return Ok(lock);
        }
    }
    eprintln!("blanket: {input} is not hash-pinned; resolving with the store uv...");
    // Store-pinned uv, not host uv: a bare machine needs only blanket.
    let uv = python::ensure_uv_for(store, platform)?.join("uv");
    let compile_input = compile_path.and_then(|path| path.to_str()).unwrap_or(input);
    let mut command = std::process::Command::new(&uv);
    command.args(["pip", "compile", compile_input, "--generate-hashes"]);
    if !ui::verbose() {
        command.arg("--quiet");
    }
    command
        .args(["--python-version", pyver])
        // Manifest index directives and ambient pip/uv index variables are
        // never trusted. Resolution is explicitly public PyPI only.
        .args(["--index-url", "https://pypi.org/simple"])
        .args(["-o", "requirements.lock.txt"])
        .current_dir(dir)
        .env_remove("UV_INDEX_URL")
        .env_remove("UV_DEFAULT_INDEX")
        .env_remove("UV_EXTRA_INDEX_URL")
        .env_remove("PIP_INDEX_URL")
        .env_remove("PIP_EXTRA_INDEX_URL")
        .env_remove("PIP_TRUSTED_HOST")
        .env_remove("PIP_FIND_LINKS");
    ui::trace_command(&command);
    let status = supervise::status_owned(&mut command, store)
        .map_err(|e| io::Error::new(e.kind(), format!("run store uv ({}): {e}", uv.display())))?;
    if !status.success() {
        return Err(io::Error::other("uv pip compile failed"));
    }
    std::fs::create_dir_all(dir.join(".blanket"))?;
    std::fs::write(&stamp_path, &source_hash)?;
    std::fs::read_to_string(&lock_path)
}

pub(crate) fn cached_lock_matches(stamp: &str, lock: &str, source_hash: &str) -> bool {
    !lock.is_empty() && stamp.trim() == source_hash
}

/// Stamp deciding whether `uv pip compile` must re-run. Deliberately NOT
/// platform-qualified: `.blanket/lock-source.hash` is per-machine state and
/// the format is byte-identical to the pre-port one, so existing darwin
/// stamps stay valid after the Linux port (platform lives in
/// `planner_input_hash`, which keys the plan cache).
pub(crate) fn lock_source_hash(pyver: &str, source: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{pyver}\x00{source}").as_bytes()))
}

pub(crate) fn no_inputs() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "no_manifest: nothing to sync here (looked for requirements.lock.txt, requirements.txt, pyproject.toml ([project], [tool.poetry], [dependency-groups]), setup.cfg, setup.py, requirements/{common.txt,base.txt,requirements.in,cpu.txt,cuda.txt,rocm.txt,xpu.txt}, package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.toml, go.mod, Gemfile, mix.exs, and .csproj/packages.lock.json)",
    )
}

pub(crate) fn has_python_input(dir: &Path) -> io::Result<bool> {
    manifest::has_manifest(dir)
}

pub(crate) struct GoInputs {
    pub(crate) go_obj: PathBuf,
    pub(crate) plan: go::GoPlan,
    pub(crate) gosum_sha256: String,
}

pub(crate) fn load_go_inputs(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
) -> io::Result<GoInputs> {
    let go_version = go::resolve_project_toolchain(platform, dir)?;
    let go_obj = go::ensure_go_for(store, platform, go_version)?;
    let plan = go::plan_go(store, platform, dir, &go_obj)?;
    if plan.go_version != go_version {
        return Err(io::Error::other(format!(
            "go.mod selected Go {go_version}, but planning selected {}; re-run blanket sync after keeping go.mod unchanged",
            plan.go_version
        )));
    }
    let gosum = std::fs::read_to_string(dir.join("go.sum")).unwrap_or_default();
    use sha2::{Digest, Sha256};
    Ok(GoInputs {
        go_obj,
        plan,
        gosum_sha256: hex::encode(Sha256::digest(gosum.as_bytes())),
    })
}

/// A package.json without a package-lock.json (bun/yarn/pnpm projects):
/// delegate lock generation to npm, mirroring the uv flow for Python.
/// Resolution is the ecosystem's job; realization is blanket's.
pub(crate) fn ensure_npm_lock(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
) -> io::Result<()> {
    if !dir.join("package.json").exists()
        || dir.join("package-lock.json").exists()
        || dir.join("pnpm-lock.yaml").exists()
        || dir.join("yarn.lock").exists()
    {
        return Ok(());
    }
    for other in ["bun.lock", "bun.lockb"] {
        if dir.join(other).exists() {
            eprintln!(
                "blanket: note: {other} found; generating package-lock.json via npm \
                 (versions resolve fresh — they may differ from {other})"
            );
            break;
        }
    }
    eprintln!("blanket: no package-lock.json; resolving with the store npm...");
    // Store node's bundled npm, not host npm: a bare machine needs only
    // blanket. npm-cli's shebang is `env node`, so the store bin leads PATH.
    let node = node::ensure_node_for(store, platform)?;
    let path = format!(
        "{}:{}",
        node.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = std::process::Command::new(node.join("bin/npm"));
    command.args(["install", "--package-lock-only", "--ignore-scripts"]);
    if !ui::verbose() {
        command.arg("--silent");
    }
    command.current_dir(dir).env("PATH", path);
    ui::trace_command(&command);
    let status = supervise::status_owned(&mut command, store).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("run store npm ({}/bin/npm): {e}", node.display()),
        )
    })?;
    if !status.success() {
        return Err(io::Error::other("npm install --package-lock-only failed"));
    }
    Ok(())
}

pub(crate) fn load_npm_plan(platform: Platform, dir: &Path) -> io::Result<Option<node::NpmPlan>> {
    if dir.join("package-lock.json").is_file() {
        return Ok(Some(node::plan_npm(
            platform,
            &std::fs::read_to_string(dir.join("package-lock.json"))?,
        )?));
    }
    if dir.join("pnpm-lock.yaml").is_file() {
        return Ok(Some(lock_import::plan_pnpm(
            platform,
            &std::fs::read_to_string(dir.join("pnpm-lock.yaml"))?,
            dir,
        )?));
    }
    if dir.join("yarn.lock").is_file() {
        let package = std::fs::read_to_string(dir.join("package.json"))?;
        return Ok(Some(lock_import::plan_yarn(
            platform,
            &std::fs::read_to_string(dir.join("yarn.lock"))?,
            &package,
            dir,
        )?));
    }
    Ok(None)
}

/// Nearest ancestor that is a blanket projection: every tailor writes
/// `.blanket/closures/<eco>.json`, so that directory is the proof. A plain
/// `node_modules` or `.venv` in a subdirectory (a docs site, a vendored
/// tool) is NOT a projection and must not stop the walk-up (Sol, task
/// runner review).
pub(crate) fn projected_root(cwd: &Path) -> PathBuf {
    cwd.ancestors()
        .find(|d| d.join(".blanket/closures").is_dir())
        .unwrap_or(cwd)
        .to_path_buf()
}

pub(crate) fn child_status_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
pub(crate) struct TempDir(pub(crate) PathBuf);

#[cfg(test)]
impl TempDir {
    pub(crate) fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blanket-main-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_participation_requires_local_manifest() {
        let temp = TempDir::new();
        let nested = temp.0.join("outer/inner");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(temp.0.join("outer/Cargo.toml"), "[package]\nname=\"o\"\n").unwrap();
        // sync/plan only join in where the invocation dir itself is a package
        assert!(is_cargo_here(&temp.0.join("outer")));
        assert!(!is_cargo_here(&nested));
        std::fs::write(nested.join("Cargo.lock"), "version = 4\n").unwrap();
        assert!(is_cargo_here(&nested));
    }

    #[test]
    fn projected_root_skips_plain_node_modules() {
        let t = TempDir::new();
        let root = t.0.join("proj");
        std::fs::create_dir_all(root.join(".blanket/closures")).unwrap();
        let sub = root.join("docs");
        std::fs::create_dir_all(sub.join("node_modules")).unwrap();
        assert_eq!(projected_root(&sub), root);
        assert_eq!(projected_root(&root), root);
        let outside = t.0.join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        assert_eq!(projected_root(&outside), outside);
    }

    #[test]
    fn cache_key_builders_track_independent_inputs() {
        let source = "six==1.17.0\n";
        let darwin_plan = planner_input_hash(
            Platform::Aarch64AppleDarwin,
            "3.12.14",
            source,
            pypi::Glibc(0, 0),
        );
        let linux_plan = planner_input_hash(
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            source,
            pypi::Glibc(2, 43),
        );
        let linux_changed_glibc = planner_input_hash(
            Platform::X86_64UnknownLinuxGnu,
            "3.12.14",
            source,
            pypi::Glibc(2, 42),
        );
        let changed_plan = planner_input_hash(
            Platform::Aarch64AppleDarwin,
            "3.12.14",
            "six==1.17.0\n# changed",
            pypi::Glibc(0, 0),
        );
        assert_ne!(darwin_plan, changed_plan); // source only
        assert_ne!(darwin_plan, linux_plan); // platform only
        assert_ne!(linux_plan, linux_changed_glibc); // host glibc only
        assert_eq!(
            darwin_plan,
            planner_input_hash(
                Platform::Aarch64AppleDarwin,
                "3.12.14",
                source,
                pypi::Glibc(2, 43),
            )
        ); // neither
        assert_eq!(
            darwin_plan,
            "dc181496c6681389a89b3191dba44abdfe8efef8044e540777e7b62c91166411"
        );

        // The lock-source stamp is platform-free on purpose (see its doc):
        // this is main's exact format, so pre-port darwin stamps stay valid.
        let lock = lock_source_hash("3.12", source);
        let changed_lock = lock_source_hash("3.12", "six==1.17.0\n# changed");
        assert_ne!(lock, changed_lock); // source only
        assert_eq!(lock, lock_source_hash("3.12", source)); // same input
        assert!(cached_lock_matches(&lock, "six==1.17.0\n", &lock));
        assert!(!cached_lock_matches(&changed_lock, "six==1.17.0\n", &lock));
        assert!(!cached_lock_matches(&lock, "", &lock));
        {
            use sha2::{Digest, Sha256};
            assert_eq!(
                lock,
                hex::encode(Sha256::digest(format!("3.12\x00{source}").as_bytes()))
            );
        }
    }

    #[test]
    fn unconstrained_python_keeps_default_and_existing_cache_inputs() {
        let selection = pyselect::select_python(Platform::Aarch64AppleDarwin, &[]).unwrap();
        assert_eq!(selection.pin.version, "3.12.14");
        let source = "six==1.17.0\n";
        assert_eq!(
            planner_input_hash(
                Platform::Aarch64AppleDarwin,
                selection.pin.version,
                source,
                pypi::Glibc(0, 0),
            ),
            "dc181496c6681389a89b3191dba44abdfe8efef8044e540777e7b62c91166411"
        );
        assert_eq!(
            lock_source_hash(selection.pin.version, source),
            "2036e745694799536bfd9bee5ce7f4fbf3a1f621d96e8d54e632e4d0c2334c67"
        );
    }

    #[test]
    fn plan_skipped_requirement_is_strict_or_recorded_once() {
        let source = ".\n";
        let strict = policy::Policy {
            strict: true,
            ..policy::Policy::default()
        };
        let error =
            record_skippable_specs_with("requirements.txt", source, |kind, subject, detail| {
                policy::record_with(&strict, kind, subject, detail)
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let mut recorded = Vec::new();
        record_skippable_specs_with("requirements.txt", source, |kind, subject, detail| {
            recorded.push((kind.to_string(), subject.to_string(), detail.to_string()));
            Ok(())
        })
        .unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(pypi::parse_requirements(source).unwrap().is_empty());
    }
}
