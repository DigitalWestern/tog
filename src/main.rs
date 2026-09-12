use blanket::{
    activity::ActivityMode, audit, cargo, cli, deps, dotnet, elixir, gc, golang, inspect, manifest,
    npm, npm_lock_import, platform::Platform, policy, project, pypi, pyselect, python, ruby,
    rustfmt, sbom, store, supervise, types, ui, xrun,
};

use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;

const PLANNER_SCHEMA: &str = "python-planner/3";

fn planner_input_hash(
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

/// What argv asked for, once the grammar has had its say.
enum Pending {
    Command(cli::Command),
    /// Bare `blanket`: sync inside a project, usage outside.
    Implicit,
    /// An unknown first word: a package.json script if one matches.
    Script {
        name: String,
        args: Vec<String>,
        message: String,
    },
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (options, pending) = match cli::parse(&args) {
        Ok(cli::Parsed::Run(invocation)) => {
            (invocation.options, Pending::Command(invocation.command))
        }
        Ok(cli::Parsed::Print(text)) => {
            print!("{text}");
            exit(0);
        }
        Ok(cli::Parsed::Implicit(options)) => (options, Pending::Implicit),
        Ok(cli::Parsed::Script {
            options,
            name,
            args,
            message,
        }) => (
            options,
            Pending::Script {
                name,
                args,
                message,
            },
        ),
        Err(error) => {
            eprint!("{}", error.render());
            exit(cli::EXIT_USAGE);
        }
    };
    if let Err(error) = ui::init(options.quiet, options.verbose, options.no_color) {
        ui::error(&format!("cannot set up output: {error}"));
        exit(cli::EXIT_FAILURE);
    }
    if let Some(dir) = &options.directory {
        if let Err(error) = std::env::set_current_dir(dir) {
            ui::error(&format!(
                "cannot change directory to {}: {error}",
                dir.display()
            ));
            exit(cli::EXIT_FAILURE);
        }
        ui::trace(&format!("working directory: {}", dir.display()));
    }
    let command = match resolve(pending) {
        Ok(command) => command,
        Err(error) => {
            ui::error(&error.to_string());
            exit(cli::EXIT_FAILURE);
        }
    };
    let code = match dispatch(command) {
        Ok(code) => code,
        Err(error) => {
            ui::error(&error.to_string());
            cli::EXIT_FAILURE
        }
    };
    exit(code);
}

/// CLI.md 2.1 and 2.2: a bare `blanket` inside a project is `sync`; an
/// unknown first word that names a package.json script runs it. Anything
/// else is the usage error the grammar already prepared (exit 2).
fn resolve(pending: Pending) -> io::Result<cli::Command> {
    match pending {
        Pending::Command(command) => Ok(command),
        Pending::Implicit => {
            let cwd = project_dir();
            if !inspect::detected(&cwd)?.is_empty() {
                ui::trace("no command given inside a project: running sync");
                return Ok(cli::Command::Sync {
                    fresh: false,
                    strict: false,
                });
            }
            eprint!(
                "blanket: no project in {}: nothing to sync here.\n\n{}",
                cwd.display(),
                cli::usage()
            );
            exit(cli::EXIT_USAGE);
        }
        Pending::Script {
            name,
            args,
            message,
        } => {
            let cwd = project_dir();
            let root = projected_root(&cwd);
            let package_json = root.join("package.json");
            let has_package_json = package_json.is_file();
            let is_script = has_package_json
                && std::fs::read_to_string(&package_json)
                    .ok()
                    .and_then(|json| npm::script_commands_from_package(&json, &name, &[]).ok())
                    .flatten()
                    .is_some();
            if is_script {
                ui::trace(&format!("'{name}' is a package.json script: running it"));
                let mut command = vec![name];
                command.extend(args);
                return Ok(cli::Command::Run { command });
            }
            let message = if has_package_json {
                format!("{message} (no package.json script named '{name}' here)")
            } else {
                message
            };
            eprint!("{}", cli::render_usage_error(&message, None));
            exit(cli::EXIT_USAGE);
        }
    }
}

fn dispatch(command: cli::Command) -> io::Result<i32> {
    use cli::Command::*;
    // Maintenance commands do not need host-platform validation. In
    // particular, GC must remain usable when inspecting a copied store on a
    // host that cannot realize its objects.
    match command {
        Gc(args) => return run_gc(&args).map(|_| 0),
        XClean {
            ecosystem,
            from,
            tool,
        } => {
            return xrun::clean(xrun::CleanRequest {
                ecosystem,
                from,
                tool,
            })
            .map(|_| 0);
        }
        StoreRoots => return run_store_roots().map(|_| 0),
        StorePath => {
            return store::Store::open().map(|s| {
                println!("{}", s.root.display());
                0
            });
        }
        Completions { shell } => {
            print!("{}", cli::completions(shell));
            return Ok(0);
        }
        // The admission gate is read-only over the project's records: no
        // store open (that would create the store tree), no lease, no
        // realization, no network. It needs the host platform only to tell
        // a foreign-platform closure from a current one, as `status` does.
        Audit { ref policy, json } => {
            let platform = Platform::host()?;
            let dir = project_dir();
            // A --policy file that cannot be read or parsed is an operator
            // mistake (exit 2), so CI can tell it from a denied build (exit 1).
            let extra = match policy {
                Some(path) => match audit::read_policy_file(path) {
                    Ok(extra) => Some(extra),
                    Err(error) => {
                        eprint!(
                            "{}",
                            cli::render_usage_error(&format!("audit: {error}"), Some("audit"))
                        );
                        return Ok(cli::EXIT_USAGE);
                    }
                },
                None => None,
            };
            let report = audit::audit(platform, &dir, extra.as_ref())?;
            ui::note(&format!(
                "audit: policy strict={} deny=[{}]",
                report.policy.strict,
                report
                    .policy
                    .deny
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            print!("{}", audit::render(&dir, &report, json)?);
            return Ok(if report.passes() {
                0
            } else {
                cli::EXIT_FAILURE
            });
        }
        Doctor { json } => {
            let store = store::Store::open()?;
            let _activity = store.activity(ActivityMode::Shared)?;
            let checks = inspect::doctor(&project_dir());
            print!("{}", inspect::render_doctor(&checks, json)?);
            if checks
                .iter()
                .any(|check| check.level == inspect::Level::Fail)
            {
                return Ok(cli::EXIT_FAILURE);
            }
            return Ok(0);
        }
        Ls {
            ref ecosystem,
            json,
        } => {
            let store = store::Store::open()?;
            let _activity = store.activity(ActivityMode::Shared)?;
            print!(
                "{}",
                inspect::ls(&project_dir(), ecosystem.as_deref(), json, ui::verbose())?
            );
            return Ok(0);
        }
        _ => {}
    }
    // Real subcommands validate the host once before any store-touching work.
    let platform = Platform::host()?;
    // A package.json `fmt` script is deliberately resolved before opening the
    // store. This preserves the cheap script path for a non-Rust project.
    if let cli::Command::Fmt {
        check,
        ref ecosystem,
        ref args,
    } = command
    {
        return run_fmt(platform, check, ecosystem.as_deref(), args);
    }
    // Keep the operation protected from its first store read through its
    // final child/projection use. Individual Store helpers acquire a short
    // compatibility lease when called directly; this long-lived lease is
    // what prevents GC from racing a CLI job.
    let store = store::Store::open()?;
    let needs_maintenance = matches!(
        &command,
        Sync { .. }
            | Plan
            | Build { .. }
            | Run { .. }
            | Add { .. }
            | Remove { .. }
            | Update { .. }
            | X { .. }
    );
    if needs_maintenance {
        let mut stderr = io::stderr().lock();
        gc::automatic_maintenance(&store, &mut stderr)?;
    }
    let _activity = store.activity(ActivityMode::Shared)?;
    match command {
        Sync { fresh, strict } => run_sync(platform, fresh, strict).map(|_| 0),
        Fmt { .. } => unreachable!("handled before opening the store"),
        Plan => run_plan(platform, &store).map(|_| 0),
        Build { args } => run_build(platform, &args, &store).map(|_| 0),
        Run { command } => run_run(platform, &command, &store, &_activity),
        Sbom { output } => run_sbom(output.as_deref()).map(|_| 0),
        Add {
            specs,
            dev,
            no_sync,
        } => run_deps(
            platform,
            deps::Request {
                verb: deps::Verb::Add,
                specs,
                dev,
            },
            no_sync,
        )
        .map(|_| 0),
        Remove {
            names,
            dev,
            no_sync,
        } => run_deps(
            platform,
            deps::Request {
                verb: deps::Verb::Remove,
                specs: names,
                dev,
            },
            no_sync,
        )
        .map(|_| 0),
        Update { names, no_sync } => run_deps(
            platform,
            deps::Request {
                verb: deps::Verb::Update,
                specs: names,
                dev: false,
            },
            no_sync,
        )
        .map(|_| 0),
        X {
            ecosystem,
            from,
            tool,
            args,
        } => {
            let cwd = project_dir();
            // `x` has its own cached projection path and therefore does not
            // pass through run_sync's policy initialization. Load the cwd
            // policy, including all applicable ancestors, before realization
            // or any cache-hit checks.
            policy::init(&cwd, false)?;
            xrun::run(
                platform,
                &cwd,
                xrun::Request {
                    ecosystem,
                    from,
                    tool,
                    args,
                },
                &_activity,
            )
        }
        XClean { .. } => unreachable!("handled above"),
        Status { json } => {
            let dir = project_dir();
            let rows = inspect::status(platform, &dir)?;
            if rows.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no project in {}: nothing to report", dir.display()),
                ));
            }
            print!("{}", inspect::render_status(&dir, &rows, json)?);
            if !rows.iter().all(inspect::EcosystemStatus::is_synced) {
                return Ok(cli::EXIT_FAILURE);
            }
            Ok(0)
        }
        Gc(_)
        | StorePath
        | StoreRoots
        | Completions { .. }
        | Doctor { .. }
        | Ls { .. }
        | Audit { .. } => {
            unreachable!("handled above")
        }
    }
}

/// `add` / `remove` / `update`: delegate the edit, report it, then the
/// ordinary sync in the project the edit landed in.
fn run_deps(platform: Platform, request: deps::Request, no_sync: bool) -> io::Result<()> {
    let cwd = project_dir();
    // Dependency edits ensure pinned tools before the ordinary sync. Set the
    // policy first so cached toolchain objects cannot initialize an empty
    // default policy and let strict/deny settings be bypassed.
    policy::init(&cwd, false)?;
    let outcome = deps::run(platform, &cwd, request)?;
    for line in &outcome.lines {
        ui::note(line);
    }
    if no_sync {
        ui::note("--no-sync: review the change, then run 'blanket'");
        return Ok(());
    }
    if outcome.project != cwd {
        std::env::set_current_dir(&outcome.project)?;
        ui::trace(&format!("syncing in {}", outcome.project.display()));
    }
    run_sync(platform, false, false)
}

fn run_sbom(output: Option<&Path>) -> io::Result<()> {
    let doc = sbom::generate(&project_dir())?;
    let text = serde_json::to_string_pretty(&doc)?;
    match output {
        Some(path) => {
            std::fs::write(path, text + "\n")?;
            eprintln!("blanket: SBOM written to {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn run_store_roots() -> io::Result<()> {
    for root in store::Store::open()?.root_diagnostics()? {
        match (root.path, root.problem) {
            (Some(path), None) => println!("{}  {}", root.key, path.display()),
            (_, Some(problem)) => println!("{}  <invalid: {}>", root.key, problem),
            _ => println!("{}  <invalid root record>", root.key),
        }
    }
    Ok(())
}

fn run_gc(args: &cli::GcArgs) -> io::Result<()> {
    let options = gc::Options {
        dry_run: args.dry_run,
        project: args.project,
        collect_legacy: args.collect_legacy,
        keep_days: args.keep_days.unwrap_or(gc::Options::default().keep_days),
        forgotten: args.forget.clone(),
    };
    let store = store::Store::open()?;
    let mut stdout = io::stdout().lock();
    // A dry run writes nothing and registration is a write, so the two
    // cannot both be honoured. Previewing the sweep as though the project
    // were registered would mean protecting a root with no record, which is
    // exactly the resolution rule GC is not allowed to bend; refuse the
    // combination instead of half-keeping either promise (A-R5).
    if args.dry_run && !args.register.is_empty() {
        return Err(io::Error::other(
            "refusing to combine --dry-run with --register: registering writes a record and a \
             dry run writes nothing. Register the project, then preview with `blanket gc \
             --dry-run`",
        ));
    }
    let Some(activity) = store.try_activity_exclusive()? else {
        // An explicitly requested mutation fails loudly; an opportunistic
        // sweep skips quietly. Migration is a requested mutation: a script
        // must be able to tell "migrated" from "never ran".
        if !args.forget.is_empty() || args.migrate_metadata {
            return Err(io::Error::other(
                "a Blanket job is using this store; retry when it finishes",
            ));
        }
        writeln!(stdout, "cleanup skipped: a Blanket job is using this store")?;
        return Ok(());
    };
    if args.migrate_metadata {
        if args.project
            || args.collect_legacy
            || !args.register.is_empty()
            || !args.forget.is_empty()
            || args.keep_days.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--migrate-metadata cannot be combined with registry or collection options",
            ));
        }
        let report = gc::migrate_metadata(&store, &activity, args.dry_run, &mut stdout)?;
        if report.unresolved != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata migration left unresolved records; no sweep was started",
            ));
        }
        return Ok(());
    }
    // Registering and forgetting the same root in one invocation is
    // ambiguous; compare the keys before either side touches the registry.
    for project in &args.register {
        let key = store::Store::root_key(project)?;
        if args.forget.iter().any(|forget| forget == &key) {
            return Err(io::Error::other(format!(
                "refusing to register and forget the same root key {key} in one invocation"
            )));
        }
    }
    // Resolve every key before changing the registry. This keeps a typo or
    // unknown key from partially applying a multi-key forget request.
    for (index, key) in args.forget.iter().enumerate() {
        if args.forget[..index].iter().any(|previous| previous == key) {
            return Err(io::Error::other(format!(
                "refusing to forget root key {key} more than once in one invocation"
            )));
        }
        store.lookup_root(key)?;
    }
    for project in &args.register {
        if options.dry_run {
            let record = store.root_record_from_project(project)?;
            writeln!(
                stdout,
                "blanket: would register root {} ({} objects)",
                record.project_path.display(),
                record.objects.len()
            )?;
        } else {
            let entry = store.register_root_from_project_with_activity(&activity, project)?;
            writeln!(stdout, "blanket: registered root {}", entry.path.display())?;
        }
    }
    for key in &args.forget {
        if options.dry_run {
            let entry = store.lookup_root(key)?;
            writeln!(
                stdout,
                "blanket: would forget root {key} ({})",
                entry.describe()
            )?;
        } else {
            let entry = store.forget_root_with_activity(&activity, key)?;
            writeln!(stdout, "blanket: forgot root {key} ({})", entry.describe())?;
        }
    }
    // Forgetting is the explicit recovery action, not an implicit sweep. A
    // later `blanket gc` may collect objects that are no longer protected;
    // this invocation must only change the requested registry records.
    if !options.dry_run && !args.forget.is_empty() {
        return Ok(());
    }
    let dry_run = options.dry_run;
    let report = gc::collect_with_activity(&store, &activity, options, &mut stdout)?;
    let verb = if dry_run { "would free" } else { "freed" };
    writeln!(
        stdout,
        "blanket: gc {verb} {} MB ({} objects, {} cached artifacts)",
        report.freed_bytes / (1024 * 1024),
        report.objects,
        report.cached_artifacts
    )?;
    Ok(())
}

fn project_dir() -> PathBuf {
    std::env::current_dir().expect("cwd")
}

/// Implicit detection for sync/plan: cargo joins the party only when the
/// invocation dir is itself a Cargo package (workspace members included).
/// Without this gate, running blanket in any project nested under an
/// unrelated Cargo workspace would silently project into that parent tree.
fn is_cargo_here(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file()
}

struct CargoInputs {
    root: PathBuf,
    rust_obj: PathBuf,
    plan: cargo::CargoPlan,
    lock_digest: String,
}

/// Workspace rooting is delegated to the pinned Cargo itself
/// (`locate-project --workspace`): an ancestor-walk for Cargo.lock picks an
/// unrelated outer lock when independent packages nest (Sol review, repro'd).
fn locate_cargo_root(rust_obj: &Path, cwd: &Path, store: &store::Store) -> io::Result<PathBuf> {
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

fn load_cargo_inputs(
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

fn ensure_cargo_lock(root: &Path, rust_obj: &Path, store: &store::Store) -> io::Result<()> {
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
type PythonPlan = (
    types::Plan,
    pyselect::PythonSelection,
    Vec<project::InputRecord>,
);

/// Candidate input files for the status record: the manifest that won, the
/// interpreter request, and every lock blanket reads or writes.
fn python_input_records(
    dir: &Path,
    manifest: &manifest::Manifest,
) -> io::Result<Vec<project::InputRecord>> {
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
    project::input_records(dir, &candidates)
}

fn read_plan(platform: Platform, dir: &Path, store: &store::Store) -> io::Result<PythonPlan> {
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

fn record_skippable_specs(input: &str, source: &str) -> io::Result<()> {
    record_skippable_specs_with(input, source, policy::record)
}

fn record_skippable_specs_with<F>(_input: &str, source: &str, mut record: F) -> io::Result<()>
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
fn is_fully_pinned(text: &str) -> bool {
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
fn locked_requirements(
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

fn cached_lock_matches(stamp: &str, lock: &str, source_hash: &str) -> bool {
    !lock.is_empty() && stamp.trim() == source_hash
}

/// Stamp deciding whether `uv pip compile` must re-run. Deliberately NOT
/// platform-qualified: `.blanket/lock-source.hash` is per-machine state and
/// the format is byte-identical to the pre-port one, so existing darwin
/// stamps stay valid after the Linux port (platform lives in
/// `planner_input_hash`, which keys the plan cache).
fn lock_source_hash(pyver: &str, source: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("{pyver}\x00{source}").as_bytes()))
}

fn run_plan(platform: Platform, store: &store::Store) -> io::Result<()> {
    let dir = project_dir();
    policy::init(&dir, false)?;
    ensure_npm_lock(platform, &dir, store)?;
    let mut any = false;
    if has_python_input(&dir)? {
        let (plan, _selection, _inputs) = read_plan(platform, &dir, store)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if let Some(plan) = load_npm_plan(platform, &dir)? {
        let v: Vec<_> = plan
            .packages
            .iter()
            .map(|p| {
                serde_json::json!({"path": p.path, "version": p.version,
                                   "url": p.url, "integrity": p.integrity})
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ecosystem": "node", "node_version": plan.node_version,
                "lock_source": plan.lock_source, "packages": v
            }))?
        );
        any = true;
    }
    if is_cargo_here(&dir) {
        let inputs = load_cargo_inputs(platform, &dir, store)?;
        println!("{}", serde_json::to_string_pretty(&inputs.plan)?);
        any = true;
    }
    if dir.join("go.mod").is_file() {
        let inputs = load_go_inputs(platform, &dir, store)?;
        println!("{}", serde_json::to_string_pretty(&inputs.plan)?);
        any = true;
    }
    if dir.join("Gemfile").is_file() {
        let ruby_obj = ruby::ensure_ruby_for(store, platform)?;
        let (plan, _) = ruby::plan_ruby(store, &dir, &ruby_obj)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if dir.join("mix.exs").is_file() {
        let beam = elixir::ensure_beam_for(store, platform)?;
        let (plan, _) = elixir::plan_elixir(store, &dir, &beam)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if dotnet::has_marker(&dir)? {
        // Preflight before SDK realization: a broken layout should fail
        // loudly here, not after a toolchain download.
        dotnet::preflight(&dir)?;
        let sdk = dotnet::ensure_sdk_for(store, platform)?;
        let (plan, _) = dotnet::plan_dotnet(store, &dir, &sdk)?;
        println!("{}", serde_json::to_string_pretty(&plan)?);
        any = true;
    }
    if !any {
        return Err(no_inputs());
    }
    Ok(())
}

fn no_inputs() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        "no_manifest: nothing to sync here (looked for requirements.lock.txt, requirements.txt, pyproject.toml ([project], [tool.poetry], [dependency-groups]), setup.cfg, setup.py, requirements/{common.txt,base.txt,requirements.in,cpu.txt,cuda.txt,rocm.txt,xpu.txt}, package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.toml, go.mod, Gemfile, mix.exs, and .csproj/packages.lock.json)",
    )
}

fn has_python_input(dir: &Path) -> io::Result<bool> {
    manifest::has_manifest(dir)
}

struct GoInputs {
    go_obj: PathBuf,
    plan: golang::GoPlan,
    gosum_sha256: String,
}

fn load_go_inputs(platform: Platform, dir: &Path, store: &store::Store) -> io::Result<GoInputs> {
    let go_version = golang::resolve_project_toolchain(platform, dir)?;
    let go_obj = golang::ensure_go_for(store, platform, go_version)?;
    let plan = golang::plan_go(store, platform, dir, &go_obj)?;
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
fn ensure_npm_lock(platform: Platform, dir: &Path, store: &store::Store) -> io::Result<()> {
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
    let node = npm::ensure_node_for(store, platform)?;
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

fn preflight_sync(platform: Platform, dir: &Path) -> io::Result<()> {
    // Syncing ends by registering this project as a GC root. Check that the
    // path can be recorded before realizing or projecting anything: a
    // finished sync that could not register would leave a projected
    // environment nothing protects, and the next sweep would collect it.
    store::Store::check_registrable(dir)?;
    if [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
    ]
    .iter()
    .any(|name| dir.join(name).is_file())
    {
        npm::preflight(platform)?;
    }
    if has_python_input(dir)? {
        let selection =
            pyselect::select_python_with_inputs(platform, &manifest::python_inputs(dir)?)?;
        python::preflight(platform, selection.pin.version)?;
    }
    if dir.join("go.mod").is_file() {
        golang::preflight_platform(platform)?;
    }
    if dir.join("Gemfile").is_file() {
        ruby::preflight_platform(platform)?;
    }
    if dir.join("mix.exs").is_file() {
        elixir::preflight_platform(platform)?;
    }
    if dotnet::has_marker(dir)? {
        dotnet::preflight_platform(platform)?;
    }
    if is_cargo_here(dir) {
        cargo::preflight_platform(platform)?;
    }
    Ok(())
}

fn run_sync(platform: Platform, fresh: bool, strict: bool) -> io::Result<()> {
    let dir = project_dir();
    policy::init(&dir, strict)?;
    preflight_sync(platform, &dir)?;
    let store = store::Store::open()?;
    ensure_npm_lock(platform, &dir, &store)?;
    let mut any = false;
    if has_python_input(&dir)? {
        let (plan, selection, inputs) = read_plan(platform, &dir, &store)?;
        let env = project::realize_env(&store, platform, &plan)?;
        project::project_env_with_inputs(&dir, &env, &plan, &selection, &inputs)?;
        ui::synced(".venv", &env);
        any = true;
    }
    if let Some(plan) = load_npm_plan(platform, &dir)? {
        let mut config = npm::BlanketConfig::default();
        if plan.lock_source == "package-lock.json" {
            let lock = std::fs::read_to_string(dir.join("package-lock.json"))?;
            if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
                npm::check_lock_freshness(&pkg, &lock)?;
                config = npm::parse_blanket_config(&pkg)?;
            }
        } else if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
            config = npm::parse_blanket_config(&pkg)?;
        }
        let env = npm::realize_node_env(&store, platform, &plan, &config.artifacts)?;
        let inputs = project::input_records(
            &dir,
            &[dir.join("package.json"), dir.join(&plan.lock_source)],
        )?;
        npm::project_node_env_recorded(
            &dir,
            &env,
            platform,
            &plan,
            &config.mutable_packages,
            fresh,
            &inputs,
        )?;
        ui::synced("node_modules", &env);
        any = true;
    }
    if dir.join("go.mod").is_file() {
        let inputs = load_go_inputs(platform, &dir, &store)?;
        let modcache = golang::realize_modcache(&store, platform, &inputs.plan, &inputs.go_obj)?;
        golang::project_go_env(
            &dir,
            &inputs.go_obj,
            &modcache,
            &inputs.plan,
            &inputs.gosum_sha256,
        )?;
        ui::synced("go modcache", &modcache);
        any = true;
    }
    if dir.join("Gemfile").is_file() {
        let ruby_obj = ruby::ensure_ruby_for(&store, platform)?;
        let (plan, lock_sha256) = ruby::plan_ruby(&store, &dir, &ruby_obj)?;
        let gems = ruby::realize_gems(&store, platform, &plan, &ruby_obj)?;
        ruby::project_ruby_env(&dir, &ruby_obj, &gems, &plan, &lock_sha256)?;
        ui::synced("gems", &gems);
        any = true;
    }
    if dir.join("mix.exs").is_file() {
        let beam = elixir::ensure_beam_for(&store, platform)?;
        let (plan, lock_sha256) = elixir::plan_elixir(&store, &dir, &beam)?;
        let deps = elixir::realize_deps(&store, platform, &plan, &beam)?;
        let projection =
            elixir::project_elixir_env(platform, &dir, &beam, &deps, &plan, &lock_sha256, fresh)?;
        ui::synced("hex deps", &projection);
        any = true;
    }
    if dotnet::has_marker(&dir)? {
        dotnet::preflight(&dir)?;
        let sdk = dotnet::ensure_sdk_for(&store, platform)?;
        let (plan, lock_sha256) = dotnet::plan_dotnet(&store, &dir, &sdk)?;
        let packages = dotnet::realize_packages(&store, platform, &plan, &sdk, &dir)?;
        dotnet::project_dotnet_env(&dir, &sdk, &packages, &plan, &lock_sha256)?;
        ui::synced("nuget packages", &packages);
        any = true;
    }
    if is_cargo_here(&dir) {
        let inputs = load_cargo_inputs(platform, &dir, &store)?;
        let rust_obj = &inputs.rust_obj;
        let vendor_obj = cargo::realize_vendor(&store, &inputs.plan)?;
        if fresh {
            let cargo_home = inputs.root.join(".blanket/cargo-home");
            if std::fs::symlink_metadata(&cargo_home).is_ok() {
                store::remove_tree(&cargo_home)?;
            }
        }
        cargo::project_cargo_env(
            &inputs.root,
            rust_obj,
            &vendor_obj,
            &inputs.plan,
            &inputs.lock_digest,
        )?;
        ui::synced("cargo env", &vendor_obj);
        any = true;
    }
    if !any {
        return Err(no_inputs());
    }
    print_exception_summary(&dir)?;
    Ok(())
}

fn load_npm_plan(platform: Platform, dir: &Path) -> io::Result<Option<npm::NpmPlan>> {
    if dir.join("package-lock.json").is_file() {
        return Ok(Some(npm::plan_npm(
            platform,
            &std::fs::read_to_string(dir.join("package-lock.json"))?,
        )?));
    }
    if dir.join("pnpm-lock.yaml").is_file() {
        return Ok(Some(npm_lock_import::plan_pnpm(
            platform,
            &std::fs::read_to_string(dir.join("pnpm-lock.yaml"))?,
            dir,
        )?));
    }
    if dir.join("yarn.lock").is_file() {
        let package = std::fs::read_to_string(dir.join("package.json"))?;
        return Ok(Some(npm_lock_import::plan_yarn(
            platform,
            &std::fs::read_to_string(dir.join("yarn.lock"))?,
            &package,
            dir,
        )?));
    }
    Ok(None)
}

fn print_exception_summary(project_dir: &Path) -> io::Result<()> {
    let dir = project_dir.join(".blanket/closures");
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().ends_with(".json") {
                continue;
            }
            let text = match std::fs::read_to_string(entry.path()) {
                Ok(text) => text,
                Err(_) => continue,
            };
            let value: serde_json::Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => continue,
            };
            total += value["body"]["exceptions"].as_array().map_or(0, Vec::len);
        }
    }
    if total > 0 {
        eprintln!(
            "blanket: {total} exception(s) recorded in .blanket/closures/*.json — \
             `blanket sync --strict` to refuse them"
        );
    }
    Ok(())
}

/// `blanket build [ecosystem] [args...]`: explicit ecosystem, or inferred
/// when exactly one build-capable ecosystem is present (Sol review 4).
fn run_build(platform: Platform, args: &[String], store: &store::Store) -> io::Result<()> {
    let cwd = project_dir();
    let (eco, rest): (&str, &[String]) = match args.first().map(String::as_str) {
        Some("cargo") => ("cargo", &args[1..]),
        Some("go") => ("go", &args[1..]),
        Some("elixir") => ("elixir", &args[1..]),
        Some("dotnet") => ("dotnet", &args[1..]),
        _ => {
            let mut present = Vec::new();
            if cwd.ancestors().any(is_cargo_here) {
                present.push("cargo");
            }
            if cwd.ancestors().any(|d| d.join("go.mod").is_file()) {
                present.push("go");
            }
            if cwd.ancestors().any(|d| d.join("mix.exs").is_file()) {
                present.push("elixir");
            }
            if dotnet::has_marker(&cwd)? {
                present.push("dotnet");
            }
            match present.as_slice() {
                [one] => (*one, args),
                [] => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "blanket build requires a Cargo.toml, go.mod, or mix.exs project",
                    ))
                }
                many => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "multiple build-capable ecosystems found ({}); specify one: \
                             `blanket build <ecosystem> ...`",
                            many.join(", ")
                        ),
                    ))
                }
            }
        }
    };
    let root = match eco {
        "cargo" => cwd
            .ancestors()
            .find(|dir| dir.join("Cargo.toml").is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no Cargo.toml found from here upward",
                )
            })?
            .to_path_buf(),
        "go" => cwd
            .ancestors()
            .find(|dir| dir.join("go.mod").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no go.mod found from here upward")
            })?
            .to_path_buf(),
        "elixir" => cwd
            .ancestors()
            .find(|dir| dir.join("mix.exs").is_file())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no mix.exs found from here upward")
            })?
            .to_path_buf(),
        _ => cwd.clone(),
    };
    policy::init(&root, false)?;
    match eco {
        "cargo" => {
            let inputs = load_cargo_inputs(platform, &cwd, &store)?;
            let vendor_obj = cargo::realize_vendor(&store, &inputs.plan)?;
            cargo::project_cargo_env(
                &inputs.root,
                &inputs.rust_obj,
                &vendor_obj,
                &inputs.plan,
                &inputs.lock_digest,
            )?;
            cargo::build_sandboxed(platform, &inputs.root, &inputs.rust_obj, &vendor_obj, rest)
        }
        "go" => {
            let root = cwd
                .ancestors()
                .find(|d| d.join("go.mod").is_file())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no go.mod found from here upward")
                })?
                .to_path_buf();
            let inputs = load_go_inputs(platform, &root, &store)?;
            let modcache =
                golang::realize_modcache(&store, platform, &inputs.plan, &inputs.go_obj)?;
            golang::project_go_env(
                &root,
                &inputs.go_obj,
                &modcache,
                &inputs.plan,
                &inputs.gosum_sha256,
            )?;
            golang::build_sandboxed(platform, &root, &inputs.go_obj, &modcache, rest)
        }
        "elixir" => {
            let root = cwd
                .ancestors()
                .find(|d| d.join("mix.exs").is_file())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "no mix.exs found from here upward")
                })?
                .to_path_buf();
            let beam = elixir::ensure_beam_for(&store, platform)?;
            let (plan, lock_sha256) = elixir::plan_elixir(&store, &root, &beam)?;
            let deps = elixir::realize_deps(&store, platform, &plan, &beam)?;
            let projection = elixir::project_elixir_env(
                platform,
                &root,
                &beam,
                &deps,
                &plan,
                &lock_sha256,
                false,
            )?;
            elixir::build_sandboxed(platform, &root, &beam, &projection, rest)
        }
        _ => {
            let sdk = dotnet::ensure_sdk_for(&store, platform)?;
            let (plan, lock_sha256) = dotnet::plan_dotnet(&store, &cwd, &sdk)?;
            let packages = dotnet::realize_packages(&store, platform, &plan, &sdk, &cwd)?;
            dotnet::project_dotnet_env(&cwd, &sdk, &packages, &plan, &lock_sha256)?;
            dotnet::build_sandboxed(platform, &cwd, &sdk, &packages, rest)
        }
    }
}

/// `blanket fmt`: realize only the Rust toolchain and its paired rustfmt
/// component, then format the Cargo workspace without resolving dependencies.
fn run_fmt(
    platform: Platform,
    check: bool,
    ecosystem: Option<&str>,
    args: &[String],
) -> io::Result<i32> {
    let cwd = project_dir();
    policy::init(&cwd, false)?;

    // `--eco` is blanket's own ecosystem selector, not something a script can
    // read: when it is given explicitly it dispatches to that ecosystem and
    // the package.json script is skipped, so `--eco rust` is a real escape
    // hatch in a polyglot root whose package.json also has a `fmt` script.
    // Without it, a script named fmt wins over the named command, matching
    // `blanket run fmt`. Preserve the command's user arguments for the script;
    // `--eco` is never appended to a delegated command line.
    match ecosystem {
        Some("rust") => {}
        Some(ecosystem) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "fmt for {ecosystem} is not implemented yet; Rust is the only supported ecosystem"
                ),
            ));
        }
        None => {
            let script_root = projected_root(&cwd);
            let package_json = script_root.join("package.json");
            let is_script = package_json.is_file()
                && std::fs::read_to_string(&package_json)
                    .ok()
                    .and_then(|json| npm::script_commands_from_package(&json, "fmt", &[]).ok())
                    .flatten()
                    .is_some();
            if is_script {
                ui::trace("'fmt' is a package.json script: running it");
                // `run` only executes package scripts in a projected
                // environment. Preserve that early, store-free refusal for a
                // package that has a script but has never been synced.
                if !script_root.join(".blanket/closures").is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no environment projected here for command 'fmt'; run `blanket sync` first",
                    ));
                }
                let mut command = vec!["fmt".to_string()];
                if check {
                    command.push("--check".into());
                }
                command.extend(args.iter().cloned());
                let store = store::Store::open()?;
                // Scope the handle to the one call that narrates. Holding it
                // any longer serialises every other thread's stderr for the
                // rest of the command: `sandbox::relay_stderr` drains a
                // child's stderr from its own thread through `io::stderr()`,
                // so an outer lock held across a child is a pipe that stops
                // being drained.
                {
                    let mut stderr = io::stderr().lock();
                    gc::automatic_maintenance(&store, &mut stderr)?;
                }
                let activity = store.activity(ActivityMode::Shared)?;
                return run_run(platform, &command, &store, &activity);
            }
        }
    }
    // Top of the Rust path, and deliberately not above the `--eco` dispatch:
    // a delegated package.json `fmt` script needs no rustfmt pin. A platform
    // with no pinned component is refused here, before `Store::open` and
    // before `ensure_rust_for` downloads ~105 MB of toolchain.
    rustfmt::preflight_platform(platform)?;
    let detected = inspect::detected(&cwd)?;
    if ecosystem.is_none() && detected.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "multiple ecosystems found ({}); specify `blanket fmt --eco rust`",
                detected.join(", ")
            ),
        ));
    }
    if !cwd
        .ancestors()
        .any(|dir| dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file())
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no Rust project here; run `blanket fmt` from a Cargo project",
        ));
    }

    let store = store::Store::open()?;
    // Same scoping as the delegated branch above: the maintenance narration
    // is the only thing that needs the handle, and the toolchain
    // provisioning and formatter children below all run outside it.
    {
        let mut stderr = io::stderr().lock();
        gc::automatic_maintenance(&store, &mut stderr)?;
    }
    let activity = store.activity(ActivityMode::Shared)?;
    let rust_version = cargo::resolve_toolchain(platform, &cwd)?.to_string();
    let rust_object = cargo::ensure_rust_for(&store, platform, &rust_version)?;
    let rustfmt_object = rustfmt::ensure_rustfmt(&store, platform, &rust_version, &rust_object)?;
    let workspace_root = locate_cargo_root(&rust_object, &cwd, &store)?.canonicalize()?;
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "object path has no UTF-8 id")
            })?;
        Ok(serde_json::json!({
            "path": path.display().to_string(),
            "id": id,
        }))
    };
    let mut refs = project::ClosureRefs::new();
    refs.object_path(&store, &activity, &rust_object)?;
    refs.object_path(&store, &activity, &rustfmt_object)?;
    project::write_closure(
        &workspace_root,
        "rustfmt",
        serde_json::json!({
            "rust_object": object_ref(&rust_object)?,
            "rustfmt_object": object_ref(&rustfmt_object)?,
            "rust_version": rust_version,
            "workspace_root": workspace_root.display().to_string(),
        }),
        &store,
        &activity,
        refs,
    )?;
    let invocation_dir = cwd.canonicalize()?;
    let status = rustfmt::run_sandboxed(
        platform,
        &invocation_dir,
        &workspace_root,
        &rust_object,
        &rustfmt_object,
        &store,
        check,
        args,
    )?;
    Ok(child_status_code(&status))
}

/// Nearest ancestor that is a blanket projection: every tailor writes
/// `.blanket/closures/<eco>.json`, so that directory is the proof. A plain
/// `node_modules` or `.venv` in a subdirectory (a docs site, a vendored
/// tool) is NOT a projection and must not stop the walk-up (Sol, task
/// runner review).
fn projected_root(cwd: &Path) -> PathBuf {
    cwd.ancestors()
        .find(|d| d.join(".blanket/closures").is_dir())
        .unwrap_or(cwd)
        .to_path_buf()
}

fn refuse_dotnet_script(has_dotnet_closure: bool, script_resolved: bool) -> bool {
    has_dotnet_closure && script_resolved
}

fn run_run(
    platform: Platform,
    cmd: &[String],
    store: &store::Store,
    activity: &blanket::activity::StoreActivity,
) -> io::Result<i32> {
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run: no command given",
        ));
    }
    // Walk up from cwd to the nearest projected root, so `blanket run`
    // works from workspace subdirectories like npm run does.
    let cwd = project_dir();
    let dir = projected_root(&cwd);
    let venv = dir.join(".venv");
    let nm = dir.join("node_modules");
    let cargo_home = dir.join(".blanket/cargo-home");
    let node_projected = std::fs::symlink_metadata(&nm)
        .map(|md| md.file_type().is_symlink())
        .unwrap_or(false)
        && std::fs::symlink_metadata(dir.join(".blanket/closures/node.json")).is_ok();
    let nearest_nm = if node_projected {
        let forest_root = nm
            .canonicalize()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        cwd.ancestors()
            .take_while(|path| path.starts_with(&dir))
            .map(|path| path.join("node_modules"))
            .find(|path| {
                std::fs::symlink_metadata(path)
                    .map(|md| md.file_type().is_symlink())
                    .unwrap_or(false)
                    && forest_root
                        .as_ref()
                        .and_then(|root| {
                            path.canonicalize().ok().map(|path| path.starts_with(root))
                        })
                        .unwrap_or(false)
            })
            .unwrap_or_else(|| nm.clone())
    } else {
        nm.clone()
    };
    let package_json = if node_projected {
        project::read_closure(&dir, "node")?;
        let path = dir.join("package.json");
        if std::fs::symlink_metadata(&path).is_ok() {
            Some((path.canonicalize()?, std::fs::read_to_string(path)?))
        } else {
            None
        }
    } else {
        None
    };
    let script_steps = package_json
        .as_ref()
        .map(|(_, json)| npm::script_commands_from_package(json, &cmd[0], &cmd[1..]))
        .transpose()?
        .flatten();
    let package_metadata = if script_steps.is_some() {
        let (_, json) = package_json
            .as_ref()
            .expect("script steps require package.json");
        let package: serde_json::Value = serde_json::from_str(json).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("package.json: {e}"))
        })?;
        Some((
            package["name"].as_str().map(str::to_string),
            package["version"].as_str().map(str::to_string),
        ))
    } else {
        None
    };
    if refuse_dotnet_script(
        std::fs::symlink_metadata(dir.join(".blanket/closures/dotnet.json")).is_ok(),
        script_steps.is_some(),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "package.json scripts are not run under a .NET projection (MSBuild belongs in the sandbox: use `blanket build dotnet`)",
        ));
    }
    let mut prefix: Vec<String> = Vec::new();
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    if venv.exists() {
        prefix.push(venv.join("bin").to_string_lossy().into_owned());
        command.env("VIRTUAL_ENV", &venv);
        command.env("PYTHONDONTWRITEBYTECODE", "1"); // site-packages is read-only
    }
    if nm.exists() {
        prefix.push(nearest_nm.join(".bin").to_string_lossy().into_owned());
        if nearest_nm != nm {
            prefix.push(nm.join(".bin").to_string_lossy().into_owned());
        }
        // Node toolchain from the store (cache hit after sync).
        let node = npm::ensure_node_for(store, platform)?;
        prefix.push(node.join("bin").to_string_lossy().into_owned());
    }
    if cargo_home.exists() {
        let closure = project::read_closure(&dir, "cargo")?;
        // Store-contained resolution: a project-editable closure must never
        // inject arbitrary executable paths (Sol review 5).
        let rust_obj = project::closure_object(store, &closure, "rust_object", "bin/rustc")?;
        prefix.push(cargo_home.join("bin").to_string_lossy().into_owned());
        prefix.push(rust_obj.join("bin").to_string_lossy().into_owned());
        command.env("CARGO_HOME", cargo_home.canonicalize()?);
        command.env_remove("RUSTUP_HOME");
        command.env_remove("RUSTUP_TOOLCHAIN");
    }
    if dir.join(".blanket/closures/go.json").exists() {
        let closure = project::read_closure(&dir, "go")?;
        let go_obj = project::closure_object(store, &closure, "go_object", "bin/go")?;
        let modcache = project::closure_object(store, &closure, "modcache_object", "")?;
        prefix.push(go_obj.join("bin").to_string_lossy().into_owned());
        for (k, v) in golang::go_env(&go_obj, &modcache, true) {
            if v.is_empty() {
                command.env_remove(&k);
            } else {
                command.env(&k, &v);
            }
        }
    }
    if dir.join(".blanket/closures/ruby.json").exists() {
        let closure = project::read_closure(&dir, "ruby")?;
        let ruby_obj = project::closure_object(store, &closure, "ruby_object", "bin/ruby")?;
        let gems_obj = project::closure_object(store, &closure, "gems_object", "")?;
        // Ruby FIRST, then gem binstubs (a gem exe must never shadow ruby).
        prefix.push(ruby_obj.join("bin").to_string_lossy().into_owned());
        prefix.push(gems_obj.join("bin").to_string_lossy().into_owned());
        let (prefixes, remove, set) = ruby::run_env(&dir, &gems_obj);
        blanket::sandbox::force_env(&mut command, &prefixes, &remove, &set);
    }
    if dir.join(".blanket/closures/elixir.json").exists() {
        let closure = project::read_closure(&dir, "elixir")?;
        let beam = project::closure_object(store, &closure, "beam_object", "elixir/bin/mix")?;
        // The deps projection is a writable clone OUTSIDE the store; verify
        // it lives under the blanket home and matches the recorded deps id.
        let deps_obj = project::closure_object(store, &closure, "deps_object", "")?;
        // Never trust the recorded projection path: reconstruct the ONE
        // expected forest path from canonical project + deps id and require
        // exact canonical equality (Sol: lexical checks admitted foreign
        // forests, dot-dot tricks, and symlinked dirs).
        let projection = elixir::expected_projection(store, &dir, &deps_obj)?;
        let recorded = closure["deps_projection"].as_str().map(PathBuf::from);
        if recorded.as_deref().and_then(|p| p.canonicalize().ok()) != Some(projection.clone())
            || !projection.is_dir()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "elixir closure projection is not the expected forest path; \
                 run `blanket sync` first",
            ));
        }
        prefix.push(beam.join("elixir/bin").to_string_lossy().into_owned());
        prefix.push(beam.join("otp/bin").to_string_lossy().into_owned());
        let scratch = std::env::temp_dir().join(format!("blanket-mix-run-{}", std::process::id()));
        std::fs::create_dir_all(&scratch)?;
        let (prefixes, remove, set) = elixir::run_env(
            &beam,
            &projection,
            &elixir::build_root(platform, &dir)?,
            &scratch,
        )?;
        blanket::sandbox::force_env(&mut command, &prefixes, &remove, &set);
    }
    if dir.join(".blanket/closures/dotnet.json").exists() {
        // This prevents accidental unsandboxed builds, not deliberate bypasses
        // through wrappers such as `sh -c`; during realization and build,
        // blanket never evaluates project code outside its sandbox. Missing-lock
        // lock generation is the explicit host-side exception.
        if let Some(reason) = dotnet::refused_run_command(cmd) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, reason));
        }
        let closure = project::read_closure(&dir, "dotnet")?;
        let sdk = project::closure_object(store, &closure, "sdk_object", "dotnet")?;
        let packages = project::closure_object(store, &closure, "packages_object", "")?;
        prefix.push(sdk.to_string_lossy().into_owned());
        let scratch = std::env::temp_dir().join(format!("blanket-dn-run-{}", std::process::id()));
        std::fs::create_dir_all(&scratch)?;
        let (prefixes, remove, set) = dotnet::run_env(&sdk, &packages, &scratch);
        blanket::sandbox::force_env(&mut command, &prefixes, &remove, &set);
    }
    if prefix.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no environment projected here for command '{}'; run `blanket sync` first",
                cmd[0]
            ),
        ));
    }
    let path = std::env::var("PATH").unwrap_or_default();
    prefix.push(path);
    command.env("PATH", prefix.join(":"));
    if let Some(steps) = script_steps {
        let ((package_json_path, _), (package_name, package_version)) = package_json
            .as_ref()
            .zip(package_metadata)
            .expect("script steps require package metadata");
        let envs: Vec<_> = command
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(|value| value.to_os_string())))
            .collect();
        let npm_envs: Vec<_> = std::env::vars_os()
            .map(|(key, _)| key)
            .chain(envs.iter().map(|(key, _)| key.clone()))
            .filter(|key| key.to_string_lossy().starts_with("npm_"))
            .collect();
        for (event, script) in steps {
            eprintln!("blanket: > {event}: {script}");
            let mut step = std::process::Command::new("/bin/sh");
            step.arg("-c").arg(script).current_dir(&dir);
            for (key, value) in &envs {
                match value {
                    Some(value) => {
                        step.env(key, value);
                    }
                    None => {
                        step.env_remove(key);
                    }
                }
            }
            for key in &npm_envs {
                step.env_remove(key);
            }
            step.env("npm_lifecycle_event", &event);
            if let Some(name) = &package_name {
                step.env("npm_package_name", name);
            }
            if let Some(version) = &package_version {
                step.env("npm_package_version", version);
            }
            step.env("npm_package_json", package_json_path);
            step.env("INIT_CWD", &cwd);
            let status = blanket::supervise::status(&mut step, activity)
                .map_err(|e| io::Error::new(e.kind(), format!("run npm script {event}: {e}")))?;
            if !status.success() {
                return Ok(child_status_code(&status));
            }
        }
        return Ok(0);
    }
    let status = blanket::supervise::status(&mut command, activity)?;
    Ok(child_status_code(&status))
}

fn child_status_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
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

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Sync ends by registering the project as a GC root, so a path no
    /// record can hold is refused before an environment is realized or
    /// projected. Refusing at the end instead would leave the project synced,
    /// unprotected and with no way to register it.
    #[test]
    fn sync_refuses_a_project_path_no_root_record_can_hold() {
        let temp = TempDir::new();
        let project = temp.0.join("project ");
        std::fs::create_dir_all(&project).unwrap();
        let error = preflight_sync(Platform::host().unwrap(), &project).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("cannot protect"), "{error}");
    }

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
    fn dotnet_run_guard_handles_options_and_msbuild_dll() {
        assert!(dotnet::refused_run_command(
            &["dotnet", "-d", "build"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        )
        .is_some());
        assert!(dotnet::refused_run_command(
            &["dotnet", "msbuild"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        )
        .is_some());
        assert!(dotnet::refused_run_command(
            &["dotnet", "exec", "/tmp/tools/MSBuild.dll"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        )
        .is_some());
        assert!(dotnet::refused_run_command(
            &["dotnet", "exec", "app.dll"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        )
        .is_none());
    }

    #[test]
    fn dotnet_projection_refuses_resolved_package_scripts() {
        assert!(refuse_dotnet_script(true, true));
        assert!(!refuse_dotnet_script(true, false));
        assert!(!refuse_dotnet_script(false, true));
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
