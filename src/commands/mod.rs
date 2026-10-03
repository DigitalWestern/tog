//! The command layer: one file per user-facing verb. This
//! is the only layer that knows about every tailor *and* the kernel; the
//! binary parses arguments and calls `resolve` then `dispatch`.

pub(crate) mod attest;
pub(crate) mod audit;
pub(crate) mod build;
pub(crate) mod completions;
pub(crate) mod deps;
pub(crate) mod doctor;
pub(crate) mod env;
pub(crate) mod fmt;
pub(crate) mod gc;
/// `pub` on purpose: the read-only closure/status views were public before
/// the move and stay reachable as `tog::commands::inspect`.
pub mod inspect;
pub(crate) mod keygen;
pub(crate) mod ls;
pub(crate) mod plan;
pub(crate) mod run;
pub(crate) mod sbom;
pub(crate) mod selfupdate;
pub(crate) mod shared;
pub(crate) mod status;
pub(crate) mod store;
pub(crate) mod sync;
pub(crate) mod toolchain;
pub(crate) mod x;

pub use crate::commands::x::environment_name as x_environment_name;
pub use crate::kernel::context::Context;

use crate::cli;
use crate::commands::shared::{project_dir, projected_root};
use crate::kernel::platform::Platform;
use crate::kernel::ui;
use crate::tailors::node;
use std::io;
use std::process::exit;

/// What argv asked for, once the grammar has had its say.
pub enum Pending {
    Command(cli::Command),
    /// Bare `tog`: sync inside a project (and then the help, printed by
    /// `main` when the sync succeeded), the help alone outside one.
    Implicit,
    /// An unknown first word: a package.json script if one matches. The
    /// sync flags reach `dispatch` beside it, so `tog --frozen <script>`
    /// governs the sync `run` performs first.
    Script {
        name: String,
        args: Vec<String>,
        message: String,
    },
}

/// A bare `tog` inside a project is `sync` (`main` prints the help after a
/// sync that succeeded); an unknown first word that names a package.json
/// script runs it. Anything else is the usage error the grammar already
/// prepared (exit 2).
pub fn resolve(pending: Pending) -> io::Result<cli::Command> {
    match pending {
        Pending::Command(command) => Ok(command),
        Pending::Implicit => {
            let cwd = project_dir();
            if !inspect::detected(&cwd)?.is_empty() {
                ui::trace("no command given inside a project: running sync");
                return Ok(cli::Command::Sync {
                    fresh: false,
                    records: Vec::new(),
                });
            }
            // Nothing to sync, so the whole invocation is the help: it goes
            // to stdout and exits 0, because someone who typed `tog` alone
            // outside a project asked for orientation, not for an error.
            // Printed here rather than returned as a command so that
            // `resolve` keeps one job and `dispatch` stays a table of verbs.
            ui::note(&format!(
                "no project in {}: nothing to sync, so here is the help",
                cwd.display()
            ));
            print!("{}", cli::usage());
            exit(0);
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
                    .and_then(|json| node::script_commands_from_package(&json, &name, &[]).ok())
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

/// Run the hidden resolution relay and return its exit status: the tool's,
/// or 128 + the signal that ended it. It runs inside the resolution
/// sandbox, so it loads no policy, opens no store, and prints nothing that
/// is not the tool's except a failure of its own.
pub fn relay(invocation: cli::RelayInvocation) -> i32 {
    use crate::kernel::resolve::relay;
    let result = relay::parse_args(
        &invocation.socket,
        &invocation.listen,
        invocation.exec_log_fd,
        invocation.env_fd,
        &invocation.argv,
    )
    .and_then(relay::run);
    match result {
        Ok(code) => code,
        Err(error) => {
            crate::kernel::ui::error(&error.to_string());
            cli::EXIT_FAILURE
        }
    }
}

/// Hand the kernel and the closure writer what the tailors know, before any
/// verb runs: every object-kind row, and each ecosystem's resolution files
/// for the resolution join. `x` roots are no project and no door records
/// them, so `x` joins nothing.
fn install_tailor_tables(command: &cli::Command) {
    crate::tailors::install_kinds();
    if !matches!(
        command,
        cli::Command::X { .. } | cli::Command::XClean { .. }
    ) {
        crate::tailors::install_resolution_files();
    }
}

/// Whether a verb that reaches `Context::open` can rewrite a closure or run
/// a resolution door: build, add/remove/update, x, and run and env, which
/// sync a stale project first. Such a verb loads the signing key first: a
/// bad key fails before the store is opened or a manifest touched, and no
/// closure is ever written unsigned under a configured key.
fn writes_closures(command: &cli::Command) -> bool {
    use cli::Command::*;
    matches!(
        command,
        Build { .. }
            | Run { .. }
            | Env { .. }
            | Add { .. }
            | Remove { .. }
            | Update { .. }
            | X { .. }
    )
}

/// Dispatch one parsed command to the verb's file. `sync` holds `--frozen`
/// and `--strict`; the parser has already refused them for a verb that
/// never syncs. `--frozen` is handed to the verbs that skip lock writes.
/// `--strict` is recorded once here, before any verb runs, and every policy
/// load in the process reads it, so no verb can load a policy without it.
pub fn dispatch(command: cli::Command, sync: cli::SyncFlags) -> io::Result<i32> {
    use cli::Command::*;
    crate::kernel::policy::request_strict(sync.strict);
    install_tailor_tables(&command);
    // Maintenance commands need no host-platform validation here: GC must
    // stay usable on a copied store from a host that cannot realize its
    // objects, `attest` checks the host itself, and `audit` is read-only (no
    // store open, no lease, no realization, no network).
    match command {
        Gc(args) => return gc::run(&args).map(|_| 0),
        XClean {
            ecosystem,
            from,
            tool,
        } => {
            return x::clean(x::CleanRequest {
                ecosystem,
                from,
                tool,
            })
            .map(|_| 0)
        }
        StoreRoots => return store::roots().map(|_| 0),
        StorePath => return store::path(),
        Completions { shell } => return completions::run(shell),
        audit @ Audit { .. } => return audit::run(audit),
        Doctor { json } => return doctor::run(json),
        Keygen { ref path } => return keygen::run(path),
        attest @ Attest { .. } => return attest::run(attest),
        Ls {
            ref ecosystem,
            json,
        } => return ls::run(ecosystem.as_deref(), json),
        _ => {}
    }
    // Real subcommands validate the host once before any store-touching work.
    let platform = Platform::host()?;
    // `update --self` needs the host (to pick the release asset) and
    // nothing else: no project, no store, no signing key.
    if let SelfUpdate = command {
        return selfupdate::run(platform);
    }
    // A package.json `fmt` script is deliberately resolved before opening the
    // store. This preserves the cheap script path for a non-Rust project.
    if let Fmt {
        check,
        ref ecosystem,
        ref args,
    } = command
    {
        return fmt::run(platform, check, ecosystem.as_deref(), args, sync.frozen);
    }
    // `sync` preflights (policy, pins, root registrability) before opening
    // the store, so a refused request touches nothing.
    if let Sync { fresh, records } = &command {
        return sync::run_command(platform, *fresh, sync.frozen, records).map(|_| 0);
    }
    // `update --toolchain` refuses a stale or unresolvable project the same
    // way sync does, before the store is opened, and then syncs.
    if let Update {
        toolchain: Some(ref update),
        no_sync,
        ..
    } = command
    {
        return toolchain::run(platform, update, no_sync).map(|_| 0);
    }
    let needs_maintenance = matches!(
        &command,
        Plan { .. }
            | Build { .. }
            | Run { .. }
            | Env { .. }
            | Add { .. }
            | Remove { .. }
            | Update { .. }
            | X { .. }
    );
    if writes_closures(&command) {
        crate::comforter::init_signing()?;
    }
    let ctx = Context::open(platform, needs_maintenance)?;
    match command {
        // `json` is not read here: plan's output is JSON either way, and
        // the flag only tells `main` which error renderer to use.
        Plan { .. } => plan::run(&ctx, sync.frozen).map(|_| 0),
        Build { args } => build::run(&ctx, &args, sync.frozen).map(|_| 0),
        Run { command } => run::run(&ctx, &command, sync.frozen),
        // Like `run`, `env` needs the store open: a closure's recorded
        // runtime is a store object, and its bin directory is part of the
        // PATH `env` prints.
        Env { shell } => env::run(&ctx, shell, sync.frozen),
        Sbom { output } => sbom::run(output.as_deref()).map(|_| 0),
        Add {
            specs,
            dev,
            no_sync,
        } => deps::run(
            &ctx,
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
        } => deps::run(
            &ctx,
            deps::Request {
                verb: deps::Verb::Remove,
                specs: names,
                dev,
            },
            no_sync,
        )
        .map(|_| 0),
        Update {
            names,
            no_sync,
            toolchain: _,
        } => deps::run(
            &ctx,
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
        } => x::run(
            &ctx,
            x::Request {
                ecosystem,
                from,
                tool,
                args,
            },
        ),
        Status { json } => status::run(ctx.platform, json),
        Fmt { .. }
        | Sync { .. }
        | Gc(_)
        | XClean { .. }
        | StorePath
        | StoreRoots
        | Completions { .. }
        | Doctor { .. }
        | Keygen { .. }
        | Attest { .. }
        | Ls { .. }
        | Audit { .. }
        | SelfUpdate => {
            unreachable!("handled above")
        }
    }
}
