//! The `tog` binary: parse argv, set up output, resolve the implicit
//! forms, and hand the command to `commands::dispatch`.

use std::process::exit;
use tog::cli;
use tog::commands;
use tog::kernel::ui;

fn main() {
    // Before parsing: resolving a first word (`tog app.ts`) can already
    // read a project's toolchain sources.
    tog::tailors::install_kernel_tables();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (options, pending) = match cli::parse(&args) {
        Ok(cli::Parsed::Run(invocation)) => (
            invocation.options,
            commands::Pending::Command(invocation.command),
        ),
        Ok(cli::Parsed::Relay(relay)) => exit(commands::relay(relay)),
        Ok(cli::Parsed::Print(text)) => {
            print!("{text}");
            exit(0);
        }
        Ok(cli::Parsed::Implicit(options)) => (options, commands::Pending::Implicit),
        Ok(cli::Parsed::Script {
            options,
            name,
            args,
            message,
        }) => (
            options,
            commands::Pending::Script {
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
    // Under `--json` stdout is the document and stderr is the failure, as
    // a JSON object: a script that asked for JSON must never have to parse
    // an English sentence to find out what went wrong.
    let json = match &pending {
        commands::Pending::Command(command) => command.json_output(),
        _ => false,
    };
    let report = |message: &str| {
        if json {
            ui::error_json(message)
        } else {
            ui::error(message)
        }
    };
    // A store this tog refuses to open fails with the reason and, on its
    // own line, the one command that is the way out.
    // Under `--json` the failure's class rides along as its own key.
    let report_failure = |error: &std::io::Error| {
        let fix = tog::kernel::store::refusal_fix(error);
        if json {
            let class = tog::kernel::error::class_of(error).map(|class| class.name());
            return ui::failure_json(&error.to_string(), fix, class);
        }
        match fix {
            Some(fix) => ui::error_with_fix(&error.to_string(), fix),
            None => report(&error.to_string()),
        }
    };
    if let Err(error) = ui::init(options.quiet, options.verbose, options.no_color) {
        report(&format!("cannot set up output: {error}"));
        exit(cli::EXIT_FAILURE);
    }
    if let Some(dir) = &options.directory {
        if let Err(error) = std::env::set_current_dir(dir) {
            report(&format!(
                "cannot change directory to {}: {error}",
                dir.display()
            ));
            exit(cli::EXIT_FAILURE);
        }
        ui::trace(&format!("working directory: {}", dir.display()));
    }
    // A bare `tog` is a sync *and* an orientation: the one word a newcomer
    // types should also show them what comes next. A short footer follows a
    // sync that succeeded (the full help would scroll the sync's own result
    // away), so a failure stays the last thing on screen, and `-q` (results
    // only) suppresses it, which is what CI would use.
    let bare = matches!(pending, commands::Pending::Implicit);
    let command = match commands::resolve(pending) {
        Ok(commands::Resolved::Command(command)) => command,
        Ok(commands::Resolved::Help { note }) => {
            ui::note(&note);
            print!("{}", cli::usage());
            exit(0);
        }
        Ok(commands::Resolved::Usage(rendered)) => {
            eprint!("{rendered}");
            exit(cli::EXIT_USAGE);
        }
        Err(error) => {
            report_failure(&error);
            exit(failure_code(&error));
        }
    };
    let code = match commands::dispatch(command, options.sync) {
        Ok(code) => code,
        Err(error) => {
            report_failure(&error);
            failure_code(&error)
        }
    };
    if let Some(footer) = cli::after_command(bare, code, ui::quiet()) {
        print!("{footer}");
    }
    exit(code);
}

/// The exit code for a command that failed with `error`: `128 + signal` when
/// a signal asked tog to stop (130 for Ctrl-C), the shell's convention and
/// what `tog run` already passes on from its child; the class's own status
/// for a classified failure (`kernel::error::Class::exit_code`); and 1
/// otherwise.
fn failure_code(error: &std::io::Error) -> i32 {
    if let Some(signal) = tog::kernel::supervise::stop_signal(error) {
        return 128 + signal;
    }
    tog::kernel::error::class_of(error).map_or(cli::EXIT_FAILURE, |class| class.exit_code())
}
