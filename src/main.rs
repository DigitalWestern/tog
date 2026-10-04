//! The `tog` binary: parse argv, set up output, resolve the implicit
//! forms, and hand the command to `commands::dispatch`.

use std::process::exit;
use tog::cli;
use tog::commands;
use tog::kernel::ui;

fn main() {
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
    let report_failure = |error: &std::io::Error| match tog::kernel::store::refusal_fix(error) {
        Some(fix) if json => ui::error_json_with_fix(&error.to_string(), fix),
        Some(fix) => ui::error_with_fix(&error.to_string(), fix),
        None => report(&error.to_string()),
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
        Ok(command) => command,
        Err(error) => {
            report_failure(&error);
            exit(cli::EXIT_FAILURE);
        }
    };
    let code = match commands::dispatch(command, options.sync) {
        Ok(code) => code,
        Err(error) => {
            report_failure(&error);
            cli::EXIT_FAILURE
        }
    };
    if bare && code == 0 && !ui::quiet() {
        print!("\n{}", cli::sync_footer());
    }
    exit(code);
}
