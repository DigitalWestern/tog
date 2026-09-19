//! The `tog` binary: parse argv, set up output, resolve the implicit
//! forms, and hand the command to `commands::dispatch`.

use tog::cli;
use tog::commands;
use tog::kernel::ui;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (options, pending) = match cli::parse(&args) {
        Ok(cli::Parsed::Run(invocation)) => (
            invocation.options,
            commands::Pending::Command(invocation.command),
        ),
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
    let command = match commands::resolve(pending) {
        Ok(command) => command,
        Err(error) => {
            ui::error(&error.to_string());
            exit(cli::EXIT_FAILURE);
        }
    };
    let code = match commands::dispatch(command) {
        Ok(code) => code,
        Err(error) => {
            ui::error(&error.to_string());
            cli::EXIT_FAILURE
        }
    };
    exit(code);
}
