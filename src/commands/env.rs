//! `tog env`: the environment `tog run` gives a child, printed as lines a
//! shell can eval.
//!
//! Nothing here decides what a projection contributes — `shared::projected_env`
//! collects that from the tailors, exactly as `run` does. This file is the
//! renderer: the PATH prefixes and the variables of a throwaway
//! `std::process::Command` turned into shell syntax.

use crate::cli::Shell;
use crate::commands::shared::projected_env;
use crate::kernel::context::Context;
use std::io;

/// One variable the environment sets, or removes when the value is `None`.
type Variable = (String, Option<String>);

/// Print the environment of the nearest projected root, in `shell` syntax,
/// on stdout, syncing it first when `run` would. Exit 1 with the same
/// explanation `run` gives when there is no project here at all.
pub fn run(ctx: &Context, shell: Option<Shell>, frozen: bool, strict: bool) -> io::Result<i32> {
    let shell = shell.unwrap_or_else(shell_from_environment);
    let cwd = ctx.project_dir();
    // What is printed is the environment the inputs describe, as `run`
    // gives it: a missing or stale projection is synced first. Everything
    // that sync and its children print is sent to stderr for the duration,
    // so stdout still carries the environment or nothing at all: this
    // output is evaled by a shell, and a package manager's summary in it
    // would be executed.
    let dir = crate::kernel::ui::with_stdout_on_stderr(|| {
        crate::commands::sync::ensure_current(ctx, &cwd, frozen, strict)
    })?;
    // Never spawned: the tailors' contribution is read back off it. A
    // program that does not exist is therefore the honest placeholder.
    let mut carrier = std::process::Command::new("");
    let prefix = projected_env(ctx, &dir, &cwd, &[], &mut carrier)?;
    if prefix.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no environment projected here, and no manifest to sync one from in {} (see \
                 PROJECT INPUTS in 'tog --help')",
                dir.display()
            ),
        ));
    }
    print!("{}", render(shell, &prefix, &variables(&carrier)));
    Ok(0)
}

/// The variables the tailors set on `carrier`, in the order `Command`
/// keeps them (sorted by name), so two runs of `tog env` over the same
/// projection print the same bytes.
///
/// PATH is dropped: it is printed from the prefix list instead, and `run`
/// likewise overwrites whatever a tailor put there. A name or value that is
/// not UTF-8 is dropped too — nothing tog sets is, and a lossy replacement
/// character would have the shell export a value that is not the one asked
/// for.
fn variables(carrier: &std::process::Command) -> Vec<Variable> {
    carrier
        .get_envs()
        .filter(|(name, _)| *name != "PATH")
        .filter_map(|(name, value)| {
            let name = name.to_str()?.to_string();
            match value {
                Some(value) => Some((name, Some(value.to_str()?.to_string()))),
                None => Some((name, None)),
            }
        })
        .collect()
}

/// The shell to print for when `--shell` did not say: what `$SHELL` names
/// when tog speaks it, bash otherwise. bash is the default because its
/// syntax is also what sh, dash and ksh read, so an unknown shell gets the
/// form most likely to work rather than a refusal.
fn shell_from_environment() -> Shell {
    let shell = std::env::var("SHELL").unwrap_or_default();
    match shell.rsplit('/').next().unwrap_or_default() {
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        _ => Shell::Bash,
    }
}

/// The environment as shell lines, PATH first.
///
/// The inherited PATH is referenced rather than expanded (`"$PATH"`,
/// `$PATH`), so the output does not freeze the PATH of the shell that ran
/// `tog env` into the shell that evals it.
fn render(shell: Shell, prefix: &[String], variables: &[Variable]) -> String {
    let mut out = String::new();
    let quote = |value: &str| quoted(shell, value);
    match shell {
        Shell::Fish => {
            let words: Vec<String> = prefix.iter().map(|dir| quote(dir)).collect();
            out.push_str(&format!("set -gx PATH {} $PATH\n", words.join(" ")));
            for (name, value) in variables {
                match value {
                    Some(value) => out.push_str(&format!("set -gx {name} {}\n", quote(value))),
                    None => out.push_str(&format!("set -e {name}\n")),
                }
            }
        }
        Shell::Bash | Shell::Zsh => {
            out.push_str(&format!(
                "export PATH={}:\"$PATH\"\n",
                quote(&prefix.join(":"))
            ));
            for (name, value) in variables {
                match value {
                    Some(value) => out.push_str(&format!("export {name}={}\n", quote(value))),
                    None => out.push_str(&format!("unset {name}\n")),
                }
            }
        }
    }
    out
}

/// A value as one shell word. Always quoted, even when nothing in it needs
/// it: what a store path or a project path contains is not tog's to
/// predict, and a quoting rule that only sometimes applies is a rule that
/// eventually gets it wrong.
///
/// `kernel::ui::shell_word` quotes for a human reading a command line and
/// leaves plain words bare; this quotes for a shell that will eval the
/// result.
fn quoted(shell: Shell, value: &str) -> String {
    let escaped = match shell {
        // fish reads `\\` and `\'` inside single quotes; a POSIX shell
        // reads nothing at all there, so only the closing quote has to be
        // escaped, by ending the quoted run for it.
        Shell::Fish => value.replace('\\', "\\\\").replace('\'', "\\'"),
        Shell::Bash | Shell::Zsh => value.replace('\'', "'\\''"),
    };
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variable(name: &str, value: Option<&str>) -> Variable {
        (name.to_string(), value.map(str::to_string))
    }

    fn fixture() -> (Vec<String>, Vec<Variable>) {
        (
            vec![
                "/proj/.venv/bin".to_string(),
                "/store/objects/abc-node/bin".to_string(),
            ],
            vec![
                variable("VIRTUAL_ENV", Some("/proj/.venv")),
                variable("PYTHONDONTWRITEBYTECODE", Some("1")),
                // A path a person chose, with a quote in it.
                variable("CARGO_HOME", Some("/it's/here/.tog/cargo-home")),
                // A variable the projection removes.
                variable("RUSTUP_TOOLCHAIN", None),
            ],
        )
    }

    #[test]
    fn env_prints_the_run_environment_as_exports() {
        let (prefix, variables) = fixture();
        assert_eq!(
            render(Shell::Bash, &prefix, &variables),
            "export PATH='/proj/.venv/bin:/store/objects/abc-node/bin':\"$PATH\"\n\
             export VIRTUAL_ENV='/proj/.venv'\n\
             export PYTHONDONTWRITEBYTECODE='1'\n\
             export CARGO_HOME='/it'\\''s/here/.tog/cargo-home'\n\
             unset RUSTUP_TOOLCHAIN\n"
        );
        // bash and zsh are the same POSIX sh syntax.
        assert_eq!(
            render(Shell::Zsh, &prefix, &variables),
            render(Shell::Bash, &prefix, &variables)
        );
    }

    #[test]
    fn fish_gets_a_path_list_and_its_own_unset() {
        let (prefix, variables) = fixture();
        assert_eq!(
            render(Shell::Fish, &prefix, &variables),
            "set -gx PATH '/proj/.venv/bin' '/store/objects/abc-node/bin' $PATH\n\
             set -gx VIRTUAL_ENV '/proj/.venv'\n\
             set -gx PYTHONDONTWRITEBYTECODE '1'\n\
             set -gx CARGO_HOME '/it\\'s/here/.tog/cargo-home'\n\
             set -e RUSTUP_TOOLCHAIN\n"
        );
        // A backslash is an escape inside fish's single quotes and nothing
        // inside a POSIX shell's.
        assert_eq!(quoted(Shell::Fish, "a\\b"), "'a\\\\b'");
        assert_eq!(quoted(Shell::Bash, "a\\b"), "'a\\b'");
    }

    /// PATH is printed from the prefix list, so a tailor that also set it
    /// must not have it printed a second time — `run` overwrites it too.
    #[test]
    fn the_variable_list_leaves_path_to_the_prefix() {
        let mut carrier = std::process::Command::new("");
        carrier.env("PATH", "/nowhere");
        carrier.env("VIRTUAL_ENV", "/proj/.venv");
        carrier.env_remove("RUSTUP_HOME");
        assert_eq!(
            variables(&carrier),
            vec![
                variable("RUSTUP_HOME", None),
                variable("VIRTUAL_ENV", Some("/proj/.venv")),
            ]
        );
    }
}
