//! `tog run <cmd>`: run a command inside the projected environment.
//! Every tailor contributes its PATH prefixes and environment through
//! `Tailor::run_env`; the package.json script protocol (npm lifecycle
//! events, `npm_*` variables) is the one ecosystem-specific piece that stays
//! here, because it decides *how* the command runs, not what it sees.

use crate::commands::shared::{self, child_status_code};
use crate::commands::sync;
use crate::kernel::context::Context;
use crate::kernel::supervise;
use crate::tailors::{self, node};
use std::io;

/// Why a resolved package.json script may not run in `dir`: the first
/// projection there that forbids it (`Tailor::refused_package_script`).
fn package_script_refusal(dir: &std::path::Path, script_resolved: bool) -> Option<String> {
    if !script_resolved {
        return None;
    }
    tailors::registry()
        .iter()
        .find_map(|tailor| tailor.refused_package_script(dir))
}

/// The habits a projected environment cannot honour, refused with the verb
/// that replaces them.
///
/// A projection is a symlink into the immutable store, so installing into
/// one either fails with the tool's own confusing error or silently leaves
/// the closure stale. Each tailor refuses its own package manager's
/// mutating verbs (`Tailor::refused_command`); what is refused here is the
/// habit no ecosystem owns: activating an environment.
pub(crate) fn refused_command(cmd: &[String]) -> Option<String> {
    let program = cmd.first()?.rsplit('/').next()?;
    let argument = |index: usize| cmd.get(index).map(String::as_str).unwrap_or_default();
    // `tog run activate` and `tog run source .venv/bin/activate`: there is
    // no activate script to find.
    if program == "activate"
        || (matches!(program, "source" | ".") && argument(1).contains("activate"))
    {
        return Some(
            "a tog environment has no activate script: 'tog run <command>' is the \
             activation, and it applies to one command instead of a shell session. \
             'tog run python', 'tog run pytest', 'tog run npm test' all see the \
             projected environment"
                .to_string(),
        );
    }
    tailors::registry()
        .iter()
        .find_map(|tailor| tailor.refused_command(cmd))
}

pub fn run(ctx: &Context, cmd: &[String], frozen: bool) -> io::Result<i32> {
    let activity = &ctx.activity;
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run: no command given",
        ));
    }
    // Before the environment is even looked up: these fail the same way in
    // every project, and the explanation is the point.
    if let Some(refusal) = refused_command(cmd) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, refusal));
    }
    // Walk up from cwd to the nearest projected root, so `tog run`
    // works from workspace subdirectories like npm run does.
    let cwd = ctx.project_dir();
    // The environment the command runs in is the one the project's inputs
    // describe, so a missing or stale projection is synced here rather than
    // reported, and the root to read is the one that sync leaves behind.
    // Outside a project this finds nothing to sync and the refusal below
    // explains.
    let dir = sync::ensure_current(ctx, &cwd, frozen)?;
    let package_json = node::tailor::projected_package_json(&dir, &cwd)?;
    let script_steps = package_json
        .as_ref()
        .map(|(_, json)| node::script_commands_from_package(json, &cmd[0], &cmd[1..]))
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
    if let Some(refusal) = package_script_refusal(&dir, script_steps.is_some()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, refusal));
    }
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    let mut prefix = shared::projected_env(ctx, &dir, &cwd, cmd, &mut command)?;
    if prefix.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no environment projected here for command '{}', and no manifest to sync one \
                 from in {} (see PROJECT INPUTS in 'tog --help')",
                cmd[0],
                dir.display()
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
            crate::kernel::ui::note(&format!("> {event}: {script}"));
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
            let status = match supervise::status(&mut step, activity) {
                Ok(status) => status,
                // An interrupt ends the chain: the step's own exit code
                // when it failed, the signal's when it survived.
                Err(error) => match supervise::interrupted(&error) {
                    Some(interrupted) if interrupted.status.success() => {
                        return Ok(128 + interrupted.signal);
                    }
                    Some(interrupted) => return Ok(child_status_code(&interrupted.status)),
                    None => {
                        return Err(io::Error::new(
                            error.kind(),
                            format!("run npm script {event}: {error}"),
                        ));
                    }
                },
            };
            if !status.success() {
                return Ok(child_status_code(&status));
            }
        }
        return Ok(0);
    }
    let status = supervise::child_status(supervise::status(&mut command, activity))?;
    Ok(child_status_code(&status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use crate::tailors::dotnet;

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

    fn refusal(words: &[&str]) -> Option<String> {
        refused_command(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>())
    }

    /// The three daily-use habits a projection cannot honour, each refused
    /// with the tog verb that replaces it.
    #[test]
    fn immutable_environments_refuse_pip_activate_and_npm_install() {
        let pip = refusal(&["pip", "install", "flask"]).expect("pip install is refused");
        assert!(pip.contains("immutable"), "{pip}");
        assert!(pip.contains("tog add <package>"), "{pip}");
        assert!(refusal(&["pip3", "uninstall", "flask"]).is_some());
        // An absolute path is the same program, and an option before the
        // verb does not hide it.
        assert!(refusal(&["/usr/bin/pip", "install", "flask"]).is_some());
        assert!(refusal(&["pip", "-q", "install", "flask"]).is_some());
        // A value-taking option puts a bare word before the subcommand;
        // reading that word as the subcommand would let the install run.
        assert!(refusal(&["pip", "--index-url", "https://m/simple", "install", "flask"]).is_some());
        assert!(refusal(&[
            "python",
            "-m",
            "pip",
            "--index-url",
            "https://m/simple",
            "install",
            "flask"
        ])
        .is_some());
        // easy_install has no subcommand: installing is all it does.
        assert!(refusal(&["easy_install", "flask"]).is_some());
        // The same pip by another road.
        let module = refusal(&["python", "-m", "pip", "install", "flask"])
            .expect("python -m pip install is refused");
        assert!(module.contains("python -m pip install"), "{module}");
        assert!(refusal(&["python3.12", "-m", "pip", "uninstall", "flask"]).is_some());
        // A value-taking python option before -m does not hide it.
        assert!(refusal(&["python", "-X", "utf8", "-m", "pip", "install", "flask"]).is_some());

        let activate = refusal(&["activate"]).expect("activate is refused");
        assert!(activate.contains("no activate script"), "{activate}");
        assert!(activate.contains("tog run <command>"), "{activate}");
        assert!(refusal(&["source", ".venv/bin/activate"]).is_some());

        let npm = refusal(&["npm", "install", "is-odd"]).expect("npm install is refused");
        assert!(npm.contains("node_modules"), "{npm}");
        // `install` and `ci` install the lockfile: the bare `tog` replaces them.
        assert!(
            npm.contains("'tog' sets node_modules up from the lockfile"),
            "{npm}"
        );
        assert!(refusal(&["npm", "ci"])
            .unwrap()
            .contains("'tog' sets node_modules up from the lockfile"));
        // `add`/`remove` change the lockfile: `tog add`/`tog remove` do.
        let add = refusal(&["pnpm", "add", "is-odd"]).expect("pnpm add is refused");
        assert!(add.starts_with("'pnpm add' would replace"), "{add}");
        assert!(add.contains("edit dependencies through tog"), "{add}");
        // Bare `yarn` and bare `bun` install; bare `npm`/`pnpm` print help.
        for bare in [["yarn"], ["bun"]] {
            let message = refusal(&bare).unwrap_or_else(|| panic!("{bare:?} is refused"));
            assert!(message.contains("node_modules"), "{bare:?}: {message}");
        }
        assert!(refusal(&["yarn", "remove", "is-odd"]).is_some());
    }

    /// A global option before the subcommand does not hide it: its value is
    /// a bare word too, so taking the first bare word as the subcommand
    /// would let the install run and replace the projection.
    #[test]
    fn a_global_option_does_not_hide_an_npm_family_install() {
        for (words, invocation) in [
            (vec!["npm", "--prefix", ".", "install"], "npm install"),
            (vec!["npm", "--loglevel", "silent", "ci"], "npm ci"),
            (vec!["npm", "--prefix=.", "i", "is-odd"], "npm i"),
            (vec!["pnpm", "-C", ".", "add", "x"], "pnpm add"),
            (vec!["pnpm", "--dir", ".", "install"], "pnpm install"),
            (vec!["pnpm", "recursive", "install"], "pnpm install"),
            (vec!["yarn", "--cwd", ".", "add", "x"], "yarn add"),
            (vec!["yarn", "workspace", "web", "add", "x"], "yarn add"),
            (vec!["yarn", "--cwd", "."], "yarn"),
            (vec!["yarn", "--silent"], "yarn"),
            (vec!["bun", "--cwd", ".", "install"], "bun install"),
            (vec!["bun", "--cwd", "."], "bun"),
            (vec!["bun", "--cwd=.", "a", "x"], "bun a"),
            (
                vec!["/x/bin/npm", "--prefix", ".", "install"],
                "npm install",
            ),
            // An option's value that spells a subcommand is read as one. That
            // fails safe: a harmless command is refused, an install never runs.
            (vec!["npm", "--prefix", "install", "run"], "npm install"),
        ] {
            let message = refusal(&words).unwrap_or_else(|| panic!("{words:?} is refused"));
            assert!(
                message.starts_with(&format!("'{invocation}' would replace")),
                "{words:?}: {message}"
            );
        }
        // The advice still follows the subcommand, not the first word.
        assert!(refusal(&["npm", "--prefix", ".", "ci"])
            .unwrap()
            .contains("'tog' sets node_modules up from the lockfile"));
        assert!(refusal(&["pnpm", "-C", ".", "add", "x"])
            .unwrap()
            .contains("edit dependencies through tog"));
        assert!(refusal(&["yarn", "--cwd", "."])
            .unwrap()
            .contains("'tog' sets node_modules up from the lockfile"));
    }

    /// Everything else still runs. A refusal that caught `npm run build`,
    /// `pip list`, or a program merely named after one would be worse than
    /// the raw error it replaces.
    #[test]
    fn running_a_command_in_the_environment_is_not_refused() {
        for words in [
            // Reading the environment is not changing it.
            vec!["pip", "list"],
            vec!["pip", "freeze"],
            vec!["pip", "show", "flask"],
            vec!["pip", "check"],
            vec!["pip", "--version"],
            vec!["pip", "download", "flask"],
            vec!["python", "-m", "pip", "list"],
            vec!["python", "-m", "pytest"],
            // `-m` after the script belongs to the script, not to python.
            vec!["python", "script.py", "-m", "pip", "install", "flask"],
            vec!["python", "-c", "print(1)", "-m", "pip", "install", "x"],
            // A value-taking python option does not end its option list.
            vec!["python", "-X", "utf8", "-m", "pip", "list"],
            // npm verbs that do not touch node_modules.
            vec!["npm", "run", "build"],
            vec!["npm", "test"],
            vec!["npm", "ls"],
            vec!["npm"],
            vec!["pnpm"],
            vec!["yarn", "why", "is-odd"],
            // A global option before a verb that leaves node_modules alone.
            vec!["npm", "--prefix", ".", "run", "build"],
            vec!["npm", "--prefix", ".", "ls"],
            vec!["pnpm", "-C", ".", "why", "is-odd"],
            // Asking yarn or bun about itself is not a bare install.
            vec!["yarn", "--version"],
            vec!["yarn", "-v"],
            vec!["yarn", "--help"],
            vec!["yarn", "-h"],
            vec!["bun", "--version"],
            vec!["bun", "--help"],
            vec!["bun", "--cwd", ".", "--help"],
            // A script or a file to run is not a bare install either.
            vec!["yarn", "build"],
            vec!["yarn", "--cwd", ".", "build"],
            vec!["yarn", "workspace", "web", "run", "build"],
            vec!["bun", "index.ts"],
            vec!["bun", "--cwd", ".", "./server.ts"],
            vec!["bun", "-e", "console.log(1)"],
            vec!["bun", "--eval=console.log(1)"],
            // `bun upgrade` upgrades bun itself, not node_modules.
            vec!["bun", "upgrade"],
            // Not these programs at all.
            vec!["pytest"],
            vec!["source", "./scripts/env.sh"],
            vec!["pip-tools", "compile"],
            vec!["pipx", "install", "httpie"],
        ] {
            assert!(refusal(&words).is_none(), "{words:?}");
        }
    }

    #[test]
    fn dotnet_projection_refuses_resolved_package_scripts() {
        let scratch = TempDir::named("run-script");
        let dir = scratch.0.clone();
        std::fs::create_dir_all(dir.join(".tog/closures")).unwrap();
        assert!(package_script_refusal(&dir, true).is_none());
        std::fs::write(dir.join(".tog/closures/dotnet.json"), "{}").unwrap();
        let refusal = package_script_refusal(&dir, true).expect("refused");
        assert!(refusal.contains("tog build dotnet"), "{refusal}");
        assert!(package_script_refusal(&dir, false).is_none());
    }
}
