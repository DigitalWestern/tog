//! `tog run <cmd>`: run a command inside the projected environment.
//! Every tailor contributes its PATH prefixes and environment through
//! `Tailor::run_env`. A command that names a project script (a
//! package.json script) runs as that script's steps instead, with the
//! variables its tailor's `Tailor::projected_script` names.

use crate::commands::shared::{self, child_status_code};
use crate::commands::sync;
use crate::kernel::context::Context;
use crate::kernel::supervise;
use crate::tailors::{self, ScriptRun};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

/// Why `program` cannot run: it is the runtime of an ecosystem the project
/// at `dir` has (`node` in a Node project), named bare, and no `prefix`
/// entry provides it, so the host's would run in its place.
fn unprovided_runtime(dir: &Path, program: &str, prefix: &[String]) -> io::Result<Option<String>> {
    if program.contains('/') {
        return Ok(None);
    }
    let Some(tailor) = tailors::detected(dir)?
        .into_iter()
        .find(|tailor| tailor.runtime_programs().contains(&program))
    else {
        return Ok(None);
    };
    let provided = prefix.iter().any(|entry| {
        Path::new(entry)
            .join(program)
            .metadata()
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    });
    Ok((!provided).then(|| {
        format!(
            "'{program}' is the {} runtime, but the project's environment does not provide it, \
             and tog does not run the host's in its place; 'tog doctor' says what is missing",
            tailor.id()
        )
    }))
}

/// The project script `cmd` names in a projection under `dir`: the first
/// tailor's `Tailor::projected_script`.
fn projected_script(
    dir: &std::path::Path,
    cwd: &std::path::Path,
    cmd: &[String],
) -> io::Result<Option<ScriptRun>> {
    for tailor in tailors::registry() {
        if let Some(script) = tailor.projected_script(dir, cwd, cmd)? {
            return Ok(Some(script));
        }
    }
    Ok(None)
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
        return Err(crate::kernel::error::refused(
            io::ErrorKind::InvalidInput,
            refusal,
        ));
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
    let script = projected_script(&dir, &cwd, cmd)?;
    if let Some(refusal) = package_script_refusal(&dir, script.is_some()) {
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
                 from in {} (see 'tog help inputs')",
                cmd[0],
                dir.display()
            ),
        ));
    }
    // A package.json script named like a runtime (`go`, `python`) is a
    // script: its steps run, not a program of that name.
    if script.is_none() {
        if let Some(refusal) = unprovided_runtime(&dir, &cmd[0], &prefix)? {
            return Err(io::Error::new(io::ErrorKind::NotFound, refusal));
        }
    }
    let path = std::env::var("PATH").unwrap_or_default();
    prefix.push(path);
    command.env("PATH", prefix.join(":"));
    if let Some(script) = script {
        let envs: Vec<_> = command
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(|value| value.to_os_string())))
            .collect();
        let scrubbed: Vec<_> = std::env::vars_os()
            .map(|(key, _)| key)
            .chain(envs.iter().map(|(key, _)| key.clone()))
            .filter(|key| key.to_string_lossy().starts_with(script.scrubbed_prefix))
            .collect();
        for (label, text) in &script.steps {
            crate::kernel::ui::note(&format!("> {label}: {text}"));
            let mut step = std::process::Command::new("/bin/sh");
            step.arg("-c").arg(text).current_dir(&dir);
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
            for key in &scrubbed {
                step.env_remove(key);
            }
            if let Some(var) = script.step_label_var {
                step.env(var, label);
            }
            for (key, value) in &script.env {
                step.env(key, value);
            }
            let status = match supervise::local_status(&mut step, activity) {
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
                            format!("run {} {label}: {error}", script.noun),
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
    let status = supervise::child_status(run_users_command(&mut command, activity))?;
    Ok(child_status_code(&status))
}

/// Run the command the user typed after `tog run`, which may itself be a
/// dependency tool (`tog run cargo build`, `tog run npm test`): it is the
/// user's program in the user's projection, not a resolution tog starts,
/// so neither the door nor the host-local tripwire applies to it.
// Reviewed site (tests/architecture.rs): the user's own program, which may be any tool.
#[allow(clippy::disallowed_methods)]
fn run_users_command(
    command: &mut std::process::Command,
    activity: &crate::kernel::activity::StoreActivity,
) -> io::Result<std::process::ExitStatus> {
    supervise::status(command, activity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// A runtime of an ecosystem the project has comes from the project's
    /// prefixes or not at all: never the host's after them.
    #[test]
    fn a_projected_ecosystems_runtime_never_falls_through_to_the_host() {
        let project = TempDir::new();
        std::fs::write(project.0.join("package.json"), r#"{"name": "p"}"#).unwrap();
        let bin = TempDir::new();
        let prefix = vec![bin.0.to_string_lossy().into_owned()];
        let why = unprovided_runtime(&project.0, "node", &prefix)
            .unwrap()
            .unwrap();
        assert!(why.contains("'node' is the node runtime"), "{why}");
        assert!(why.contains("does not run the host's"), "{why}");
        assert!(why.contains("tog doctor"), "{why}");
        assert!(!why.contains("run 'tog' to sync"), "{why}");
        // A file named like the runtime that cannot be executed is not it.
        let node = bin.0.join("node");
        std::fs::write(&node, "").unwrap();
        assert!(unprovided_runtime(&project.0, "node", &prefix)
            .unwrap()
            .is_some());
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            unprovided_runtime(&project.0, "node", &prefix).unwrap(),
            None
        );
        // The programs that ship in the runtime count as the runtime.
        for program in ["npm", "npx"] {
            assert!(
                unprovided_runtime(&project.0, program, &prefix)
                    .unwrap()
                    .is_some(),
                "{program}"
            );
        }
        for (manifest, program) in [
            ("requirements.txt", "pip"),
            ("Gemfile", "bundle"),
            ("go.mod", "gofmt"),
            ("mix.exs", "iex"),
        ] {
            let other = TempDir::new();
            std::fs::write(other.0.join(manifest), "").unwrap();
            assert!(
                unprovided_runtime(&other.0, program, &[])
                    .unwrap()
                    .is_some(),
                "{program}"
            );
        }
        // Another ecosystem's runtime, any other program, and an explicit
        // path are the user's to name.
        for program in ["python", "git", "/usr/bin/node", "./node"] {
            assert_eq!(
                unprovided_runtime(&project.0, program, &[]).unwrap(),
                None,
                "{program}"
            );
        }
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
        // Bare `yarn` installs; bare `npm`, `pnpm` and `bun` print help.
        let message = refusal(&["yarn"]).expect("bare yarn is refused");
        assert!(message.contains("node_modules"), "{message}");
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
            (vec!["bun", "--cwd=.", "a", "x"], "bun a"),
            (
                vec!["/x/bin/npm", "--prefix", ".", "install"],
                "npm install",
            ),
            // An option's value that spells a subcommand is read as one. That
            // fails safe: a harmless command is refused, an install never runs.
            (vec!["npm", "--prefix", "install", "run"], "npm install"),
            // npm reads camelCase as kebab-case and a unique prefix as the
            // command it starts.
            (vec!["npm", "installTest"], "npm install-test"),
            (vec!["npm", "dedu"], "npm dedupe"),
            (vec!["npm", "upd"], "npm update"),
            (vec!["npm", "cleanInstall"], "npm clean-install"),
            // A harmless command named by abbreviation may be an option's
            // value, so the scan reads on for an install.
            (vec!["npm", "--prefix", "doc", "install"], "npm install"),
            // An install another command runs.
            (vec!["npm", "exec", "--", "npm", "install"], "npm install"),
            (vec!["npm", "x", "-c", "cd web && npm ci"], "npm ci"),
            (vec!["npx", "-p", "npm", "npm", "i", "x"], "npm i"),
            (vec!["npx", "yarn", "add", "x"], "yarn add"),
            (vec!["pnpm", "dlx", "npm", "install"], "npm install"),
            (
                vec!["yarn", "dlx", "-p", "pnpm", "pnpm", "add", "x"],
                "pnpm add",
            ),
            (vec!["bunx", "/x/bin/bun", "install"], "bun install"),
            // A program named with its version is the same program.
            (vec!["npx", "npm@10", "install"], "npm install"),
            (vec!["npx", "pnpm@9", "install"], "pnpm install"),
            (vec!["pnpm", "dlx", "pnpm@9", "install"], "pnpm install"),
            (vec!["npx", "yarn@1", "add", "x"], "yarn add"),
            // A shell line given as an option's value, or glued to `&&`.
            (vec!["npm", "exec", "--call=npm ci"], "npm ci"),
            (vec!["npx", "--call=npm ci"], "npm ci"),
            (vec!["npx", "--call=yarn"], "yarn"),
            (vec!["npm", "exec", "-c", "cd web&&npm ci"], "npm ci"),
            (vec!["npx", "-c", "true;(pnpm i)"], "pnpm i"),
            (vec!["npx", "-c", "CI=1 npm ci"], "npm ci"),
            // A runner named by abbreviation is not lost to a later exact
            // word (`x` is npm's own `exec` alias).
            (vec!["npm", "exe", "--", "bun", "a", "x"], "bun a"),
            // A subcommand whose remaining words are the program's own again.
            (
                vec!["yarn", "workspaces", "foreach", "-A", "install"],
                "yarn install",
            ),
            (vec!["yarn", "workspaces", "focus"], "yarn focus"),
            (vec!["pnpm", "with", "current", "add", "x"], "pnpm add"),
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
            // Bare bun prints its help.
            vec!["bun"],
            vec!["bun", "--cwd", "."],
            // npm abbreviations of harmless commands, and an ambiguous one.
            vec!["npm", "outd"],
            vec!["npm", "runScript", "build"],
            vec!["npm", "d"],
            // A runner that runs something other than an install.
            vec!["npx", "eslint", "--fix", "."],
            vec!["npm", "exec", "--", "tsc", "-p", "."],
            vec!["npx", "-c", "npm run build"],
            vec!["pnpm", "dlx", "create-vite", "app"],
            // Only the word in the program's place is a program: the words
            // after it are its own arguments.
            vec!["npx", "create-turbo@latest", "-m", "yarn"],
            vec!["npx", "--yes", "create-turbo", "-m", "yarn"],
            vec!["npm", "exec", "--", "create-vite", "app", "--pm", "pnpm"],
            vec!["npx", "--package=yarn", "yarn", "--version"],
            vec!["npx", "-p", "yarn", "yarn", "--version"],
            vec!["yarn", "workspaces", "foreach", "-A", "run", "build"],
            vec!["yarn", "workspaces", "list"],
            vec!["yarn", "workspaces"],
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
