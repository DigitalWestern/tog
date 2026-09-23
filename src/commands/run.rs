//! `tog run <cmd>`: run a command inside the projected environment.
//! Every tailor contributes its PATH prefixes and environment through
//! `Tailor::run_env`; the package.json script protocol (npm lifecycle
//! events, `npm_*` variables) is the one ecosystem-specific piece that stays
//! here, because it decides *how* the command runs, not what it sees.

use crate::comforter;
use crate::commands::shared::{self, child_status_code};
use crate::commands::sync;
use crate::kernel::context::Context;
use crate::kernel::supervise;
use crate::tailors::node;
use std::io;

fn refuse_dotnet_script(has_dotnet_closure: bool, script_resolved: bool) -> bool {
    has_dotnet_closure && script_resolved
}

/// The npm-family subcommands that write into `node_modules`. `npm run`,
/// `npm test`, `npm ls` and the rest are untouched: only the ones that
/// install are a problem.
const NODE_INSTALL_VERBS: &[&str] = &[
    "install",
    "i",
    "add",
    "ci",
    "uninstall",
    "remove",
    "rm",
    "update",
    "upgrade",
    "link",
    "dedupe",
];

/// The npm-family verbs that install the lockfile rather than change it.
/// The advice differs: the bare `tog` replaces these, not `tog add`.
const NODE_REINSTALL_VERBS: &[&str] = &["install", "i", "ci"];

/// The pip subcommands that try to write into the environment. Reading
/// commands (`pip list`, `pip freeze`, `pip show`, `pip check`) work
/// against a projected .venv and are none of tog's business.
const PIP_MUTATING_VERBS: &[&str] = &["install", "uninstall", "wheel"];

/// Every pip subcommand, so an option's *value* is never mistaken for one.
/// `pip --index-url x install y` has two bare words before the package;
/// taking the first would read the URL as the subcommand and let an
/// install through.
const PIP_SUBCOMMANDS: &[&str] = &[
    "install",
    "uninstall",
    "wheel",
    "download",
    "freeze",
    "inspect",
    "list",
    "show",
    "check",
    "config",
    "search",
    "cache",
    "index",
    "hash",
    "completion",
    "debug",
    "help",
];

/// pip's subcommand: the first word that is one, wherever it sits among
/// the global options.
fn pip_subcommand(cmd: &[String], from: usize) -> &str {
    cmd.iter()
        .skip(from)
        .map(String::as_str)
        .find(|word| PIP_SUBCOMMANDS.contains(word))
        .unwrap_or_default()
}

/// Python options that take a separate value, so the value is not mistaken
/// for the script name when looking for `-m`.
const PYTHON_VALUE_OPTIONS: &[&str] = &["-X", "-W", "-Q", "--check-hash-based-pycs"];

/// `python -m pip install ...` reaches the same pip by another road.
///
/// `-m` is only python's while it is still an option: in
/// `python script.py -m pip install x` the `-m` belongs to the script, and
/// refusing that would refuse a program tog knows nothing about.
fn python_module_pip_verb(cmd: &[String]) -> Option<&str> {
    let program = cmd.first()?.rsplit('/').next()?;
    if !program.starts_with("python") {
        return None;
    }
    let mut index = 1;
    while let Some(word) = cmd.get(index).map(String::as_str) {
        if word == "-m" {
            // `-m <module>` ends python's own options.
            if cmd.get(index + 1).map(String::as_str)? != "pip" {
                return None;
            }
            return Some(pip_subcommand(cmd, index + 2));
        }
        if !word.starts_with('-') {
            // The script or the `-c` program: everything after is its own.
            return None;
        }
        index += if PYTHON_VALUE_OPTIONS.contains(&word) {
            2
        } else {
            1
        };
    }
    None
}

fn pip_refusal(program: &str, verb: &str) -> String {
    format!(
        "'{program} {verb}' cannot change a tog environment: .venv is a projection of an \
         immutable store object, so nothing can be installed into or removed from it. Add the \
         dependency instead ('tog add <package>', 'tog remove <package>'), then \
         'tog run python ...'"
    )
}

/// The habits a projected environment cannot honour, refused with the verb
/// that replaces them.
///
/// A projection is a symlink into the immutable store. `pip install` finds
/// no pip and reports a missing file; `npm install` succeeds, silently
/// replaces the symlink with a real directory, and the next `tog status`
/// says `missing`. Both are better refused with an explanation than left
/// to produce their own. Only the mutating verbs are refused: reading the
/// environment with `pip list` or `npm ls` is fine.
pub(crate) fn refused_command(cmd: &[String]) -> Option<String> {
    let program = cmd.first()?.rsplit('/').next()?;
    let argument = |index: usize| cmd.get(index).map(String::as_str).unwrap_or_default();
    if let Some(verb) = python_module_pip_verb(cmd) {
        if PIP_MUTATING_VERBS.contains(&verb) {
            return Some(pip_refusal("python -m pip", verb));
        }
        return None;
    }
    match program {
        "pip" | "pip3" | "easy_install" => {
            let verb = pip_subcommand(cmd, 1);
            // easy_install has no subcommand: installing is all it does.
            (program == "easy_install" || PIP_MUTATING_VERBS.contains(&verb))
                .then(|| pip_refusal(program, verb))
        }
        // `tog run activate` and `tog run source .venv/bin/activate`: there
        // is no activate script to find.
        "activate" | "source" | "."
            if program == "activate" || argument(1).contains("activate") =>
        {
            Some(
                "a tog environment has no activate script: 'tog run <command>' is the \
                 activation, and it applies to one command instead of a shell session. \
                 'tog run python', 'tog run pytest', 'tog run npm test' all see the \
                 projected environment"
                    .to_string(),
            )
        }
        // Bare `yarn` and bare `bun` install; bare `npm` and `pnpm` print
        // help. Everything else needs an installing subcommand.
        "npm" | "pnpm" | "yarn" | "bun" => {
            let verb = argument(1);
            let bare_install = verb.is_empty() && matches!(program, "yarn" | "bun");
            if !bare_install && !NODE_INSTALL_VERBS.contains(&verb) {
                return None;
            }
            let invocation = if verb.is_empty() {
                program.to_string()
            } else {
                format!("{program} {verb}")
            };
            // `install` and `ci` install what the lockfile already says, so
            // what replaces them is the bare `tog`, not `tog add`.
            let advice = if bare_install || NODE_REINSTALL_VERBS.contains(&verb) {
                "'tog' sets node_modules up from the lockfile ('tog --fresh' rebuilds it); to change what is in it, \
                 'tog add <package>', 'tog remove <package>', 'tog update'"
            } else {
                "edit dependencies through tog instead: 'tog add <package>', \
                 'tog remove <package>', 'tog update'; 'tog --fresh' rebuilds node_modules"
            };
            Some(format!(
                "'{invocation}' would replace the node_modules projection with a real directory \
                 and leave the closure stale. {advice}"
            ))
        }
        _ => None,
    }
}

pub fn run(ctx: &Context, cmd: &[String], frozen: bool, strict: bool) -> io::Result<i32> {
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
    let dir = sync::ensure_current(ctx, &cwd, frozen, strict)?;
    let (node_projected, _) = node::tailor::projected_node_modules(&dir, &cwd);
    let package_json = if node_projected {
        comforter::read_closure(&dir, "node")?;
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
    if refuse_dotnet_script(
        std::fs::symlink_metadata(dir.join(".tog/closures/dotnet.json")).is_ok(),
        script_steps.is_some(),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "package.json scripts are not run under a .NET projection (MSBuild belongs in the sandbox: use `tog build dotnet`)",
        ));
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
            let status = supervise::status(&mut step, activity)
                .map_err(|e| io::Error::new(e.kind(), format!("run npm script {event}: {e}")))?;
            if !status.success() {
                return Ok(child_status_code(&status));
            }
        }
        return Ok(0);
    }
    let status = supervise::status(&mut command, activity)?;
    Ok(child_status_code(&status))
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(refuse_dotnet_script(true, true));
        assert!(!refuse_dotnet_script(true, false));
        assert!(!refuse_dotnet_script(false, true));
    }
}
