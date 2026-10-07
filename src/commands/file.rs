//! `tog <file>` where the project does not have the file's ecosystem, or
//! outside any project: the file runs on that ecosystem's runtime alone,
//! the one `tog x` would use here (the project's lock when it pins one,
//! the shipped runtime otherwise), realized into the store. It never runs
//! on the host's interpreter, and it writes no closure and no lock.

use crate::cli;
use crate::commands::shared::{child_status_code, selected_toolchain};
use crate::kernel::context::Context;
use crate::kernel::{policy, sandbox, ui};
use crate::tailors::{self, LoneFile};
use std::io;
use std::path::Path;
use std::process::Command;

pub fn run(ctx: &Context, request: &cli::FileRun) -> io::Result<i32> {
    let (ecosystem, file) = (request.ecosystem.as_str(), request.file.as_str());
    let tailor = tailors::by_id(ecosystem).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported ecosystem '{ecosystem}'"),
        )
    })?;
    let cwd = ctx.project_dir();
    policy::init(&cwd)?;
    let toolchain = selected_toolchain(ctx.platform, &cwd, ecosystem)?;
    let extension = Path::new(file)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    // Realizing a runtime can record policy exceptions, and a record needs
    // an open frame. A denied kind is refused as it is recorded; a permitted
    // one is printed then, and no closure carries it, as in `tog fmt`.
    let attribution = policy::Attribution::open(ecosystem)?;
    let lone = tailor
        .lone_file(ctx, &toolchain, &extension)
        .map_err(|error| io::Error::new(error.kind(), format!("'{file}': {error}")))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "'{file}' is a {ecosystem} file, and a {ecosystem} file runs only inside a \
                     {ecosystem} project: tog looks for {} ('tog help inputs')",
                    tailor.input_files()
                ),
            )
        })?;
    attribution.discard();
    let mut command = command_for(&lone, file, &request.args)
        .ok_or_else(|| io::Error::other(format!("{ecosystem}: a lone file names no program")))?;
    ui::trace_command(&command);
    let status = crate::kernel::supervise::child_status(run_file(&mut command, ctx))?;
    Ok(child_status_code(&status))
}

/// The child that runs `file` with `args` as `lone` states it: the
/// runtime's directories ahead of the host PATH, and the environment
/// scrubbed before tog's variables are set, so the host's interpreter
/// configuration (RUBYOPT, GEM_HOME, ERL_LIBS, ...) never reaches the
/// program. `None`: `lone` names no program.
fn command_for(lone: &LoneFile, file: &str, args: &[String]) -> Option<Command> {
    let (program, leading) = lone.program.split_first()?;
    let mut path: Vec<String> = lone
        .path
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    path.push(std::env::var("PATH").unwrap_or_default());
    let mut command = Command::new(program);
    command.args(leading).arg(file).args(args);
    sandbox::force_env(&mut command, &lone.remove_prefixes, &lone.remove, &lone.env);
    command.env("PATH", path.join(":"));
    Some(command)
}

/// Run the user's file. It is the user's program, as `tog x`'s tool is,
/// not a resolution tog starts, so neither the door nor the host-local
/// tripwire applies to it.
// Reviewed site (tests/architecture.rs): the user's own program, run on a tog-realized runtime.
#[allow(clippy::disallowed_methods)]
fn run_file(command: &mut Command, ctx: &Context) -> io::Result<std::process::ExitStatus> {
    crate::kernel::supervise::status(command, &ctx.activity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::OsStr;

    /// The environment edits `command` makes, by name: `None` removes.
    fn edits(command: &Command) -> BTreeMap<String, Option<String>> {
        command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    /// The host's interpreter configuration never reaches a lone file:
    /// each runtime's scrub removes what `tog run` removes for it, and
    /// tog's own variables are set over it.
    #[test]
    fn a_lone_file_does_not_inherit_the_hosts_interpreter_configuration() {
        for (key, value) in [
            ("GEM_HOME", "/home/someone/.gem"),
            ("RUBYOPT", "-r/tmp/evil"),
            ("BUNDLE_GEMFILE", "/home/someone/Gemfile"),
            ("ERL_LIBS", "/home/someone/erl"),
            ("MIX_HOME", "/home/someone/.mix"),
        ] {
            std::env::set_var(key, value);
        }
        let runtime = Path::new("/store/objects/x-runtime");
        let scratch = Path::new("/store/run-homes/k/eco");
        let args = vec!["--port".to_string(), "3".to_string()];

        let (remove_prefixes, remove, env) = crate::tailors::ruby::lone_env(&scratch.join("gems"));
        let ruby = LoneFile {
            program: vec![runtime.join("bin/ruby").to_string_lossy().into_owned()],
            path: vec![runtime.join("bin")],
            remove_prefixes,
            remove,
            env,
        };
        let command = command_for(&ruby, "t.rb", &args).unwrap();
        assert_eq!(
            command.get_program(),
            OsStr::new("/store/objects/x-runtime/bin/ruby")
        );
        let argv: Vec<_> = command.get_args().collect();
        assert_eq!(argv, ["t.rb", "--port", "3"]);
        let env = edits(&command);
        for removed in ["RUBYOPT", "BUNDLE_GEMFILE"] {
            assert_eq!(env.get(removed), Some(&None), "{removed}: {env:?}");
        }
        // The host's GEM_HOME is replaced, not inherited.
        for gem_dir in ["GEM_HOME", "GEM_PATH"] {
            assert_eq!(
                env[gem_dir].as_deref(),
                Some("/store/run-homes/k/eco/gems"),
                "{gem_dir}"
            );
        }
        assert_eq!(env["GEMRC"].as_deref(), Some("/dev/null"));
        assert!(env["PATH"]
            .as_deref()
            .unwrap()
            .starts_with("/store/objects/x-runtime/bin:"));

        let (remove_prefixes, remove, env) =
            crate::tailors::elixir::lone_env(Path::new("/store/objects/beam"), scratch);
        let elixir = LoneFile {
            program: vec!["/store/objects/beam/elixir/bin/elixir".into()],
            path: vec![],
            remove_prefixes,
            remove,
            env,
        };
        let env = edits(&command_for(&elixir, "t.exs", &[]).unwrap());
        assert_eq!(env.get("ERL_LIBS"), Some(&None), "{env:?}");
        assert_eq!(env["HEX_OFFLINE"].as_deref(), Some("1"));
        assert_eq!(env["HOME"].as_deref(), Some("/store/run-homes/k/eco"));
        // Removed by prefix, then set to the scratch home: tog's value wins.
        assert_eq!(
            env["MIX_HOME"].as_deref(),
            Some("/store/run-homes/k/eco/mix")
        );
        for key in [
            "GEM_HOME",
            "RUBYOPT",
            "BUNDLE_GEMFILE",
            "ERL_LIBS",
            "MIX_HOME",
        ] {
            std::env::remove_var(key);
        }
    }

    /// A lone `.go` runs with module mode off and every cache in the
    /// scratch directory, so a go.mod above the file does not apply and
    /// the host's module cache is never read.
    #[test]
    fn a_lone_go_file_runs_outside_any_module_from_scratch_caches() {
        let temp = crate::kernel::testutil::TempDir::new();
        let scratch = temp.0.join("go");
        let env: BTreeMap<String, String> =
            crate::tailors::go::lone_env(Path::new("/store/objects/go"), &scratch)
                .unwrap()
                .into_iter()
                .collect();
        assert_eq!(env["GO111MODULE"], "off");
        assert_eq!(env["GOPROXY"], "off");
        assert_eq!(env["GOROOT"], "/store/objects/go");
        for (key, sub) in [
            ("GOMODCACHE", "gomodcache"),
            ("GOCACHE", "gocache"),
            ("GOPATH", "gopath"),
            ("GOTMPDIR", "gotmp"),
        ] {
            let dir = scratch.join(sub);
            assert_eq!(env[key], dir.display().to_string(), "{key}");
            assert!(dir.is_dir(), "{key}");
        }
    }
}
