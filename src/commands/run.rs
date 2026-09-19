//! `tog run <cmd>`: run a command inside the projected environment.
//! Every tailor contributes its PATH prefixes and environment through
//! `Tailor::run_env`; the package.json script protocol (npm lifecycle
//! events, `npm_*` variables) is the one ecosystem-specific piece that stays
//! here, because it decides *how* the command runs, not what it sees.

use crate::comforter;
use crate::commands::shared::{child_status_code, projected_root};
use crate::kernel::context::Context;
use crate::kernel::supervise;
use crate::tailors;
use crate::tailors::node;
use std::io;

fn refuse_dotnet_script(has_dotnet_closure: bool, script_resolved: bool) -> bool {
    has_dotnet_closure && script_resolved
}

pub fn run(ctx: &Context, cmd: &[String]) -> io::Result<i32> {
    let activity = &ctx.activity;
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run: no command given",
        ));
    }
    // Walk up from cwd to the nearest projected root, so `tog run`
    // works from workspace subdirectories like npm run does.
    let cwd = ctx.project_dir();
    let dir = projected_root(&cwd);
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
    let mut prefix: Vec<String> = Vec::new();
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    for tailor in tailors::registry() {
        prefix.extend(tailor.run_env(ctx, &dir, &cwd, cmd, &mut command)?);
    }
    if prefix.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no environment projected here for command '{}'; run `tog sync` first",
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
            eprintln!("tog: > {event}: {script}");
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

    #[test]
    fn dotnet_projection_refuses_resolved_package_scripts() {
        assert!(refuse_dotnet_script(true, true));
        assert!(!refuse_dotnet_script(true, false));
        assert!(!refuse_dotnet_script(false, true));
    }
}
