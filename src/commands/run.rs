//! `blanket run <cmd>`: run a command inside the projected environment.
//! Needs each tailor's run-time environment (closure objects, PATH, env).

use crate::comforter;
use crate::commands::context::Context;
use crate::commands::shared::{child_status_code, project_dir, projected_root};
use crate::tailors::dotnet;
use crate::tailors::elixir;
use crate::tailors::go;
use crate::tailors::node;
use crate::tailors::ruby;
use std::io;
use std::path::Path;
use std::path::PathBuf;

fn refuse_dotnet_script(has_dotnet_closure: bool, script_resolved: bool) -> bool {
    has_dotnet_closure && script_resolved
}

pub fn run(ctx: &Context, cmd: &[String]) -> io::Result<i32> {
    let platform = ctx.platform;
    let store = &ctx.store;
    let activity = &ctx.activity;
    if cmd.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "run: no command given",
        ));
    }
    // Walk up from cwd to the nearest projected root, so `blanket run`
    // works from workspace subdirectories like npm run does.
    let cwd = project_dir();
    let dir = projected_root(&cwd);
    let venv = dir.join(".venv");
    let nm = dir.join("node_modules");
    let cargo_home = dir.join(".blanket/cargo-home");
    let node_projected = std::fs::symlink_metadata(&nm)
        .map(|md| md.file_type().is_symlink())
        .unwrap_or(false)
        && std::fs::symlink_metadata(dir.join(".blanket/closures/node.json")).is_ok();
    let nearest_nm = if node_projected {
        let forest_root = nm
            .canonicalize()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        cwd.ancestors()
            .take_while(|path| path.starts_with(&dir))
            .map(|path| path.join("node_modules"))
            .find(|path| {
                std::fs::symlink_metadata(path)
                    .map(|md| md.file_type().is_symlink())
                    .unwrap_or(false)
                    && forest_root
                        .as_ref()
                        .and_then(|root| {
                            path.canonicalize().ok().map(|path| path.starts_with(root))
                        })
                        .unwrap_or(false)
            })
            .unwrap_or_else(|| nm.clone())
    } else {
        nm.clone()
    };
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
        std::fs::symlink_metadata(dir.join(".blanket/closures/dotnet.json")).is_ok(),
        script_steps.is_some(),
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "package.json scripts are not run under a .NET projection (MSBuild belongs in the sandbox: use `blanket build dotnet`)",
        ));
    }
    let mut prefix: Vec<String> = Vec::new();
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    if venv.exists() {
        prefix.push(venv.join("bin").to_string_lossy().into_owned());
        command.env("VIRTUAL_ENV", &venv);
        command.env("PYTHONDONTWRITEBYTECODE", "1"); // site-packages is read-only
    }
    if nm.exists() {
        prefix.push(nearest_nm.join(".bin").to_string_lossy().into_owned());
        if nearest_nm != nm {
            prefix.push(nm.join(".bin").to_string_lossy().into_owned());
        }
        // Node toolchain from the store (cache hit after sync).
        let node = node::ensure_node_for(store, platform)?;
        prefix.push(node.join("bin").to_string_lossy().into_owned());
    }
    if cargo_home.exists() {
        let closure = comforter::read_closure(&dir, "cargo")?;
        // Store-contained resolution: a project-editable closure must never
        // inject arbitrary executable paths (Sol review 5).
        let rust_obj = comforter::closure_object(store, &closure, "rust_object", "bin/rustc")?;
        prefix.push(cargo_home.join("bin").to_string_lossy().into_owned());
        prefix.push(rust_obj.join("bin").to_string_lossy().into_owned());
        command.env("CARGO_HOME", cargo_home.canonicalize()?);
        command.env_remove("RUSTUP_HOME");
        command.env_remove("RUSTUP_TOOLCHAIN");
    }
    if dir.join(".blanket/closures/go.json").exists() {
        let closure = comforter::read_closure(&dir, "go")?;
        let go_obj = comforter::closure_object(store, &closure, "go_object", "bin/go")?;
        let modcache = comforter::closure_object(store, &closure, "modcache_object", "")?;
        prefix.push(go_obj.join("bin").to_string_lossy().into_owned());
        for (k, v) in go::go_env(&go_obj, &modcache, true) {
            if v.is_empty() {
                command.env_remove(&k);
            } else {
                command.env(&k, &v);
            }
        }
    }
    if dir.join(".blanket/closures/ruby.json").exists() {
        let closure = comforter::read_closure(&dir, "ruby")?;
        let ruby_obj = comforter::closure_object(store, &closure, "ruby_object", "bin/ruby")?;
        let gems_obj = comforter::closure_object(store, &closure, "gems_object", "")?;
        // Ruby FIRST, then gem binstubs (a gem exe must never shadow ruby).
        prefix.push(ruby_obj.join("bin").to_string_lossy().into_owned());
        prefix.push(gems_obj.join("bin").to_string_lossy().into_owned());
        let (prefixes, remove, set) = ruby::run_env(&dir, &gems_obj);
        crate::kernel::sandbox::force_env(&mut command, &prefixes, &remove, &set);
    }
    if dir.join(".blanket/closures/elixir.json").exists() {
        let closure = comforter::read_closure(&dir, "elixir")?;
        let beam = comforter::closure_object(store, &closure, "beam_object", "elixir/bin/mix")?;
        // The deps projection is a writable clone OUTSIDE the store; verify
        // it lives under the blanket home and matches the recorded deps id.
        let deps_obj = comforter::closure_object(store, &closure, "deps_object", "")?;
        // Never trust the recorded projection path: reconstruct the ONE
        // expected forest path from canonical project + deps id and require
        // exact canonical equality (Sol: lexical checks admitted foreign
        // forests, dot-dot tricks, and symlinked dirs).
        let projection = elixir::expected_projection(store, &dir, &deps_obj)?;
        let recorded = closure["deps_projection"].as_str().map(PathBuf::from);
        if recorded.as_deref().and_then(|p| p.canonicalize().ok()) != Some(projection.clone())
            || !projection.is_dir()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "elixir closure projection is not the expected forest path; \
                 run `blanket sync` first",
            ));
        }
        prefix.push(beam.join("elixir/bin").to_string_lossy().into_owned());
        prefix.push(beam.join("otp/bin").to_string_lossy().into_owned());
        let scratch = std::env::temp_dir().join(format!("blanket-mix-run-{}", std::process::id()));
        std::fs::create_dir_all(&scratch)?;
        let (prefixes, remove, set) = elixir::run_env(
            &beam,
            &projection,
            &elixir::build_root(platform, &dir)?,
            &scratch,
        )?;
        crate::kernel::sandbox::force_env(&mut command, &prefixes, &remove, &set);
    }
    if dir.join(".blanket/closures/dotnet.json").exists() {
        // This prevents accidental unsandboxed builds, not deliberate bypasses
        // through wrappers such as `sh -c`; during realization and build,
        // blanket never evaluates project code outside its sandbox. Missing-lock
        // lock generation is the explicit host-side exception.
        if let Some(reason) = dotnet::refused_run_command(cmd) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, reason));
        }
        let closure = comforter::read_closure(&dir, "dotnet")?;
        let sdk = comforter::closure_object(store, &closure, "sdk_object", "dotnet")?;
        let packages = comforter::closure_object(store, &closure, "packages_object", "")?;
        prefix.push(sdk.to_string_lossy().into_owned());
        let scratch = std::env::temp_dir().join(format!("blanket-dn-run-{}", std::process::id()));
        std::fs::create_dir_all(&scratch)?;
        let (prefixes, remove, set) = dotnet::run_env(&sdk, &packages, &scratch);
        crate::kernel::sandbox::force_env(&mut command, &prefixes, &remove, &set);
    }
    if prefix.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no environment projected here for command '{}'; run `blanket sync` first",
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
            eprintln!("blanket: > {event}: {script}");
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
            let status = crate::kernel::supervise::status(&mut step, activity)
                .map_err(|e| io::Error::new(e.kind(), format!("run npm script {event}: {e}")))?;
            if !status.success() {
                return Ok(child_status_code(&status));
            }
        }
        return Ok(0);
    }
    let status = crate::kernel::supervise::status(&mut command, activity)?;
    Ok(child_status_code(&status))
}

#[cfg(test)]
mod tests {
    use super::*;

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
