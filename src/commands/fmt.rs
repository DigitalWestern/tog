//! `blanket fmt`: the pinned rustfmt over a Cargo workspace, or a delegated
//! package.json `fmt` script. Needs the cargo tailor and its rustfmt component.

use crate::comforter;
use crate::commands::context::Context;
use crate::commands::inspect;
use crate::commands::run;
use crate::commands::shared::{child_status_code, locate_cargo_root, project_dir, projected_root};
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::ui;
use crate::tailors::cargo;
use crate::tailors::cargo::rustfmt;
use crate::tailors::node;
use std::io;
use std::path::Path;

/// `blanket fmt`: realize only the Rust toolchain and its paired rustfmt
/// component, then format the Cargo workspace without resolving dependencies.
pub fn run(
    platform: Platform,
    check: bool,
    ecosystem: Option<&str>,
    args: &[String],
) -> io::Result<i32> {
    let cwd = project_dir();
    policy::init(&cwd, false)?;

    // `--eco` is blanket's own ecosystem selector, not something a script can
    // read: when it is given explicitly it dispatches to that ecosystem and
    // the package.json script is skipped, so `--eco rust` is a real escape
    // hatch in a polyglot root whose package.json also has a `fmt` script.
    // Without it, a script named fmt wins over the named command, matching
    // `blanket run fmt`. Preserve the command's user arguments for the script;
    // `--eco` is never appended to a delegated command line.
    match ecosystem {
        Some("rust") => {}
        Some(ecosystem) => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "fmt for {ecosystem} is not implemented yet; Rust is the only supported ecosystem"
                ),
            ));
        }
        None => {
            let script_root = projected_root(&cwd);
            let package_json = script_root.join("package.json");
            let is_script = package_json.is_file()
                && std::fs::read_to_string(&package_json)
                    .ok()
                    .and_then(|json| node::script_commands_from_package(&json, "fmt", &[]).ok())
                    .flatten()
                    .is_some();
            if is_script {
                ui::trace("'fmt' is a package.json script: running it");
                // `run` only executes package scripts in a projected
                // environment. Preserve that early, store-free refusal for a
                // package that has a script but has never been synced.
                if !script_root.join(".blanket/closures").is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no environment projected here for command 'fmt'; run `blanket sync` first",
                    ));
                }
                let mut command = vec!["fmt".to_string()];
                if check {
                    command.push("--check".into());
                }
                command.extend(args.iter().cloned());
                // `Context::open` scopes the maintenance narration's stderr
                // handle to the one call that narrates. Holding it any longer
                // serialises every other thread's stderr for the rest of the
                // command: `sandbox::relay_stderr` drains a child's stderr
                // from its own thread through `io::stderr()`, so an outer
                // lock held across a child is a pipe that stops being drained.
                let ctx = Context::open(platform, true)?;
                return run::run(&ctx, &command);
            }
        }
    }
    // Top of the Rust path, and deliberately not above the `--eco` dispatch:
    // a delegated package.json `fmt` script needs no rustfmt pin. A platform
    // with no pinned component is refused here, before `Store::open` and
    // before `ensure_rust_for` downloads ~105 MB of toolchain.
    rustfmt::preflight_platform(platform)?;
    let detected = inspect::detected(&cwd)?;
    if ecosystem.is_none() && detected.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "multiple ecosystems found ({}); specify `blanket fmt --eco rust`",
                detected.join(", ")
            ),
        ));
    }
    if !cwd
        .ancestors()
        .any(|dir| dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file())
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no Rust project here; run `blanket fmt` from a Cargo project",
        ));
    }

    // Same scoping as the delegated branch above: the maintenance narration
    // is the only thing that needs the handle, and the toolchain
    // provisioning and formatter children below all run outside it.
    let ctx = Context::open(platform, true)?;
    let store = &ctx.store;
    let activity = &ctx.activity;
    let rust_version = cargo::resolve_toolchain(platform, &cwd)?.to_string();
    let rust_object = cargo::ensure_rust_for(&store, platform, &rust_version)?;
    let rustfmt_object = rustfmt::ensure_rustfmt(&store, platform, &rust_version, &rust_object)?;
    let workspace_root = locate_cargo_root(&rust_object, &cwd, &store)?.canonicalize()?;
    let object_ref = |path: &Path| -> io::Result<serde_json::Value> {
        let id = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "object path has no UTF-8 id")
            })?;
        Ok(serde_json::json!({
            "path": path.display().to_string(),
            "id": id,
        }))
    };
    let mut refs = comforter::ClosureRefs::new();
    refs.object_path(&store, &activity, &rust_object)?;
    refs.object_path(&store, &activity, &rustfmt_object)?;
    comforter::write_closure(
        &workspace_root,
        "rustfmt",
        serde_json::json!({
            "rust_object": object_ref(&rust_object)?,
            "rustfmt_object": object_ref(&rustfmt_object)?,
            "rust_version": rust_version,
            "workspace_root": workspace_root.display().to_string(),
        }),
        &store,
        &activity,
        refs,
    )?;
    let invocation_dir = cwd.canonicalize()?;
    let status = rustfmt::run_sandboxed(
        platform,
        &invocation_dir,
        &workspace_root,
        &rust_object,
        &rustfmt_object,
        &store,
        check,
        args,
    )?;
    Ok(child_status_code(&status))
}
