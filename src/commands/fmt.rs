//! `tog fmt`: the pinned formatter of the one ecosystem that has one
//! (Rust today), or a delegated package.json `fmt` script. The formatter
//! itself is `Tailor::fmt`; this file only decides which of the two runs.

use crate::commands::inspect;
use crate::commands::run;
use crate::commands::shared::{project_dir, projected_root};
use crate::kernel::context::Context;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::ui;
use crate::tailors::node;
use crate::tailors::{self, Tailor};
use std::io;

pub fn run(
    platform: Platform,
    check: bool,
    ecosystem: Option<&str>,
    args: &[String],
) -> io::Result<i32> {
    let cwd = project_dir();
    policy::init(&cwd, false)?;

    // `--eco` is tog's own ecosystem selector, not something a script can
    // read: when it is given explicitly it dispatches to that ecosystem and
    // the package.json script is skipped, so `--eco rust` is a real escape
    // hatch in a polyglot root whose package.json also has a `fmt` script.
    // Without it, a script named fmt wins over the named command, matching
    // `tog run fmt`. Preserve the command's user arguments for the script;
    // `--eco` is never appended to a delegated command line.
    let formatter: &dyn Tailor = match ecosystem {
        Some(ecosystem) => match tailors::registry()
            .iter()
            .copied()
            .find(|tailor| tailor.fmt_ecosystem() == Some(ecosystem))
        {
            Some(tailor) => tailor,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "fmt for {ecosystem} is not implemented yet; Rust is the only supported ecosystem"
                    ),
                ));
            }
        },
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
                if !script_root.join(".tog/closures").is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no environment projected here for command 'fmt'; run `tog sync` first",
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
            tailors::registry()
                .iter()
                .copied()
                .find(|tailor| tailor.fmt_ecosystem().is_some())
                .expect("one ecosystem has a pinned formatter")
        }
    };
    // The rustfmt record is signed like every closure; a configured key
    // that cannot be loaded fails here, before the store is opened.
    crate::comforter::init_signing()?;
    // Top of the formatter path, and deliberately not above the `--eco`
    // dispatch: a delegated package.json `fmt` script needs no formatter
    // pin. The tailor refuses a host with no pinned component here, before
    // the store is opened.
    formatter.fmt_preflight(platform)?;
    let detected = inspect::detected(&cwd)?;
    if ecosystem.is_none() && detected.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "multiple ecosystems found ({}); specify `tog fmt --eco rust`",
                detected.join(", ")
            ),
        ));
    }
    formatter.fmt_check_project(&cwd)?;

    // Same scoping as the delegated branch above: the maintenance narration
    // is the only thing that needs the handle, and the toolchain
    // provisioning and formatter children below all run outside it.
    let ctx = Context::open(platform, true)?;
    let mut attribution = policy::Attribution::open("rustfmt")?;
    let status = formatter.fmt(&ctx, &cwd, check, args, &mut attribution)?;
    attribution.finish(true)?;
    if crate::comforter::signing_key().is_none() {
        ui::note("fmt: rustfmt record unsigned; tog audit reports it outdated (set TOG_SIGNING_KEY to sign)");
    }
    Ok(status)
}
