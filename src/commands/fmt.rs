//! `tog fmt`: the pinned formatter of the one ecosystem that has one
//! (Rust today), or a delegated package.json `fmt` script. The formatter
//! itself is `Tailor::fmt`; this file only decides which of the two runs.

use crate::comforter::toolchain::{self as project_toolchain, Mode};
use crate::commands::inspect;
use crate::commands::run;
use crate::commands::shared::{ecosystem_inputs, project_dir, projected_root};
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::policy;
use crate::kernel::toolchain::lock::LOCK_PATH;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::node;
use crate::tailors::{self, Tailor};
use std::io;
use std::path::Path;

pub fn run(
    platform: Platform,
    check: bool,
    ecosystem: Option<&str>,
    args: &[String],
    frozen: bool,
) -> io::Result<i32> {
    let cwd = project_dir();
    policy::init(&cwd)?;

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
                // `run` syncs a package that has never been synced before
                // it runs the script, so there is nothing to refuse here.
                // `--frozen` governs that sync as it would `tog run fmt`,
                // and `--strict` already holds for the whole process.
                let mut command = vec!["fmt".to_string()];
                if check {
                    command.push("--check".into());
                }
                command.extend(args.iter().cloned());
                let ctx = Context::open(platform)?;
                return run::run(&ctx, &command, frozen);
            }
            tailors::registry()
                .iter()
                .copied()
                .find(|tailor| tailor.fmt_ecosystem().is_some())
                .expect("one ecosystem has a pinned formatter")
        }
    };
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

    let ctx = Context::open(platform)?;
    // The formatter rides in the same bundle as the toolchain, so it is
    // chosen by the same committed lock and never by a fresh selection.
    // A workspace is formatted as one, so the lock at its root decides,
    // whichever member `tog fmt` runs from: start from the nearest project
    // at or above `cwd` (normally the root already), find the workspace
    // root with it, and resolve again there when the root holds a lock of
    // its own that was not the one read.
    let resolve_at = |dir: &Path| -> io::Result<Selected> {
        let held = ProjectRoot::open(dir)?;
        project_toolchain::resolve(
            &held,
            platform,
            ecosystem_inputs(&[formatter])?,
            Mode::ReadOnly,
            false,
        )?
        .get(formatter.lock_ecosystem())
        .cloned()
    };
    let cwd_real = cwd.canonicalize()?;
    let start = cwd_real
        .ancestors()
        .find(|dir| dir.join(LOCK_PATH).symlink_metadata().is_ok() || dir.join(".tog").is_dir())
        .unwrap_or(&cwd_real)
        .to_path_buf();
    let first = resolve_at(&start)?;
    // Realizing a toolchain can record policy exceptions (a local
    // toolchain's `external-toolchain`), and a record needs an open frame.
    // A kind the policy denies is refused as it is recorded, so the gate
    // holds here as in a sync. A permitted one is printed when recorded,
    // and `tog fmt` publishes no closure to carry it (a synced project's
    // cargo closure records the same fact), so the frame is discarded.
    let attribution = policy::Attribution::open("fmt")?;
    let root = formatter.fmt_root(&ctx, &cwd, &first)?;
    let decides = if root.join(LOCK_PATH).symlink_metadata().is_ok() {
        root
    } else {
        cwd_real
    };
    let selected = if decides == start {
        first
    } else {
        resolve_at(&decides)?
    };
    let status = formatter.fmt(&ctx, &cwd, check, args, &selected)?;
    attribution.discard();
    Ok(status)
}
