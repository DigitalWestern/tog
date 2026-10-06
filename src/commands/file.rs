//! `tog <file>` where the project does not have the file's ecosystem, or
//! outside any project: the file runs on that ecosystem's runtime alone,
//! the one `tog x` would use here (the project's lock when it pins one,
//! the shipped runtime otherwise), realized into the store. It never runs
//! on the host's interpreter, and it writes no closure and no lock.

use crate::cli;
use crate::commands::shared::{child_status_code, selected_toolchain};
use crate::kernel::context::Context;
use crate::kernel::{policy, ui};
use crate::tailors;
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
    let Some((program, leading)) = lone.program.split_first() else {
        return Err(io::Error::other(format!(
            "{ecosystem}: a lone file names no program"
        )));
    };
    let mut path: Vec<String> = lone
        .path
        .iter()
        .map(|dir| dir.to_string_lossy().into_owned())
        .collect();
    path.push(std::env::var("PATH").unwrap_or_default());
    let mut command = Command::new(program);
    command
        .args(leading)
        .arg(file)
        .args(&request.args)
        .env("PATH", path.join(":"));
    for (key, value) in lone.env {
        command.env(key, value);
    }
    ui::trace_command(&command);
    let status = crate::kernel::supervise::child_status(run_file(&mut command, ctx))?;
    Ok(child_status_code(&status))
}

/// Run the user's file. It is the user's program, as `tog x`'s tool is,
/// not a resolution tog starts, so neither the door nor the host-local
/// tripwire applies to it.
// Reviewed site (tests/architecture.rs): the user's own program, run on a tog-realized runtime.
#[allow(clippy::disallowed_methods)]
fn run_file(command: &mut Command, ctx: &Context) -> io::Result<std::process::ExitStatus> {
    crate::kernel::supervise::status(command, &ctx.activity)
}
