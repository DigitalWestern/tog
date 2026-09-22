//! From a Node project to its inputs: missing-lock generation through the
//! store npm and the lockfile-to-`NpmPlan` importers.

use crate::kernel::platform::Platform;
use crate::kernel::store;
use crate::kernel::supervise;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::node;
use crate::tailors::node::lock_import;
use std::io;
use std::path::Path;

/// A package.json with no lockfile tog can import (package-lock.json,
/// pnpm-lock.yaml, yarn.lock): delegate lock generation to npm, mirroring
/// the uv flow for Python. Resolution is the ecosystem's job; realization
/// is tog's.
pub fn ensure_npm_lock(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
    selected: &Selected,
) -> io::Result<()> {
    if !dir.join("package.json").exists()
        || dir.join("package-lock.json").exists()
        || dir.join("pnpm-lock.yaml").exists()
        || dir.join("yarn.lock").exists()
    {
        return Ok(());
    }
    for other in ["bun.lock", "bun.lockb"] {
        if dir.join(other).exists() {
            ui::warning(&format!(
                "{other} found; generating package-lock.json via npm \
                 (versions resolve fresh — they may differ from {other})"
            ));
            break;
        }
    }
    ui::note("no package-lock.json; resolving with the store npm...");
    // Store node's bundled npm, not host npm: a bare machine needs only
    // tog. npm-cli's shebang is `env node`, so the store bin leads PATH.
    // The npm that writes this lock is the one bundled in the Node the
    // project's toolchain selection names.
    let node = node::realize_runtime(store, platform, selected)?;
    let path = format!(
        "{}:{}",
        node.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = std::process::Command::new(node.join("bin/npm"));
    command.args(["install", "--package-lock-only", "--ignore-scripts"]);
    if !ui::verbose() {
        command.arg("--silent");
    }
    command.current_dir(dir).env("PATH", path);
    ui::trace_command(&command);
    let status = supervise::status_owned(&mut command, store).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("run store npm ({}/bin/npm): {e}", node.display()),
        )
    })?;
    if !status.success() {
        return Err(io::Error::other("npm install --package-lock-only failed"));
    }
    Ok(())
}

pub fn load_npm_plan(
    platform: Platform,
    dir: &Path,
    selected: &Selected,
) -> io::Result<Option<node::NpmPlan>> {
    let node_version = selected.version("node")?;
    if dir.join("package-lock.json").is_file() {
        return Ok(Some(node::plan_npm_with(
            platform,
            &std::fs::read_to_string(dir.join("package-lock.json"))?,
            node_version,
        )?));
    }
    if dir.join("pnpm-lock.yaml").is_file() {
        return Ok(Some(lock_import::plan_pnpm(
            platform,
            &std::fs::read_to_string(dir.join("pnpm-lock.yaml"))?,
            dir,
            node_version,
        )?));
    }
    if dir.join("yarn.lock").is_file() {
        let package = std::fs::read_to_string(dir.join("package.json"))?;
        return Ok(Some(lock_import::plan_yarn(
            platform,
            &std::fs::read_to_string(dir.join("yarn.lock"))?,
            &package,
            dir,
            node_version,
        )?));
    }
    Ok(None)
}
