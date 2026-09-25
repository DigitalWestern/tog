//! From a Node project to its inputs: missing-lock generation through the
//! store npm and the lockfile-to-`NpmPlan` importers.

use crate::comforter::InputRecord;
use crate::kernel::fsroot::{Entry, ProjectRoot};
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
/// is tog's. The project is read through the held descriptor; npm itself
/// runs in `project.path()`.
pub fn ensure_npm_lock(
    platform: Platform,
    project: &ProjectRoot,
    store: &store::Store,
    activity: &crate::kernel::activity::StoreActivity,
    selected: &Selected,
) -> io::Result<()> {
    if !input_exists(project, "package.json")
        || input_exists(project, "package-lock.json")
        || input_exists(project, "pnpm-lock.yaml")
        || input_exists(project, "yarn.lock")
    {
        return Ok(());
    }
    let dir = project.path();
    let bun_lock = ["bun.lock", "bun.lockb"]
        .into_iter()
        .find(|other| input_exists(project, other));
    if let Some(other) = bun_lock {
        ui::note(&format!(
            "{other} found but no package-lock.json; generating one with npm \
             (versions resolve fresh and may differ from {other})"
        ));
    }
    ui::note("no package-lock.json; resolving with the store npm...");
    // Store node's bundled npm, not host npm: a bare machine needs only
    // tog. npm-cli's shebang is `env node`, so the store bin leads PATH.
    // The npm that writes this lock is the one bundled in the Node the
    // project's toolchain selection names.
    let node = node::realize_runtime(store, activity, platform, selected)?;
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
    let status = supervise::status(&mut command, activity).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("run store npm ({}/bin/npm): {e}", node.display()),
        )
    })?;
    if !status.success() {
        return Err(io::Error::other("npm install --package-lock-only failed"));
    }
    if let Some(other) = bun_lock {
        // Said once the file exists, with its full path: an automatic sync
        // can run from a subdirectory of the project, where a relative
        // `git add` would name the wrong place.
        let lock = dir.join("package-lock.json");
        ui::warning(
            &format!(
                "{} was generated from package.json, not from {other}, so its versions may \
                 differ; commit it so every sync reads the same lock",
                lock.display()
            ),
            &ui::shell_line(&["git", "add", &lock.display().to_string()]),
        );
    }
    Ok(())
}

/// The plan from whichever lock the project has, read through the held
/// descriptor (a lock npm just generated is read back the same way).
pub fn load_npm_plan(
    platform: Platform,
    project: &ProjectRoot,
    selected: &Selected,
) -> io::Result<Option<node::NpmPlan>> {
    let node_version = selected.version("node")?;
    if project.is_input_file(Path::new("package-lock.json")) {
        return Ok(Some(node::plan_npm_with(
            platform,
            &read_input(project, "package-lock.json")?,
            node_version,
        )?));
    }
    if project.is_input_file(Path::new("pnpm-lock.yaml")) {
        return Ok(Some(lock_import::plan_pnpm(
            platform,
            &read_input(project, "pnpm-lock.yaml")?,
            project,
            node_version,
        )?));
    }
    if project.is_input_file(Path::new("yarn.lock")) {
        let package = read_input(project, "package.json")?;
        return Ok(Some(lock_import::plan_yarn(
            platform,
            &read_input(project, "yarn.lock")?,
            &package,
            project,
            node_version,
        )?));
    }
    Ok(None)
}

/// A package.json with no lock tog can import is refused by name:
/// package-lock.json is the lock `prepare` generates, and `--frozen` skips
/// `prepare`. A directory with no package.json is not a Node project and
/// plans nothing.
pub fn require_lock(project: &ProjectRoot) -> io::Result<()> {
    let locked = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]
        .iter()
        .any(|lock| input_exists(project, lock));
    if input_exists(project, "package.json") && !locked {
        Err(crate::tailors::missing_lock(project, "package-lock.json"))
    } else {
        Ok(())
    }
}

/// `Path::exists` for a project input, resolved from the held descriptor.
pub(crate) fn input_exists(project: &ProjectRoot, relative: impl AsRef<Path>) -> bool {
    !matches!(
        project.input_entry(relative.as_ref()),
        Ok(Entry::Absent) | Err(_)
    )
}

/// `fs::read_to_string` of a project input through the held descriptor: an
/// absent file is a `NotFound` error naming its project path.
pub(crate) fn read_input(project: &ProjectRoot, relative: impl AsRef<Path>) -> io::Result<String> {
    let relative = relative.as_ref();
    project.read_input_string(relative)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{}: not found", project.path().join(relative).display()),
        )
    })
}

/// The input records a Node closure keeps: project-relative names hashed
/// through the held project descriptor.
pub(crate) fn input_records(project: &ProjectRoot, names: &[&str]) -> io::Result<Vec<InputRecord>> {
    let names: Vec<std::path::PathBuf> = names.iter().map(std::path::PathBuf::from).collect();
    crate::comforter::input_records(project, &names)
}

#[cfg(test)]
mod tests {
    /// A project with its manifest but no lock is refused by name and
    /// nothing is written: the lock is `prepare`'s to generate, and a
    /// frozen run skips `prepare`.
    #[test]
    fn a_missing_lock_is_refused_by_name_and_nothing_is_written() {
        let temp = crate::kernel::testutil::TempDir::named("node-frozen");
        std::fs::write(temp.0.join("package.json"), "{\"name\": \"hello\"}\n").unwrap();
        let project = crate::kernel::fsroot::ProjectRoot::open(&temp.0).unwrap();
        let error = super::require_lock(&project).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        let message = error.to_string();
        assert!(
            message.contains("package-lock.json is missing and --frozen never creates it"),
            "{message}"
        );
        assert!(
            message.contains("run `tog` once without --frozen"),
            "{message}"
        );
        assert!(!temp.0.join("package-lock.json").exists());
        std::fs::write(temp.0.join("package-lock.json"), "").unwrap();
        super::require_lock(&project).unwrap();
    }

    /// A directory with no package.json is not a Node project: nothing to
    /// plan, and nothing to refuse.
    #[test]
    fn no_package_json_is_not_a_missing_lock() {
        let temp = crate::kernel::testutil::TempDir::named("node-frozen-empty");
        let project = crate::kernel::fsroot::ProjectRoot::open(&temp.0).unwrap();
        super::require_lock(&project).unwrap();
    }
}
