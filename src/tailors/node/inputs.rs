//! From a Node project to its inputs: missing-lock generation through the
//! store npm and the lockfile-to-`NpmPlan` importers.

use crate::comforter::InputRecord;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::Platform;
use crate::kernel::resolve::{DelegateSpec, ResolutionDoor};
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
///
/// npm runs through `door`, a missing-lock door.
pub fn ensure_npm_lock(
    project: &ProjectRoot,
    selected: &Selected,
    door: &mut ResolutionDoor<'_>,
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
    let node = node::realize_runtime(door.store(), door.lease(), door.platform(), selected)?;
    let path = format!(
        "{}:{}",
        node.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut spec = DelegateSpec::new(node.join("bin/npm"));
    spec.arg("install").args(node::NPM_RESOLVE_ONLY);
    node::quiet_npm(&mut spec);
    if !ui::verbose() {
        spec.arg("--silent");
    }
    spec.lock_root(dir).env("PATH", path);
    spec.trace();
    let report = door.run(spec).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("run store npm ({}/bin/npm): {e}", node.display()),
        )
    })?;
    if !report.status.success() {
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
    use crate::kernel::platform::Platform;
    use crate::kernel::store;

    /// The store npm resolves a missing lock and does nothing else: no
    /// audit POST, no update-notifier fetch, no funding lookup (#212). A
    /// stand-in Node object whose npm records its argv and environment
    /// keeps the test offline.
    #[test]
    fn the_store_npm_only_resolves() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = crate::kernel::testutil::TempDir::named("npm-quiet");
        let root = temp.0.join("store");
        for sub in ["objects", "meta", "cache/sha256", "tmp"] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        let store = store::Store::for_test(root.canonicalize().unwrap());
        crate::tailors::install_kinds();
        let platform = Platform::host().unwrap();
        let selected = crate::tailors::node::shipped_selection().unwrap();
        let staged = store.stage().unwrap();
        for file in [
            "bin/node",
            "include/node/node.h",
            "lib/node_modules/npm/bin/npm-cli.js",
            "lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js",
        ] {
            std::fs::create_dir_all(staged.join(file).parent().unwrap()).unwrap();
            std::fs::write(staged.join(file), "").unwrap();
        }
        let npm = staged.join("bin/npm");
        std::fs::write(
            &npm,
            "#!/bin/sh\necho \"$@\" > npm-args.txt\nenv | grep -i '^npm_config_' > npm-env.txt\n\
             echo '{\"lockfileVersion\":3,\"packages\":{}}' > package-lock.json\n",
        )
        .unwrap();
        std::fs::set_permissions(&npm, std::fs::Permissions::from_mode(0o755)).unwrap();
        store
            .commit_with_deps(
                &crate::tailors::node::runtime_identity(&selected, platform).unwrap(),
                &staged,
                &[],
                &store::ObjectDeps::new(),
            )
            .unwrap();
        let project_dir = temp.0.join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join("package.json"), r#"{"name":"p"}"#).unwrap();
        let project = crate::kernel::fsroot::ProjectRoot::open(&project_dir).unwrap();
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        super::ensure_npm_lock(
            &project,
            &selected,
            &mut crate::kernel::testutil::DoorScope::new().door(
                &store,
                &activity,
                platform,
                crate::kernel::resolve::DoorKind::MissingLock,
            ),
        )
        .unwrap();
        let args = std::fs::read_to_string(project_dir.join("npm-args.txt")).unwrap();
        for flag in [
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
        ] {
            assert!(args.split_whitespace().any(|arg| arg == flag), "{args}");
        }
        let env = std::fs::read_to_string(project_dir.join("npm-env.txt")).unwrap();
        for line in [
            "NPM_CONFIG_AUDIT=false",
            "NPM_CONFIG_FUND=false",
            "NPM_CONFIG_UPDATE_NOTIFIER=false",
        ] {
            assert!(env.lines().any(|l| l == line), "{env}");
        }
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
