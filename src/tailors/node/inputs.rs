//! From a Node project to its inputs: missing-lock generation through the
//! store npm (confined, see `super::resolve`) and the lockfile-to-`NpmPlan`
//! importers.

use crate::comforter::InputRecord;
use crate::kernel::fsroot::{Entry, ProjectRoot};
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
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
    // tog. The npm that writes this lock is the one bundled in the Node
    // the project's toolchain selection names, confined through the door,
    // which publishes the lock with the signed resolution record.
    node::resolve::generate_lock(door, project, selected)?;
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
    Ok(load_npm_plan_with_basis(platform, project, selected)?.map(|planned| planned.plan))
}

/// A plan with the closure's `resolution_basis`: the lock root's
/// resolution files by digest, the lock at the bytes the plan read.
pub struct Planned {
    pub plan: node::NpmPlan,
    pub basis: crate::comforter::join::Digests,
}

/// [`load_npm_plan`] with the `resolution_basis` taken at the same
/// moment, from the lock bytes the plan was built from.
pub fn load_npm_plan_with_basis(
    platform: Platform,
    project: &ProjectRoot,
    selected: &Selected,
) -> io::Result<Option<Planned>> {
    let node_version = selected.version("node")?;
    let planned = |lock_name: &str, lock_text: &str, plan: node::NpmPlan| -> io::Result<Planned> {
        Ok(Planned {
            plan,
            basis: node::resolve::resolution_basis(project, lock_name, lock_text)?,
        })
    };
    if project.is_input_file(Path::new("package-lock.json")) {
        let text = read_input(project, "package-lock.json")?;
        let plan = node::plan_npm_with(platform, &text, node_version)?;
        return planned("package-lock.json", &text, plan).map(Some);
    }
    if project.is_input_file(Path::new("pnpm-lock.yaml")) {
        let text = read_input(project, "pnpm-lock.yaml")?;
        let plan = lock_import::plan_pnpm(platform, &text, project, node_version)?;
        return planned("pnpm-lock.yaml", &text, plan).map(Some);
    }
    if project.is_input_file(Path::new("yarn.lock")) {
        let package = read_input(project, "package.json")?;
        let text = read_input(project, "yarn.lock")?;
        let plan = lock_import::plan_yarn(platform, &text, &package, project, node_version)?;
        // yarn.lock is no door's output; the basis covers the manifests.
        return planned("yarn.lock", &text, plan).map(Some);
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
    /// The basis names the lock at the bytes the plan read: a lock swapped
    /// in afterwards (another tog, an editor) is not what this closure was
    /// planned from, and the join's `check_basis` refuses it. The old
    /// closure-time read would have taken the new lock as the basis.
    #[test]
    fn the_basis_is_the_planned_lock_not_the_lock_on_disk_later() {
        use crate::kernel::resolve::record::sha256_hex;
        let temp = crate::kernel::testutil::TempDir::named("node-basis");
        let project_dir = temp.0.join("project");
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join("package.json"), r#"{"name":"p"}"#).unwrap();
        let old_lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"p"}}}"#;
        std::fs::write(project_dir.join("package-lock.json"), old_lock).unwrap();
        std::fs::write(project_dir.join(".npmrc"), "fund=false\n").unwrap();
        let project = crate::kernel::fsroot::ProjectRoot::open(&project_dir).unwrap();
        let selected = crate::tailors::node::shipped_selection().unwrap();
        let planned = super::load_npm_plan_with_basis(
            crate::kernel::platform::Platform::X86_64UnknownLinuxGnu,
            &project,
            &selected,
        )
        .unwrap()
        .unwrap();
        let new_lock =
            r#"{"lockfileVersion":3,"packages":{"":{"name":"p","dependencies":{"x":"1"}}}}"#;
        std::fs::write(project_dir.join("package-lock.json"), new_lock).unwrap();
        assert_eq!(
            planned.basis.get("package-lock.json").map(String::as_str),
            Some(sha256_hex(old_lock.as_bytes()).as_str())
        );
        assert_ne!(
            planned.basis["package-lock.json"],
            sha256_hex(new_lock.as_bytes())
        );
        assert_eq!(
            planned.basis.get("package.json").map(String::as_str),
            Some(sha256_hex(br#"{"name":"p"}"#).as_str())
        );
        assert!(planned.basis.contains_key(".npmrc"));
        assert!(!planned.basis.contains_key("pnpm-lock.yaml"));
        // The join sees the swap: the disk no longer matches the basis.
        let files = crate::kernel::resolve::record::ResolutionFiles {
            outputs: crate::tailors::node::resolve::resolution_outputs(&project).unwrap(),
            inputs: crate::tailors::node::resolve::resolution_inputs(&project).unwrap(),
        };
        let error =
            crate::comforter::join::check_basis_for_test(&project, "node", &files, &planned.basis)
                .unwrap_err()
                .to_string();
        assert!(error.contains("package-lock.json changed"), "{error}");
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
