//! From a Cargo project to its inputs: toolchain resolution, workspace root
//! discovery through the pinned Cargo, missing-lock generation, and the
//! `CargoPlan`.

use crate::kernel::activity::StoreActivity;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::store;
use crate::kernel::supervise;
use crate::kernel::toolchain::Selected;
use crate::kernel::ui;
use crate::tailors::cargo;
use std::io;
use std::path::{Path, PathBuf};

/// Implicit detection for sync/plan: cargo joins the party only when the
/// invocation dir is itself a Cargo package (workspace members included).
/// Without this gate, running tog in any project nested under an
/// unrelated Cargo workspace would silently project into that parent tree.
/// The project is read through the held descriptor.
pub fn is_cargo_here(project: &ProjectRoot) -> bool {
    project.is_input_file(Path::new("Cargo.toml")) || project.is_input_file(Path::new("Cargo.lock"))
}

pub struct CargoInputs {
    pub root: PathBuf,
    pub rust_obj: PathBuf,
    pub plan: cargo::CargoPlan,
    pub lock_digest: String,
}

/// Workspace rooting is delegated to the pinned Cargo itself
/// (`locate-project --workspace`): an ancestor-walk for Cargo.lock picks an
/// unrelated outer lock when independent packages nest.
pub fn locate_cargo_root(
    rust_obj: &Path,
    cwd: &Path,
    activity: &StoreActivity,
) -> io::Result<PathBuf> {
    let mut command = std::process::Command::new(rust_obj.join("bin/cargo"));
    command
        .args([
            "locate-project",
            "--workspace",
            "--message-format",
            "plain",
            "--offline",
        ])
        .current_dir(cwd)
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    ui::trace_command(&command);
    let out = supervise::output(&mut command, activity)
        .map_err(|e| io::Error::new(e.kind(), format!("run store cargo locate-project: {e}")))?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let manifest = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    manifest
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("cargo locate-project returned no manifest path"))
}

/// `toolchain` is the project's selection, and it decides which Rust this
/// call realizes. `lock_root` is the directory the selection was resolved
/// in: the components and cross targets its toolchain file asks for are
/// read there, through the rows the toolchain lock records and the
/// descriptor it is held by, and assembled onto that Rust. One the pinned
/// release does not publish is an error before any project write.
///
/// `project` is where Cargo runs (sync passes the same root for both). It
/// is read through its held descriptor: Cargo runs in `project.path()`, but
/// the lock it names is read back from the directory `project` holds (or,
/// for a workspace rooted above it, from that root).
pub fn load_cargo_inputs(
    platform: Platform,
    lock_root: &ProjectRoot,
    project: &ProjectRoot,
    store: &store::Store,
    activity: &StoreActivity,
    toolchain: &Selected,
) -> io::Result<CargoInputs> {
    let rust_version = toolchain.version("rustc")?;
    let (rust_obj, root, workspace) =
        locate_workspace(platform, lock_root, project, store, activity, toolchain)?;
    let lock = read_cargo_lock(&workspace)?
        .ok_or_else(|| crate::tailors::missing_lock(&workspace, "Cargo.lock"))?;
    let plan = cargo::plan_cargo(&lock, rust_version)?;
    Ok(CargoInputs {
        root,
        rust_obj,
        plan,
        lock_digest: cargo::lock_digest(&lock),
    })
}

/// The Rust the selection names, realized, and the workspace Cargo
/// reports for `project`: its root path and that root held as a
/// descriptor. Lock generation and planning share it so both see the same
/// workspace.
fn locate_workspace(
    platform: Platform,
    lock_root: &ProjectRoot,
    project: &ProjectRoot,
    store: &store::Store,
    activity: &StoreActivity,
    toolchain: &Selected,
) -> io::Result<(PathBuf, PathBuf, ProjectRoot)> {
    let extras = cargo::project_extras_in(lock_root)?;
    let rust_obj = cargo::realize_toolchain(store, activity, platform, toolchain, &extras)?;
    let root = locate_cargo_root(&rust_obj, project.path(), activity)?;
    // Cargo is the one tailor whose registered root is not the directory
    // sync was run in: a member of a workspace sends its closure and its
    // record to the workspace root. The preflight checked the invocation
    // directory, so check the root as soon as it is known — before a lock,
    // a vendor object or a cargo-home lands in a workspace that cannot be
    // registered and so cannot be protected.
    store::Store::check_registrable(&root)?;
    let workspace = workspace_root(project, &root)?;
    Ok((rust_obj, root, workspace))
}

/// `prepare`: the workspace's Cargo.lock, generated by the Rust the
/// selection names when there is none. The one place the Cargo tailor
/// writes project inputs.
pub fn ensure_lock(
    platform: Platform,
    project: &ProjectRoot,
    store: &store::Store,
    activity: &StoreActivity,
    toolchain: &Selected,
) -> io::Result<()> {
    let (rust_obj, root, workspace) =
        locate_workspace(platform, project, project, store, activity, toolchain)?;
    if read_cargo_lock(&workspace)?.is_some() {
        return Ok(());
    }
    ensure_cargo_lock(&root, &rust_obj, activity)?;
    if read_cargo_lock(&workspace)?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} was not generated", root.join("Cargo.lock").display()),
        ));
    }
    Ok(())
}

/// The workspace root Cargo reported, held as a descriptor: the project
/// itself or a directory inside it resolved from the project's descriptor,
/// and only a root above the project opened by its path.
pub(crate) fn workspace_root(project: &ProjectRoot, root: &Path) -> io::Result<ProjectRoot> {
    match project.relative(root) {
        Some(relative) if relative.as_os_str().is_empty() => project.try_clone(),
        Some(relative) => project.input_subdir(relative)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("workspace root {} is not a directory", root.display()),
            )
        }),
        None => ProjectRoot::open(root),
    }
}

/// The workspace's Cargo.lock, read through the held descriptor; `None`
/// when there is none yet.
fn read_cargo_lock(workspace: &ProjectRoot) -> io::Result<Option<String>> {
    workspace.read_input_string(Path::new("Cargo.lock"))
}

pub fn ensure_cargo_lock(root: &Path, rust_obj: &Path, activity: &StoreActivity) -> io::Result<()> {
    ui::note(
        "no Cargo.lock; generating it with the store Rust toolchain \
         (network allowed, unsandboxed)...",
    );
    let mut command = std::process::Command::new(rust_obj.join("bin/cargo"));
    command
        .arg("generate-lockfile")
        .current_dir(root)
        .env("CARGO_NET_OFFLINE", "false")
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    ui::trace_command(&command);
    let status = supervise::status(&mut command, activity).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "could not run store Cargo to generate Cargo.lock: {e}; \
                     run `tog` after fixing the project or network"
            ),
        )
    })?;
    if !status.success() {
        return Err(io::Error::other(
            "store Cargo generate-lockfile failed; check the project manifest and network",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn cargo_participation_requires_local_manifest() {
        let temp = TempDir::new();
        let nested = temp.0.join("outer/inner");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(temp.0.join("outer/Cargo.toml"), "[package]\nname=\"o\"\n").unwrap();
        // sync/plan only join in where the invocation dir itself is a package
        let open = |dir: &Path| ProjectRoot::open(dir).unwrap();
        assert!(is_cargo_here(&open(&temp.0.join("outer"))));
        assert!(!is_cargo_here(&open(&nested)));
        std::fs::write(nested.join("Cargo.lock"), "version = 4\n").unwrap();
        assert!(is_cargo_here(&open(&nested)));
    }

    #[test]
    fn a_held_project_keeps_reading_its_own_lock_after_a_rename() {
        let temp = TempDir::new();
        let dir = temp.0.join("project");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.lock"), "# original\nversion = 4\n").unwrap();
        let project = ProjectRoot::open(&dir).unwrap();
        // Another directory takes the path mid-sync, first with no Cargo
        // files at all, then with a lock of its own.
        std::fs::rename(&dir, temp.0.join("moved")).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        assert!(is_cargo_here(&project));
        let workspace = workspace_root(&project, project.path()).unwrap();
        assert_eq!(
            read_cargo_lock(&workspace).unwrap().as_deref(),
            Some("# original\nversion = 4\n")
        );
        std::fs::write(dir.join("Cargo.lock"), "# replacement\nversion = 4\n").unwrap();
        assert_eq!(
            read_cargo_lock(&workspace).unwrap().as_deref(),
            Some("# original\nversion = 4\n")
        );
    }
}
