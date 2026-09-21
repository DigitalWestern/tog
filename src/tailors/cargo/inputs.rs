//! From a Cargo project to its inputs: toolchain resolution, workspace root
//! discovery through the pinned Cargo, missing-lock generation, and the
//! `CargoPlan`.

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
pub fn is_cargo_here(dir: &Path) -> bool {
    dir.join("Cargo.toml").is_file() || dir.join("Cargo.lock").is_file()
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
pub fn locate_cargo_root(rust_obj: &Path, cwd: &Path, store: &store::Store) -> io::Result<PathBuf> {
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
    let out = supervise::output_owned(&mut command, store)
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

/// `toolchain` is the project's selection, and it is the only thing that
/// decides which Rust this call realizes. The toolchain file is still read,
/// but only for the components it asks for that tog does not provide: that
/// list is this run's `toolchain-component-unavailable` exception, and it is
/// recorded before anything is downloaded.
pub fn load_cargo_inputs(
    platform: Platform,
    cwd: &Path,
    store: &store::Store,
    toolchain: &Selected,
) -> io::Result<CargoInputs> {
    let rust_version = toolchain.version("rustc")?;
    cargo::toolchain_file_components(platform, cwd)?;
    let rust_obj = cargo::ensure_rust_for(store, platform, rust_version)?;
    let root = locate_cargo_root(&rust_obj, cwd, store)?;
    // Cargo is the one tailor whose registered root is not the directory
    // sync was run in: a member of a workspace sends its closure and its
    // record to the workspace root. The preflight checked the invocation
    // directory, so check the root as soon as it is known — before a lock,
    // a vendor object or a cargo-home lands in a workspace that cannot be
    // registered and so cannot be protected.
    store::Store::check_registrable(&root)?;
    if !root.join("Cargo.lock").is_file() {
        ensure_cargo_lock(&root, &rust_obj, store)?;
    }
    let lock = std::fs::read_to_string(root.join("Cargo.lock"))?;
    let plan = cargo::plan_cargo(&lock, rust_version)?;
    Ok(CargoInputs {
        root,
        rust_obj,
        plan,
        lock_digest: cargo::lock_digest(&lock),
    })
}

pub fn ensure_cargo_lock(root: &Path, rust_obj: &Path, store: &store::Store) -> io::Result<()> {
    eprintln!(
        "tog: no Cargo.lock; generating it with the store Rust toolchain \
         (network allowed, unsandboxed)..."
    );
    let mut command = std::process::Command::new(rust_obj.join("bin/cargo"));
    command
        .arg("generate-lockfile")
        .current_dir(root)
        .env("CARGO_NET_OFFLINE", "false")
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    ui::trace_command(&command);
    let status = supervise::status_owned(&mut command, store).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "could not run store Cargo to generate Cargo.lock: {e}; \
                     use `tog sync` after fixing the project or network"
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
        assert!(is_cargo_here(&temp.0.join("outer")));
        assert!(!is_cargo_here(&nested));
        std::fs::write(nested.join("Cargo.lock"), "version = 4\n").unwrap();
        assert!(is_cargo_here(&nested));
    }
}
