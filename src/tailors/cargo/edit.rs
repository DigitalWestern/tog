//! `tog add` / `remove` / `update` for Cargo (`Tailor::edit_manifest`):
//! the store cargo edits Cargo.toml and Cargo.lock.

use crate::kernel::resolve::{DelegateSpec, ResolutionDoor};
use crate::tailors::edit::{
    registry_latest, run_inherited, EditOutcome, EditVerb, ManifestEdit, PackageRegistry,
};
use std::io;

/// How `tog add` names this ecosystem's public registry.
pub(crate) const REGISTRY: PackageRegistry = PackageRegistry {
    prefix: "cargo",
    name: "crates.io",
};

/// `Tailor::registry_exists`: `Some(latest version)` when crates.io knows
/// `name`.
pub(crate) fn registry_exists(name: &str) -> io::Result<Option<String>> {
    let url = format!("https://crates.io/api/v1/crates/{name}");
    registry_latest(REGISTRY, name, &url, |v| {
        v["crate"]["max_stable_version"]
            .as_str()
            .or_else(|| v["crate"]["max_version"].as_str())
            .map(str::to_string)
    })
}

/// `Tailor::edit_manifest` for Cargo.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    let (project, texts) = (edit.project, &edit.texts());
    // `cargo add` and `cargo remove` need only cargo, so the edit runs on
    // the base toolchain of the project's selection. The components and
    // targets the toolchain file asks for are provisioned by the sync that
    // follows.
    let rust_obj = super::realize_runtime(
        door.store(),
        door.lease(),
        door.platform(),
        &edit.host.toolchain(project, "cargo")?,
    )?;
    let mut spec = DelegateSpec::new(rust_obj.join("bin/cargo"));
    match edit.verb {
        EditVerb::Add => {
            spec.arg("add");
            if edit.dev {
                spec.arg("--dev");
            }
            if !texts.is_empty() {
                spec.arg("--").args(texts);
            }
        }
        EditVerb::Remove => {
            spec.arg("remove");
            if edit.dev {
                spec.arg("--dev");
            }
            if !texts.is_empty() {
                spec.arg("--").args(texts);
            }
        }
        EditVerb::Update => {
            spec.arg("update");
            for name in texts {
                spec.args(["-p", name]);
            }
        }
    }
    spec.lock_root(project)
        .env("CARGO_NET_OFFLINE", "false")
        .env_remove("RUSTUP_HOME")
        .env_remove("RUSTUP_TOOLCHAIN");
    run_inherited(door, spec, "store cargo")?;
    Ok(EditOutcome {
        files: vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()],
        sync_root: project.to_path_buf(),
    })
}
