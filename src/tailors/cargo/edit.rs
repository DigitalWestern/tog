//! `tog add` / `remove` / `update` for Cargo (`Tailor::edit_manifest`):
//! the store cargo edits Cargo.toml and Cargo.lock, confined through the
//! edit door, which publishes them with the signed resolution record.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::provider::cargo_door::{self, CargoPublish, CargoRun};
use crate::kernel::resolve::{record, ResolutionDoor};
use crate::tailors::edit::{registry_latest, EditOutcome, EditVerb, ManifestEdit, PackageRegistry};
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

/// `Tailor::edit_manifest` for Cargo: the store cargo, confined through
/// the edit door at the workspace root, edits the manifest and the lock,
/// which the door publishes with the signed resolution record.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    let (project, texts) = (edit.project, &edit.texts());
    // `cargo add` and `cargo remove` need only cargo, so the edit runs on
    // the base toolchain of the project's selection. The components and
    // targets the toolchain file asks for are provisioned by the sync that
    // follows.
    let selected = edit.host.toolchain(project, "cargo")?;
    // The lock, the record, and the closure belong to the workspace root;
    // an edit in a member names the member's manifest from there. tog's
    // own walk finds it, before anything is realized.
    let root = super::inputs::locate_cargo_root(project)?;
    crate::kernel::store::Store::check_registrable(&root)?;
    let rust_obj = super::realize_runtime(door.store(), door.lease(), door.platform(), &selected)?;
    let held = ProjectRoot::open(project)?;
    let workspace = super::inputs::workspace_root(&held, &root)?;
    let member = workspace
        .relative(held.path())
        .filter(|relative| !relative.as_os_str().is_empty())
        .map(|relative| relative.join("Cargo.toml").to_string_lossy().into_owned());
    let mut args: Vec<String> = Vec::new();
    match edit.verb {
        EditVerb::Add | EditVerb::Remove => {
            let verb = if matches!(edit.verb, EditVerb::Add) {
                "add"
            } else {
                "remove"
            };
            args.push(verb.into());
            if edit.dev {
                args.push("--dev".into());
            }
        }
        EditVerb::Update => args.push("update".into()),
    }
    if let Some(manifest) = &member {
        args.extend(["--manifest-path".to_string(), manifest.clone()]);
    }
    match edit.verb {
        EditVerb::Update => {
            for name in texts {
                args.extend(["-p".to_string(), name.clone()]);
            }
        }
        _ if !texts.is_empty() => {
            args.push("--".into());
            args.extend(texts.iter().cloned());
        }
        _ => {}
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let spec = crate::tailors::record_spec(
        &super::tailor::Cargo,
        &workspace,
        super::resolve::cargo_tool(&selected)?,
        &refs,
    )?;
    // The manifest, the lock and the signed record are published together
    // by the edit door's transaction, or not at all.
    cargo_door::run_cargo_checked(
        door,
        CargoRun {
            rust_obj: &rust_obj,
            lock_root: workspace.path(),
            args: &refs,
            publish: CargoPublish::Project {
                outputs: super::resolve::resolution_outputs(&workspace)?,
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )?;
    Ok(EditOutcome {
        files: vec!["Cargo.toml".to_string(), "Cargo.lock".to_string()],
        sync_root: project.to_path_buf(),
    })
}
