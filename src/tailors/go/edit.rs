//! `tog add` / `remove` / `update` for Go (`Tailor::edit_manifest`): the
//! store go's `go get` edits go.mod and go.sum.

use crate::kernel::resolve::ResolutionDoor;
use crate::tailors::edit::{
    other, registry_latest, EditOutcome, EditVerb, ManifestEdit, PackageRegistry,
};
use std::io;

/// How `tog add` names this ecosystem's public registry.
pub(crate) const REGISTRY: PackageRegistry = PackageRegistry {
    prefix: "go",
    name: "the Go module proxy",
};

/// `Tailor::registry_exists`: `Some(latest version)` when the Go module proxy knows
/// `name`.
pub(crate) fn registry_exists(name: &str) -> io::Result<Option<String>> {
    let lower = name.to_ascii_lowercase();
    let url = format!("https://proxy.golang.org/{lower}/@latest");
    registry_latest(REGISTRY, name, &url, |v| {
        v["Version"].as_str().map(str::to_string)
    })
}

/// A module path begins with a host, and a host has a dot.
pub(crate) fn claims_package_name(name: &str) -> bool {
    match name.split_once('/') {
        Some((host, _)) => host.contains('.') && !host.starts_with('.'),
        None => false,
    }
}

/// `Tailor::edit_manifest` for Go.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    let (project, texts) = (edit.project, &edit.texts());
    if edit.dev {
        return Err(other(
            "--dev has no meaning in Go (one dependency set per module)",
        ));
    }
    let go_obj = super::realize_runtime(
        door.store(),
        door.lease(),
        door.platform(),
        &edit.host.toolchain(project, "go")?,
    )?;
    let scratch = door.store().stage_with_activity(door.lease())?;
    let args: Vec<String> = match edit.verb {
        EditVerb::Add => std::iter::once("get".to_string())
            .chain(texts.iter().cloned())
            .collect(),
        EditVerb::Remove => std::iter::once("get".to_string())
            .chain(texts.iter().map(|name| format!("{name}@none")))
            .collect(),
        EditVerb::Update => {
            let mut args = vec!["get".to_string(), "-u".to_string()];
            if texts.is_empty() {
                args.push("./...".to_string());
            }
            args.extend(texts.iter().cloned());
            args
        }
    };
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = super::run_checked(door, &go_obj, project, &scratch, false, &refs);
    let _ = crate::kernel::store::remove_tree(&scratch);
    result?;
    Ok(EditOutcome {
        files: vec!["go.mod".to_string(), "go.sum".to_string()],
        sync_root: project.to_path_buf(),
    })
}
