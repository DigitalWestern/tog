//! `tog add` / `remove` / `update` for Elixir (`Tailor::edit_manifest`).
//! Mix has no command that edits mix.exs, so add and remove refuse with the
//! exact line to write; update runs the store mix's `deps.update` through
//! the edit door, which publishes mix.lock with its signed record.

use crate::kernel::resolve::ResolutionDoor;
use crate::tailors::edit::{
    by_hand, registry_latest, EditOutcome, EditVerb, ManifestEdit, PackageRegistry,
};
use std::io;

/// How `tog add` names this ecosystem's public registry.
pub(crate) const REGISTRY: PackageRegistry = PackageRegistry {
    prefix: "hex",
    name: "Hex",
};

/// `Tailor::registry_exists`: `Some(latest version)` when Hex knows
/// `name`.
pub(crate) fn registry_exists(name: &str) -> io::Result<Option<String>> {
    let url = format!("https://hex.pm/api/packages/{name}");
    registry_latest(REGISTRY, name, &url, |v| {
        v["latest_stable_version"]
            .as_str()
            .or_else(|| v["latest_version"].as_str())
            .map(str::to_string)
    })
}

/// `Tailor::edit_manifest` for Elixir.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    let (project, texts) = (edit.project, &edit.texts());
    match edit.verb {
        EditVerb::Add => {
            let lines = texts
                .iter()
                .map(|text| {
                    let (name, constraint) = text.split_once('@').unwrap_or((text, "~> x.y"));
                    format!("{{:{name}, \"{constraint}\"}}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            Err(by_hand(format!(
                "there is no 'mix add': put {lines} in the deps list of mix.exs, then 'tog' (it runs mix deps.get and re-locks)"
            )))
        }
        EditVerb::Remove => Err(by_hand(format!(
            "there is no 'mix remove': delete {} from the deps list of mix.exs, then 'tog'",
            texts
                .iter()
                .map(|name| format!("{{:{name}, ...}}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        EditVerb::Update => {
            let selected = edit.host.toolchain(project, "elixir")?;
            let beam =
                super::realize_runtime(door.store(), door.lease(), door.platform(), &selected)?;
            let mut args = vec!["mix", "deps.update"];
            if texts.is_empty() {
                args.push("--all");
            }
            args.extend(texts.iter().map(String::as_str));
            let root = crate::kernel::fsroot::ProjectRoot::open(project)?;
            super::resolve::update(door, &root, &beam, &selected, &args)?;
            Ok(EditOutcome {
                files: vec!["mix.lock".to_string()],
                sync_root: project.to_path_buf(),
            })
        }
    }
}
