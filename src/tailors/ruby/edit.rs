//! `tog add` / `remove` / `update` for Ruby (`Tailor::edit_manifest`): the
//! store Bundler edits the Gemfile and Gemfile.lock.

use crate::kernel::resolve::ResolutionDoor;
use crate::tailors::edit::{registry_latest, EditOutcome, EditVerb, ManifestEdit, PackageRegistry};
use std::io;

/// How `tog add` names this ecosystem's public registry.
pub(crate) const REGISTRY: PackageRegistry = PackageRegistry {
    prefix: "gem",
    name: "RubyGems",
};

/// `Tailor::registry_exists`: `Some(latest version)` when RubyGems knows
/// `name`.
pub(crate) fn registry_exists(name: &str) -> io::Result<Option<String>> {
    let url = format!("https://rubygems.org/api/v1/gems/{name}.json");
    registry_latest(REGISTRY, name, &url, |v| {
        v["version"].as_str().map(str::to_string)
    })
}

/// `Tailor::edit_manifest` for Ruby.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    let (project, texts, dev) = (edit.project, &edit.texts(), edit.dev);
    let ruby_obj = super::realize_runtime(
        door.store(),
        door.lease(),
        door.platform(),
        &edit.host.toolchain(project, "ruby")?,
    )?;
    let scratch = door.store().stage_with_activity(door.lease())?;
    let result = (|| -> io::Result<()> {
        match edit.verb {
            EditVerb::Add => {
                for text in texts {
                    let (name, constraint) = text.split_once('@').unwrap_or((text, ""));
                    let mut args = vec!["bundle", "add", name];
                    if !constraint.is_empty() {
                        args.extend(["--version", constraint]);
                    }
                    if dev {
                        args.extend(["--group", "development"]);
                    }
                    super::run_checked(door, &ruby_obj, project, &scratch, &args)?;
                }
                Ok(())
            }
            EditVerb::Remove => {
                let mut args = vec!["bundle", "remove"];
                args.extend(texts.iter().map(String::as_str));
                super::run_checked(door, &ruby_obj, project, &scratch, &args)
            }
            EditVerb::Update => {
                let mut args = vec!["bundle", "update"];
                if texts.is_empty() {
                    args.push("--all");
                }
                args.extend(texts.iter().map(String::as_str));
                super::run_checked(door, &ruby_obj, project, &scratch, &args)
            }
        }
    })();
    let _ = crate::kernel::store::remove_tree(&scratch);
    result?;
    Ok(EditOutcome {
        files: vec!["Gemfile".to_string(), "Gemfile.lock".to_string()],
        sync_root: project.to_path_buf(),
    })
}
