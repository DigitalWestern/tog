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

/// Bundler's CLI remove unconditionally installs in the shipped release.
/// Use only its Gemfile editor, then re-lock in a separate delegated run.
pub(crate) const REMOVE_GEMS: &str =
    "abort 'no gems requested' if ARGV.empty?; Bundler::Injector.remove(ARGV)";

/// The Ruby and Bundler commands one edit runs, in order. Resolution only ever
/// writes the Gemfile and Gemfile.lock: `bundle add` and `bundle update`
/// would also install every gem they resolve into the host's gem paths
/// (#211), so `add` skips the install and an update is `bundle lock
/// --update`. tog realizes the gems from the lock afterwards.
fn bundler_runs(verb: EditVerb, texts: &[String], dev: bool) -> Vec<Vec<&str>> {
    match verb {
        EditVerb::Add => texts
            .iter()
            .map(|text| {
                let (name, constraint) = text.split_once('@').unwrap_or((text, ""));
                let mut args = vec!["bundle", "add", name, "--skip-install"];
                if !constraint.is_empty() {
                    args.extend(["--version", constraint]);
                }
                if dev {
                    args.extend(["--group", "development"]);
                }
                args
            })
            .collect(),
        EditVerb::Remove => {
            let mut args = vec![
                "ruby",
                "-rbundler",
                "-rbundler/injector",
                "-e",
                REMOVE_GEMS,
                "--",
            ];
            args.extend(texts.iter().map(String::as_str));
            vec![args, vec!["bundle", "lock"]]
        }
        EditVerb::Update => {
            // Bare `bundle lock --update` re-resolves every gem.
            let mut args = vec!["bundle", "lock", "--update"];
            args.extend(texts.iter().map(String::as_str));
            vec![args]
        }
    }
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
        for args in bundler_runs(edit.verb, texts, dev) {
            super::run_checked(door, &ruby_obj, project, &scratch, &args)?;
        }
        Ok(())
    })();
    let _ = crate::kernel::store::remove_tree(&scratch);
    result?;
    Ok(EditOutcome {
        files: vec!["Gemfile".to_string(), "Gemfile.lock".to_string()],
        sync_root: project.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No edit installs a gem (#211): `add` skips the install and an
    /// update only re-locks, for every gem or the named ones.
    #[test]
    fn bundler_edits_resolve_without_installing() {
        let texts = |list: &[&str]| list.iter().map(|t| t.to_string()).collect::<Vec<_>>();
        let added = texts(&["rails@~> 7.1", "rack"]);
        assert_eq!(
            bundler_runs(EditVerb::Add, &added, true),
            [
                vec![
                    "bundle",
                    "add",
                    "rails",
                    "--skip-install",
                    "--version",
                    "~> 7.1",
                    "--group",
                    "development"
                ],
                vec![
                    "bundle",
                    "add",
                    "rack",
                    "--skip-install",
                    "--group",
                    "development"
                ],
            ]
        );
        assert_eq!(
            bundler_runs(EditVerb::Update, &[], false),
            [vec!["bundle", "lock", "--update"]]
        );
        let named = texts(&["rack"]);
        assert_eq!(
            bundler_runs(EditVerb::Update, &named, false),
            [vec!["bundle", "lock", "--update", "rack"]]
        );
        assert_eq!(
            bundler_runs(EditVerb::Remove, &named, false),
            [
                vec![
                    "ruby",
                    "-rbundler",
                    "-rbundler/injector",
                    "-e",
                    REMOVE_GEMS,
                    "--",
                    "rack"
                ],
                vec!["bundle", "lock"],
            ]
        );
    }
}
