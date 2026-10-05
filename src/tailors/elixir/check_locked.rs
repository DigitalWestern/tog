//! Whether `mix deps.get --check-locked` needs to run again (Elixir
//! tailor): the hash of everything the check reads, and the store record of
//! the last hash it passed on.

use super::*;
use crate::kernel::fsroot::ProjectRoot;
use sha2::{Digest as _, Sha256};
use std::io;
use std::path::Path;

/// The store record kind holding, per project, the input hash of the last
/// `mix deps.get --check-locked` that passed there.
const CHECK_LOCKED: &str = "mix-check-locked";

/// Directory names the manifest walk never enters: tog's and the user's
/// dot state, `_build`, fetched dependency sources, and JavaScript assets.
fn skipped_by_manifest_walk(name: &str) -> bool {
    name.starts_with('.') || name.starts_with('_') || name == "deps" || name == "node_modules"
}

/// The hash of everything `mix deps.get --check-locked` reads to decide that
/// mix.exs and mix.lock agree: the project's canonical path, the BEAM object
/// that runs the check, the lock, and every `.exs` file in the project (an
/// umbrella's apps each have a mix.exs, and `config/*.exs` is evaluated
/// before the deps are read). Equal hashes mean the check would read the
/// same bytes and give the same answer, so asking the Hex registry again is
/// redundant.
///
/// `None`, so the check runs every time, when the walk cannot vouch for
/// what mix reads: a symlinked directory or `.exs` below the root (the walk
/// never follows one), a `path:` dependency outside the project, in a
/// directory the walk skips or not written as a plain string, or a tree the
/// walk cannot read. The root's
/// own mix.exs is read the way mix reads it, following a symlink.
pub(super) fn check_locked_inputs(
    project: &ProjectRoot,
    beam_obj: &Path,
    lock: &str,
) -> io::Result<Option<String>> {
    use crate::kernel::fsroot::Entry;
    fn walk(dir: &ProjectRoot, rel: &Path, files: &mut Vec<(String, String)>) -> io::Result<bool> {
        let at_root = rel.as_os_str().is_empty();
        let names = dir
            .read_input_dir(Path::new("."))?
            .ok_or_else(|| err(format!("mix.exs walk: {} vanished", dir.path().display())))?;
        for name in names {
            let lossy = name.to_string_lossy();
            let child = Path::new(&name);
            match dir.entry(child)? {
                Entry::Directory if !skipped_by_manifest_walk(&lossy) => {
                    let sub = dir.subdir(child)?.ok_or_else(|| {
                        err(format!(
                            "mix.exs walk: {} vanished",
                            dir.path().join(child).display()
                        ))
                    })?;
                    if !walk(&sub, &rel.join(child), files)? {
                        return Ok(false);
                    }
                }
                Entry::Regular if lossy.ends_with(".exs") && !(at_root && lossy == "mix.exs") => {
                    let content = dir.read_file(child)?.ok_or_else(|| {
                        err(format!(
                            "mix.exs walk: {} vanished",
                            dir.path().join(child).display()
                        ))
                    })?;
                    if lossy == "mix.exs" && path_dependency_escapes(rel, &content) {
                        return Ok(false);
                    }
                    let rel = rel.join(child).to_string_lossy().into_owned();
                    files.push((rel, hex::encode(Sha256::digest(&content))));
                }
                // An app reached only through a symlinked directory, or an
                // `.exs` the walk would have to follow, is one it cannot
                // vouch for. A symlink to anything else is not mix's input, and
                // neither is a dangling one: mix cannot read an app there.
                Entry::Symlink
                    if (lossy.ends_with(".exs") && !(at_root && lossy == "mix.exs"))
                        || (!skipped_by_manifest_walk(&lossy)
                            && fs::metadata(dir.path().join(child))
                                .is_ok_and(|target| target.is_dir())) =>
                {
                    return Ok(false);
                }
                _ => {}
            }
        }
        Ok(true)
    }
    let root_manifest = project
        .read_input(Path::new("mix.exs"))?
        .ok_or_else(|| err("mix.exs not found"))?;
    if path_dependency_escapes(Path::new(""), &root_manifest) {
        return Ok(None);
    }
    let mut files = vec![(
        "mix.exs".to_string(),
        hex::encode(Sha256::digest(&root_manifest)),
    )];
    // A tree the walk cannot read through (an unreadable directory, an
    // entry swapped mid-walk) is one it cannot vouch for: the check runs.
    if !matches!(walk(project, Path::new(""), &mut files), Ok(true)) {
        return Ok(None);
    }
    files.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"elixir-check-locked/2\0");
    hasher.update(project.path().as_os_str().as_encoded_bytes());
    hasher.update(b"\0");
    hasher.update(crate::kernel::store::object_id_from_path(beam_obj)?.as_bytes());
    hasher.update(b"\0");
    hasher.update(Sha256::digest(lock.as_bytes()));
    for (rel, hash) in &files {
        hasher.update(format!("{hash}  {rel}\n").as_bytes());
    }
    Ok(Some(hex::encode(hasher.finalize())))
}

/// Whether a mix.exs in `dir` (project-relative) names a `path:` dependency
/// the walk does not cover: one that leaves the project, one inside a
/// directory the walk skips (see [`skipped_by_manifest_walk`]), or one whose path
/// is not a plain string literal (an interpolation, a sigil, a variable),
/// since tog never evaluates mix.exs to find out where that points. A
/// `path:` inside a comment counts too, which only costs a registry check.
/// `deps_path:`, `config_path:` and the like are other keys.
fn path_dependency_escapes(dir: &Path, manifest: &[u8]) -> bool {
    let text = String::from_utf8_lossy(manifest);
    let mut rest = text.as_ref();
    while let Some(at) = rest.find("path:") {
        let preceded_by_word = rest[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        rest = &rest[at + "path:".len()..];
        if preceded_by_word {
            continue;
        }
        let Some(literal) = rest.trim_start().strip_prefix('"') else {
            return true;
        };
        let Some(end) = literal.find('"') else {
            return true;
        };
        let target = &literal[..end];
        if target.contains("#{") || target.contains('\\') || target.starts_with(['/', '~']) {
            return true;
        }
        // Resolve the target the way mix does (lexically, from this
        // mix.exs's directory). One the walk never enters (`_libs/core`,
        // `deps/core`, `.vendor/core`) is as unhashed as one outside.
        let mut resolved: Vec<_> = dir.iter().map(|part| part.to_string_lossy()).collect();
        for part in target.split('/') {
            match part {
                "" | "." => {}
                ".." if resolved.pop().is_none() => return true,
                ".." => {}
                _ => resolved.push(part.into()),
            }
        }
        if resolved.iter().any(|part| skipped_by_manifest_walk(part)) {
            return true;
        }
    }
    false
}

/// Whether the last passing check in this project, as tog recorded it in the
/// store, read exactly `inputs`. The record is store data: a repository
/// cannot ship one, so a match means tog itself saw the check pass on these
/// bytes.
pub(super) fn check_locked_passed(
    store: &Store,
    project: &ProjectRoot,
    inputs: &str,
) -> io::Result<bool> {
    Ok(store
        .read_project_record(CHECK_LOCKED, project.path())?
        .is_some_and(|value| value["input_hash"].as_str() == Some(inputs)))
}

/// Record that the check passed on `inputs`. A failed write costs the next
/// sync one registry round trip and nothing else, so it is reported and the
/// sync goes on.
pub(super) fn record_check_locked(
    store: &Store,
    activity: &StoreActivity,
    project: &ProjectRoot,
    inputs: &str,
) {
    let value = serde_json::json!({"input_hash": inputs});
    if let Err(error) = store.write_project_record(activity, CHECK_LOCKED, project.path(), &value) {
        ui::note(&format!(
            "the passing mix.exs and mix.lock check was not recorded in the store \
             ({error}); the next sync runs it again"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;
    use std::path::PathBuf;

    /// The check's input hash moves with the lock, the root mix.exs, an
    /// umbrella app's mix.exs and the BEAM object, ignores files the check
    /// does not read, and refuses to vouch for a symlinked app manifest.
    /// Only a record for the same hash lets a sync skip the check.
    #[test]
    fn the_check_locked_inputs_cover_what_the_check_reads() {
        let temp = TempDir::named("elixir-check-inputs");
        let root = temp.0.join("app");
        fs::create_dir_all(root.join("apps/web")).unwrap();
        fs::create_dir_all(root.join("deps/jason")).unwrap();
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(root.join("mix.exs"), "root").unwrap();
        fs::write(root.join("apps/web/mix.exs"), "web").unwrap();
        fs::write(root.join("deps/jason/mix.exs"), "dep").unwrap();
        let project = ProjectRoot::open(&root).unwrap();
        let beam = PathBuf::from(format!("/store/objects/{}-beam-29", "a".repeat(40)));
        let beam = beam.as_path();
        let hash = |project: &ProjectRoot, beam: &Path, lock: &str| {
            check_locked_inputs(project, beam, lock).unwrap().unwrap()
        };
        let base = hash(&project, beam, "lock");
        assert_eq!(hash(&project, beam, "lock"), base);
        fs::write(root.join("lib/app.ex"), "code").unwrap();
        fs::write(root.join("deps/jason/mix.exs"), "dep 2").unwrap();
        assert_eq!(hash(&project, beam, "lock"), base, "unread files moved it");
        assert_ne!(hash(&project, beam, "lock 2"), base);
        assert_ne!(
            hash(
                &project,
                &PathBuf::from(format!("/store/objects/{}-beam-29", "b".repeat(40))),
                "lock"
            ),
            base
        );
        fs::write(root.join("apps/web/mix.exs"), "web 2").unwrap();
        let web = hash(&project, beam, "lock");
        assert_ne!(web, base);
        fs::write(root.join("mix.exs"), "root 2").unwrap();
        assert_ne!(hash(&project, beam, "lock"), web);

        let store_root = temp.0.join("store");
        for sub in ["objects", "meta", "tmp"] {
            fs::create_dir_all(store_root.join(sub)).unwrap();
        }
        let store = Store::for_test(store_root.canonicalize().unwrap());
        let activity = store
            .activity(crate::kernel::activity::ActivityMode::Shared)
            .unwrap();
        let current = hash(&project, beam, "lock");
        assert!(!check_locked_passed(&store, &project, &current).unwrap());
        record_check_locked(&store, &activity, &project, &current);
        assert!(check_locked_passed(&store, &project, &current).unwrap());
        assert!(!check_locked_passed(&store, &project, &base).unwrap());

        // config/*.exs is evaluated before the deps are read.
        let before = hash(&project, beam, "lock");
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(root.join("config/config.exs"), "import Config").unwrap();
        assert_ne!(hash(&project, beam, "lock"), before);

        // A symlink to a file mix never reads is not an input, and neither
        // is a dangling one: mix cannot read an app through it.
        std::os::unix::fs::symlink(root.join("lib/app.ex"), root.join("README.md")).unwrap();
        hash(&project, beam, "lock");
        std::os::unix::fs::symlink(temp.0.join("nowhere"), root.join("apps/old")).unwrap();
        hash(&project, beam, "lock");
        // An app reached only through a symlinked directory is.
        fs::create_dir_all(temp.0.join("outside/api")).unwrap();
        std::os::unix::fs::symlink(temp.0.join("outside/api"), root.join("apps/api")).unwrap();
        assert_eq!(check_locked_inputs(&project, beam, "lock").unwrap(), None);
        fs::remove_file(root.join("apps/api")).unwrap();

        fs::remove_file(root.join("apps/web/mix.exs")).unwrap();
        std::os::unix::fs::symlink(root.join("mix.exs"), root.join("apps/web/mix.exs")).unwrap();
        assert_eq!(check_locked_inputs(&project, beam, "lock").unwrap(), None);
    }

    /// A `path:` dependency the walk covers keeps the hash; one outside the
    /// project, or one tog would have to evaluate mix.exs to place, does not.
    #[test]
    fn a_path_dependency_outside_the_project_is_not_vouched_for() {
        let inside = Path::new("apps/web");
        for manifest in [
            r#"{:core, path: "../core"}"#,
            r#"{:core, in_umbrella: true}, deps_path: "../../deps", config_path: "x""#,
            r#"{:local, path: "./vendor/local"}"#,
        ] {
            assert!(
                !path_dependency_escapes(inside, manifest.as_bytes()),
                "{manifest}"
            );
        }
        for manifest in [
            r#"{:core, path: "../../../core"}"#,
            r#"{:core, path: "/opt/core"}"#,
            r#"{:core, path: "~/core"}"#,
            r##"{:core, path: "#{root}/core"}"##,
            r#"{:core, path: Path.expand("../core", __DIR__)}"#,
            r#"{:core, path:"../../../x"}"#,
            // Inside the project, but where the walk never looks.
            r#"{:core, path: "../../_libs/core"}"#,
            r#"{:core, path: "../../deps/core"}"#,
            r#"{:core, path: "./.vendor/core"}"#,
            r#"{:core, path: "../web/node_modules/core"}"#,
        ] {
            assert!(
                path_dependency_escapes(inside, manifest.as_bytes()),
                "{manifest}"
            );
        }
        assert!(path_dependency_escapes(
            Path::new(""),
            br#"{:a, path: "../a"}"#
        ));
        // Leaving a skipped directory again lands where the walk does look.
        assert!(!path_dependency_escapes(
            Path::new(""),
            br#"{:a, path: "_build/../libs/a"}"#
        ));
    }

    /// A `path:` dependency in a directory the walk skips is not hashed, so
    /// the hash refuses to vouch rather than miss an edit to its mix.exs.
    #[test]
    fn a_path_dependency_the_walk_skips_is_not_vouched_for() {
        let temp = TempDir::named("elixir-check-skipped-path");
        let root = temp.0.join("app");
        fs::create_dir_all(root.join("_libs/core")).unwrap();
        fs::write(root.join("_libs/core/mix.exs"), "core").unwrap();
        fs::write(root.join("mix.exs"), r#"{:core, path: "_libs/core"}"#).unwrap();
        let project = ProjectRoot::open(&root).unwrap();
        let beam = PathBuf::from(format!("/store/objects/{}-beam-29", "a".repeat(40)));
        assert_eq!(check_locked_inputs(&project, &beam, "lock").unwrap(), None);
        fs::write(root.join("mix.exs"), r#"{:core, path: "libs/core"}"#).unwrap();
        assert!(check_locked_inputs(&project, &beam, "lock")
            .unwrap()
            .is_some());
    }
}
