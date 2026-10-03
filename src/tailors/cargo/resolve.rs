//! The Cargo resolution doors: `tog add`/`remove`/`update`, a missing
//! `Cargo.lock`, and `tog attest`'s lock check, each the store cargo
//! confined through the kernel's cargo door (TLS interception, the
//! crates.io route, the git row) at the workspace root.
//!
//! The workspace root is where cargo runs and what the door snapshots and
//! publishes: `Cargo.lock` lives there, and so do the closure and the
//! resolution record. An edit made in a member names the member's manifest
//! with `--manifest-path`.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::provider::cargo_door::{self, CargoPublish, CargoRun};
use crate::kernel::resolve::record;
use crate::kernel::resolve::snapshot::PathGlob;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::toolchain::Selected;
use std::io;
use std::path::{Component, Path, PathBuf};

/// How deep a `[workspace] members` glob is expanded.
const MAX_MEMBER_DEPTH: usize = 8;

/// The cargo a resolution record names: the selected Rust release.
pub(crate) fn cargo_tool(toolchain: &Selected) -> io::Result<record::Tool> {
    Ok(record::Tool {
        name: "cargo".to_string(),
        version: toolchain.version("rustc")?.to_string(),
    })
}

/// `Tailor::resolution_outputs` for Cargo: the workspace root's
/// `Cargo.toml` and `Cargo.lock`, and the manifest of every member its
/// `[workspace] members` names (an edit in a member writes that member's
/// manifest).
pub(crate) fn resolution_outputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut outputs = vec![PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")];
    for member in member_dirs(root)? {
        let manifest = member.join("Cargo.toml");
        if !outputs.contains(&manifest) {
            outputs.push(manifest);
        }
    }
    Ok(outputs)
}

/// `Tailor::resolution_inputs` for Cargo: the configuration cargo reads at
/// the workspace root (its registries, source replacement, `net` settings).
pub(crate) fn resolution_inputs(_root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    Ok(cargo_door::CONFIG_FILES.iter().map(PathBuf::from).collect())
}

/// The member directories (relative to `root`) its `[workspace]` names:
/// each `members` entry, a path or a glob, that holds a `Cargo.toml` and is
/// not under an `exclude` entry. A member outside the root (`../x`) is not
/// listed: the door publishes only inside its lock root.
fn member_dirs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let Some(text) = root.read_input_string(Path::new("Cargo.toml"))? else {
        return Ok(Vec::new());
    };
    let manifest: toml::Table = toml::from_str(&text).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {error}", root.path().join("Cargo.toml").display()),
        )
    })?;
    let workspace = manifest.get("workspace").and_then(|w| w.as_table());
    let list = |key: &str| -> Vec<String> {
        workspace
            .and_then(|w| w.get(key))
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .filter_map(relative_pattern)
                    .collect()
            })
            .unwrap_or_default()
    };
    let exclude: Vec<PathBuf> = list("exclude").iter().map(PathBuf::from).collect();
    let mut found = Vec::new();
    for pattern in list("members") {
        let candidates = if pattern.contains(['*', '?', '[']) {
            expand(root.path(), &pattern)?
        } else {
            vec![PathBuf::from(&pattern)]
        };
        for dir in candidates {
            let excluded = exclude.iter().any(|ex| dir.starts_with(ex));
            if !excluded && root.is_input_file(&dir.join("Cargo.toml")) && !found.contains(&dir) {
                found.push(dir);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// A members or exclude entry as a path under the root: `./` and a
/// trailing `/` dropped, `None` for one that leaves the root.
fn relative_pattern(entry: &str) -> Option<String> {
    let trimmed = entry.trim_start_matches("./").trim_end_matches('/');
    let path = Path::new(trimmed);
    let inside = !trimmed.is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    inside.then(|| trimmed.to_string())
}

/// The directories under `root` a members glob matches, at its depth (any
/// depth up to [`MAX_MEMBER_DEPTH`] for `**`). Hidden directories and
/// `target` are skipped, and symlinks are not followed.
fn expand(root: &Path, pattern: &str) -> io::Result<Vec<PathBuf>> {
    let glob = PathGlob::new(pattern)?;
    let depth = pattern.split('/').count();
    let any_depth = pattern.split('/').any(|part| part == "**");
    let mut found = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(relative) = stack.pop() {
        let level = relative.components().count();
        if level > 0 && (level == depth || any_depth) && glob.matches(&relative) {
            found.push(relative.clone());
        }
        if level >= MAX_MEMBER_DEPTH || (!any_depth && level >= depth) {
            continue;
        }
        let entries = match std::fs::read_dir(root.join(&relative)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let skip = name.to_string_lossy().starts_with('.') || name == "target";
            if !skip && entry.file_type()?.is_dir() {
                stack.push(relative.join(name));
            }
        }
    }
    Ok(found)
}

/// `cargo generate-lockfile` at the workspace root `root` (held as
/// `workspace`), through `door` (a missing-lock door): the lock and the
/// signed resolution record are published together.
pub(crate) fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    workspace: &ProjectRoot,
    rust_obj: &Path,
    toolchain: &Selected,
) -> io::Result<()> {
    let args = ["generate-lockfile"];
    let tailor = super::tailor::Cargo;
    let spec = crate::tailors::record_spec(&tailor, workspace, cargo_tool(toolchain)?, &args)?;
    cargo_door::run_cargo_checked(
        door,
        CargoRun {
            rust_obj,
            lock_root: workspace.path(),
            args: &args,
            publish: CargoPublish::Project {
                outputs: resolution_outputs(workspace)?,
                receipt: Some(record::producer(spec, Default::default())),
            },
        },
    )
    .map(drop)
}

/// `tog attest` for Cargo: `cargo metadata --locked` at the workspace root
/// through `door`'s transaction with the record's producer. `--locked`
/// fails when `Cargo.lock` is not what the manifests resolve to, and the
/// run downloads every crate (cargo reads each one's manifest), each
/// verified against its index checksum by the proxy. The check publishes
/// nothing, not even the receipt: `tog attest` publishes every record only
/// once every check passed.
pub(crate) fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    rust_obj: &Path,
    root: &Path,
    toolchain: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    let err = |text: String| io::Error::other(text);
    if project.relative(root).map(|rel| rel.as_os_str().is_empty()) != Some(true) {
        return Err(err(format!(
            "{} is a member of the Cargo workspace at {}; its Cargo.lock and resolution record \
             live there, so run `tog attest cargo` in {}",
            project.path().display(),
            root.display(),
            root.display()
        )));
    }
    let args = ["metadata", "--locked", "--format-version", "1"];
    let tailor = super::tailor::Cargo;
    let mut spec = crate::tailors::record_spec(&tailor, project, cargo_tool(toolchain)?, &args)?;
    spec.require_unchanged = true;
    spec.publish_receipt = false;
    let slot = record::RecordSlot::default();
    let report = cargo_door::run_cargo(
        door,
        CargoRun {
            rust_obj,
            lock_root: project.path(),
            args: &args,
            publish: CargoPublish::Project {
                outputs: resolution_outputs(project)?,
                receipt: Some(record::producer(spec, slot.clone())),
            },
        },
    )?;
    if !report.status.success() {
        return Err(err(format!(
            "Cargo.lock in {} is not what cargo resolves the manifests to, so it is not \
             attested; run `tog` to bring it up to date and commit the result\n{}",
            project.path().display(),
            String::from_utf8_lossy(&report.stderr).trim()
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("cargo's lock check published no record".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    fn package(dir: &Path, name: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n"),
        )
        .unwrap();
    }

    /// The outputs are the root's manifest and lock and every member's
    /// manifest the `[workspace]` names, by path or glob, less `exclude`;
    /// a member outside the root and a directory with no manifest are not.
    #[test]
    fn outputs_name_every_member_manifest_inside_the_root() {
        let temp = TempDir::named("cargo-outputs");
        let root = temp.0.join("ws");
        for (dir, name) in [
            ("app", "app"),
            ("crates/a", "a"),
            ("crates/b", "b"),
            ("crates/skipped", "skipped"),
            ("crates/.hidden", "hidden"),
            ("nested/deep/c", "c"),
        ] {
            package(&root.join(dir), name);
        }
        fs::create_dir_all(root.join("crates/empty")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"./app/\", \"crates/*\", \"nested/**\", \"../outside\"]\n\
             exclude = [\"crates/skipped\"]\n",
        )
        .unwrap();
        let held = ProjectRoot::open(&root).unwrap();
        let outputs: Vec<String> = resolution_outputs(&held)
            .unwrap()
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        assert_eq!(
            outputs,
            vec![
                "Cargo.toml",
                "Cargo.lock",
                "app/Cargo.toml",
                "crates/a/Cargo.toml",
                "crates/b/Cargo.toml",
                "nested/deep/c/Cargo.toml",
            ]
        );
        // A single package has just its manifest and lock.
        package(&temp.0.join("single"), "single");
        let single = ProjectRoot::open(&temp.0.join("single")).unwrap();
        assert_eq!(
            resolution_outputs(&single).unwrap(),
            vec![PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")]
        );
        assert_eq!(
            resolution_inputs(&single).unwrap(),
            vec![
                PathBuf::from(".cargo/config.toml"),
                PathBuf::from(".cargo/config")
            ]
        );
    }
}
