//! The Node resolution doors (node tailor): a missing `package-lock.json`,
//! `tog attest`'s lock checks, and what every Node door's record covers,
//! each the store npm or the pinned pnpm confined through the tailor's door
//! ([`super::door`]: TLS interception, the npm route, the git row).
//!
//! The lock root is where the lock lives: the project, or the pnpm
//! workspace root, which is also where the closure and the resolution
//! record live. An edit made in a workspace member runs there, below the
//! root, and writes the member's manifest and the root's lock.

use super::door::{self, NodeRun, NodeTool};
use super::edit::NodeLock;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::door::Publish;
use crate::kernel::resolve::{record, ResolutionDoor};
use crate::kernel::toolchain::Selected;
use crate::tailors::edit::EditHost;
use std::io;
use std::path::{Component, Path, PathBuf};

/// The lock files a Node door may write, beside `package.json`.
pub(crate) const LOCKS: [&str; 3] = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"];

/// The files a Node door's tool reads at the lock root but never writes.
const INPUTS: [&str; 3] = [".npmrc", "pnpm-workspace.yaml", ".pnpmfile.cjs"];

/// The deepest workspace member an npm `workspaces` glob is expanded to.
const MAX_DEPTH: usize = 24;

/// `Tailor::resolution_outputs` for Node: the lock root's `package.json`
/// and every lock a door writes there, and the `package.json` of every
/// workspace member ([`workspace_members`]): npm and pnpm read each to
/// resolve, and an edit made in a member writes it.
pub(crate) fn resolution_outputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut outputs = vec![PathBuf::from("package.json")];
    outputs.extend(LOCKS.iter().map(PathBuf::from));
    for member in workspace_members(root)? {
        outputs.push(member.join("package.json"));
    }
    Ok(outputs)
}

/// `Tailor::resolution_inputs` for Node: the configuration npm and pnpm
/// read at the lock root (`.npmrc`, which can name a scoped registry or a
/// program; `pnpm-workspace.yaml`, which names the members and, since
/// pnpm 10, settings; `.pnpmfile.cjs`, project code pnpm runs), and each
/// member's own `.npmrc`.
pub(crate) fn resolution_inputs(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut inputs: Vec<PathBuf> = INPUTS.iter().map(PathBuf::from).collect();
    for member in workspace_members(root)? {
        inputs.push(member.join(".npmrc"));
    }
    Ok(inputs)
}

/// The workspace members of the project at `root`, relative to it, from
/// every place a member can be named: npm's `workspaces` in
/// `package.json` (each glob expanded, and its literal path too),
/// `pnpm-workspace.yaml`'s `packages`, the `importers` of
/// `pnpm-lock.yaml`, and the `workspaces` the root entry of
/// `package-lock.json` records. The union: receipt coverage is never
/// smaller than the tool's own member set, and an extra manifest is only
/// an extra output. A member named by a path that is not plain and
/// relative, or a members list tog cannot read, is an error: a member
/// left out would leave the record attesting a manifest it never covered.
pub(crate) fn workspace_members(root: &ProjectRoot) -> io::Result<Vec<PathBuf>> {
    let mut members: Vec<PathBuf> = Vec::new();
    let mut add = |named: &str, source: &str| -> io::Result<()> {
        let trimmed = named.trim_start_matches("./").trim_end_matches('/');
        if trimmed.is_empty() || trimmed == "." {
            return Ok(());
        }
        let path = PathBuf::from(trimmed);
        let plain = path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
        if !plain {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{source} names the workspace member {named:?}, which is not a plain path \
                     inside the project; a resolution record names files inside the project only"
                ),
            ));
        }
        if root.is_input_file(&path.join("package.json")) && !members.contains(&path) {
            members.push(path);
        }
        Ok(())
    };
    if let Some(text) = root.read_input_string(Path::new("package.json"))? {
        let package: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("package.json: {error}"))
        })?;
        for pattern in npm_workspace_patterns(&package)? {
            for dir in expand_workspace_glob(root, &pattern)? {
                add(&dir, "package.json")?;
            }
        }
    }
    match super::lock_import::pnpm_workspace_members(root)? {
        Some(found) => {
            for member in found {
                add(&member, "pnpm-workspace.yaml")?;
            }
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pnpm-workspace.yaml: packages is not a list tog can read, so the workspace's \
                 members cannot be named in a resolution record; write it as a plain list of \
                 patterns",
            ))
        }
    }
    if let Some(text) = root.read_input_string(Path::new("pnpm-lock.yaml"))? {
        for importer in super::lock_import::pnpm_lock_importers(&text)? {
            add(&importer, "pnpm-lock.yaml")?;
        }
    }
    if let Some(text) = root.read_input_string(Path::new("package-lock.json"))? {
        let lock: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("package-lock.json: {error}"),
            )
        })?;
        let listed = lock["packages"][""]["workspaces"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.as_str());
        for entry in listed {
            for dir in expand_workspace_glob(root, entry)? {
                add(&dir, "package-lock.json")?;
            }
        }
    }
    members.sort();
    Ok(members)
}

/// `Tailor::preflight`'s share: the workspace members can be named, so a
/// `pnpm-workspace.yaml` tog cannot read refuses the sync before anything
/// is realized rather than when the closure is written.
pub(crate) fn check_members_readable(root: &ProjectRoot) -> io::Result<()> {
    workspace_members(root).map(drop)
}

/// The `workspaces` patterns of a `package.json`: a list, or the object
/// form's `packages` list. A `!` pattern narrows npm's set; it is left out
/// so the record covers what it would exclude too.
fn npm_workspace_patterns(package: &serde_json::Value) -> io::Result<Vec<String>> {
    Ok(npm_workspace_entries(package)?
        .into_iter()
        .filter(|entry| !entry.starts_with('!'))
        .collect())
}

/// Whether npm, run in `root_dir.join(member)`, would take `root_dir` as
/// its workspace root: `root_dir/package.json` names `member` in
/// `workspaces` (a literal path or a glob, less any `!` pattern that
/// matches it), and the member has a `package.json`. This is npm's own
/// rule (`@npmcli/config`'s `loadLocalPrefix`, through
/// `@npmcli/map-workspaces`), so a root `package.json` that is missing,
/// unreadable, or has no list is simply not a root, as it is for npm.
pub(crate) fn npm_workspace_names(root_dir: &Path, member: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(root_dir.join("package.json")) else {
        return false;
    };
    let Ok(package) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let Ok(entries) = npm_workspace_entries(&package) else {
        return false;
    };
    if entries.is_empty() || !root_dir.join(member).join("package.json").is_file() {
        return false;
    }
    let relative = member.to_string_lossy().replace('\\', "/");
    let relative = relative.trim_end_matches('/');
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let matches = |pattern: &str| {
        let trimmed = pattern.trim_start_matches("./").trim_end_matches('/');
        if trimmed == relative {
            return true;
        }
        trimmed.contains(['*', '?', '['])
            && glob::Pattern::new(trimmed)
                .map(|compiled| compiled.matches_with(relative, options))
                .unwrap_or(false)
    };
    let mut named = false;
    for entry in &entries {
        match entry.strip_prefix('!') {
            Some(excluded) => {
                if matches(excluded) {
                    named = false;
                }
            }
            None => {
                if matches(entry) {
                    named = true;
                }
            }
        }
    }
    named
}

/// Every `workspaces` entry of a `package.json` as written, `!` patterns
/// included: a list, or the object form's `packages` list.
fn npm_workspace_entries(package: &serde_json::Value) -> io::Result<Vec<String>> {
    let list = match package.get("workspaces") {
        None => return Ok(Vec::new()),
        Some(serde_json::Value::Array(list)) => list,
        Some(serde_json::Value::Object(object)) => match object.get("packages") {
            None => return Ok(Vec::new()),
            Some(serde_json::Value::Array(list)) => list,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "package.json: workspaces.packages is not a list",
                ))
            }
        },
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "package.json: workspaces is not a list",
            ))
        }
    };
    Ok(list
        .iter()
        .filter_map(|entry| entry.as_str())
        .map(str::to_string)
        .collect())
}

/// The directories under the project that `pattern` (an npm `workspaces`
/// entry: a path, or a glob with `*`, `?`, `[..]`, and `**`) names, and its
/// literal path, each relative to the root. The walk follows no symlink
/// and skips `node_modules`.
fn expand_workspace_glob(root: &ProjectRoot, pattern: &str) -> io::Result<Vec<String>> {
    let trimmed = pattern.trim_start_matches("./").trim_end_matches('/');
    let mut found = vec![trimmed.to_string()];
    if !trimmed.contains(['*', '?', '[']) {
        return Ok(found);
    }
    let compiled = glob::Pattern::new(trimmed).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package.json: the workspaces pattern {pattern:?} is not a glob: {error}"),
        )
    })?;
    let options = glob::MatchOptions {
        case_sensitive: true,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };
    let mut stack: Vec<(PathBuf, usize)> = vec![(PathBuf::new(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Some(entries) = root.read_input_dir(if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &dir
        })?
        else {
            continue;
        };
        for name in entries {
            if name == "node_modules" {
                continue;
            }
            let path = dir.join(&name);
            if !matches!(
                root.entry(&path),
                Ok(crate::kernel::fsroot::Entry::Directory)
            ) {
                continue;
            }
            let relative = path.to_string_lossy().into_owned();
            if compiled.matches_with(&relative, options) {
                found.push(relative);
            }
            if depth + 1 < MAX_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    Ok(found)
}

/// The closure's `resolution_basis`: every resolution file of the lock
/// root that exists, by digest, with the lock `lock_name` (when it is one
/// of [`LOCKS`]) taken from `lock_text`, the bytes the plan was built from. Computed at plan time,
/// so a lock another writer swaps in while the sync realizes does not
/// become the basis of a closure planned from the old one (the join's
/// `check_basis` then refuses the closure instead).
pub(crate) fn resolution_basis(
    root: &ProjectRoot,
    lock_name: &str,
    lock_text: &str,
) -> io::Result<crate::comforter::join::Digests> {
    let mut listed = resolution_outputs(root)?;
    listed.extend(resolution_inputs(root)?);
    let mut basis = record::file_digests(root, &listed)?;
    // Only a lock a door writes is part of the basis: `yarn.lock` is no
    // door's output and no record names it, so the join compares the
    // manifests alone for a yarn project (a basis entry the resolution
    // files do not list would read as a change on every sync).
    if LOCKS.contains(&lock_name) {
        basis.insert(
            lock_name.to_string(),
            record::sha256_hex(lock_text.as_bytes()),
        );
    }
    Ok(basis)
}

/// Refuse a project whose manifests name a `file:` or `link:` dependency
/// (or a bare path spec, which npm reads the same way) that resolves
/// outside the lock root. The door snapshots the lock root alone, so a
/// confined npm or pnpm would not find the directory; the refusal names
/// the manifest and the path before any tool runs. The alternative, a
/// read root like cargo's out-of-root path dependencies, is deferred: a
/// resolution record names files inside the project only, so it could not
/// cover such a directory either. A path that does not exist is left for
/// the tool to report.
pub(crate) fn refuse_external_path_dependencies(root: &ProjectRoot) -> io::Result<()> {
    const FIELDS: [&str; 4] = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    let real_root = std::fs::canonicalize(root.path())?;
    let mut manifests = vec![PathBuf::from("package.json")];
    manifests.extend(
        workspace_members(root)?
            .into_iter()
            .map(|member| member.join("package.json")),
    );
    for manifest in manifests {
        let Some(text) = root.read_input_string(&manifest)? else {
            continue;
        };
        let Ok(package) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let dir = root
            .path()
            .join(manifest.parent().unwrap_or_else(|| Path::new("")));
        // npm's `overrides` nests (a child override under a parent's key)
        // and pnpm's live under `pnpm.overrides`; both take the same specs.
        let mut specs: Vec<(String, &str)> = Vec::new();
        for field in FIELDS {
            if let Some(entries) = package.get(field).and_then(|value| value.as_object()) {
                for (name, spec) in entries {
                    if let Some(spec) = spec.as_str() {
                        specs.push((name.clone(), spec));
                    }
                }
            }
        }
        for overrides in [
            package.get("overrides"),
            package.get("pnpm").and_then(|pnpm| pnpm.get("overrides")),
        ] {
            let mut stack: Vec<(String, &serde_json::Value)> = overrides
                .and_then(|value| value.as_object())
                .into_iter()
                .flatten()
                .map(|(name, value)| (name.clone(), value))
                .collect();
            while let Some((name, value)) = stack.pop() {
                match value {
                    serde_json::Value::String(spec) => specs.push((name, spec)),
                    serde_json::Value::Object(nested) => stack.extend(
                        nested
                            .iter()
                            .map(|(child, value)| (format!("{name} > {child}"), value)),
                    ),
                    _ => {}
                }
            }
        }
        {
            for (name, spec) in specs {
                let Some(target) = path_spec_target(spec) else {
                    continue;
                };
                let Ok(found) = std::fs::canonicalize(dir.join(target)) else {
                    continue;
                };
                if !found.starts_with(&real_root) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "{} names the dependency {name} as {spec:?} ({}), outside the project \
                             at {}; a confined npm or pnpm reads the project alone, so move it \
                             inside the project or depend on it from a registry",
                            root.path().join(&manifest).display(),
                            found.display(),
                            root.path().display()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The directory a `file:` or `link:` spec (or a bare path, as npm reads
/// `./x`, `../x`, `/x`) names, relative to its manifest; `None` for any
/// other spec. A `file:` tarball is a path too and is checked like a
/// directory.
fn path_spec_target(spec: &str) -> Option<&str> {
    if let Some(rest) = spec.strip_prefix("file:") {
        return Some(rest.strip_prefix("//").unwrap_or(rest));
    }
    if let Some(rest) = spec.strip_prefix("link:") {
        return Some(rest);
    }
    if spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('/') {
        return Some(spec);
    }
    None
}

/// A `package.json` with no lock tog can import: the store npm writes
/// `package-lock.json` through `door` (a missing-lock door), published
/// with the signed resolution record.
pub(crate) fn generate_lock(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    selected: &Selected,
) -> io::Result<()> {
    refuse_external_path_dependencies(project)?;
    let outputs = resolution_outputs(project)?;
    let node_obj = super::realize_runtime(door.store(), door.lease(), door.platform(), selected)?;
    let args = npm_resolve_args("install", &[]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let spec = crate::tailors::record_spec(
        &super::tailor::Node,
        project,
        door::npm_tool(&node_obj)?,
        &refs,
    )?;
    door::run_node_checked(
        door,
        NodeRun {
            tool: NodeTool::Npm {
                node_obj: &node_obj,
            },
            lock_root: project.path(),
            cwd: None,
            args,
            publish: Publish::Project {
                outputs,
                receipt: Some(record::producer(spec, Default::default())),
            },
            capture: false,
        },
    )
    .map(drop)
}

/// npm's `verb`, lock-only and quiet but for errors, with `extra` after the
/// resolve-only flags (the caller adds `--` and the operands).
pub(crate) fn npm_resolve_args(verb: &str, extra: &[&str]) -> Vec<String> {
    let mut args = Vec::new();
    // Errors stay visible (`--silent` hid npm's own words for a failed
    // spawn of the forced git); progress and notices are off.
    if !crate::kernel::ui::verbose() {
        args.push("--loglevel=error".to_string());
    }
    args.push(verb.to_string());
    args.extend(super::NPM_RESOLVE_ONLY.iter().map(|flag| flag.to_string()));
    args.extend(extra.iter().map(|flag| flag.to_string()));
    args
}

/// `tog attest` for Node: npm's `install --package-lock-only` (npm exits 0
/// either way, so the byte-unchanged rule is the check) or pnpm's
/// `install --lockfile-only --frozen-lockfile` at the lock root through
/// `door`'s transaction with the record's producer. The check publishes
/// nothing, not even the receipt: `tog attest` publishes every record
/// only once every check passed.
pub(crate) fn attest_project(
    door: &mut ResolutionDoor<'_>,
    project: &ProjectRoot,
    host: &dyn EditHost,
    toolchain: &Selected,
) -> io::Result<(record::ResolutionRecord, Vec<u8>)> {
    let err = |text: String| io::Error::other(text);
    let lock_name = match super::edit::node_lock_for(project.path())? {
        NodeLock::Own { name, .. } => name,
        NodeLock::UnlistedUnderPnpmWorkspace { workspace_root } => {
            return Err(super::edit::unlisted_member_refusal(
                project.path(),
                &workspace_root,
            ))
        }
        member => {
            let (root, lock_name) = member.workspace().expect("a workspace member");
            return Err(super::edit::member_lock_elsewhere(
                project.path(),
                root,
                lock_name,
            ));
        }
    };
    if !project.is_input_file(Path::new(&lock_name)) {
        return Err(err(format!(
            "{} has no lock to attest; run `tog` first to write package-lock.json",
            project.path().display()
        )));
    }
    if lock_name == "yarn.lock" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "{} is locked by yarn (yarn.lock), and yarn is not a pinned tool, so tog has no \
                 lock check to run for it; convert with 'npm install --package-lock-only' or \
                 'pnpm install --lockfile-only', then attest",
                project.path().display()
            ),
        ));
    }
    refuse_external_path_dependencies(project)?;
    let outputs = resolution_outputs(project)?;
    let node_obj = super::realize_runtime(door.store(), door.lease(), door.platform(), toolchain)?;
    let tailor = super::tailor::Node;
    let slot = record::RecordSlot::default();
    let report = if lock_name == "pnpm-lock.yaml" {
        let lock_text = super::inputs::read_input(project, &lock_name)?;
        let pinned = super::edit::pinned_pnpm(door, host, project.path(), &lock_text)?;
        let args: Vec<String> = [
            "install",
            "--lockfile-only",
            "--frozen-lockfile",
            "--reporter",
            "append-only",
        ]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut spec =
            crate::tailors::record_spec(&tailor, project, door::pnpm_tool(&pinned.version), &refs)?;
        spec.require_unchanged = true;
        spec.publish_receipt = false;
        door::run_node(
            door,
            NodeRun {
                tool: NodeTool::Pnpm {
                    node_obj: &node_obj,
                    program: &pinned.program,
                },
                lock_root: project.path(),
                cwd: None,
                args,
                publish: Publish::Project {
                    outputs: outputs.clone(),
                    receipt: Some(record::producer(spec, slot.clone())),
                },
                capture: true,
            },
        )?
    } else {
        let args = npm_resolve_args("install", &[]);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut spec =
            crate::tailors::record_spec(&tailor, project, door::npm_tool(&node_obj)?, &refs)?;
        spec.require_unchanged = true;
        spec.publish_receipt = false;
        door::run_node(
            door,
            NodeRun {
                tool: NodeTool::Npm {
                    node_obj: &node_obj,
                },
                lock_root: project.path(),
                cwd: None,
                args,
                publish: Publish::Project {
                    outputs: outputs.clone(),
                    receipt: Some(record::producer(spec, slot.clone())),
                },
                capture: true,
            },
        )?
    };
    if !report.status.success() {
        return Err(err(format!(
            "{lock_name} in {} is not what the lock check accepts, so it is not attested; run \
             `tog` to bring it up to date and commit the result\n{}",
            project.path().display(),
            crate::kernel::resolve::confine::scrub_signing_key(
                String::from_utf8_lossy(&report.stderr).trim()
            )
        )));
    }
    let signed = slot.borrow_mut().take();
    signed.ok_or_else(|| err("the Node lock check published no record".into()))
}

/// The ledger of a `tog x` resolution, rooted under the cache root it
/// resolved into, the way a planner door's ledger is rooted under its
/// project, so GC keeps it with the root.
pub(crate) fn root_x_ledger(
    door: &ResolutionDoor<'_>,
    root: &Path,
    report: &crate::kernel::resolve::DelegateReport,
) -> io::Result<()> {
    if let Some(objects) = &report.ledger {
        let held = ProjectRoot::open(root)?;
        crate::kernel::resolve::ledger::root(door.store(), door.lease(), &held, objects)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;
    use std::fs;

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    /// npm's words on a failure are kept: the resolve-only form lowers the
    /// log level to errors rather than silencing npm.
    #[test]
    fn npm_resolve_args_keep_errors_visible() {
        let args = npm_resolve_args("install", &["--save-dev"]);
        assert!(!args.iter().any(|arg| arg == "--silent"), "{args:?}");
        assert!(
            args.contains(&"--loglevel=error".to_string()) || crate::kernel::ui::verbose(),
            "{args:?}"
        );
        assert_eq!(args[args.len() - 1], "--save-dev");
        assert!(args.contains(&"install".to_string()));
        assert!(args.contains(&"--package-lock-only".to_string()));
    }

    /// The outputs are the lock root's manifest and locks and every
    /// member manifest named anywhere: npm's `workspaces` (a glob, its
    /// literal path, a `!` ignored, a directory without a manifest not
    /// listed, `node_modules` and a symlinked directory never entered),
    /// pnpm's `packages`, the pnpm lock's importers, and the npm lock's
    /// root `workspaces`. The inputs are the root's configuration and each
    /// member's `.npmrc`.
    #[test]
    fn outputs_name_every_member_manifest_from_every_source() {
        let temp = TempDir::named("node-outputs");
        let root = temp.0.join("ws");
        write(
            &root,
            "package.json",
            r#"{"name":"ws","workspaces":["packages/*","apps/**","tools/cli","!packages/skip","lit[1]"]}"#,
        );
        for member in [
            "packages/a",
            "packages/skip",
            "apps/web",
            "apps/nested/deep",
            "tools/cli",
            "lit[1]",
            "lit1",
            "fromyaml/y",
            "fromlock/l",
            "fromnpmlock/n",
            "node_modules/packages/evil",
        ] {
            write(&root, &format!("{member}/package.json"), "{}");
        }
        fs::create_dir_all(root.join("packages/empty")).unwrap();
        write(&temp.0, "elsewhere/package.json", "{}");
        std::os::unix::fs::symlink(temp.0.join("elsewhere"), root.join("packages/linked")).unwrap();
        write(&root, "pnpm-workspace.yaml", "packages:\n  - fromyaml/*\n");
        write(
            &root,
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\n  fromlock/l:\n    dependencies: {}\n",
        );
        write(
            &root,
            "package-lock.json",
            r#"{"lockfileVersion":3,"packages":{"":{"workspaces":["fromnpmlock/*"]}}}"#,
        );
        write(&root, "packages/a/.npmrc", "");
        let held = ProjectRoot::open(&root).unwrap();
        let outputs: Vec<String> = resolution_outputs(&held)
            .unwrap()
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        assert_eq!(
            outputs,
            [
                "package.json",
                "package-lock.json",
                "npm-shrinkwrap.json",
                "pnpm-lock.yaml",
                "apps/nested/deep/package.json",
                "apps/web/package.json",
                "fromlock/l/package.json",
                "fromnpmlock/n/package.json",
                "fromyaml/y/package.json",
                "lit1/package.json",
                "lit[1]/package.json",
                "packages/a/package.json",
                "packages/skip/package.json",
                "tools/cli/package.json",
            ]
        );
        let inputs: Vec<String> = resolution_inputs(&held)
            .unwrap()
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        assert_eq!(
            inputs[..3],
            [".npmrc", "pnpm-workspace.yaml", ".pnpmfile.cjs"]
        );
        assert!(inputs.contains(&"packages/a/.npmrc".to_string()));
        assert!(inputs.contains(&"tools/cli/.npmrc".to_string()));

        // A member named outside the project cannot be in a record.
        write(&root, "package.json", r#"{"workspaces":["../elsewhere"]}"#);
        let error = resolution_outputs(&held).unwrap_err().to_string();
        assert!(
            error.contains("../elsewhere") && error.contains("not a plain path"),
            "{error}"
        );
        // A members list tog cannot read fails closed.
        write(&root, "package.json", r#"{"workspaces":"packages/*"}"#);
        assert!(resolution_outputs(&held).is_err());
        write(&root, "package.json", "{}");
        write(&root, "pnpm-workspace.yaml", "packages: &a\n  - x\n");
        let error = resolution_outputs(&held).unwrap_err().to_string();
        assert!(error.contains("pnpm-workspace.yaml"), "{error}");
        // A `file:` dependency outside the project is refused by name; one
        // inside, a registry spec, and a missing path are not.
        fs::remove_file(root.join("pnpm-workspace.yaml")).unwrap();
        write(
            &root,
            "package.json",
            r#"{"dependencies":{"a":"file:packages/a","b":"^1.0.0","c":"file:../missing"}}"#,
        );
        refuse_external_path_dependencies(&held).unwrap();
        write(
            &root,
            "package.json",
            r#"{"dependencies":{"out":"file:../elsewhere"}}"#,
        );
        let error = refuse_external_path_dependencies(&held)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("file:../elsewhere") && error.contains("outside the project"),
            "{error}"
        );
        write(&root, "package.json", r#"{"workspaces":["packages/a"]}"#);
        write(
            &root,
            "packages/a/package.json",
            r#"{"devDependencies":{"out":"../../../elsewhere"}}"#,
        );
        let error = refuse_external_path_dependencies(&held)
            .unwrap_err()
            .to_string();
        assert!(error.contains("packages/a/package.json"), "{error}");
        write(&root, "packages/a/package.json", "{}");
        // peerDependencies, npm overrides (nested) and pnpm.overrides too.
        for manifest in [
            r#"{"peerDependencies":{"out":"file:../elsewhere"}}"#,
            r#"{"overrides":{"parent":{"out":"file:../elsewhere"}}}"#,
            r#"{"pnpm":{"overrides":{"out":"link:../elsewhere"}}}"#,
        ] {
            write(&root, "package.json", manifest);
            let error = refuse_external_path_dependencies(&held)
                .unwrap_err()
                .to_string();
            assert!(error.contains("../elsewhere"), "{manifest}: {error}");
        }
        write(
            &root,
            "package.json",
            r#"{"overrides":{"a":{"b":"^1.0.0"}},"pnpm":{"overrides":{"c":"2"}}}"#,
        );
        refuse_external_path_dependencies(&held).unwrap();
        assert_eq!(path_spec_target("file://../x"), Some("../x"));
        assert_eq!(path_spec_target("link:../x"), Some("../x"));
        assert_eq!(path_spec_target("workspace:*"), None);
        assert_eq!(path_spec_target("github:a/b"), None);
        // A single project has just its manifest and locks.
        let single = temp.0.join("single");
        write(&single, "package.json", "{}");
        let single = ProjectRoot::open(&single).unwrap();
        assert_eq!(
            resolution_outputs(&single).unwrap(),
            [
                "package.json",
                "package-lock.json",
                "npm-shrinkwrap.json",
                "pnpm-lock.yaml"
            ]
            .map(PathBuf::from)
            .to_vec()
        );
        assert_eq!(
            resolution_inputs(&single).unwrap(),
            INPUTS.map(PathBuf::from).to_vec()
        );
    }
}
