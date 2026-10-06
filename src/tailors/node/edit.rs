//! `tog add` / `remove` / `update` for Node (`Tailor::edit_manifest`).
//!
//! A project with its own package-lock.json (or none yet) is edited by the
//! store node's npm. A pnpm lock, its own or its workspace's, is edited by
//! the exact pnpm the project's `packageManager` field pins, realized in
//! the `tog x` cache (see `corepack`). Both run confined through the edit
//! door (`super::door`), which publishes the manifest and the lock with
//! the signed resolution record. yarn is not a pinned tool, so a yarn
//! project refuses with the command to run.

use super::corepack::{self, CorepackAlgo, CorepackHash};
use super::door::{self, NodeRun, NodeTool, PnpmProgram};
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::resolve::door::Publish;
use crate::kernel::resolve::{record, DoorKind, ResolutionDoor};
use crate::tailors::edit::{
    other, registry_latest, CachedTool, EditHost, EditOutcome, EditVerb, ManifestEdit,
    PackageRegistry,
};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Node

/// How `tog add` names this ecosystem's public registry.
pub(crate) const REGISTRY: PackageRegistry = PackageRegistry {
    prefix: "npm",
    name: "npm",
};

/// `Tailor::registry_exists`: `Some(latest version)` when npm knows
/// `name`.
pub(crate) fn registry_exists(name: &str) -> io::Result<Option<String>> {
    let url = format!("https://registry.npmjs.org/{name}");
    registry_latest(REGISTRY, name, &url, |v| {
        v["dist-tags"]["latest"].as_str().map(str::to_string)
    })
}

/// npm's `@scope/name` is npm's alone.
pub(crate) fn claims_package_name(name: &str) -> bool {
    name.starts_with('@') && name.contains('/')
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NodePackageManager {
    Pnpm {
        version: String,
        corepack_hash: Option<CorepackHash>,
    },
}

impl NodePackageManager {
    fn name(&self) -> &'static str {
        "pnpm"
    }

    fn version(&self) -> &str {
        let Self::Pnpm { version, .. } = self;
        version
    }

    fn corepack_hash(&self) -> Option<&CorepackHash> {
        let Self::Pnpm { corepack_hash, .. } = self;
        corepack_hash.as_ref()
    }
}

/// Split a `packageManager` version off its Corepack `+<algo>.<hex>` hash
/// suffix. The suffix is diagnosed on its own terms: an unknown algorithm
/// names the algorithm and the supported set rather than blaming a version
/// that is already exact.
fn package_manager_version(
    value: &str,
    package_json: &Path,
) -> io::Result<(String, Option<CorepackHash>)> {
    let (version, suffix) = match value.split_once('+') {
        Some((version, suffix)) => (version, Some(suffix)),
        None => (value, None),
    };
    let hash = match suffix {
        None => None,
        Some(suffix) => {
            let (algo, hex) = suffix.split_once('.').ok_or_else(|| {
                other(format!(
                    "{}: packageManager hash suffix must be +<algo>.<hex>, found \"+{suffix}\"; supported algorithms are {}",
                    package_json.display(),
                    CorepackAlgo::SUPPORTED
                ))
            })?;
            let parsed = CorepackAlgo::parse(algo).ok_or_else(|| {
                other(format!(
                    "{}: packageManager hash algorithm {algo:?} is not supported; tog verifies {}; drop the suffix or re-pin with one of those",
                    package_json.display(),
                    CorepackAlgo::SUPPORTED
                ))
            })?;
            if hex.len() != parsed.hex_len() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(other(format!(
                    "{}: packageManager has a malformed {} hash",
                    package_json.display(),
                    parsed.name()
                )));
            }
            Some(CorepackHash {
                algo: parsed,
                hex: hex.to_ascii_lowercase(),
            })
        }
    };
    if !corepack::is_exact_version(version) {
        return Err(other(format!(
            "{}: packageManager version must be an exact release such as pnpm@9.12.3 (a prerelease suffix is allowed)",
            package_json.display()
        )));
    }
    Ok((version.to_string(), hash))
}

fn parse_package_manager_value(value: &str, package_json: &Path) -> io::Result<NodePackageManager> {
    let version = value.strip_prefix("pnpm@").ok_or_else(|| {
        other(format!(
            "{}: packageManager must be pnpm@<exact-version>, found {value:?}",
            package_json.display()
        ))
    })?;
    let (version, corepack_hash) = package_manager_version(version, package_json)?;
    Ok(NodePackageManager::Pnpm {
        version,
        corepack_hash,
    })
}

fn pnpm_lock_format(lock_text: &str) -> Option<String> {
    lock_text
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("lockfileVersion:")
                .map(|version| version.trim().trim_matches(['\'', '"']))
        })
        .filter(|version| !version.is_empty())
        .map(str::to_string)
}

fn node_package_manager(root: &Path, lock_text: &str) -> io::Result<NodePackageManager> {
    let package_json = root.join("package.json");
    let text = fs::read_to_string(&package_json).map_err(|error| {
        other(format!(
            "read {}: {error}; add a package.json with a packageManager field",
            package_json.display()
        ))
    })?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| other(format!("{}: {error}", package_json.display())))?;
    let field = value.get("packageManager").ok_or_else(|| {
        let format = pnpm_lock_format(lock_text)
            .map(|format| format!(" pnpm-lock.yaml is lockfile format {format};"))
            .unwrap_or_default();
        other(format!(
            "{}: packageManager is required;{format} set packageManager to the exact pnpm version your team runs, e.g. from `pnpm --version`",
            package_json.display()
        ))
    })?;
    let value = field.as_str().ok_or_else(|| {
        other(format!(
            "{}: packageManager must be a string like pnpm@9.12.3",
            package_json.display()
        ))
    })?;
    parse_package_manager_value(value, &package_json)
}

fn node_lock_at(directory: &Path) -> Option<&'static str> {
    ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"]
        .into_iter()
        .find(|name| directory.join(name).is_file())
}

/// What an ancestor `pnpm-lock.yaml` says about a project below it.
///
/// `pnpm-workspace.yaml` existing is not the question: since pnpm 10 that file
/// is also the project-level settings file, so `pnpm config set
/// --location=project` writes one in a repository that has no workspace at
/// all. The lock's `importers` list is the authority pnpm itself produced.
#[derive(Debug)]
enum PnpmMembership {
    Listed,
    UnlistedInWorkspace,
    NotAWorkspace,
}

fn pnpm_membership(root: &Path, project: &Path) -> io::Result<PnpmMembership> {
    let canonical_root = root.canonicalize()?;
    let canonical_project = project.canonicalize()?;
    let relative = canonical_project
        .strip_prefix(&canonical_root)
        .map_err(|_| {
            other(format!(
                "project {} is outside pnpm workspace root {}",
                canonical_project.display(),
                canonical_root.display()
            ))
        })?;
    let mut key = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(other(format!(
                "project {} is not a plain path below pnpm workspace root {}",
                canonical_project.display(),
                canonical_root.display()
            )));
        };
        let part = part.to_str().ok_or_else(|| {
            other(format!(
                "project {} has a path component that is not UTF-8",
                canonical_project.display()
            ))
        })?;
        if !key.is_empty() {
            key.push('/');
        }
        key.push_str(&part.replace('\\', "/"));
    }
    if key.is_empty() {
        key.push('.');
    }
    let lock_path = root.join("pnpm-lock.yaml");
    let text = fs::read_to_string(&lock_path)
        .map_err(|error| other(format!("read {}: {error}", lock_path.display())))?;
    let importers = super::lock_import::pnpm_lock_importers(&text).map_err(|error| {
        other(format!(
            "{}: {error}; tog reads workspace membership from this file, so it must parse. If it is the result of an unresolved merge conflict, resolve the conflict or delete the file and run 'pnpm install' in {} to regenerate it, then run tog again",
            lock_path.display(),
            root.display()
        ))
    })?;
    if importers.iter().any(|importer| importer == &key) {
        return Ok(PnpmMembership::Listed);
    }
    if importers.iter().any(|importer| importer != ".") {
        return Ok(PnpmMembership::UnlistedInWorkspace);
    }
    Ok(PnpmMembership::NotAWorkspace)
}

/// Select the lockfile to edit. A lockfile in the project itself wins in the
/// same order as sync. A workspace root may be inherited: a pnpm root when
/// its `pnpm-lock.yaml` lists the project among its importers, an npm root
/// when its `package.json` names the project in `workspaces` (npm's own
/// rule, so a confined npm run in the member finds the same root it would
/// find unconfined; the root's lock, when it has one, is then the lock to
/// edit, `yarn.lock` included). Any other ancestor lock is a boundary.
///
/// The last variant is not an advisory flag a caller may drop: tog
/// cannot tell a member added since the last install from a project the
/// workspace deliberately excludes, so each caller has to say what it does
/// about that, and anything that would write a lockfile must refuse.
pub(crate) enum NodeLock {
    Own { name: String, root: PathBuf },
    PnpmWorkspaceMember { root: PathBuf },
    NpmWorkspaceMember { root: PathBuf },
    UnlistedUnderPnpmWorkspace { workspace_root: PathBuf },
}

impl NodeLock {
    /// The root whose lock a workspace member's edit writes, with the
    /// lock's name there; `None` for a project that is its own root or
    /// one the pnpm workspace does not list.
    pub(crate) fn workspace(&self) -> Option<(&Path, &'static str)> {
        match self {
            NodeLock::PnpmWorkspaceMember { root } => Some((root, "pnpm-lock.yaml")),
            NodeLock::NpmWorkspaceMember { root } => {
                Some((root, node_lock_at(root).unwrap_or("package-lock.json")))
            }
            NodeLock::Own { .. } | NodeLock::UnlistedUnderPnpmWorkspace { .. } => None,
        }
    }
}

pub(crate) fn node_lock_for(project: &Path) -> io::Result<NodeLock> {
    let own = |name: &str| NodeLock::Own {
        name: name.to_string(),
        root: project.to_path_buf(),
    };
    if let Some(lock_name) = node_lock_at(project) {
        return Ok(own(lock_name));
    }
    if project.join(".tog").is_dir() {
        return Ok(own("package-lock.json"));
    }
    for ancestor in project.ancestors().skip(1) {
        let lock_name = node_lock_at(ancestor);
        if lock_name == Some("pnpm-lock.yaml") {
            match pnpm_membership(ancestor, project)? {
                PnpmMembership::Listed => {
                    return Ok(NodeLock::PnpmWorkspaceMember {
                        root: ancestor.to_path_buf(),
                    });
                }
                PnpmMembership::UnlistedInWorkspace => {
                    return Ok(NodeLock::UnlistedUnderPnpmWorkspace {
                        workspace_root: ancestor.to_path_buf(),
                    });
                }
                PnpmMembership::NotAWorkspace => break,
            }
        }
        // npm needs no lock at the root to take it as the workspace root,
        // so neither does tog: a root that has none yet gets its first
        // lock from the member's edit, at the root.
        let relative = project
            .strip_prefix(ancestor)
            .expect("an ancestor is a prefix of the project");
        if super::resolve::npm_workspace_names(ancestor, relative) {
            return Ok(NodeLock::NpmWorkspaceMember {
                root: ancestor.to_path_buf(),
            });
        }
        if lock_name.is_some() || ancestor.join(".tog").is_dir() {
            break;
        }
    }
    Ok(own("package-lock.json"))
}

/// The refusal for a command run in a workspace member whose lock, and
/// with it tog's record and projection, live at the root: the member
/// cannot be resolved or synced alone.
pub(crate) fn member_lock_elsewhere(project: &Path, root: &Path, lock_name: &str) -> io::Error {
    other(format!(
        "{} is a member of the workspace at {}; its {lock_name} and resolution record live \
         there, so run this command in {}",
        project.display(),
        root.display(),
        root.display()
    ))
}

fn is_yarn_berry(root: &Path) -> bool {
    if root.join(".yarnrc.yml").is_file() {
        return true;
    }
    let Ok(text) = fs::read_to_string(root.join("package.json")) else {
        return false;
    };
    let Ok(package) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    let Some(value) = package
        .get("packageManager")
        .and_then(|value| value.as_str())
    else {
        return false;
    };
    let Some(version) = value.strip_prefix("yarn@") else {
        return false;
    };
    version
        .split(['.', '-', '+'])
        .next()
        .and_then(|major| major.parse::<u64>().ok())
        .is_some_and(|major| major >= 2)
}

fn yarn_refusal(root: &Path, verb: EditVerb, texts: &[String], dev: bool) -> io::Error {
    if is_yarn_berry(root) {
        return other(
            "this project uses Yarn Berry; Berry cache checksums are not npm tarball integrity values; convert with 'npm install --package-lock-only' or 'pnpm install --lockfile-only', then 'tog'",
        );
    }
    let tool_verb = verb.command();
    other(format!(
        "this project is locked by yarn (yarn.lock) and yarn is not a pinned tool; run 'yarn {tool_verb}{}{}', then 'tog' (it imports yarn.lock)",
        if dev && verb == EditVerb::Add { " -D" } else { "" },
        texts.iter().map(|text| format!(" {text}")).collect::<String>()
    ))
}

/// pnpm's `verb`, lock-only, with the operands after `--`. The modules
/// state, the store, the proxy, and the forced settings (`ignore-scripts`
/// among them, as `--config.ignore-scripts=true`, the one spelling every
/// verb's parser takes: `pnpm remove` rejects the `--ignore-scripts` flag)
/// are the door's (`super::door`).
fn pnpm_edit_args(
    verb: EditVerb,
    texts: &[String],
    dev: bool,
    workspace_root: bool,
) -> Vec<String> {
    let mut args = vec![verb.command().to_string(), "--lockfile-only".into()];
    args.extend(["--reporter", "append-only"].map(str::to_string));
    if workspace_root {
        args.push("-w".into());
    }
    if dev && verb == EditVerb::Add {
        args.push("-D".into());
    }
    if !texts.is_empty() {
        args.push("--".into());
        args.extend(texts.iter().cloned());
    }
    args
}

/// The refusal for a project under a pnpm workspace whose lock does not
/// list it: tog cannot tell a member added since the last install from a
/// deliberate exclusion, and never writes a lock inside a workspace.
pub(crate) fn unlisted_member_refusal(project: &Path, workspace_root: &Path) -> io::Error {
    other(format!(
        "{} sits under the pnpm workspace {} but {} does not list it as an importer, so tog cannot tell whether it is a workspace member. If it is a member you added since the last install, run 'pnpm install' in {} and then run tog again. If it is deliberately outside the workspace, put a .tog directory in {} to make it its own root. Tog refuses rather than write a package-lock.json inside a pnpm workspace",
        project.display(),
        workspace_root.display(),
        workspace_root.join("pnpm-lock.yaml").display(),
        workspace_root.display(),
        project.display()
    ))
}

/// `Tailor::edit_root` for Node: the root whose lock an edit in `project`
/// writes. A project the workspace lock does not list is its own root here;
/// its edit refuses.
pub(crate) fn edit_root(project: &Path) -> io::Result<PathBuf> {
    Ok(match node_lock_for(project)? {
        NodeLock::Own { root, .. } => root,
        NodeLock::PnpmWorkspaceMember { root } | NodeLock::NpmWorkspaceMember { root } => root,
        NodeLock::UnlistedUnderPnpmWorkspace { .. } => project.to_path_buf(),
    })
}

/// `Tailor::edit_manifest` for Node.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    let project = edit.project;
    let selected = node_lock_for(project)?;
    let (lock_name, lock_root) = match &selected {
        NodeLock::Own { name, root } => (name.as_str(), root.clone()),
        NodeLock::UnlistedUnderPnpmWorkspace { workspace_root } => {
            return Err(unlisted_member_refusal(project, workspace_root));
        }
        member => {
            let (root, name) = member.workspace().expect("a workspace member");
            (name, root.to_path_buf())
        }
    };
    if lock_name == "package-lock.json" {
        return npm_edit(edit, door, lock_root);
    }
    let lock_text = fs::read_to_string(lock_root.join(lock_name))?;
    if lock_name == "yarn.lock" {
        return Err(yarn_refusal(&lock_root, edit.verb, &edit.texts(), edit.dev));
    }
    pnpm_edit(edit, door, lock_name, lock_root, &lock_text)
}

/// A project with its own package-lock.json (or no lock yet), or a member
/// of an npm workspace whose root `lock_root` has one or none: the store
/// node's npm edits it, confined through the edit door at the lock root
/// (running in the member, where npm's own workspace detection finds the
/// root and applies the edit to that member), which publishes the
/// manifests and the lock with the signed resolution record.
fn npm_edit(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
    lock_root: PathBuf,
) -> io::Result<EditOutcome> {
    let (project, verb, dev, texts) = (edit.project, edit.verb, edit.dev, &edit.texts());
    let held = ProjectRoot::open(&lock_root)?;
    crate::kernel::store::Store::check_registrable(held.path())?;
    super::resolve::refuse_external_path_dependencies(&held)?;
    let outputs = super::resolve::resolution_outputs(&held)?;
    let node_obj = super::realize_runtime(
        door.store(),
        door.lease(),
        door.platform(),
        &edit.host.toolchain(project, "node")?,
    )?;
    let cwd = member_dir(&held, project, "npm")?;
    let (npm_verb, extra): (&str, &[&str]) = match verb {
        EditVerb::Add if dev => ("install", &["--save-dev"]),
        EditVerb::Add => ("install", &[]),
        EditVerb::Remove => ("uninstall", &[]),
        EditVerb::Update => ("update", &[]),
    };
    let mut args = super::resolve::npm_resolve_args(npm_verb, extra);
    if !texts.is_empty() {
        args.push("--".into());
        args.extend(texts.iter().cloned());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let spec = crate::tailors::record_spec(
        &super::tailor::Node,
        &held,
        door::npm_tool(&node_obj)?,
        &refs,
    )?;
    let package_label = package_label(&cwd);
    door::run_node_checked(
        door,
        NodeRun {
            tool: NodeTool::Npm {
                node_obj: &node_obj,
            },
            lock_root: held.path(),
            cwd,
            args,
            publish: Publish::Project {
                outputs,
                receipt: Some(record::producer(spec, Default::default())),
            },
            capture: false,
        },
    )?;
    Ok(EditOutcome {
        files: vec![package_label, "package-lock.json".into()],
        sync_root: lock_root,
    })
}

/// The manifest an edit names in its report: the member's, below the
/// lock root, or the root's own.
fn package_label(cwd: &Option<PathBuf>) -> String {
    match cwd {
        Some(member) => member.join("package.json").to_string_lossy().into_owned(),
        None => "package.json".to_string(),
    }
}

/// The pnpm a project's `packageManager` pins, realized in the `tog x`
/// cache and found in the store: what a Node door runs. The cache root's
/// lifecycle lock is held for as long as this lives.
pub(crate) struct PinnedPnpm {
    #[allow(dead_code)]
    tool: CachedTool,
    pub version: String,
    pub program: PnpmProgram,
}

/// The pinned pnpm of the project whose lock root is `lock_root`
/// (`lock_text` is its `pnpm-lock.yaml`, for the refusal's words). The
/// pinned pnpm is a registry tool: it resolves through an `x` door on a
/// Node scope nested in `door`'s, which publishes only when this call
/// realized it.
pub(crate) fn pinned_pnpm(
    door: &mut ResolutionDoor<'_>,
    host: &dyn EditHost,
    lock_root: &Path,
    lock_text: &str,
) -> io::Result<PinnedPnpm> {
    let manager = node_package_manager(lock_root, lock_text)?;
    let mut node_attribution = door.attribution().nested("node")?;
    let tool = {
        let mut x_door = ResolutionDoor::open(
            door.store(),
            door.lease(),
            door.platform(),
            DoorKind::X,
            &mut node_attribution,
        )?;
        corepack::realize_node_tool(
            host,
            &mut x_door,
            lock_root,
            manager.name(),
            manager.version(),
            manager.corepack_hash(),
        )?
    };
    if tool.realized {
        node_attribution.finish(true)?;
    } else {
        node_attribution.discard();
    }
    let program = door::pnpm_program(&tool.root, manager.version())?;
    Ok(PinnedPnpm {
        tool,
        version: manager.version().to_string(),
        program,
    })
}

/// A pnpm lock, the project's own or its workspace's: the exact pnpm the
/// `packageManager` field pins edits it, confined through the edit door
/// at the workspace root (running in the member the edit was made in),
/// which publishes the manifest and the lock with the signed resolution
/// record.
fn pnpm_edit(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
    lock_name: &str,
    lock_root: PathBuf,
    lock_text: &str,
) -> io::Result<EditOutcome> {
    let project = edit.project;
    let workspace = ProjectRoot::open(&lock_root)?;
    crate::kernel::store::Store::check_registrable(workspace.path())?;
    super::resolve::refuse_external_path_dependencies(&workspace)?;
    let outputs = super::resolve::resolution_outputs(&workspace)?;
    let pinned = pinned_pnpm(door, edit.host, workspace.path(), lock_text)?;
    let node_obj = super::realize_runtime(
        door.store(),
        door.lease(),
        door.platform(),
        &edit.host.toolchain(project, "node")?,
    )?;
    let cwd = member_dir(&workspace, project, "pnpm")?;
    let args = pnpm_edit_args(
        edit.verb,
        &edit.texts(),
        edit.dev,
        lock_name == "pnpm-lock.yaml"
            && cwd.is_none()
            && workspace.is_input_file(Path::new("pnpm-workspace.yaml")),
    );
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let spec = crate::tailors::record_spec(
        &super::tailor::Node,
        &workspace,
        door::pnpm_tool(&pinned.version),
        &refs,
    )?;
    let package_label = package_label(&cwd);
    door::run_node_checked(
        door,
        NodeRun {
            tool: NodeTool::Pnpm {
                node_obj: &node_obj,
                program: &pinned.program,
            },
            lock_root: workspace.path(),
            cwd,
            args,
            publish: Publish::Project {
                outputs,
                receipt: Some(record::producer(spec, Default::default())),
            },
            capture: false,
        },
    )?;
    Ok(EditOutcome {
        files: vec![package_label, lock_name.to_string()],
        sync_root: lock_root,
    })
}

/// Where below the workspace root the edited project is: `None` at the
/// root itself. The project was placed by the lock's importers
/// (`pnpm_membership`) or the root's `workspaces`
/// (`resolve::npm_workspace_names`), so it lies under the root.
fn member_dir(workspace: &ProjectRoot, project: &Path, tool: &str) -> io::Result<Option<PathBuf>> {
    let real = project.canonicalize()?;
    match workspace.relative(&real) {
        Some(relative) if relative.as_os_str().is_empty() => Ok(None),
        Some(relative) => Ok(Some(relative.to_path_buf())),
        None => Err(other(format!(
            "{} is not below the {tool} workspace root {}",
            real.display(),
            workspace.path().display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    #[test]
    fn pnpm_package_manager_requires_an_exact_release_and_verifies_hash_syntax() {
        let package_json = Path::new("package.json");
        for (value, accepted) in [
            ("pnpm@9", false),
            ("pnpm@9.x", false),
            ("pnpm@^9.1.0", false),
            ("pnpm@latest", false),
            ("pnpm@9.01.2", false),
            ("pnpm@9.1.2", true),
        ] {
            assert_eq!(
                parse_package_manager_value(value, package_json).is_ok(),
                accepted,
                "unexpected acceptance for {value}"
            );
        }
        assert_eq!(
            parse_package_manager_value("pnpm@9.12.3", package_json).unwrap(),
            NodePackageManager::Pnpm {
                version: "9.12.3".into(),
                corepack_hash: None,
            }
        );
        assert_eq!(
            parse_package_manager_value(
                &format!("pnpm@9.1.2-rc.1+sha224.{}", "A".repeat(56)),
                package_json
            )
            .unwrap(),
            NodePackageManager::Pnpm {
                version: "9.1.2-rc.1".into(),
                corepack_hash: Some(CorepackHash {
                    algo: CorepackAlgo::Sha224,
                    hex: "a".repeat(56),
                }),
            }
        );
        let garbage =
            parse_package_manager_value("not-a-package-manager", package_json).unwrap_err();
        assert!(garbage.to_string().contains("packageManager"), "{garbage}");
        let malformed_hash =
            parse_package_manager_value("pnpm@9.1.2+sha224.not-a-hash", package_json).unwrap_err();
        assert!(malformed_hash.to_string().contains("malformed sha224"));
    }

    /// Corepack has written three hash algorithms over its life; every one it
    /// writes is a pin, so none of them may be misdiagnosed as an inexact
    /// version. An algorithm tog cannot verify is refused by name.
    #[test]
    fn corepack_hash_suffixes_accept_every_supported_algorithm() {
        let package_json = Path::new("package.json");
        for (algo, width) in [
            (CorepackAlgo::Sha224, 56),
            (CorepackAlgo::Sha256, 64),
            (CorepackAlgo::Sha512, 128),
        ] {
            let value = format!("pnpm@9.15.4+{}.{}", algo.name(), "B".repeat(width));
            assert_eq!(
                parse_package_manager_value(&value, package_json).unwrap(),
                NodePackageManager::Pnpm {
                    version: "9.15.4".into(),
                    corepack_hash: Some(CorepackHash {
                        algo,
                        hex: "b".repeat(width),
                    }),
                },
                "rejected {value}"
            );
            // The right hex for the wrong algorithm is a malformed hash, not a
            // silently accepted one.
            let short = format!("pnpm@9.15.4+{}.{}", algo.name(), "b".repeat(width - 2));
            let error = parse_package_manager_value(&short, package_json).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("malformed {} hash", algo.name())),
                "{error}"
            );
        }

        let unknown = parse_package_manager_value(
            &format!("pnpm@9.15.4+sha1.{}", "c".repeat(40)),
            package_json,
        )
        .unwrap_err()
        .to_string();
        assert!(unknown.contains("\"sha1\""), "{unknown}");
        assert!(unknown.contains("sha224, sha256, sha512"), "{unknown}");
        assert!(!unknown.contains("exact release"), "{unknown}");

        let shapeless = parse_package_manager_value("pnpm@9.15.4+deadbeef", package_json)
            .unwrap_err()
            .to_string();
        assert!(shapeless.contains("+<algo>.<hex>"), "{shapeless}");
        assert!(!shapeless.contains("exact release"), "{shapeless}");
    }

    #[test]
    fn missing_pnpm_package_manager_names_lock_format_without_floating_suggestion() {
        let scratch = TempDir::named("node-package-manager");
        let root = scratch.0.clone();
        fs::write(root.join("package.json"), "{}\n").unwrap();
        let missing = node_package_manager(&root, "lockfileVersion: '9.0'\n").unwrap_err();
        let missing = missing.to_string();
        assert!(
            missing.contains(
                "pnpm-lock.yaml is lockfile format 9.0; set packageManager to the exact pnpm version your team runs, e.g. from `pnpm --version`"
            ),
            "{missing}"
        );
        assert!(!missing.contains("pnpm major 9"), "{missing}");
    }

    /// `pnpm-lock.yaml` decides membership, so two shapes a glob-based
    /// reading would send down the npm branch — writing a stray
    /// `package-lock.json` inside a pnpm workspace — resolve correctly: an
    /// alternation group, which pnpm's glob engine supports and tog's
    /// matcher does not, and a block sequence at the parent key's own
    /// indent, which is ordinary hand-written YAML that tog's
    /// lockfile-shaped parser rejects.
    #[test]
    fn workspace_membership_comes_from_the_lock_not_the_glob() {
        let scratch = TempDir::named("ws-importers");
        let root = scratch.0.clone();
        let member = root.join("apps/web");
        fs::create_dir_all(&member).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  apps/web: {}\n",
        )
        .unwrap();
        // Both hostile-to-tog shapes at once: alternation, at indent 0.
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n- '(apps|libs)/*'\n",
        )
        .unwrap();
        assert!(
            matches!(
                pnpm_membership(&root, &member).unwrap(),
                PnpmMembership::Listed
            ),
            "a member the lock enumerates was not recognised"
        );
        assert!(
            matches!(
                pnpm_membership(&root, &root).unwrap(),
                PnpmMembership::Listed
            ),
            "the workspace root itself was not recognised"
        );

        let stranger = root.join("apps/other");
        fs::create_dir_all(&stranger).unwrap();
        assert!(
            matches!(
                pnpm_membership(&root, &stranger).unwrap(),
                PnpmMembership::UnlistedInWorkspace
            ),
            "a directory the lock does not enumerate was treated as a member"
        );

        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\t bad\n",
        )
        .unwrap();
        let error = pnpm_membership(&root, &member).unwrap_err();
        assert!(error.to_string().contains("pnpm install"), "{error}");
    }

    #[test]
    fn pnpm_edit_argv_is_delimited_and_workspace_aware() {
        let args = pnpm_edit_args(EditVerb::Add, &["@scope/pkg@1.2.3".into()], true, true);
        assert_eq!(
            args,
            vec![
                "add",
                "--lockfile-only",
                "--reporter",
                "append-only",
                "-w",
                "-D",
                "--",
                "@scope/pkg@1.2.3"
            ]
        );
        // Every verb comes from `EditVerb::command`. The modules state, the
        // store, the proxy and `ignore-scripts` are the door's settings, in
        // the `--config.` spelling every verb's parser takes (`remove`
        // rejects `--ignore-scripts` and `--modules-dir` as flags).
        for verb in [EditVerb::Add, EditVerb::Remove, EditVerb::Update] {
            let args = pnpm_edit_args(verb, &[], false, false);
            assert_eq!(args[0], verb.command());
            assert_eq!(args[1], "--lockfile-only");
            assert!(!args.contains(&"-w".to_string()));
            assert!(!args.contains(&"--".to_string()));
        }
    }

    fn selected(project: &Path) -> (String, PathBuf) {
        match node_lock_for(project).unwrap() {
            NodeLock::Own { name, root } => (name, root),
            NodeLock::PnpmWorkspaceMember { root } => ("pnpm-lock.yaml".to_string(), root),
            NodeLock::NpmWorkspaceMember { root } => ("npm workspace".to_string(), root),
            NodeLock::UnlistedUnderPnpmWorkspace { workspace_root } => panic!(
                "expected a lock selection, got a refusal under the pnpm workspace {}",
                workspace_root.display()
            ),
        }
    }

    #[test]
    fn a_backslash_in_a_directory_name_takes_pnpms_own_slash_importer_key() {
        let scratch = TempDir::named("pnpm-backslash");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("packages").join("a\\b")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/a/b: {}\n",
        )
        .unwrap();
        let member = root.join("packages").join("a\\b");
        assert!(
            matches!(
                pnpm_membership(&root, &member).unwrap(),
                PnpmMembership::Listed
            ),
            "pnpm 9.12.3 writes the importer key packages/a/b for the on-disk \
             directory packages/a\\b, so tog must normalise the same way"
        );
    }

    #[test]
    fn a_project_the_workspace_lock_does_not_list_refuses_instead_of_selecting_npm() {
        let scratch = TempDir::named("pnpm-unlisted");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("packages/listed")).unwrap();
        fs::create_dir_all(root.join("packages/added-since-install")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/listed: {}\n",
        )
        .unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\n",
        )
        .unwrap();

        assert_eq!(
            selected(&root.join("packages/listed")),
            ("pnpm-lock.yaml".to_string(), root.clone())
        );

        let unlisted = node_lock_for(&root.join("packages/added-since-install")).unwrap();
        assert!(
            matches!(
                unlisted,
                NodeLock::UnlistedUnderPnpmWorkspace { ref workspace_root } if workspace_root == &root
            ),
            "a member added since the last pnpm install must be reported, not \
             silently handed to npm"
        );
    }

    #[test]
    fn a_settings_only_pnpm_workspace_yaml_does_not_make_a_single_package_repo_a_workspace() {
        let scratch = TempDir::named("pnpm-settings-only");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("examples/demo")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nsettings:\n\n  autoInstallPeers: true\n\nimporters:\n\n  .: {}\n",
        )
        .unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "onlyBuiltDependencies:\n  - esbuild\n",
        )
        .unwrap();

        let nested = root.join("examples/demo");
        assert_eq!(
            selected(&nested),
            ("package-lock.json".to_string(), nested.clone()),
            "since pnpm 10 pnpm-workspace.yaml is also the project settings \
             file, so its presence alone must not make an ordinary \
             single-package repository a workspace that swallows every \
             subdirectory"
        );
        assert!(
            matches!(
                pnpm_membership(&root, &nested).unwrap(),
                PnpmMembership::NotAWorkspace
            ),
            "a lock whose only importer is the root itself describes a \
             single-package repository"
        );
    }

    #[test]
    fn node_lock_selection_prefers_own_lock_and_reads_workspace_membership_from_the_lock() {
        let scratch = TempDir::named("node-lock-selection");
        let root = scratch.0.clone();
        fs::create_dir_all(root.join("packages/lib")).unwrap();
        fs::create_dir_all(root.join("packages/private")).unwrap();
        fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/lib: {}\n",
        )
        .unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - '!packages/private'\n  - packages/*\n",
        )
        .unwrap();
        let member = root.join("packages/lib");
        assert_eq!(
            selected(&member),
            ("pnpm-lock.yaml".to_string(), root.clone())
        );

        let independent = root.join("packages/private");
        let excluded = node_lock_for(&independent).unwrap();
        assert!(
            matches!(
                excluded,
                NodeLock::UnlistedUnderPnpmWorkspace { ref workspace_root } if workspace_root == &root
            ),
            "tog does not reimplement pnpm's exclusion globs, so a project \
             the lock does not list is ambiguous and must refuse rather than \
             guess npm"
        );

        fs::create_dir_all(independent.join(".tog")).unwrap();
        assert_eq!(
            selected(&independent),
            ("package-lock.json".to_string(), independent.clone()),
            "a .tog directory is how a project inside a workspace tree \
             declares itself its own root"
        );
        fs::remove_dir_all(independent.join(".tog")).unwrap();

        fs::write(independent.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(
            selected(&independent),
            ("package-lock.json".to_string(), independent.clone())
        );

        fs::write(member.join("package-lock.json"), "{}\n").unwrap();
        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(selected(&member), ("package-lock.json".to_string(), member));

        let boundary = root.join("packages/boundary");
        fs::create_dir_all(boundary.join(".tog")).unwrap();
        assert_eq!(
            selected(&boundary),
            ("package-lock.json".to_string(), boundary)
        );
    }

    /// An npm workspace member edits the root's lock, by npm's own rule:
    /// the root `package.json` names the member in `workspaces` (a glob
    /// or a literal path, less a `!` pattern), and the member has a
    /// manifest. The root needs no lock yet; a root with `yarn.lock` is
    /// still the root (its edit then refuses as yarn's). A member's own
    /// lock or `.tog` directory, a `!` exclusion, a directory without a
    /// manifest, and a root whose `workspaces` does not name the project
    /// each leave the project its own root, as before.
    #[test]
    fn an_npm_workspace_member_takes_the_root_as_its_lock_root() {
        let scratch = TempDir::named("npm-workspace-member");
        let root = scratch.0.clone();
        let app = root.join("packages/app");
        let util = root.join("packages/util");
        let skipped = root.join("packages/skipped");
        let no_manifest = root.join("packages/empty");
        let deep = root.join("apps/nested/deep");
        let tool = root.join("tools/cli");
        for dir in [&app, &util, &skipped, &no_manifest, &deep, &tool] {
            fs::create_dir_all(dir).unwrap();
        }
        for dir in [&app, &util, &skipped, &deep, &tool] {
            fs::write(dir.join("package.json"), "{}\n").unwrap();
        }
        fs::write(
            root.join("package.json"),
            r#"{"workspaces":["packages/*","!packages/skipped","apps/**","./tools/cli/"]}"#,
        )
        .unwrap();

        let member = |project: &Path| match node_lock_for(project).unwrap() {
            NodeLock::NpmWorkspaceMember { root } => Some(root),
            NodeLock::Own { .. } => None,
            _ => panic!("a pnpm selection for {}", project.display()),
        };
        // No lock at the root yet: it is the root all the same, and the
        // root's lock name defaults to npm's.
        assert_eq!(member(&app), Some(root.clone()));
        assert_eq!(
            node_lock_for(&app).unwrap().workspace().unwrap().1,
            "package-lock.json"
        );
        assert_eq!(member(&util), Some(root.clone()));
        assert_eq!(member(&deep), Some(root.clone()));
        assert_eq!(member(&tool), Some(root.clone()));
        assert_eq!(edit_root(&app).unwrap(), root);
        assert_eq!(member(&skipped), None, "a `!` pattern excludes");
        assert_eq!(member(&no_manifest), None, "no manifest, no member");
        assert_eq!(member(&root.join("packages")), None);

        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(member(&app), Some(root.clone()));
        assert_eq!(
            node_lock_for(&app).unwrap().workspace().unwrap().1,
            "package-lock.json"
        );
        assert_eq!(member(&skipped), None);
        assert_eq!(
            selected(&skipped),
            ("package-lock.json".to_string(), skipped.clone()),
            "an excluded project under a root lock is its own root, as before"
        );

        // The member's own lock, and its own `.tog`, win.
        fs::write(app.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(
            selected(&app),
            ("package-lock.json".to_string(), app.clone())
        );
        fs::remove_file(app.join("package-lock.json")).unwrap();
        fs::create_dir_all(app.join(".tog")).unwrap();
        assert_eq!(
            selected(&app),
            ("package-lock.json".to_string(), app.clone())
        );
        fs::remove_dir_all(app.join(".tog")).unwrap();
        assert_eq!(member(&app), Some(root.clone()));

        // A yarn root is still the root; the edit is then yarn's refusal.
        fs::remove_file(root.join("package-lock.json")).unwrap();
        fs::write(root.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(member(&app), Some(root.clone()));
        assert_eq!(
            node_lock_for(&app).unwrap().workspace().unwrap().1,
            "yarn.lock"
        );
        fs::remove_file(root.join("yarn.lock")).unwrap();

        // A root manifest that names other members, or is not JSON, is
        // not this project's root; with a lock there it is a boundary.
        fs::write(root.join("package.json"), r#"{"workspaces":["apps/*"]}"#).unwrap();
        assert_eq!(member(&app), None);
        fs::write(root.join("package.json"), "not json").unwrap();
        assert_eq!(member(&app), None);
        fs::write(root.join("package.json"), r#"{"workspaces":"packages/*"}"#).unwrap();
        assert_eq!(member(&app), None);

        // The refusal a sync or attest in a member gets names the root.
        let error = member_lock_elsewhere(&app, &root, "package-lock.json").to_string();
        assert!(
            error.contains(&root.display().to_string()) && error.contains("package-lock.json"),
            "{error}"
        );
    }

    #[test]
    fn ancestor_non_pnpm_locks_and_no_lock_projects_are_boundaries() {
        let scratch = TempDir::named("node-lock-boundaries");
        let root = scratch.0.clone();
        let nested = root.join("tools/nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("package.json"), "{}\n").unwrap();

        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        assert_eq!(
            selected(&nested),
            ("package-lock.json".to_string(), nested.clone())
        );
        fs::remove_file(root.join("package-lock.json")).unwrap();
        fs::write(root.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(
            selected(&nested),
            ("package-lock.json".to_string(), nested.clone())
        );
        fs::remove_file(root.join("yarn.lock")).unwrap();
        assert_eq!(selected(&nested), ("package-lock.json".to_string(), nested));
    }

    #[test]
    fn unmatched_pnpm_workspace_is_a_boundary_to_an_outer_workspace() {
        let scratch = TempDir::named("nested-pnpm-boundary");
        let root = scratch.0.clone();
        let inner = root.join("inner");
        let member = inner.join("member");
        fs::create_dir_all(&member).unwrap();
        fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - inner/**\n",
        )
        .unwrap();
        fs::write(inner.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
        fs::write(
            inner.join("pnpm-workspace.yaml"),
            "packages:\n  - '!member'\n",
        )
        .unwrap();
        fs::write(member.join("package.json"), "{}\n").unwrap();

        assert_eq!(selected(&member), ("package-lock.json".to_string(), member));
    }

    #[test]
    fn yarn_berry_uses_conversion_refusal_without_delegation() {
        let scratch = TempDir::named("yarn-berry-detection");
        let root = scratch.0.clone();
        fs::write(
            root.join("package.json"),
            "{\"packageManager\":\"yarn@1.22.22\"}\n",
        )
        .unwrap();
        assert!(!is_yarn_berry(&root));
        fs::write(root.join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
        assert!(is_yarn_berry(&root));
        fs::remove_file(root.join(".yarnrc.yml")).unwrap();
        fs::write(
            root.join("package.json"),
            "{\"packageManager\":\"yarn@2.4.3\"}\n",
        )
        .unwrap();
        assert!(is_yarn_berry(&root));
        let error = yarn_refusal(&root, EditVerb::Add, &["react".into()], false);
        assert!(
            error.to_string().contains(
                "convert with 'npm install --package-lock-only' or 'pnpm install --lockfile-only'"
            ),
            "{error}"
        );
    }
}
