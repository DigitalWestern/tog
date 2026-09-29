//! `tog add` / `remove` / `update` for Node (`Tailor::edit_manifest`).
//!
//! A project with its own package-lock.json (or none yet) is edited by the
//! store node's npm. A pnpm lock, its own or its workspace's, is edited by
//! the exact pnpm the project's `packageManager` field pins, realized in
//! the `tog x` cache (see `corepack`). yarn is not a pinned tool, so a yarn
//! project refuses with the command to run.

use super::corepack::{self, CorepackAlgo, CorepackHash};
use crate::kernel::resolve::{DelegateSpec, DoorKind, ResolutionDoor};
use crate::kernel::ui;
use crate::tailors::edit::{
    other, registry_latest, run_inherited, EditOutcome, EditVerb, ManifestEdit, PackageRegistry,
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

    fn executable(&self) -> &'static str {
        "pnpm"
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
/// same order as sync. Only a pnpm workspace root may be inherited, and only
/// when that root's `pnpm-lock.yaml` lists the project among its importers.
/// Any other ancestor lock is a boundary.
///
/// The third variant is not an advisory flag a caller may drop: tog
/// cannot tell a member added since the last install from a project the
/// workspace deliberately excludes, so each caller has to say what it does
/// about that, and anything that would write a lockfile must refuse.
enum NodeLock {
    Own { name: String, root: PathBuf },
    PnpmWorkspaceMember { root: PathBuf },
    UnlistedUnderPnpmWorkspace { workspace_root: PathBuf },
}

fn node_lock_for(project: &Path) -> io::Result<NodeLock> {
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
        if let Some(lock_name) = node_lock_at(ancestor) {
            if lock_name != "pnpm-lock.yaml" {
                break;
            }
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
        if ancestor.join(".tog").is_dir() {
            break;
        }
    }
    Ok(own("package-lock.json"))
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

fn node_delegate_args(
    verb: EditVerb,
    texts: &[String],
    dev: bool,
    workspace_root: bool,
    scratch: &PnpmScratch,
) -> Vec<String> {
    let mut args = vec![verb.command().to_string()];
    args.push("--lockfile-only".into());
    // Match the npm branch's defence in depth: `--lockfile-only` should mean
    // nothing installs and no lifecycle script runs, but pnpm still runs
    // `prepare` for git-URL dependencies while resolving. pnpm's `remove`
    // parser rejects `--ignore-scripts` outright ("Unknown option:
    // 'ignore-scripts'"), so the flag goes only on the verbs whose parser
    // accepts it; `npm_config_ignore_scripts` in the delegate's environment
    // (see `node`) is what covers all three.
    if verb != EditVerb::Remove {
        args.push("--ignore-scripts".into());
    }
    args.extend(["--reporter", "append-only"].map(str::to_string));
    // Keep pnpm's modules state out of the user's project (see
    // `PnpmScratch`). `--config.<name>=<value>` is the spelling every verb's
    // parser accepts; `remove` and `update` reject `--modules-dir` as a flag.
    args.push("--config.enable-modules-dir=false".into());
    // `enable-modules-dir=false` only means "do not link into the modules
    // directory" for the isolated linker. A project `.npmrc` carrying
    // `node-linker=hoisted` makes the delegate a real installer again: it
    // downloads packages and rewrites the user's `node_modules`, replacing
    // symlinks with copied directories. `node-linker=pnp` fails with a raw
    // pnpm stack trace. Force the linker so no project file can pick either.
    args.push("--config.node-linker=isolated".into());
    args.push(format!("--config.modules-dir={}", scratch.modules_dir));
    args.push(format!(
        "--config.virtual-store-dir={}",
        scratch.virtual_store_dir
    ));
    // pnpm falls back to `~/.pnpm-store` whenever its default store would
    // land on a different filesystem from the project: outside the project,
    // outside the tog store, and never reclaimed by `gc`.
    args.push(format!("--config.store-dir={}", scratch.store_dir));
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

/// Where pnpm keeps its modules state during an edit: a per-run stage
/// under `<store>/tmp`, never the user's project.
///
/// Even with `--lockfile-only`, pnpm's modules directory is live: at a
/// workspace root `add -w --lockfile-only` performs a full install, every
/// verb reads `node_modules/.modules.yaml` and refuses with
/// `ERR_PNPM_UNEXPECTED_STORE` when the store recorded there is not the one
/// it is given, and the workspace path deletes `<virtual-store-dir>/lock.yaml`
/// when the current lockfile is empty. Three settings, all honoured by
/// `add`, `remove`, and `update` of pnpm 9.12.3 (verified against the real
/// binary; `tests/deps_e2e.rs::pnpm_edits_leave_an_installed_project_untouched`
/// keeps proving it), move all of that out of the project:
/// `enable-modules-dir=false` links nothing, `modules-dir` decides where
/// `.modules.yaml` is looked for, and `virtual-store-dir` decides where the
/// current lockfile lives. pnpm joins both paths onto a project directory
/// (`path.join`, so an absolute value would land inside the project), hence
/// the relative spellings. Nothing is created at either path; the stage
/// exists so the paths resolve somewhere tog owns, and it is removed when
/// the delegate returns (a leftover has the `stage-` name `gc::sweep_stages`
/// reclaims).
struct PnpmScratch {
    /// `--config.modules-dir`, relative to the project pnpm runs in.
    ///
    /// pnpm joins this onto *every* importer's own directory, and one
    /// relative path cannot escape the project from importers at differing
    /// depths: computed for a workspace root, it lands back inside the
    /// project for any deeper member. What keeps the project untouched is
    /// therefore not this path but `enable-modules-dir=false` together with
    /// `node-linker=isolated` — with both, pnpm creates no importer
    /// `node_modules` at all, and this path only ever names a
    /// `.modules.yaml` to read. Remove either flag and the path alone will
    /// not save you.
    modules_dir: String,
    /// `--config.virtual-store-dir`, relative to the lock root, which is what
    /// pnpm resolves it against.
    virtual_store_dir: String,
    /// `--config.store-dir`. Absolute: pnpm resolves the store directory
    /// against the cwd rather than joining it onto an importer, so an
    /// absolute path is both safe here and the only spelling that pins the
    /// store no matter which directory the delegate runs in.
    store_dir: String,
}

fn pnpm_scratch(stage: &Path, project: &Path, lock_root: &Path) -> io::Result<PnpmScratch> {
    let stage = stage.canonicalize()?;
    let project = project.canonicalize()?;
    let lock_root = lock_root.canonicalize()?;
    let modules = stage.join("modules");
    Ok(PnpmScratch {
        modules_dir: relative_path(&project, &modules)
            .to_string_lossy()
            .into_owned(),
        virtual_store_dir: relative_path(&lock_root, &modules.join(".pnpm"))
            .to_string_lossy()
            .into_owned(),
        store_dir: stage.join("pnpm-store").to_string_lossy().into_owned(),
    })
}

/// `to` expressed relative to the directory `from`; both must be absolute and
/// free of `..` (canonical), so the answer is a lexical prefix strip.
fn relative_path(from: &Path, to: &Path) -> PathBuf {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from
        .iter()
        .zip(to.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for component in &to[common..] {
        out.push(component);
    }
    out
}

/// `Tailor::edit_root` for Node: the root whose lock an edit in `project`
/// writes. A project the workspace lock does not list is its own root here;
/// its edit refuses.
pub(crate) fn edit_root(project: &Path) -> io::Result<PathBuf> {
    Ok(match node_lock_for(project)? {
        NodeLock::Own { root, .. } => root,
        NodeLock::PnpmWorkspaceMember { root } => root,
        NodeLock::UnlistedUnderPnpmWorkspace { .. } => project.to_path_buf(),
    })
}

/// `Tailor::edit_manifest` for Node.
pub(crate) fn edit_manifest(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<EditOutcome> {
    let project = edit.project;
    let (lock_name, lock_root) = match node_lock_for(project)? {
        NodeLock::Own { name, root } => (name, root),
        NodeLock::PnpmWorkspaceMember { root } => ("pnpm-lock.yaml".to_string(), root),
        NodeLock::UnlistedUnderPnpmWorkspace { workspace_root } => {
            return Err(other(format!(
                "{} sits under the pnpm workspace {} but {} does not list it as an importer, so tog cannot tell whether it is a workspace member. If it is a member you added since the last install, run 'pnpm install' in {} and then run tog again. If it is deliberately outside the workspace, put a .tog directory in {} to make it its own root. Tog refuses rather than write a package-lock.json inside a pnpm workspace",
                project.display(),
                workspace_root.display(),
                workspace_root.join("pnpm-lock.yaml").display(),
                workspace_root.display(),
                project.display()
            )));
        }
    };
    if lock_name == "package-lock.json" {
        return npm_edit(edit, door);
    }
    let lock_text = fs::read_to_string(lock_root.join(&lock_name))?;
    if lock_name == "yarn.lock" {
        return Err(yarn_refusal(&lock_root, edit.verb, &edit.texts(), edit.dev));
    }
    pnpm_edit(edit, door, &lock_name, lock_root, &lock_text)
}

/// A project with its own package-lock.json (or no lock yet): the store
/// node's npm edits it.
fn npm_edit(edit: &ManifestEdit<'_>, door: &mut ResolutionDoor<'_>) -> io::Result<EditOutcome> {
    let (project, verb, dev, texts) = (edit.project, edit.verb, edit.dev, &edit.texts());
    let node_obj = super::realize_runtime(
        door.store(),
        door.lease(),
        door.platform(),
        &edit.host.toolchain(project, "node")?,
    )?;
    let mut spec = DelegateSpec::new(node_obj.join("bin/npm"));
    if !ui::verbose() {
        spec.arg("--silent");
    }
    match verb {
        EditVerb::Add => {
            spec.args(["install", "--package-lock-only", "--ignore-scripts"]);
            if dev {
                spec.arg("--save-dev");
            }
            if !texts.is_empty() {
                spec.arg("--").args(texts);
            }
        }
        EditVerb::Remove => {
            spec.args(["uninstall", "--package-lock-only", "--ignore-scripts"]);
            if !texts.is_empty() {
                spec.arg("--").args(texts);
            }
        }
        EditVerb::Update => {
            spec.args(["update", "--package-lock-only", "--ignore-scripts"]);
            if !texts.is_empty() {
                spec.arg("--").args(texts);
            }
        }
    }
    spec.lock_root(project).env(
        "PATH",
        format!(
            "{}:{}",
            node_obj.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        ),
    );
    run_inherited(door, spec, "store npm")?;
    Ok(EditOutcome {
        files: vec!["package.json".into(), "package-lock.json".into()],
        sync_root: project.to_path_buf(),
    })
}

/// A pnpm lock, the project's own or its workspace's: the exact pnpm the
/// `packageManager` field pins edits it.
fn pnpm_edit(
    edit: &ManifestEdit<'_>,
    door: &mut ResolutionDoor<'_>,
    lock_name: &str,
    lock_root: PathBuf,
    lock_text: &str,
) -> io::Result<EditOutcome> {
    let project = edit.project;
    let manager = node_package_manager(&lock_root, lock_text)?;
    // The pinned pnpm is a registry tool: it resolves through an `x` door
    // on a Node scope nested in the edit's, which publishes only when this
    // call realized it.
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
            edit.host,
            &mut x_door,
            &lock_root,
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
    let node_obj = super::realize_runtime(
        door.store(),
        door.lease(),
        door.platform(),
        &edit.host.toolchain(project, "node")?,
    )?;
    let executable = tool
        .root
        .join("node_modules/.bin")
        .join(manager.executable());
    if !executable.is_file() {
        return Err(other(format!(
            "store {}@{} has no {} executable",
            manager.name(),
            manager.version(),
            manager.name()
        )));
    }
    // One per-run stage holds pnpm's isolated HOME/XDG root (so pnpm never
    // reads or writes the user's pnpm config, store or registry metadata
    // cache) and the scratch its modules state is pointed at (see
    // `PnpmScratch`). It is removed when the delegate returns; a leftover
    // from a killed run carries the `stage-` name `tog gc` sweeps.
    let stage = door.store().stage_with_activity(door.lease())?;
    let package_path = project.join("package.json");
    let result = (|| -> io::Result<()> {
        let scratch = pnpm_scratch(&stage, project, &lock_root)?;
        let args = node_delegate_args(
            edit.verb,
            &edit.texts(),
            edit.dev,
            lock_name == "pnpm-lock.yaml"
                && project == lock_root
                && lock_root.join("pnpm-workspace.yaml").is_file(),
            &scratch,
        );
        let pnpm_home_dir = stage.join("home");
        let pnpm_config = pnpm_home_dir.join("xdg-config");
        let pnpm_data = pnpm_home_dir.join("xdg-data");
        let pnpm_cache = pnpm_home_dir.join("xdg-cache");
        let pnpm_state = pnpm_home_dir.join("xdg-state");
        fs::create_dir_all(&pnpm_home_dir)?;
        let mut spec = DelegateSpec::new(&executable);
        spec.args(&args).lock_root(project).env(
            "PATH",
            format!(
                "{}:{}:{}",
                node_obj.join("bin").display(),
                tool.root.join("node_modules/.bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        );
        spec.env("HOME", &pnpm_home_dir)
            .env("XDG_CONFIG_HOME", &pnpm_config)
            .env("XDG_DATA_HOME", &pnpm_data)
            .env("XDG_CACHE_HOME", &pnpm_cache)
            .env("XDG_STATE_HOME", &pnpm_state);
        // `npm_config_ignore_scripts` is set after the `npm_config_` strip
        // (which `force_env` applies case-insensitively, the way npm and pnpm
        // read `/^npm_config_/i`), so it is tog's value, not the user's.
        // It is the only way to say "run no lifecycle script" to
        // `pnpm remove`, whose parser rejects the `--ignore-scripts` flag;
        // `add` and `update` carry the flag too, and `--lockfile-only`
        // itself forces `ignoreScripts` inside pnpm's install options.
        spec.force_env(
            &["npm_config_", "PNPM_", "YARN_", "COREPACK_"],
            &["NODE_OPTIONS"],
            &[
                ("CI".into(), "1".into()),
                ("npm_config_ignore_scripts".into(), "true".into()),
            ],
        );
        run_inherited(door, spec, &format!("store {}", manager.name()))?;
        Ok(())
    })();
    let _ = crate::kernel::store::remove_tree(&stage);
    result?;
    let package_label = package_path
        .strip_prefix(&lock_root)
        .unwrap_or(&package_path)
        .to_string_lossy()
        .into_owned();
    Ok(EditOutcome {
        files: vec![package_label, lock_name.to_string()],
        sync_root: lock_root,
    })
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
    fn node_delegate_argv_is_delimited_and_workspace_aware() {
        let scratch = PnpmScratch {
            modules_dir: "../../store/tmp/stage-1/modules".into(),
            virtual_store_dir: "../store/tmp/stage-1/modules/.pnpm".into(),
            store_dir: "/store/tmp/stage-1/pnpm-store".into(),
        };
        let args = node_delegate_args(
            EditVerb::Add,
            &["@scope/pkg@1.2.3".into()],
            true,
            true,
            &scratch,
        );
        assert_eq!(
            args,
            vec![
                "add",
                "--lockfile-only",
                "--ignore-scripts",
                "--reporter",
                "append-only",
                "--config.enable-modules-dir=false",
                "--config.node-linker=isolated",
                "--config.modules-dir=../../store/tmp/stage-1/modules",
                "--config.virtual-store-dir=../store/tmp/stage-1/modules/.pnpm",
                "--config.store-dir=/store/tmp/stage-1/pnpm-store",
                "-w",
                "-D",
                "--",
                "@scope/pkg@1.2.3"
            ]
        );
        // Every verb comes from `EditVerb::command`, and every verb whose pnpm
        // parser accepts `--ignore-scripts` carries it. `remove` is the one
        // exception: pnpm rejects the flag there ("Unknown option:
        // 'ignore-scripts'"), so `npm_config_ignore_scripts` in the delegate
        // environment is what stops its lifecycle scripts.
        for verb in [EditVerb::Add, EditVerb::Remove, EditVerb::Update] {
            let args = node_delegate_args(verb, &[], false, false, &scratch);
            assert_eq!(args[0], verb.command());
            // The modules-state redirection is on every verb: `remove` and
            // `update` reject `--modules-dir` as a flag but take `--config.`.
            assert!(args.contains(&"--config.enable-modules-dir=false".to_string()));
            // Without a forced linker a project `.npmrc` (`node-linker=hoisted`)
            // turns the delegate back into a real installer.
            assert!(args.contains(&"--config.node-linker=isolated".to_string()));
            assert!(args
                .iter()
                .any(|arg| arg.starts_with("--config.store-dir=")));
            assert!(args
                .iter()
                .any(|arg| arg.starts_with("--config.modules-dir=")));
            assert!(args
                .iter()
                .any(|arg| arg.starts_with("--config.virtual-store-dir=")));
            assert_eq!(
                args.contains(&"--ignore-scripts".to_string()),
                verb != EditVerb::Remove,
                "{verb:?} delegate argv: {args:?}"
            );
        }
    }

    /// Lexically resolve `base/relative` (`..` pops), the way pnpm's
    /// `path.join` does, to check where a relative setting lands.
    fn lexical_join(base: &Path, relative: &str) -> PathBuf {
        let mut out = base.to_path_buf();
        for component in Path::new(relative).components() {
            match component {
                std::path::Component::ParentDir => {
                    out.pop();
                }
                std::path::Component::Normal(name) => out.push(name),
                _ => {}
            }
        }
        out
    }

    /// pnpm joins `modules-dir` onto every importer's directory and
    /// `virtual-store-dir` onto the lock root. From the project pnpm runs in
    /// both land in tog's stage, and from any shallower importer the
    /// modules dir still escapes the project tree. A root-computed one lands
    /// back inside the project for a deeper importer; the linker flags, not
    /// this path, are what keep that harmless.
    #[test]
    fn pnpm_scratch_paths_resolve_where_pnpm_joins_them() {
        let temp = TempDir::named("pnpm-scratch");
        let root = temp.0.clone();
        let stage = root.join("store/tmp/stage-1");
        let lock_root = root.join("proj");
        let member = lock_root.join("packages/lib");
        fs::create_dir_all(&stage).unwrap();
        fs::create_dir_all(&member).unwrap();
        let stage_c = stage.canonicalize().unwrap();
        let lock_root_c = lock_root.canonicalize().unwrap();
        let member_c = member.canonicalize().unwrap();

        let scratch = pnpm_scratch(&stage, &member, &lock_root).unwrap();
        assert!(
            !scratch.modules_dir.starts_with('/'),
            "{}",
            scratch.modules_dir
        );
        assert!(
            !scratch.virtual_store_dir.starts_with('/'),
            "{}",
            scratch.virtual_store_dir
        );
        assert_eq!(
            lexical_join(&member_c, &scratch.modules_dir),
            stage_c.join("modules")
        );
        assert_eq!(
            lexical_join(&lock_root_c, &scratch.virtual_store_dir),
            stage_c.join("modules/.pnpm")
        );
        // The root importer joins the same modules-dir onto its own path.
        let from_root = lexical_join(&lock_root_c, &scratch.modules_dir);
        assert!(
            !from_root.starts_with(&lock_root_c),
            "root importer's modules dir {} is inside the project",
            from_root.display()
        );

        let scratch = pnpm_scratch(&stage, &lock_root, &lock_root).unwrap();
        assert_eq!(
            lexical_join(&lock_root_c, &scratch.modules_dir),
            stage_c.join("modules")
        );
        // A root-computed modules-dir lands INSIDE the project for a deeper
        // importer. This is a property of `path.join` and one relative path,
        // not something to be fixed by computing it differently; it is
        // asserted here so nobody reads the previous claim ("escapes from
        // every importer") back into the code. Safety comes from the linker
        // flags in `node_delegate_args`, and
        // `deps_e2e::pnpm_edits_leave_an_installed_project_untouched` is what
        // proves it end to end.
        let from_member = lexical_join(&member_c, &scratch.modules_dir);
        assert!(
            from_member.starts_with(&lock_root_c),
            "expected the documented in-project landing, got {}",
            from_member.display()
        );
        assert_eq!(
            relative_path(Path::new("/a/b/c"), Path::new("/a/x/y")),
            PathBuf::from("../../x/y")
        );
        assert_eq!(
            relative_path(Path::new("/a"), Path::new("/a/x")),
            PathBuf::from("x")
        );
    }

    fn selected(project: &Path) -> (String, PathBuf) {
        match node_lock_for(project).unwrap() {
            NodeLock::Own { name, root } => (name, root),
            NodeLock::PnpmWorkspaceMember { root } => ("pnpm-lock.yaml".to_string(), root),
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
