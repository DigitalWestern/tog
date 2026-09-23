//! Projection of a node env into the project (node tailor): the
//! node_modules forest, workspace links, bin links, and the closure record.

use super::*;

pub(super) fn workspace_set(plan: &NpmPlan) -> Vec<String> {
    if !plan.workspaces.is_empty() {
        return plan.workspaces.clone();
    }
    let mut workspaces = BTreeMap::<String, ()>::new();
    for path in plan
        .packages
        .iter()
        .map(|package| package.path.as_str())
        .chain(plan.links.iter().map(|link| link.path.as_str()))
    {
        if let Some((workspace, _)) = workspace_path(path) {
            workspaces.insert(workspace.to_string(), ());
        }
    }
    workspaces.into_keys().collect()
}

pub(super) fn previous_workspace_set(project_dir: &Path) -> Vec<String> {
    let path = project_dir.join(".tog/closures/node.json");
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    value["body"]["workspaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|workspace| workspace.as_str().map(str::to_string))
        // Older closures listed workspace-local packages such as
        // "packages/lib/node_modules/c" as workspaces. Nothing under a
        // node_modules can be a workspace; reconciling such an entry would
        // stat and back up a path inside the old read-only forest.
        .filter(|workspace| !workspace.contains("/node_modules/"))
        .collect()
}

pub(super) fn safe_workspace_path(workspace: &str) -> bool {
    !workspace.is_empty()
        && !workspace.starts_with('/')
        && Path::new(workspace)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

pub(super) fn canonical_workspace_parent(path: &Path) -> io::Result<PathBuf> {
    let mut candidate = path.to_path_buf();
    loop {
        match candidate.canonicalize() {
            Ok(path) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                candidate = candidate
                    .parent()
                    .ok_or_else(|| err("workspace path has no existing parent"))?
                    .to_path_buf();
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn validate_workspace_parents(
    project_dir: &Path,
    previous: &[String],
    current: &[String],
) -> io::Result<()> {
    let project_root = project_dir.canonicalize()?;
    for workspace in previous {
        if !safe_workspace_path(workspace) {
            continue;
        }
        let path = project_dir.join(workspace);
        let canonical = canonical_workspace_parent(&path)?;
        if !canonical.starts_with(&project_root) {
            return Err(err(format!(
                "workspace path {workspace:?} resolves outside the project"
            )));
        }
    }
    for workspace in current {
        if !safe_workspace_path(workspace) {
            return Err(err(format!(
                "workspace path {workspace:?} is not a safe project-relative path"
            )));
        }
        let path = project_dir.join(workspace);
        let canonical = canonical_workspace_parent(&path)?;
        if !canonical.starts_with(&project_root) {
            return Err(err(format!(
                "workspace path {workspace:?} resolves outside the project"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn managed_projection_symlink(path: &Path, project_dir: &Path, home: &Path) -> bool {
    managed_projection_symlink_for_store(path, project_dir, home, None)
}

pub(super) fn managed_projection_symlink_for_store(
    path: &Path,
    project_dir: &Path,
    home: &Path,
    store_root: Option<&Path>,
) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_symlink() {
        return false;
    }
    let Ok(target) = fs::read_link(path) else {
        return false;
    };
    let target = if target.is_absolute() {
        target
    } else {
        path.parent().unwrap_or(project_dir).join(target)
    };
    // The link itself may have been created through a symlinked TMPDIR
    // (`/tmp` -> `/private/tmp` on macOS). Canonicalize the ownership roots
    // too, otherwise a real target never matches its logical root spelling.
    let target = target.canonicalize().unwrap_or(target);
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let project_dir = project_dir
        .canonicalize()
        .unwrap_or_else(|_| project_dir.to_path_buf());
    target.starts_with(home.join("forests"))
        || store_root.is_some_and(|root| target.starts_with(root.join("forests")))
        || target.starts_with(home.join("store"))
        || target.starts_with(project_dir.join(".tog/nm"))
}

pub(super) fn relative_path(from: &Path, to: &Path) -> io::Result<PathBuf> {
    let from: Vec<_> = from.components().collect();
    let to: Vec<_> = to.components().collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    if common == 0 {
        return Err(err(format!(
            "cannot make relative link from {} to {}",
            from.iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
            to.iter()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/")
        )));
    }
    let mut result = PathBuf::new();
    for _ in common..from.len() {
        result.push("..");
    }
    for component in &to[common..] {
        result.push(component.as_os_str());
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    Ok(result)
}

pub(super) fn replace_with_symlink(path: &Path, target: &Path, label: &str) -> io::Result<()> {
    crate::comforter::replace_project_symlink(path, target, label)
}

/// Project the env into the project as a "forest": the root and every
/// package-local importer node_modules is a symlink to a WRITABLE per-project
/// directory under the forest projection, holding one symlink per top-level
/// entry into the immutable store object. Tools that treat node_modules' top
/// level as scratch space (vite's .vite dep cache, prisma's .prisma client)
/// get real writable directories, while package contents stay read-only in
/// the store — pnpm's proven layout.
///
/// If mutable packages are declared, the whole tree is instead cloned
/// copy-on-write (APFS clone on macOS, reflink on Linux) so runtime writes
/// inside those packages succeed and realpath stays coherent; the closure
/// records them as unattested.
pub fn project_node_env(
    project_dir: &Path,
    env_obj: &Path,
    platform: Platform,
    plan: &NpmPlan,
    mutable: &[String],
    fresh: bool,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    project_node_env_recorded(
        project_dir,
        env_obj,
        platform,
        plan,
        mutable,
        fresh,
        &[],
        None,
        &serde_json::Value::Null,
        attribution,
    )
}

/// The object id inside a native-library closure reference, checked because
/// the id becomes a closure root reference.
fn native_reference_id(reference: &Option<serde_json::Value>) -> io::Result<Option<&str>> {
    reference
        .as_ref()
        .map(|reference| {
            reference["id"].as_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native library closure reference has no object id",
                )
            })
        })
        .transpose()
}

/// The per-project transaction lock held across durable root publication and
/// the visible closure rename.
///
/// Synthetic unit fixtures use placeholder object paths and the legacy
/// closure writer. It acquires the transaction lock itself, so do not hold a
/// second descriptor for that test-only path (Linux flock descriptors are
/// independently blocking even within one process).
fn projection_project_lock(
    store: &Store,
    project_dir: &Path,
    strict_refs: bool,
) -> io::Result<Option<fs::File>> {
    if !strict_refs {
        #[cfg(not(test))]
        {
            return Err(err(
                "Node closure references must name complete store objects",
            ));
        }
    }
    #[cfg(test)]
    {
        if strict_refs {
            Ok(Some(store.project_lock(project_dir)?))
        } else {
            Ok(None)
        }
    }
    #[cfg(not(test))]
    {
        Ok(Some(store.project_lock(project_dir)?))
    }
}

/// Reserve a backup name for every real (npm-made) node_modules the new
/// projection is about to replace, plus the managed projections of workspaces
/// that have left the lockfile.
///
/// A workspace can disappear from the imported lockfile (or stop having
/// package-local dependencies) while its old managed projection remains in the
/// source tree. Reconcile the previous closure before projecting the new set.
/// Real directories are user state and retain backup_real_dir semantics; only
/// symlinks proven to target tog-owned roots are removed automatically.
///
/// Returns (backup paths, pending moves) — nothing is moved yet.
#[allow(clippy::type_complexity)]
fn reserve_projection_backups(
    project_dir: &Path,
    nm: &Path,
    store: &Store,
    home: &Path,
    previous_workspaces: &[String],
    workspaces: &[String],
) -> io::Result<(Vec<PathBuf>, Vec<(PathBuf, PathBuf)>)> {
    let mut backup_paths = Vec::new();
    let mut pending_backups = Vec::new();
    for workspace in previous_workspaces {
        if workspaces.contains(workspace) || !safe_workspace_path(workspace) {
            continue;
        }
        let workspace_nm = project_dir.join(workspace).join("node_modules");
        if !managed_projection_symlink_for_store(
            &workspace_nm,
            project_dir,
            home,
            Some(&store.root),
        ) {
            if let Some(backup) =
                crate::comforter::reserve_backup_real_dir_for_store(&workspace_nm, store)?
            {
                pending_backups.push((workspace_nm, backup.clone()));
                backup_paths.push(backup);
            }
        }
    }
    // A real (npm-made) node_modules is moved aside automatically so
    // pointing tog at an existing project is one command. Workspace
    // importers get the same treatment in their source directories.
    if let Some(backup) = crate::comforter::reserve_backup_real_dir_for_store(nm, store)? {
        pending_backups.push((nm.to_path_buf(), backup.clone()));
        backup_paths.push(backup);
    }
    for workspace in workspaces {
        let workspace_nm = project_dir.join(workspace).join("node_modules");
        if let Some(backup) =
            crate::comforter::reserve_backup_real_dir_for_store(&workspace_nm, store)?
        {
            pending_backups.push((workspace_nm, backup.clone()));
            backup_paths.push(backup);
        }
    }
    Ok((backup_paths, pending_backups))
}

/// Where this projection lives: its id and the forest paths derived from it.
struct ForestPaths {
    proj_id: String,
    nm_root: PathBuf,
    proj_dir: PathBuf,
    /// The projected tree must itself be NAMED node_modules: Node's module
    /// resolution only treats a directory as a package root when its
    /// basename is node_modules, and cloned packages realpath to this tree.
    forest: PathBuf,
}

/// Projection id: env object + mutable declarations + layout schema.
///
/// Forests live OUTSIDE the project (under the tog home, keyed by project
/// path): anything inside the project gets crawled by test runners and type
/// checkers, and the forest links into store packages whose own test files
/// must never be picked up.
fn forest_paths(
    project_dir: &Path,
    env_obj: &Path,
    store: &Store,
    plan: &NpmPlan,
    mutable: &[String],
    workspaces: &[String],
) -> io::Result<ForestPaths> {
    use sha2::{Digest as _, Sha256};
    let env_name = env_obj.file_name().unwrap().to_string_lossy().into_owned();
    let link_key: String = plan
        .links
        .iter()
        .map(|l| format!("{}={};", l.path, l.target))
        .collect();
    let workspace_key = workspaces.join(",");
    let proj_id = hex::encode(Sha256::digest(
        format!(
            "node-forest/2\x00{env_name}\x00{}\x00{workspace_key}\x00{link_key}",
            mutable.join(",")
        )
        .as_bytes(),
    ))[..32]
        .to_string();
    let project_key = &hex::encode(Sha256::digest(
        project_dir.canonicalize()?.as_os_str().as_bytes(),
    ))[..32];
    let nm_root = store.root.join("forests").join(project_key);
    let proj_dir = nm_root.join(&proj_id);
    let forest = proj_dir.join("node_modules");
    Ok(ForestPaths {
        proj_id,
        nm_root,
        proj_dir,
        forest,
    })
}

/// Managed projections of workspaces that have left the lockfile: only
/// symlinks proven to target tog-owned roots are removed automatically.
fn remove_stale_workspace_links(
    project_dir: &Path,
    store: &Store,
    home: &Path,
    previous_workspaces: &[String],
    workspaces: &[String],
) -> io::Result<()> {
    for workspace in previous_workspaces {
        if workspaces.contains(workspace) || !safe_workspace_path(workspace) {
            continue;
        }
        let workspace_nm = project_dir.join(workspace).join("node_modules");
        if managed_projection_symlink_for_store(&workspace_nm, project_dir, home, Some(&store.root))
        {
            fs::remove_file(workspace_nm)?;
        }
    }
    Ok(())
}

/// Materialize the forest (root plus one per workspace) when it is missing or
/// incomplete. Built in a sibling temp dir and renamed into place, so a
/// concurrent reader never sees a half-built tree.
#[allow(clippy::too_many_arguments)]
fn build_project_forest(
    store: &Store,
    platform: Platform,
    env_obj: &Path,
    paths: &ForestPaths,
    workspaces: &[String],
    mutable: &[String],
    fresh: bool,
) -> io::Result<()> {
    let ForestPaths {
        proj_id,
        nm_root,
        proj_dir,
        forest,
    } = paths;
    if fresh && proj_dir.exists() {
        crate::kernel::store::remove_tree(proj_dir)?;
    }
    let workspace_forests_ready = workspaces.iter().all(|workspace| {
        proj_dir
            .join("workspaces")
            .join(encode_workspace_path(workspace))
            .join("node_modules")
            .is_dir()
    });
    if !forest.exists() || !workspace_forests_ready {
        fs::create_dir_all(nm_root)?;
        let tmp = nm_root.join(format!(".{proj_id}.tmp.{}", std::process::id()));
        if tmp.exists() {
            crate::kernel::store::remove_tree(&tmp)?;
        }
        fs::create_dir_all(&tmp)?;
        let src = env_obj.join("node_modules");
        if mutable.is_empty() {
            build_forest(&src, &tmp.join("node_modules"))?;
        } else {
            crate::comforter::clone_tree_for_store(
                store,
                &src,
                &tmp.join("node_modules"),
                platform,
            )?;
        }
        for workspace in workspaces {
            let src = env_obj
                .join("workspaces")
                .join(encode_workspace_path(workspace))
                .join("node_modules");
            let dest = tmp
                .join("workspaces")
                .join(encode_workspace_path(workspace))
                .join("node_modules");
            if mutable.is_empty() {
                build_forest(&src, &dest)?;
            } else {
                crate::comforter::clone_tree_for_store(store, &src, &dest, platform)?;
            }
        }
        fs::rename(&tmp, proj_dir)?;
    }
    Ok(())
}

/// Workspace links: symlinks into the project's own source dirs. The targets
/// are user-owned and writable by nature. Idempotent — the projection id
/// covers the link set, so a changed set is a new forest.
fn link_workspace_sources(
    project_dir: &Path,
    plan: &NpmPlan,
    proj_dir: &Path,
    forest: &Path,
) -> io::Result<()> {
    for l in &plan.links {
        let link_root = workspace_path(&l.path)
            .map(|(workspace, _)| {
                proj_dir
                    .join("workspaces")
                    .join(encode_workspace_path(workspace))
                    .join("node_modules")
            })
            .unwrap_or_else(|| forest.to_path_buf());
        let rel = importer_relative_path(&l.path).trim_start_matches("node_modules/");
        let link = link_root.join(rel);
        // Every directory between the forest root and the link must be the
        // forest's own. A symlink on the way is a package's store object (or
        // a source directory): creating the link through it would write
        // into content tog must never modify.
        let mut walked = link_root.clone();
        for component in Path::new(rel)
            .parent()
            .into_iter()
            .flat_map(Path::components)
        {
            walked.push(component);
            if walked
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(err(format!(
                    "workspace link {} would be created through {}, which is not a forest directory; refusing to write into it",
                    l.path,
                    walked.display()
                )));
            }
        }
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        if link.symlink_metadata().is_err() {
            let target = relative_path(
                link.parent()
                    .ok_or_else(|| err("workspace link has no parent"))?,
                &project_dir.join(&l.target),
            )?;
            std::os::unix::fs::symlink(target, &link)?;
        }
    }
    Ok(())
}

/// iCloud/Drive-synced folders resurrect each replaced symlink as a
/// "node_modules 2"-style duplicate. Ones that are symlinks into
/// tog-owned paths are ours from earlier projections: remove them (test
/// runners crawl through them otherwise). Anything else is only warned
/// about — never delete what we didn't create.
fn remove_sync_duplicate_links(project_dir: &Path, store: &Store, home: &Path) {
    let Ok(entries) = fs::read_dir(project_dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with("node_modules ") {
            continue;
        }
        let p = e.path();
        // Only targets under tog-owned roots count as ours — never
        // delete a user's own symlink on a loose match.
        let is_ours = fs::read_link(&p)
            .map(|t| {
                t.starts_with(home.join("forests"))
                    || t.starts_with(store.root.join("forests"))
                    || t.starts_with(home.join("store"))
                    || t.starts_with(project_dir.join(".tog/nm"))
            })
            .unwrap_or(false);
        if is_ours {
            let _ = fs::remove_file(&p);
            crate::kernel::ui::note(&format!("removed stale sync-duplicate symlink {name:?}"));
        } else {
            crate::kernel::ui::warning(
                &format!("{name:?} looks like a cloud-sync duplicate of node_modules"),
                &crate::kernel::ui::shell_line(&["rm", "-rf", &p.display().to_string()]),
            );
        }
    }
}

/// The closure record `tog status` and `tog gc` read.
#[allow(clippy::too_many_arguments)]
fn node_closure_body(
    env_obj: &Path,
    native_reference: &Option<serde_json::Value>,
    paths: &ForestPaths,
    backup_paths: &[PathBuf],
    plan: &NpmPlan,
    workspaces: &[String],
    mutable: &[String],
    inputs: &[crate::comforter::InputRecord],
) -> serde_json::Value {
    // Mutable declarations expand to every matching physical lockfile path.
    let mutable_paths: Vec<&str> = plan
        .packages
        .iter()
        .filter(|p| mutable.iter().any(|m| *m == p.name))
        .map(|p| p.path.as_str())
        .collect();
    serde_json::json!({
        "env_object": env_obj,
        "native_libs": native_reference,
        "projection_schema": "node-forest/2",
        "projection_id": paths.proj_id,
        "forest_path": paths.forest,
        "backup_paths": backup_paths,
        "node_version": plan.node_version,
        "workspaces": workspaces,
        "mutable_packages": mutable,
        "mutable_paths": mutable_paths,
        "mutable_state": if mutable.is_empty() { "none" } else { "unattested" },
        // Honest scope: clone mode makes the WHOLE projected tree writable
        // (path coherence requires it); mutable_paths lists only where
        // writes are expected, not where they are possible.
        "mutable_scope": if mutable.is_empty() { "none" } else { "whole-tree-clone" },
        "workspace_links": plan.links.iter().map(|l| {
            serde_json::json!({"path": l.path, "target": l.target})
        }).collect::<Vec<_>>(),
        "lock_source": plan.lock_source,
        "inputs": inputs,
        "packages": plan.packages.iter().map(|p| {
            serde_json::json!({"path": p.path, "version": p.version, "integrity": p.integrity})
        }).collect::<Vec<_>>(),
    })
}

/// `project_node_env` plus the input files recorded for `tog status`
/// (package.json and the lockfile the plan came from).
#[allow(clippy::too_many_arguments)]
pub fn project_node_env_recorded(
    project_dir: &Path,
    env_obj: &Path,
    platform: Platform,
    plan: &NpmPlan,
    mutable: &[String],
    fresh: bool,
    inputs: &[crate::comforter::InputRecord],
    // On a project path: the bundle this projection was built from and the
    // Node object realized from it, recorded so a later run resolves the
    // same bytes through the closure instead of the pin table.
    toolchain: Option<(&crate::kernel::toolchain::Selected, &Path)>,
    // The helper decision (`tailors::helper_record`), stored beside the
    // toolchain record; `Null` writes none.
    helpers: &serde_json::Value,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    if !mutable.is_empty() {
        crate::kernel::policy::record(
            crate::kernel::policy::UNATTESTED_MUTABLE_STATE,
            &mutable.join(", "),
            "mutable package projection is unattested",
        )?;
    }
    let nm = project_dir.join("node_modules");
    let workspaces = workspace_set(plan);
    let previous_workspaces = previous_workspace_set(project_dir);
    // Resolve every old and new workspace parent before any policy, backup,
    // removal, or projection mutation. A lexical `packages/lib` can be an
    // external symlink after the previous closure was written.
    validate_workspace_parents(project_dir, &previous_workspaces, &workspaces)?;
    let store = crate::comforter::store_from_object_path(env_obj)
        .ok_or_else(|| err("environment object is not in a Tog store"))?;
    let activity = store.activity(crate::kernel::activity::ActivityMode::Shared)?;
    let env_obj = env_obj.canonicalize()?;
    let native_reference = crate::kernel::provider::nativelibs::env_reference(&env_obj)?;
    let native_id = native_reference_id(&native_reference)?;
    let valid_env = env_obj
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(crate::kernel::store::is_object_id);
    let valid_native = native_id
        .map(crate::kernel::store::is_object_id)
        .unwrap_or(true);
    let strict_refs = valid_env && valid_native;
    let project_lock = projection_project_lock(&store, project_dir, strict_refs)?;
    let home = store
        .root
        .parent()
        .ok_or_else(|| err("cannot locate tog home for legacy forests"))?;
    let (backup_paths, pending_backups) = reserve_projection_backups(
        project_dir,
        &nm,
        &store,
        home,
        &previous_workspaces,
        &workspaces,
    )?;

    let paths = forest_paths(project_dir, &env_obj, &store, plan, mutable, &workspaces)?;
    let ForestPaths {
        proj_dir, forest, ..
    } = &paths;
    store.ensure_namespace(Path::new("forests"))?;
    store.ensure_namespace(Path::new("backups"))?;
    // The record names the bundle and the object; the direct reference is
    // what keeps that object alive, so it is taken wherever references are.
    let runtime_record = toolchain.map(|(selected, runtime)| {
        let mut record = crate::comforter::toolchain::closure_record(selected, runtime);
        if !helpers.is_null() {
            record["toolchain"]["helpers"] = helpers.clone();
        }
        record
    });
    let mut refs = crate::comforter::ClosureRefs::new();
    if strict_refs {
        refs.object_path(&store, &activity, &env_obj)?;
        if let Some((_, runtime)) = toolchain {
            refs.object_path(&store, &activity, runtime)?;
        }
        if let Some(native_id) = native_id {
            refs.object_id(&store, &activity, native_id)?;
        }
        refs.forest(&store, &activity, forest)?;
        for backup in &backup_paths {
            refs.backup(&store, &activity, backup)?;
        }
    }
    // The root is durable before any stale managed link is removed, any user
    // directory is moved, or the new forest is published.
    if strict_refs {
        let project_lock = project_lock
            .as_ref()
            .expect("strict Node publication owns a project lock");
        crate::comforter::persist_root_for_refs_with_project_lock(
            project_dir,
            &store,
            &activity,
            &refs,
            &project_lock,
        )?;
    }
    for (source, backup) in pending_backups {
        // Reaching here means the path was a real directory, not tog's
        // symlink: either a project tog has never synced, or one where an
        // `npm install` overwrote the projection. `move_reserved_backup`
        // says so once the move has happened, with where the packages went.
        crate::comforter::move_reserved_backup(&source, &backup)?;
    }
    remove_stale_workspace_links(project_dir, &store, home, &previous_workspaces, &workspaces)?;
    build_project_forest(
        &store,
        platform,
        &env_obj,
        &paths,
        &workspaces,
        mutable,
        fresh,
    )?;
    link_workspace_sources(project_dir, plan, proj_dir, forest)?;
    // Old forests are deliberately NOT pruned here: a dev server may still
    // be running from one, and pruning would break it mid-session. They are
    // cheap symlink trees; explicit `tog gc` with liveness checks is the
    // collection path.
    remove_sync_duplicate_links(project_dir, &store, home);

    replace_with_symlink(&nm, forest, "node_modules")?;
    for workspace in &workspaces {
        let workspace_dir = project_dir.join(workspace);
        let workspace_nm = workspace_dir.join("node_modules");
        let workspace_forest = proj_dir
            .join("workspaces")
            .join(encode_workspace_path(workspace))
            .join("node_modules");
        replace_with_symlink(&workspace_nm, &workspace_forest, "workspace-node_modules")?;
    }

    let meta_dir = project_dir.join(".tog");
    fs::create_dir_all(&meta_dir)?;
    let mut body = node_closure_body(
        &env_obj,
        &native_reference,
        &paths,
        &backup_paths,
        plan,
        &workspaces,
        mutable,
        inputs,
    );
    if let Some(record) = runtime_record {
        for (key, value) in record.as_object().into_iter().flatten() {
            body[key] = value.clone();
        }
    }
    #[cfg(test)]
    if !strict_refs {
        return crate::comforter::write_closure_legacy(project_dir, "node", body, attribution);
    }
    let project_lock = project_lock
        .as_ref()
        .expect("strict Node publication owns a project lock");
    crate::comforter::write_closure_with_project_lock(
        project_dir,
        "node",
        body,
        &store,
        &activity,
        refs,
        &project_lock,
        attribution,
    )
}

/// One symlink per top-level entry of the object's node_modules; scoped
/// packages get a real @scope dir with per-package symlinks so new scoped
/// siblings can be written at runtime.
pub(super) fn build_forest(src: &Path, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('@') {
            let scope_dir = dest.join(&name);
            fs::create_dir(&scope_dir)?;
            for sub in fs::read_dir(entry.path())? {
                let sub = sub?;
                std::os::unix::fs::symlink(sub.path(), scope_dir.join(sub.file_name()))?;
            }
        } else {
            std::os::unix::fs::symlink(entry.path(), dest.join(&name))?;
        }
    }
    Ok(())
}

/// npm-compatible mode normalization: tarballs in the wild carry broken
/// permission bits (e.g. pngjs ships directories without the execute bit,
/// making them untraversable). npm's extractor ORs minimum modes onto every
/// entry; after extraction we do the same, ORing 0o755 onto directories and
/// 0o644 onto files. Top-down so unreadable dirs get fixed before we descend
/// into them.
pub(super) fn normalize_modes(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let md = fs::symlink_metadata(path)?;
    let ft = md.file_type();
    if ft.is_symlink() {
        return Ok(());
    }
    let mode = md.permissions().mode();
    if ft.is_dir() {
        if mode & 0o755 != 0o755 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o755))?;
        }
        for entry in fs::read_dir(path)? {
            normalize_modes(&entry?.path())?;
        }
    } else if mode & 0o644 != 0o644 {
        fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o644))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A link nested under a registry package would be created through the
    /// forest's symlink into that package's store object. Projection refuses
    /// it by name and leaves the object untouched; a top-level link is fine.
    #[test]
    fn workspace_links_are_never_created_through_a_package_symlink() {
        let root =
            std::env::temp_dir().join(format!("tog-link-through-package-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let project = root.join("project");
        let forest = root.join("forest/node_modules");
        let object = root.join("store/objects/parent");
        for dir in [project.join("vendor/a"), forest.clone(), object.clone()] {
            fs::create_dir_all(dir).unwrap();
        }
        std::os::unix::fs::symlink(&object, forest.join("parent")).unwrap();
        let plan = |path: &str| NpmPlan {
            node_version: String::new(),
            packages: Vec::new(),
            links: vec![NpmLink {
                path: path.to_string(),
                target: "vendor/a".to_string(),
            }],
            workspaces: Vec::new(),
            lock_source: "pnpm-lock.yaml".to_string(),
        };

        let error = link_workspace_sources(
            &project,
            &plan("node_modules/parent/node_modules/a"),
            &root.join("forest"),
            &forest,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("which is not a forest directory"),
            "{error}"
        );
        assert!(
            fs::read_dir(&object).unwrap().next().is_none(),
            "nothing may be written into the store object"
        );

        link_workspace_sources(
            &project,
            &plan("node_modules/a"),
            &root.join("forest"),
            &forest,
        )
        .unwrap();
        assert!(forest.join("a").symlink_metadata().unwrap().is_symlink());
        let _ = fs::remove_dir_all(root);
    }
}

pub(super) fn dir_size(path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let md = entry.metadata()?;
        total += if md.is_dir() {
            dir_size(&entry.path())?
        } else {
            md.len()
        };
    }
    Ok(total)
}
