//! Projection of a node env into the project (node tailor): the
//! node_modules forest, workspace links, bin links, and the closure record.

use super::*;
use crate::kernel::fsroot::ProjectRoot;

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

/// The workspaces the previous closure recorded, read from tog's own state
/// through the held project descriptor.
pub(super) fn previous_workspace_set(project: &ProjectRoot) -> Vec<String> {
    let Ok(Some(bytes)) = project.read_file(Path::new(".tog/closures/node.json")) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
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

#[cfg(test)]
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
    managed_target(path, target, project_dir, home, store_root)
}

/// `managed_projection_symlink_for_store` for a project-relative link read
/// through the held project descriptor, so the link judged is the one in
/// the directory being synced.
fn managed_projection_link(
    project: &ProjectRoot,
    relative: &Path,
    home: &Path,
    store_root: Option<&Path>,
) -> bool {
    let Ok(Some(target)) = project.read_link(relative) else {
        return false;
    };
    let path = project.path().join(relative);
    managed_target(&path, target, project.path(), home, store_root)
}

fn managed_target(
    path: &Path,
    target: PathBuf,
    project_dir: &Path,
    home: &Path,
    store_root: Option<&Path>,
) -> bool {
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

pub(super) fn replace_with_symlink(
    project: &ProjectRoot,
    relative: &Path,
    target: &Path,
    label: &str,
) -> io::Result<()> {
    crate::comforter::replace_project_symlink(project, relative, target, label)
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
/// records them as unattested. A registry package that depends on a
/// workspace package asks for the same clone: Node resolves a package's
/// dependencies from its real path, so only a copy inside the projection
/// can reach a link into the project's own source.
pub fn project_node_env(
    activity: &StoreActivity,
    project: &ProjectRoot,
    env_obj: &Path,
    platform: Platform,
    plan: &NpmPlan,
    mutable: &[String],
    fresh: bool,
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<()> {
    project_node_env_recorded(
        activity,
        project,
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
/// The project's transaction lock, held across the projection switch and
/// the closure write. Every reference must name a complete store object.
fn projection_project_lock(
    store: &Store,
    project: &ProjectRoot,
    strict_refs: bool,
) -> io::Result<fs::File> {
    if !strict_refs {
        return Err(err(
            "Node closure references must name complete store objects",
        ));
    }
    store.project_lock_in(project)
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
/// A workspace member's node_modules that git tracks (`tracked`) is left
/// where it is: it is the user's source, not npm's output.
///
/// Returns (backup paths, pending moves) — nothing is moved yet.
#[allow(clippy::type_complexity)]
fn reserve_projection_backups(
    project: &ProjectRoot,
    nm: &Path,
    store: &Store,
    home: &Path,
    previous_workspaces: &[String],
    workspaces: &[String],
    tracked: &[String],
) -> io::Result<(Vec<PathBuf>, Vec<(PathBuf, PathBuf)>)> {
    let mut backup_paths = Vec::new();
    let mut pending_backups = Vec::new();
    for workspace in previous_workspaces {
        if workspaces.contains(workspace)
            || !safe_workspace_path(workspace)
            || tracked.contains(workspace)
        {
            continue;
        }
        let workspace_nm = Path::new(workspace).join("node_modules");
        if !managed_projection_link(project, &workspace_nm, home, Some(&store.root)) {
            if let Some(backup) =
                crate::comforter::reserve_backup_real_dir_for_store(project, &workspace_nm, store)?
            {
                pending_backups.push((workspace_nm, backup.clone()));
                backup_paths.push(backup);
            }
        }
    }
    // A real (npm-made) node_modules is moved aside automatically so
    // pointing tog at an existing project is one command. Workspace
    // importers get the same treatment in their source directories.
    if let Some(backup) = crate::comforter::reserve_backup_real_dir_for_store(project, nm, store)? {
        pending_backups.push((nm.to_path_buf(), backup.clone()));
        backup_paths.push(backup);
    }
    for workspace in workspaces.iter().filter(|w| !tracked.contains(w)) {
        let workspace_nm = Path::new(workspace).join("node_modules");
        if let Some(backup) =
            crate::comforter::reserve_backup_real_dir_for_store(project, &workspace_nm, store)?
        {
            pending_backups.push((workspace_nm, backup.clone()));
            backup_paths.push(backup);
        }
    }
    Ok((backup_paths, pending_backups))
}

/// The workspace members, old and new, whose node_modules is a real
/// directory holding files git tracks. Some repositories commit one as a
/// test fixture; moving it into the store's backups would delete source
/// from the working tree, so the member is left unprojected and the user is
/// told. A tracked node_modules at the project root stops the sync instead:
/// nothing in the project could resolve its dependencies without it.
fn git_tracked_node_modules(
    project: &ProjectRoot,
    previous_workspaces: &[String],
    workspaces: &[String],
    activity: &StoreActivity,
) -> io::Result<Vec<String>> {
    let real = |importer: &Path| {
        project
            .entry(&importer.join("node_modules"))
            .map(|entry| entry == crate::kernel::fsroot::Entry::Directory)
    };
    let mut candidates: Vec<String> = Vec::new();
    if real(Path::new(""))? {
        candidates.push("node_modules".to_string());
    }
    for workspace in workspaces.iter().chain(previous_workspaces) {
        let path = format!("{workspace}/node_modules");
        if safe_workspace_path(workspace)
            && real(Path::new(workspace))?
            && !candidates.contains(&path)
        {
            candidates.push(path);
        }
    }
    let tracked = crate::kernel::gitsrc::tracked_among(project, &candidates, activity)?;
    if tracked.iter().any(|path| path == "node_modules") {
        return Err(err(
            "node_modules holds files git tracks (git ls-files node_modules), and \
             tog will not move committed source aside to project dependencies \
             there; untrack them (git rm -r --cached node_modules) and run `tog` again",
        ));
    }
    let mut members = Vec::new();
    for path in tracked {
        let member = path
            .strip_suffix("/node_modules")
            .unwrap_or(&path)
            .to_string();
        if workspaces.contains(&member) {
            crate::kernel::ui::warning_next(
                &format!(
                    "{path} holds files git tracks, so tog left it in place and did not \
                     project workspace {member}'s dependencies"
                ),
                &crate::kernel::ui::shell_line(&["git", "ls-files", &path]),
            );
        }
        members.push(member);
    }
    Ok(members)
}

/// Name in the closure the members `git_tracked_node_modules` kept back:
/// `status` checks every other member's link, and these keep their own
/// directory by design.
fn record_unprojected(body: &mut serde_json::Value, tracked: &[String], workspaces: &[String]) {
    let kept: Vec<&String> = tracked.iter().filter(|m| workspaces.contains(m)).collect();
    if !kept.is_empty() {
        body["unprojected_workspaces"] = serde_json::json!(kept);
    }
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

/// The registry packages that depend on a workspace package, by lock path.
/// One is enough to make the projection a clone.
///
/// pnpm and npm plans carry the answer. A yarn.lock records neither peer
/// dependencies nor an edge to a workspace package, so for a Yarn plan with
/// workspace links the answer is read from each realized package's own
/// manifest, walked over the plan's placements the way Node walks them.
fn workspace_dependents(plan: &NpmPlan, env_obj: &Path) -> Vec<String> {
    let from_manifests = plan.lock_source == "yarn.lock" && !plan.links.is_empty();
    let placed = |path: &str| {
        if plan.links.iter().any(|link| link.path == path) {
            Some(true)
        } else {
            // Followed, as Node follows it: a dangling symlink a package
            // ships is not there, and the walk goes on past it.
            env_package_path(env_obj, path).exists().then_some(false)
        }
    };
    plan.packages
        .iter()
        .filter(|package| {
            package.needs_workspace
                || from_manifests && manifest_needs_workspace(&placed, env_obj, &package.path)
        })
        .map(|package| package.path.clone())
        .collect()
}

/// Whether the realized package at `path` names, in its own manifest, a
/// dependency that Node resolves to a workspace link.
fn manifest_needs_workspace(
    placed: &impl Fn(&str) -> Option<bool>,
    env_obj: &Path,
    path: &str,
) -> bool {
    let manifest = env_package_path(env_obj, path).join("package.json");
    let Some(manifest) = fs::read_to_string(manifest)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
    else {
        return false;
    };
    let needs_workspace =
        |name: &String| super::plan::resolves_to_workspace_link(placed, path, name);
    let names: Vec<&String> = super::plan::dependency_names(&manifest).collect();
    names.into_iter().any(needs_workspace)
}

/// Why a projection is a writable clone rather than a forest of links:
/// declared-mutable packages, and registry packages that depend on a
/// workspace package. Neither means a forest.
struct CloneReasons<'a> {
    mutable: &'a [String],
    dependents: Vec<String>,
}

impl CloneReasons<'_> {
    fn cloned(&self) -> bool {
        !self.mutable.is_empty() || !self.dependents.is_empty()
    }
}

/// The reasons this projection is a clone, each recorded as the exception
/// it is.
fn record_clone_reasons<'a>(
    plan: &NpmPlan,
    env_obj: &Path,
    mutable: &'a [String],
) -> io::Result<CloneReasons<'a>> {
    if !mutable.is_empty() {
        crate::kernel::policy::record(
            crate::kernel::policy::UNATTESTED_MUTABLE_STATE,
            &mutable.join(", "),
            "mutable package projection is unattested",
        )?;
    }
    let dependents = workspace_dependents(plan, env_obj);
    for dependent in &dependents {
        crate::kernel::policy::record(
            crate::kernel::policy::UNATTESTED_MUTABLE_STATE,
            dependent,
            "depends on a workspace package, which Node only finds from a real path inside the project, so node_modules is projected as a writable copy that tog does not attest",
        )?;
    }
    Ok(CloneReasons {
        mutable,
        dependents,
    })
}

/// Projection id: env object + mutable declarations + layout schema.
///
/// Forests live OUTSIDE the project (under the store root, keyed by project
/// path): anything inside the project gets crawled by test runners and type
/// checkers, and the forest links into store packages whose own test files
/// must never be picked up.
fn forest_paths(
    project: &ProjectRoot,
    env_obj: &Path,
    store: &Store,
    plan: &NpmPlan,
    reasons: &CloneReasons,
    workspaces: &[String],
) -> io::Result<ForestPaths> {
    use sha2::{Digest as _, Sha256};
    let CloneReasons {
        mutable,
        dependents,
    } = reasons;
    // A plan whose packages need a workspace package is a clone, not a
    // forest of links, so it must never share a directory with one. The key
    // is extended only for such a plan: every other projection keeps its id.
    let dependent_key = if dependents.is_empty() {
        String::new()
    } else {
        format!("\x00needs-workspace:{}", dependents.join(","))
    };
    let env_name = env_obj.file_name().unwrap().to_string_lossy().into_owned();
    let link_key: String = plan
        .links
        .iter()
        .map(|l| format!("{}={};", l.path, l.target))
        .collect();
    let workspace_key = workspaces.join(",");
    let proj_id = hex::encode(Sha256::digest(
        format!(
            "node-forest/2\x00{env_name}\x00{}\x00{workspace_key}\x00{link_key}{dependent_key}",
            mutable.join(",")
        )
        .as_bytes(),
    ))[..32]
        .to_string();
    // The held root's path is already canonical: keying on it rather than
    // re-canonicalizing the pathname keeps a renamed project on its own key.
    let project_key = Store::forest_project_key(project.path());
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
    project: &ProjectRoot,
    store: &Store,
    home: &Path,
    previous_workspaces: &[String],
    workspaces: &[String],
) -> io::Result<()> {
    for workspace in previous_workspaces {
        if workspaces.contains(workspace) || !safe_workspace_path(workspace) {
            continue;
        }
        let workspace_nm = Path::new(workspace).join("node_modules");
        if managed_projection_link(project, &workspace_nm, home, Some(&store.root)) {
            project.remove_symlink(&workspace_nm)?;
        }
    }
    Ok(())
}

/// Materialize the forest (root plus one per workspace) when it is missing or
/// incomplete. Built in a sibling temp dir and renamed into place, so a
/// concurrent reader never sees a half-built tree.
#[allow(clippy::too_many_arguments)]
fn build_project_forest(
    activity: &StoreActivity,
    platform: Platform,
    env_obj: &Path,
    paths: &ForestPaths,
    workspaces: &[String],
    cloned: bool,
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
        if !cloned {
            build_forest(&src, &tmp.join("node_modules"))?;
        } else {
            crate::comforter::clone_tree_with_activity(
                activity,
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
            if !cloned {
                build_forest(&src, &dest)?;
            } else {
                // `cp` creates the clone itself but not the directory the
                // clone goes in.
                if let Some(parent) = dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                crate::comforter::clone_tree_with_activity(activity, &src, &dest, platform)?;
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
        let target = relative_path(
            link.parent()
                .ok_or_else(|| err("workspace link has no parent"))?,
            &project_dir.join(&l.target),
        )?;
        match link.symlink_metadata() {
            Err(_) => std::os::unix::fs::symlink(target, &link)?,
            // The link an earlier sync planted here.
            Ok(_) if fs::read_link(&link).is_ok_and(|existing| existing == target) => {}
            // A cloned package can ship something of its own where the lock
            // puts the link (a bundled copy, or a symlink to one). Leaving
            // it would hand the package that copy instead of the workspace
            // package, silently.
            Ok(_) => {
                return Err(err(format!(
                    "workspace link {} cannot be planted: the package it sits in already ships {}",
                    l.path,
                    importer_relative_path(&l.path)
                )));
            }
        }
    }
    Ok(())
}

/// iCloud/Drive-synced folders resurrect each replaced symlink as a
/// "node_modules 2"-style duplicate. Ones that are symlinks into
/// tog-owned paths are ours from earlier projections: remove them (test
/// runners crawl through them otherwise). Anything else is only warned
/// about — never delete what we didn't create.
///
/// The project is listed, and each link read and removed, through the held
/// descriptor.
fn remove_sync_duplicate_links(project: &ProjectRoot, store: &Store, home: &Path) {
    let project_dir = project.path();
    let Ok(Some(entries)) = project.read_input_dir(Path::new(".")) else {
        return;
    };
    for file_name in entries {
        let name = file_name.to_string_lossy().into_owned();
        if !name.starts_with("node_modules ") {
            continue;
        }
        let p = project_dir.join(&file_name);
        // Only targets under tog-owned roots count as ours — never
        // delete a user's own symlink on a loose match.
        let is_ours = project
            .read_link(Path::new(&file_name))
            .ok()
            .flatten()
            .map(|t| {
                t.starts_with(home.join("forests"))
                    || t.starts_with(store.root.join("forests"))
                    || t.starts_with(home.join("store"))
                    || t.starts_with(project_dir.join(".tog/nm"))
            })
            .unwrap_or(false);
        if is_ours {
            let _ = project.remove_symlink(Path::new(&file_name));
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
    reasons: &CloneReasons,
    inputs: &[crate::comforter::InputRecord],
) -> serde_json::Value {
    let cloned = reasons.cloned();
    let CloneReasons {
        mutable,
        dependents,
    } = reasons;
    // Mutable declarations expand to every matching physical lockfile path.
    let mutable_paths: Vec<&str> = plan
        .packages
        .iter()
        .filter(|p| mutable.contains(&p.name))
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
        "mutable_state": if cloned { "unattested" } else { "none" },
        // Honest scope: clone mode makes the WHOLE projected tree writable
        // (path coherence requires it); mutable_paths lists only where
        // writes are expected, not where they are possible.
        "mutable_scope": if cloned { "whole-tree-clone" } else { "none" },
        // Registry packages that depend on a workspace package: the other
        // reason the tree is a clone, whether or not anything is declared
        // mutable.
        "workspace_dependents": dependents,
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
    activity: &StoreActivity,
    project: &ProjectRoot,
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
    let reasons = record_clone_reasons(plan, env_obj, mutable)?;
    let project_dir = project.path();
    let nm = Path::new("node_modules");
    let workspaces = workspace_set(plan);
    let previous_workspaces = previous_workspace_set(project);
    // Resolve every old and new workspace parent before any policy, backup,
    // removal, or projection mutation. A lexical `packages/lib` can be an
    // external symlink after the previous closure was written.
    validate_workspace_parents(project_dir, &previous_workspaces, &workspaces)?;
    let tracked = git_tracked_node_modules(project, &previous_workspaces, &workspaces, activity)?;
    let store = crate::comforter::store_from_object_path(env_obj)
        .ok_or_else(|| err("environment object is not in a Tog store"))?;
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
    let project_lock = projection_project_lock(&store, project, strict_refs)?;
    let home = store
        .root
        .parent()
        .ok_or_else(|| err("cannot locate tog home for legacy forests"))?;
    let (backup_paths, pending_backups) = reserve_projection_backups(
        project,
        nm,
        &store,
        home,
        &previous_workspaces,
        &workspaces,
        &tracked,
    )?;

    let paths = forest_paths(project, &env_obj, &store, plan, &reasons, &workspaces)?;
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
    refs.object_path(&store, activity, &env_obj)?;
    if let Some((_, runtime)) = toolchain {
        refs.object_path(&store, activity, runtime)?;
    }
    if let Some(native_id) = native_id {
        refs.object_id(&store, activity, native_id)?;
    }
    refs.forest(&store, activity, forest)?;
    for backup in &backup_paths {
        refs.backup(&store, activity, backup)?;
    }
    // The root is durable before any stale managed link is removed, any user
    // directory is moved, or the new forest is published.
    crate::comforter::persist_root_for_refs_with_project_lock(
        project,
        &store,
        activity,
        &refs,
        &project_lock,
    )?;
    for (source, backup) in pending_backups {
        // Reaching here means the path was a real directory, not tog's
        // symlink: either a project tog has never synced, or one where an
        // `npm install` overwrote the projection. `move_reserved_backup`
        // says so once the move has happened, with where the packages went.
        crate::comforter::move_reserved_backup(project, &source, &backup)?;
    }
    remove_stale_workspace_links(project, &store, home, &previous_workspaces, &workspaces)?;
    build_project_forest(
        activity,
        platform,
        &env_obj,
        &paths,
        &workspaces,
        reasons.cloned(),
        fresh,
    )?;
    link_workspace_sources(project_dir, plan, proj_dir, forest)?;
    // Old forests are deliberately NOT pruned here: a dev server may still
    // be running from one, and pruning would break it mid-session. They are
    // cheap symlink trees; explicit `tog gc` with liveness checks is the
    // collection path.
    remove_sync_duplicate_links(project, &store, home);

    replace_with_symlink(project, nm, forest, "node_modules")?;
    for workspace in workspaces.iter().filter(|w| !tracked.contains(w)) {
        let workspace_nm = Path::new(workspace).join("node_modules");
        let workspace_forest = proj_dir
            .join("workspaces")
            .join(encode_workspace_path(workspace))
            .join("node_modules");
        replace_with_symlink(
            project,
            &workspace_nm,
            &workspace_forest,
            "workspace-node_modules",
        )?;
    }

    project.create_dir_all(Path::new(".tog"))?;
    let mut body = node_closure_body(
        &env_obj,
        &native_reference,
        &paths,
        &backup_paths,
        plan,
        &workspaces,
        &reasons,
        inputs,
    );
    record_unprojected(&mut body, &tracked, &workspaces);
    if let Some(record) = runtime_record {
        crate::comforter::merge_record(&mut body, record);
    }
    crate::comforter::write_closure_with_project_lock(
        project,
        "node",
        body,
        &store,
        activity,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    /// A link nested under a registry package would be created through the
    /// forest's symlink into that package's store object. Projection refuses
    /// it by name and leaves the object untouched; a top-level link is fine.
    #[test]
    fn workspace_links_are_never_created_through_a_package_symlink() {
        let scratch = TempDir::named("link-through-package");
        let root = scratch.0.clone();
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
    }

    /// vite commits a fixture `node_modules` inside a workspace member
    /// (#174). Only a real directory holding a tracked file is kept back;
    /// an untracked npm-made one, and a member git cannot see, are moved
    /// aside as before. A tracked one at the project root stops the sync.
    #[test]
    fn a_node_modules_git_tracks_is_never_moved_aside() {
        let scratch = TempDir::named("tracked-node-modules");
        let project = scratch.0.join("project");
        for dir in [
            "packages/fixture/node_modules/dep",
            "packages/built/node_modules/dep",
            "packages/linked",
        ] {
            fs::create_dir_all(project.join(dir)).unwrap();
        }
        fs::write(
            project.join("packages/fixture/node_modules/dep/index.js"),
            "",
        )
        .unwrap();
        fs::write(project.join("packages/built/node_modules/dep/index.js"), "").unwrap();
        std::os::unix::fs::symlink(
            project.join("packages/fixture/node_modules"),
            project.join("packages/linked/node_modules"),
        )
        .unwrap();
        let workspaces = ["packages/fixture", "packages/built", "packages/linked"]
            .map(String::from)
            .to_vec();
        let (_lease_dir, activity) = crate::kernel::testutil::detached_lease();

        let held = ProjectRoot::open(&project).unwrap();
        // Outside a repository nothing is tracked.
        assert!(git_tracked_node_modules(&held, &[], &workspaces, &activity)
            .unwrap()
            .is_empty());

        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(&project)
                .output()
                .unwrap();
            assert!(status.status.success(), "{status:?}");
        };
        git(&["init", "-q"]);
        git(&["add", "packages/fixture/node_modules/dep/index.js"]);
        git(&["commit", "-q", "-m", "fixture"]);
        assert_eq!(
            git_tracked_node_modules(&held, &[], &workspaces, &activity).unwrap(),
            ["packages/fixture"]
        );
        // A member that left the lockfile is kept back the same way.
        assert_eq!(
            git_tracked_node_modules(&held, &workspaces[..1], &[], &activity).unwrap(),
            ["packages/fixture"]
        );

        fs::create_dir_all(project.join("node_modules")).unwrap();
        fs::write(project.join("node_modules/.keep"), "").unwrap();
        git(&["add", "node_modules/.keep"]);
        git(&["commit", "-q", "-m", "root"]);
        let error = git_tracked_node_modules(&held, &[], &workspaces, &activity).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("node_modules holds files git tracks"),
            "{error}"
        );
    }

    fn git_fixture(dir: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@t"])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn projection_preserves_tracked_source_across_git_and_directory_boundaries() {
        let _lock = crate::kernel::policy::attribution_test_lock();
        for shape in [
            "corrupt-index",
            "renamed-root",
            "renamed-member",
            "submodule",
            "departed-submodule",
            "suffix-member",
            "damaged-member",
            "outer-tracked",
            "candidate-checkout",
            "descendant-checkout",
            "search-only-parent",
        ] {
            let temp = TempDir::named(shape);
            let project = temp.0.join("project");
            let store_root = temp.0.join("home/store");
            let env_id = format!("{}-npm-env-0", "1".repeat(40));
            let env = store_root.join("objects").join(&env_id);
            let workspace = if shape == "suffix-member" {
                "packages/member/node_modules"
            } else {
                "packages/member"
            };
            let root_case = matches!(shape, "corrupt-index" | "renamed-root");
            let source = if root_case {
                project.join("node_modules")
            } else {
                project.join(workspace).join("node_modules")
            };
            fs::create_dir_all(&source).unwrap();
            fs::write(source.join("fixture.js"), "committed source").unwrap();
            fs::create_dir_all(env.join("node_modules")).unwrap();
            for namespace in ["meta", "cache/sha256", "tmp", "roots"] {
                fs::create_dir_all(store_root.join(namespace)).unwrap();
            }
            fs::write(
                store_root.join("meta").join(format!("{env_id}.json")),
                serde_json::json!({"id": env_id,
                    "identity": {"kind": "test", "name": env_id, "version": "0", "inputs": {}}
                })
                .to_string(),
            )
            .unwrap();
            fs::create_dir_all(
                env.join("workspaces")
                    .join(encode_workspace_path(workspace))
                    .join("node_modules"),
            )
            .unwrap();
            git_fixture(&project, &["init", "-q"]);
            if shape.contains("submodule") {
                let member = project.join(workspace);
                git_fixture(&member, &["init", "-q"]);
                git_fixture(&member, &["add", "node_modules/fixture.js"]);
                git_fixture(&member, &["commit", "-qm", "fixture"]);
                git_fixture(
                    &project,
                    &[
                        "-c",
                        "protocol.file.allow=always",
                        "submodule",
                        "add",
                        "--",
                        member.to_str().unwrap(),
                        workspace,
                    ],
                );
                git_fixture(&project, &["submodule", "absorbgitdirs", workspace]);
            } else if !matches!(
                shape,
                "damaged-member" | "candidate-checkout" | "descendant-checkout"
            ) {
                let tracked = if root_case {
                    "node_modules/fixture.js".to_string()
                } else {
                    format!("{workspace}/node_modules/fixture.js")
                };
                git_fixture(&project, &["add", &tracked]);
            }
            if shape == "outer-tracked" {
                git_fixture(&project.join(workspace), &["init", "-q"]);
            }
            if shape == "candidate-checkout" {
                git_fixture(&source, &["init", "-q"]);
                git_fixture(&source, &["add", "fixture.js"]);
            }
            if shape == "descendant-checkout" {
                let child = source.join("dep");
                fs::create_dir(&child).unwrap();
                fs::write(child.join("fixture.js"), "committed dependency").unwrap();
                git_fixture(&child, &["init", "-q"]);
                git_fixture(&child, &["add", "fixture.js"]);
            }
            if shape == "damaged-member" {
                let member = project.join(workspace);
                git_fixture(&member, &["init", "-q"]);
                git_fixture(&member, &["add", "node_modules/fixture.js"]);
                fs::remove_file(member.join(".git/HEAD")).unwrap();
            }
            if shape == "corrupt-index" {
                fs::write(project.join(".git/index"), "corrupt index").unwrap();
            }
            if shape == "departed-submodule" {
                fs::create_dir_all(project.join(".tog/closures")).unwrap();
                fs::write(
                    project.join(".tog/closures/node.json"),
                    serde_json::json!({
                        "schema": "closure/1", "ecosystem": "node",
                        "body": {"workspaces": [workspace]}
                    })
                    .to_string(),
                )
                .unwrap();
            }
            let held = ProjectRoot::open(&project).unwrap();
            if shape == "search-only-parent" {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o111)).unwrap();
                let (_lease_dir, activity) = crate::kernel::testutil::detached_lease();
                assert_eq!(
                    git_tracked_node_modules(&held, &[], &[workspace.into()], &activity).unwrap(),
                    [workspace]
                );
            }
            let mut actual = project.clone();
            if shape.starts_with("renamed-") {
                actual = temp.0.join("moved");
                fs::rename(&project, &actual).unwrap();
                fs::create_dir(&project).unwrap();
            }
            crate::kernel::store::make_read_only_for_test(&env).unwrap();
            let workspaces = if root_case || shape == "departed-submodule" {
                Vec::new()
            } else {
                vec![workspace.to_string()]
            };
            let plan = NpmPlan {
                node_version: "24.20.0".into(),
                packages: Vec::new(),
                links: Vec::new(),
                workspaces,
                lock_source: "pnpm-lock.yaml".into(),
            };
            let store = crate::kernel::store::Store::for_test(store_root);
            let activity = store
                .activity(crate::kernel::activity::ActivityMode::Shared)
                .unwrap();
            let mut attribution = crate::kernel::policy::Attribution::open("node").unwrap();
            let result = project_node_env(
                &activity,
                &held,
                &env,
                Platform::host().unwrap(),
                &plan,
                &[],
                false,
                &mut attribution,
            );
            attribution.finish(result.is_ok()).unwrap();
            if root_case || matches!(shape, "renamed-member" | "damaged-member") {
                let error = result.unwrap_err().to_string();
                let expected = if matches!(shape, "corrupt-index" | "damaged-member") {
                    "cannot check Git-tracked source"
                } else if shape == "renamed-member" {
                    "the project directory was moved or replaced"
                } else {
                    "node_modules holds files git tracks"
                };
                assert!(error.contains(expected), "{shape}: {error}");
            } else {
                result.unwrap();
            }
            let remaining = actual.join(if root_case {
                PathBuf::from("node_modules")
            } else {
                Path::new(workspace).join("node_modules")
            });
            assert!(
                fs::symlink_metadata(&remaining).unwrap().is_dir(),
                "{shape}"
            );
            assert_eq!(
                fs::read_to_string(remaining.join("fixture.js")).unwrap(),
                "committed source",
                "{shape}"
            );
            assert!(
                !temp.0.join("home/store/backups").exists()
                    || fs::read_dir(temp.0.join("home/store/backups"))
                        .unwrap()
                        .next()
                        .is_none(),
                "{shape}"
            );
            if shape.starts_with("renamed-") {
                assert!(fs::read_dir(&project).unwrap().next().is_none(), "{shape}");
            }
        }
    }
}
