//! Publish the Elixir dependency forest after checking resolution policy.

use super::*;

/// Project: clonefile the deps object into a writable per-project tree
/// (native builds write into their source dirs — npm mutablePackages
/// precedent; recorded unattested) + closure envelope.
pub fn project_elixir_env(
    activity: &StoreActivity,
    platform: Platform,
    project: &ProjectRoot,
    beam_obj: &Path,
    deps_obj: &Path,
    plan: &ElixirPlan,
    lock_sha256: &str,
    resolution_basis: &crate::comforter::join::Digests,
    fresh: bool,
    selected: &Selected,
    ledgers: &[crate::kernel::resolve::ledger::LedgerObjects],
    attribution: &mut crate::kernel::policy::Attribution,
) -> io::Result<PathBuf> {
    let spec = beam_spec(platform, selected)?;
    let beam_obj = beam_obj.canonicalize()?;
    let deps_obj = deps_obj.canonicalize()?;
    let store = crate::comforter::store_from_object_path(&beam_obj)
        .ok_or_else(|| err("BEAM object is not in a Tog store"))?;
    let project_dir = project.path();
    let proj_dir = expected_projection(&store, project_dir, &deps_obj)?;
    let project_lock = store.project_lock_in(project)?;
    store.ensure_namespace(Path::new("forests"))?;
    let mut refs = crate::comforter::ClosureRefs::new();
    refs.object_path(&store, activity, &beam_obj)?;
    refs.object_path(&store, activity, &deps_obj)?;
    refs.forest(&store, activity, &proj_dir)?;
    // The planner doors' ledgers, kept as long as this closure is and
    // named in the body so a root rebuilt from the closure keeps them.
    let mut ledger_refs = Vec::new();
    for objects in ledgers {
        for id in [&objects.ledger, &objects.diagnostics] {
            refs.object_id(&store, activity, id)?;
            ledger_refs.push(crate::comforter::object_ref(&store.object_path(id))?);
        }
    }
    let mut body = closure_body(
        &beam_obj,
        &deps_obj,
        &proj_dir,
        plan,
        lock_sha256,
        &spec,
        selected,
    )?;
    body["resolution_ledgers"] = ledger_refs.into();
    body[crate::comforter::join::BASIS_FIELD] =
        crate::comforter::join::basis_value(resolution_basis);
    // Refuse stale inputs or denied receipts before a fresh sync mutates
    // the forest still referenced by the active closure. Keep this lock
    // through publication and its final recheck.
    crate::comforter::join::join_for_closure(
        project,
        "elixir",
        &mut body,
        &store,
        activity,
        Some(&mut refs),
    )?;
    // Protect the dependency projection before cloning or publishing it.
    crate::comforter::persist_root_for_refs_with_project_lock(
        project,
        &store,
        activity,
        &refs,
        &project_lock,
    )?;
    if fresh && proj_dir.exists() {
        crate::kernel::store::remove_tree(&proj_dir)?;
    }
    if !proj_dir.exists() {
        // Atomic publication: clone into a tmp sibling, then rename — a
        // crashed clone must never be trusted as a complete forest.
        let parent = proj_dir.parent().unwrap();
        fs::create_dir_all(parent)?;
        let tmp = parent.join(format!(
            ".hex-deps.tmp.{}",
            crate::kernel::fsroot::random_suffix()?
        ));
        crate::comforter::clone_tree_with_activity(activity, &deps_obj, &tmp, platform)?;
        fs::rename(&tmp, &proj_dir)?;
    }
    crate::comforter::write_closure_with_project_lock(
        project,
        "elixir",
        body,
        &store,
        activity,
        refs,
        &project_lock,
        attribution,
    )?;
    Ok(proj_dir)
}
