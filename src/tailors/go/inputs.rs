//! From a Go project to its inputs: toolchain selection from go.mod, the
//! `GoPlan`, and the go.sum digest.

use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::platform::Platform;
use crate::kernel::resolve::ResolutionDoor;
use crate::kernel::store;
use crate::kernel::toolchain::Selected;
use crate::tailors::go;
use std::io;
use std::path::PathBuf;

pub struct GoInputs {
    pub go_obj: PathBuf,
    pub plan: go::GoPlan,
    pub gosum_sha256: String,
}

/// `toolchain` is the project's selection, and it is the only thing that
/// decides which Go this call realizes and plans with. go.mod's `go` and
/// `toolchain` directives were read by toolchain-input discovery and
/// answered by selection; reading them again here could only disagree with
/// the lock this run is honoring. The project is read through the held
/// descriptor `project`.
///
/// The planning tool runs through `door`, a planner door.
pub fn load_go_inputs(
    project: &ProjectRoot,
    toolchain: &Selected,
    door: &mut ResolutionDoor<'_>,
) -> io::Result<GoInputs> {
    let (store, activity, platform) = (door.store(), door.lease(), door.platform());
    let go_version = toolchain.version("go")?;
    let go_obj = go::realize_runtime(store, activity, platform, toolchain)?;
    let mut plan = go::plan_go(door, project, &go_obj, go_version, true)?;
    // A cached plan can name artifacts this store never downloaded. When the
    // module cache object is missing too, plan again, which fetches them;
    // when the object is present, nothing is fetched, so an offline warm
    // sync stays offline.
    if !modcache_realizable(store, activity, platform, toolchain, &plan)? {
        plan = go::plan_go(door, project, &go_obj, go_version, false)?;
    }
    // An absent go.sum digests as the empty string; an unreadable one is
    // an error, never a digest of nothing.
    let gosum = go::read_gosum(project)?.unwrap_or_default();
    use sha2::{Digest, Sha256};
    Ok(GoInputs {
        go_obj,
        plan,
        gosum_sha256: hex::encode(Sha256::digest(gosum.as_bytes())),
    })
}

/// Whether this store can realize `plan`'s module cache from what it holds:
/// the object itself, or every artifact the skeleton copies. A cached plan
/// names the artifacts its planning run put in that run's store; another
/// store (a different `TOG_STORE`), or a cache `gc` aged out, lacks them.
pub(super) fn modcache_realizable(
    store: &store::Store,
    activity: &crate::kernel::activity::StoreActivity,
    platform: Platform,
    selected: &Selected,
    plan: &go::GoPlan,
) -> io::Result<bool> {
    go::validate_plan(plan)?;
    let row = go::runtime_row(platform, selected)?;
    let id = go::modcache_identity(&row.version, row.digest.hex(), plan).object_id();
    if store.has_with_activity(activity, &id)? {
        return Ok(true);
    }
    Ok(plan.modules.iter().all(|m| {
        [&m.zip_sha256, &m.modfile_sha256, &m.info_sha256]
            .iter()
            .all(|hash| store.cache_path("sha256", hash).is_file())
    }))
}
