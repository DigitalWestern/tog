//! From a Go project to its inputs: toolchain selection from go.mod, the
//! `GoPlan`, and the go.sum digest. Moved from `commands/shared.rs` (Stage 3).

use crate::kernel::platform::Platform;
use crate::kernel::store;
use crate::tailors::go;
use std::io;
use std::path::{Path, PathBuf};

pub struct GoInputs {
    pub go_obj: PathBuf,
    pub plan: go::GoPlan,
    pub gosum_sha256: String,
}

pub fn load_go_inputs(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
) -> io::Result<GoInputs> {
    let go_version = go::resolve_project_toolchain(platform, dir)?;
    let go_obj = go::ensure_go_for(store, platform, go_version)?;
    let plan = go::plan_go(store, platform, dir, &go_obj)?;
    if plan.go_version != go_version {
        return Err(io::Error::other(format!(
            "go.mod selected Go {go_version}, but planning selected {}; re-run blanket sync after keeping go.mod unchanged",
            plan.go_version
        )));
    }
    let gosum = std::fs::read_to_string(dir.join("go.sum")).unwrap_or_default();
    use sha2::{Digest, Sha256};
    Ok(GoInputs {
        go_obj,
        plan,
        gosum_sha256: hex::encode(Sha256::digest(gosum.as_bytes())),
    })
}
