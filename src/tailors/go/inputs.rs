//! From a Go project to its inputs: toolchain selection from go.mod, the
//! `GoPlan`, and the go.sum digest.

use crate::kernel::platform::Platform;
use crate::kernel::store;
use crate::kernel::toolchain::Selected;
use crate::tailors::go;
use std::io;
use std::path::{Path, PathBuf};

pub struct GoInputs {
    pub go_obj: PathBuf,
    pub plan: go::GoPlan,
    pub gosum_sha256: String,
}

/// `toolchain` is the project's selection, and it is the only thing that
/// decides which Go this call realizes and plans with. go.mod's `go` and
/// `toolchain` directives were read by toolchain-input discovery and
/// answered by selection; reading them again here could only disagree with
/// the lock this run is honoring.
pub fn load_go_inputs(
    platform: Platform,
    dir: &Path,
    store: &store::Store,
    toolchain: &Selected,
) -> io::Result<GoInputs> {
    let go_version = toolchain.version("go")?;
    let go_obj = go::ensure_go_for(store, platform, go_version)?;
    let plan = go::plan_go(store, dir, &go_obj, go_version)?;
    let gosum = std::fs::read_to_string(dir.join("go.sum")).unwrap_or_default();
    use sha2::{Digest, Sha256};
    Ok(GoInputs {
        go_obj,
        plan,
        gosum_sha256: hex::encode(Sha256::digest(gosum.as_bytes())),
    })
}
