//! `tog update --toolchain [<ecosystem>]`: the one verb that replaces a
//! committed `tog-toolchain.toml`.
//!
//! It re-reads the project's declarative toolchain sources, selects from the
//! shipped catalog again, writes one lock, and then syncs from it. Nothing
//! about a dependency lock is touched: a runtime moving and a dependency
//! graph moving are different decisions, and mixing them would hide one
//! inside the other.

use crate::cli::ToolchainUpdate;
use crate::comforter::toolchain::Mode;
use crate::commands::sync;
use crate::kernel::platform::Platform;
use std::io;

pub fn run(platform: Platform, update: &ToolchainUpdate, no_sync: bool) -> io::Result<()> {
    // The dispatcher has already recorded `--strict`, and the sync loads
    // the policy chain in its preflight and holds it while it runs.
    sync::run_in_mode(
        platform,
        false,
        Mode::Update {
            only: update.ecosystem.clone(),
        },
        no_sync,
    )
}
