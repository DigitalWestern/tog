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

pub fn run(
    platform: Platform,
    update: &ToolchainUpdate,
    no_sync: bool,
    strict: bool,
) -> io::Result<()> {
    // `strict` is the global `--strict`; without it the policy chain
    // decides strictness on its own. Reading `policy::strict()` here would
    // be worse than wrong: it initializes the policy to the default before
    // the project's chain has been loaded.
    sync::run_in_mode(
        platform,
        false,
        strict,
        Mode::Update {
            only: update.ecosystem.clone(),
        },
        no_sync,
    )
}
