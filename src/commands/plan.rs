//! `tog plan`: print each detected ecosystem's plan as JSON without
//! realizing anything, through the tailor registry.

use crate::cli::SyncFlags;
use crate::comforter::toolchain::{self as project_toolchain, Mode};
use crate::commands::shared::{ecosystem_inputs_in, no_inputs};
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy;
use crate::tailors;
use std::io;

pub fn run(ctx: &Context, sync: SyncFlags) -> io::Result<()> {
    let dir = ctx.project_dir();
    // One descriptor for the whole plan, as sync holds one.
    let root = ProjectRoot::open(&dir)?;
    policy::init_in(&root, sync.strict)?;
    let present = tailors::detected_in(&root)?;
    // Planning reads the lock and writes nothing: no lock is created here,
    // and a project that has none plans against the shipped selection.
    let toolchain = project_toolchain::resolve(
        &root,
        ctx.platform,
        ecosystem_inputs_in(&root, &present)?,
        Mode::ReadOnly,
        false,
    )?;
    let mut any = false;
    for tailor in &present {
        let selected = toolchain.get(tailor.lock_ecosystem())?;
        let mut attribution = policy::Attribution::open("plan")?;
        // `prepare` is missing-lock generation: it runs the ecosystem's own
        // tool in the project and writes a dependency lock. Frozen promises
        // not to modify project inputs, so it never reaches that call at
        // all; a project with no dependency lock fails inside the tailor,
        // which is the one place that knows which file is missing.
        if !sync.frozen {
            tailor.prepare(ctx, &root, selected, &mut attribution)?;
        }
        if let Some(text) = tailor.plan(ctx, &root, selected)? {
            println!("{text}");
            any = true;
        }
        attribution.discard();
    }
    if !any {
        return Err(no_inputs());
    }
    Ok(())
}
