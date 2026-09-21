//! `tog plan`: print each detected ecosystem's plan as JSON without
//! realizing anything, through the tailor registry.

use crate::comforter::toolchain::{self as project_toolchain, Mode};
use crate::commands::shared::{ecosystem_inputs, no_inputs};
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy;
use crate::tailors;
use std::io;

pub fn run(ctx: &Context) -> io::Result<()> {
    let dir = ctx.project_dir();
    policy::init(&dir, false)?;
    let present = tailors::detected(&dir)?;
    // Planning reads the lock and writes nothing: no lock is created here,
    // and a project that has none plans against the shipped selection.
    let root = ProjectRoot::open(&dir)?;
    let toolchain = project_toolchain::resolve(
        &root,
        ctx.platform,
        ecosystem_inputs(&dir, &present)?,
        Mode::ReadOnly,
        false,
    )?;
    let mut any = false;
    for tailor in &present {
        let selected = toolchain.get(tailor.lock_ecosystem())?;
        let mut attribution = policy::Attribution::open("plan")?;
        tailor.prepare(ctx, &dir, selected, &mut attribution)?;
        if let Some(text) = tailor.plan(ctx, &dir, selected)? {
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
