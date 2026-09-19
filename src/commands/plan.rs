//! `tog plan`: print each detected ecosystem's plan as JSON without
//! realizing anything, through the tailor registry.

use crate::commands::shared::no_inputs;
use crate::kernel::context::Context;
use crate::kernel::policy;
use crate::tailors;
use std::io;

pub fn run(ctx: &Context) -> io::Result<()> {
    let dir = ctx.project_dir();
    policy::init(&dir, false)?;
    let present = tailors::detected(&dir)?;
    let mut any = false;
    for tailor in &present {
        let mut attribution = policy::Attribution::open("plan")?;
        tailor.prepare(ctx, &dir, &mut attribution)?;
        if let Some(text) = tailor.plan(ctx, &dir)? {
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
