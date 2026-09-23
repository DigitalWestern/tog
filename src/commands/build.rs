//! `tog build [ecosystem] [args...]`: a sandboxed build for the one
//! build-capable ecosystem present, or the named one, through the tailor
//! registry.

use crate::comforter::toolchain::{self as project_toolchain, Mode};
use crate::commands::shared::ecosystem_inputs;
use crate::kernel::context::Context;
use crate::kernel::fsroot::ProjectRoot;
use crate::kernel::policy;
use crate::tailors::{self, Tailor};
use std::io;

/// Explicit ecosystem, or inferred when exactly one build-capable ecosystem
/// is present.
pub fn run(ctx: &Context, args: &[String], frozen: bool, strict: bool) -> io::Result<()> {
    let cwd = ctx.project_dir();
    let explicit = args
        .first()
        .and_then(|word| tailors::by_id(word))
        .filter(|tailor| tailor.builds());
    let (tailor, rest): (&dyn Tailor, &[String]) = match explicit {
        Some(tailor) => (tailor, &args[1..]),
        None => {
            let mut present = Vec::new();
            for tailor in tailors::registry() {
                if tailor.builds() && tailor.build_present(&cwd)? {
                    present.push(*tailor);
                }
            }
            match present.as_slice() {
                [one] => (*one, args),
                [] => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "tog build requires a Cargo.toml, go.mod, or mix.exs project",
                    ))
                }
                many => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "multiple build-capable ecosystems found ({}); specify one: \
                             `tog build <ecosystem> ...`",
                            many.iter()
                                .map(|tailor| tailor.id())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ))
                }
            }
        }
    };
    // A build against inputs the lock no longer describes is the bug the
    // sync-on-the-way-in exists to prevent, so when the ecosystem being
    // built is stale or never synced the project is synced first, as `run`
    // does: that sync may write a lock, like `cargo build` updating
    // Cargo.lock. CI that must not write one runs `tog --frozen build`,
    // whose implicit sync runs frozen (or `tog --frozen` first, and this
    // check then finds nothing to do). Only the built ecosystem's
    // row decides, and only it is host preflighted, prepared and realized;
    // the toolchain lock still covers the whole project, so an unrelated
    // ecosystem blocks the build only when its lock section is stale, not
    // when this host cannot run it or its install fails (see
    // `sync::ensure_current_for`).
    crate::commands::sync::ensure_current_for(ctx, &cwd, Some(tailor.id()), frozen, strict)?;
    let root = tailor.build_root(&cwd)?;
    policy::init(&root, false)?;
    // The build itself honors the lock the sync above left and never
    // writes one.
    let held = ProjectRoot::open(&root)?;
    let toolchain = project_toolchain::resolve(
        &held,
        ctx.platform,
        ecosystem_inputs(&root, &[tailor])?,
        Mode::ReadOnly,
        false,
    )?;
    let selected = toolchain.get(tailor.lock_ecosystem())?;
    let mut attribution = policy::Attribution::open(tailor.id())?;
    tailor.build(ctx, &root, &cwd, rest, selected, &mut attribution)?;
    attribution.finish(true)
}
