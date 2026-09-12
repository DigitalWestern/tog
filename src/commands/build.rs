//! `blanket build [ecosystem] [args...]`: a sandboxed build for the one
//! build-capable ecosystem present, or the named one, through the tailor
//! registry.

use crate::kernel::context::Context;
use crate::kernel::policy;
use crate::tailors::{self, Tailor};
use std::io;

/// Explicit ecosystem, or inferred when exactly one build-capable ecosystem
/// is present (Sol review 4).
pub fn run(ctx: &Context, args: &[String]) -> io::Result<()> {
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
                        "blanket build requires a Cargo.toml, go.mod, or mix.exs project",
                    ))
                }
                many => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "multiple build-capable ecosystems found ({}); specify one: \
                             `blanket build <ecosystem> ...`",
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
    let root = tailor.build_root(&cwd)?;
    policy::init(&root, false)?;
    tailor.build(ctx, &root, &cwd, rest)
}
