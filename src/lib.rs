//! blanket: a universal package-manager kernel.
//!
//! Layers point one way, `commands → tailors → kernel` (REFACTOR.md §2):
//! `kernel/` is the ecosystem-agnostic core, `tailors/` holds one adapter
//! per ecosystem, `comforter/` realizes and projects environments, and the
//! command implementations at the top level are what the binary calls.

pub mod cli;
pub mod comforter;
pub mod kernel;
pub mod tailors;

pub mod audit;
pub mod deps;
pub mod inspect;
pub mod sbom;
pub mod xrun;

// Stage 1 compatibility shims (REFACTOR.md §4, Stage 1 step 4): every
// pre-move module name keeps resolving so call sites and in-flight branches
// compile unchanged. The follow-up sweep PR deletes these.
pub use comforter as project;
pub use kernel::{
    activity, archive, dirhash, fetch, gc, gitsrc, objmeta, platform, policy, sandbox, store,
    supervise, types, ui,
};
pub use tailors::cargo::{self, rustfmt};
pub use tailors::go as golang;
pub use tailors::node::{self as npm, lock_import as npm_lock_import};
pub(crate) use tailors::python::build_requires;
pub use tailors::python::{
    self, artifacts, build, manifest, nativelibs, pep440, pypi, pyselect, wheel,
};
pub use tailors::{dotnet, elixir, ruby};
