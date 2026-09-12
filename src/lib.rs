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
