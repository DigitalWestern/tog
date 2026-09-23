//! tog: a universal package-manager kernel.
//!
//! Layers point one way, `commands → tailors → comforter → kernel`:
//! `kernel/` is the ecosystem-agnostic core, `tailors/` holds one adapter
//! per ecosystem, `comforter/` records closures and projects them, and
//! `commands/` holds one file per verb, which is what the binary calls.

// Tests spawn fixtures and take leases freely. Production code is still
// checked: clippy lints the non-test build of this crate too (clippy.toml).
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod cli;
pub mod comforter;
pub mod kernel;
pub mod tailors;

pub mod commands;
