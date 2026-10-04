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
#[cfg(not(tog_dead_code))]
pub mod comforter;
#[cfg(tog_dead_code)]
mod comforter;
#[cfg(not(tog_dead_code))]
pub mod kernel;
#[cfg(tog_dead_code)]
mod kernel;
#[cfg(not(tog_dead_code))]
pub mod tailors;
#[cfg(tog_dead_code)]
mod tailors;

pub mod commands;
