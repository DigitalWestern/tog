//! blanket: a universal package-manager kernel.
//!
//! Layers point one way, `commands → tailors → comforter → kernel`:
//! `kernel/` is the ecosystem-agnostic core, `tailors/` holds one adapter
//! per ecosystem, `comforter/` records closures and projects them, and
//! `commands/` holds one file per verb, which is what the binary calls.

pub mod cli;
pub mod comforter;
pub mod kernel;
pub mod tailors;

pub mod commands;
