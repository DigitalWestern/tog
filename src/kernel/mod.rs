//! The kernel: the ecosystem-agnostic core (store, fetch, sandbox, policy,
//! GC, supervision). Nothing in this folder may name a tailor or a command;
//! cross-layer knowledge flows through traits and data (REFACTOR.md §2).

pub mod activity;
pub mod archive;
pub mod context;
pub mod cyclonedx;
pub mod dirhash;
pub mod fetch;
pub mod gc;
pub mod gitsrc;
pub mod objmeta;
pub mod platform;
pub mod policy;
pub mod sandbox;
pub mod store;
pub mod supervise;
#[cfg(test)]
pub(crate) mod testutil;
pub mod types;
pub mod ui;
