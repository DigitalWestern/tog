//! The kernel: the ecosystem-agnostic core (store, fetch, sandbox, policy,
//! GC, supervision). Nothing in this folder may name a tailor or a command;
//! cross-layer knowledge flows through traits and data.

pub mod activity;
pub mod archive;
pub mod context;
pub mod cyclonedx;
pub mod digest;
pub mod dirhash;
pub mod fetch;
pub mod fsroot;
pub mod gc;
pub mod gitsrc;
pub mod objmeta;
pub mod platform;
pub mod policy;
pub mod provider;
pub mod sandbox;
pub mod semver;
pub mod signing;
pub mod store;
pub mod supervise;
#[cfg(test)]
pub(crate) mod testutil;
pub mod toolchain;
pub mod types;
pub mod ui;
