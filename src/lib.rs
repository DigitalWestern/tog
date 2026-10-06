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

/// Under `--cfg tog_dead_code` the internal modules are private, so rustc's
/// dead-code lint reports what no command reaches. This list is what is
/// reached from outside the library, where that lint cannot see: the
/// binary (`src/main.rs`) and the integration tests (`tests/*.rs`). Each
/// line names its caller. A new entry needs a caller outside `src/`; an
/// item no one calls is deleted instead (#247). A method cannot be listed
/// here, so the few the integration tests call carry
/// `#[cfg_attr(tog_dead_code, allow(dead_code))]` and a comment naming
/// the test.
#[cfg(tog_dead_code)]
pub mod boundary {
    // src/main.rs
    pub use crate::kernel::supervise::stop_signal;
    pub use crate::kernel::ui::{error_json_with_fix, error_with_fix, init};
    // tests/npm_scripts.rs
    pub use crate::kernel::fetch::download_verified_digest;
    pub use crate::tailors::node::{ensure_node_for, realize_node_env};
    // tests/node_env_evidence.rs
    pub use crate::kernel::gc::collect;
    // tests/native_libs.rs
    pub use crate::kernel::provider::nativelibs::{size_bytes, NativeLibSet};
    // tests/native_libs.rs, tests/sandbox_deny.rs
    pub use crate::kernel::sandbox::run_build_spec;
    // tests/sandbox_deny.rs
    pub use crate::kernel::resolve::confine::SocketScan;
    // tests/linux_python.rs
    pub use crate::tailors::python::ensure_uv_for;
    // tests/build_isolation.rs, tests/sandbox_deny.rs
    pub use crate::tailors::python::build::{
        build_sdist_wheel, build_sdist_wheel_with_runtime_plan,
    };
    // tests/toolchain_lock.rs
    pub use crate::kernel::provider::rust::rust_object_id;
    // tests/kernel_smoke.rs, tests/git_deps.rs
    pub use crate::tailors::python::env::realize_env;
}
