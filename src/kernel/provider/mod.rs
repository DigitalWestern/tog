//! Shared toolchain providers (kernel layer): the pinned toolchains and
//! build inputs that more than one tailor realizes.
//!
//! A Python sdist with a Rust extension needs Rust and a vendored crate
//! closure; an npm native addon needs a CPython for node-gyp; both mount the
//! pinned native library set and consult the install-time artifact policy.
//! Each of those lives here once, so every tailor that needs one reaches it
//! from below instead of reaching into a sibling tailor. The modules know
//! artifact formats (a Cargo.lock, a python-build-standalone tarball) the way
//! `dirhash` knows Go's module hash; they name no tailor. Object-kind rows
//! for what they commit stay with the tailor whose ecosystem the kind
//! belongs to, and are installed with every other tailor's rows.

pub mod artifacts;
pub mod cargo_door;
pub mod cpython;
pub mod crates;
pub mod crates_index;
pub mod nativelibs;
pub mod rust;
pub mod rust_channel;
pub mod rust_extras;
pub mod rust_path;
