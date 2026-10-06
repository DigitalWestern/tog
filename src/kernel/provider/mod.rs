//! Shared toolchain providers (kernel layer): the pinned toolchains and
//! build inputs that more than one tailor realizes.
//!
//! A Python sdist with a Rust extension needs Rust and a vendored crate
//! closure; an npm native addon needs a CPython for node-gyp; both mount the
//! pinned native library set and consult the install-time artifact policy.
//! Each of those lives here once, so every tailor that needs one reaches it
//! from below instead of reaching into a sibling tailor. The modules know
//! artifact formats (a Cargo.lock, a python-build-standalone tarball) the way
//! `dirhash` knows Go's module hash; they name no tailor. The object-kind
//! rows for what they commit live here too (`objects`), because the layer
//! that makes an object declares its kind.

pub mod artifacts;
pub mod cargo_door;
pub mod cpython;
pub mod crates;
pub mod crates_index;
pub mod nativelibs;
pub mod objects;
pub mod rust;
pub mod rust_channel;
pub mod rust_extras;
pub mod rust_path;
