//! Object kinds the Cargo tailor produces itself. None: every object a
//! Cargo sync commits (the Rust toolchain, its components, rustfmt, and the
//! vendored crate closure) is made by a kernel provider, whose rows live in
//! `kernel::provider::objects` (#191).

use crate::kernel::objmeta::ObjectKind;

pub static KINDS: &[ObjectKind] = &[];
