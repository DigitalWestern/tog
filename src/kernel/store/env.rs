//! `BLANKET_STORE` handling (kernel store): the process-global lock tests
//! take around the variable, and the home lookup the default location uses.

use super::*;

/// Serializes every test that sets or clears `BLANKET_STORE`. The variable is
/// process-global, so an unguarded test clearing it mid-run sends a guarded one
/// to the real `~/.blanket/store` — which is populated, and fails any assertion
/// about a fresh store. One lock for the whole crate: separate per-module locks
/// do not exclude each other. Poison is ignored deliberately, so a single
/// failing test does not cascade into every other holder.
#[cfg(test)]
pub(crate) static STORE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME set"))
}
