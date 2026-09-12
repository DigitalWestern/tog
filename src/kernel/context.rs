//! What every store-backed command needs: the validated host platform, an
//! opened store, and the shared activity lease that keeps GC from racing
//! the command (REFACTOR.md §4 Stage 2 step 1). Kernel layer, so that a
//! tailor can take a `&Context` without naming the command layer.

use crate::kernel::activity::{ActivityMode, StoreActivity};
use crate::kernel::gc;
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use std::io;
use std::path::PathBuf;

pub struct Context {
    pub platform: Platform,
    pub store: Store,
    /// Keeps the operation protected from its first store read through its
    /// final child/projection use. Individual `Store` helpers acquire a
    /// short compatibility lease when called directly; this long-lived lease
    /// is what prevents GC from racing a CLI job.
    pub activity: StoreActivity,
}

impl Context {
    /// Open the store, run the opportunistic maintenance sweep if this
    /// command asks for one, then take the shared lease.
    pub fn open(platform: Platform, maintenance: bool) -> io::Result<Self> {
        let store = Store::open()?;
        if maintenance {
            // Scope the narration's stderr handle to the one call that uses
            // it: a lock held across a child whose stderr is relayed from
            // another thread is a pipe that stops being drained.
            let mut stderr = io::stderr().lock();
            gc::automatic_maintenance(&store, &mut stderr)?;
        }
        let activity = store.activity(ActivityMode::Shared)?;
        Ok(Self {
            platform,
            store,
            activity,
        })
    }

    /// The project directory is the current directory, read each time it is
    /// asked for: `add`/`remove`/`update` may change directory to the
    /// project the edit landed in before running the ordinary sync.
    pub fn project_dir(&self) -> PathBuf {
        project_dir()
    }
}

/// The project directory: the current directory, as every command reads it.
pub fn project_dir() -> PathBuf {
    std::env::current_dir().expect("cwd")
}
