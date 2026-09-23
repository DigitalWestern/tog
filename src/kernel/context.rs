//! What every store-backed command needs: the validated host platform, an
//! opened store, and the shared activity lease that keeps GC from racing
//! the command. Kernel layer, so that a tailor can take a `&Context` without
//! naming the command layer.

use crate::kernel::activity::{ActivityMode, StoreActivity};
use crate::kernel::gc;
use crate::kernel::platform::Platform;
use crate::kernel::store::Store;
use std::io;
use std::path::PathBuf;

pub struct Context {
    pub platform: Platform,
    pub store: Store,
    project_dir: Option<PathBuf>,
    /// Keeps the operation protected from its first store read through its
    /// final child/projection use, which is what prevents GC from racing a
    /// CLI job. Every store helper borrows this lease as a `&StoreActivity`
    /// parameter; only the lease-free root-registry calls (`register_root`
    /// and friends) take their own.
    pub activity: StoreActivity,
}

impl Context {
    /// Open the store, run the opportunistic maintenance sweep if this
    /// command asks for one, then take the shared lease.
    pub fn open(platform: Platform, maintenance: bool) -> io::Result<Self> {
        Self::open_with_project_dir(platform, None, maintenance)
    }

    /// Open a context whose project directory is independent of the process
    /// cwd. Production dispatch uses `open`, which keeps the existing dynamic
    /// cwd behavior needed by dependency edits.
    pub fn open_in(
        platform: Platform,
        project_dir: &std::path::Path,
        maintenance: bool,
    ) -> io::Result<Self> {
        Self::open_with_project_dir(platform, Some(project_dir.to_path_buf()), maintenance)
    }

    // Reviewed site (tests/architecture.rs): operation boundary: the shared lease every command borrows via `Context`.
    #[allow(clippy::disallowed_methods)]
    fn open_with_project_dir(
        platform: Platform,
        project_dir: Option<PathBuf>,
        maintenance: bool,
    ) -> io::Result<Self> {
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
            project_dir,
            activity,
        })
    }

    /// The directory `open_in` pinned, or the current directory read fresh
    /// on every call: `add`/`remove`/`update` may change directory to the
    /// project the edit landed in before running the ordinary sync.
    pub fn project_dir(&self) -> PathBuf {
        self.project_dir.clone().unwrap_or_else(project_dir)
    }
}

/// The project directory: the current directory, as every command reads it.
pub fn project_dir() -> PathBuf {
    std::env::current_dir().expect("cwd")
}
