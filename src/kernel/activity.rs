//! Lifetime protection for operations that consume a Tog store.
//!
//! The cache lease in `fetch` deliberately has different sharing semantics;
//! this module owns the operation-level reader/writer lock.  A lease is an
//! operation-owned RAII value.  Cloning it is an explicit way for nested work
//! to keep the same operation alive; no process-global "some job is active"
//! bit is used as authorization.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread::ThreadId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityMode {
    Shared,
    Exclusive,
}

impl ActivityMode {
    fn flock_operation(self) -> libc::c_int {
        match self {
            Self::Shared => libc::LOCK_SH,
            Self::Exclusive => libc::LOCK_EX,
        }
    }

    pub(crate) fn satisfies(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::Exclusive, Self::Shared)
                | (Self::Shared, Self::Shared)
                | (Self::Exclusive, Self::Exclusive)
        )
    }
}

#[derive(Debug)]
struct Coordinator {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct State {
    readers: usize,
    reader_owners: HashMap<ThreadId, usize>,
    writer: bool,
    writer_owner: Option<ThreadId>,
}

#[derive(Debug)]
struct LocalLease {
    coordinator: Arc<Coordinator>,
    mode: ActivityMode,
    owner: ThreadId,
}

impl Drop for LocalLease {
    fn drop(&mut self) {
        let mut state = self
            .coordinator
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self.mode {
            ActivityMode::Shared => {
                state.readers = state.readers.saturating_sub(1);
                if let Some(count) = state.reader_owners.get_mut(&self.owner) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        state.reader_owners.remove(&self.owner);
                    }
                }
            }
            ActivityMode::Exclusive => {
                state.writer = false;
                state.writer_owner = None;
            }
        }
        self.coordinator.changed.notify_all();
    }
}

static COORDINATORS: OnceLock<Mutex<HashMap<PathBuf, Weak<Coordinator>>>> = OnceLock::new();

fn coordinator_for(root: &Path) -> Arc<Coordinator> {
    let registry = COORDINATORS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(coordinator) = registry.get(root).and_then(Weak::upgrade) {
        return coordinator;
    }
    let coordinator = Arc::new(Coordinator {
        state: Mutex::new(State::default()),
        changed: Condvar::new(),
    });
    registry.insert(root.to_path_buf(), Arc::downgrade(&coordinator));
    coordinator
}

fn local_lease(
    coordinator: &Arc<Coordinator>,
    mode: ActivityMode,
    nonblocking: bool,
) -> io::Result<Option<Arc<LocalLease>>> {
    let owner = std::thread::current().id();
    let mut state = coordinator
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    match mode {
        ActivityMode::Shared => {
            // A thread that already holds this store's exclusive lease would
            // otherwise wait on itself for ever, both here and on the second
            // flock descriptor. An exclusive lease already satisfies a shared
            // read, so the fix is always to pass the token down.
            if state.writer_owner == Some(owner) {
                return Err(io::Error::other(
                    "this thread already holds the exclusive activity lease for this store; \
                     pass that lease to the call instead of taking a shared one",
                ));
            }
            if nonblocking && state.writer {
                return Ok(None);
            }
            while state.writer {
                state = coordinator
                    .changed
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            state.readers += 1;
            *state.reader_owners.entry(owner).or_default() += 1;
        }
        ActivityMode::Exclusive => {
            if state.writer_owner == Some(owner) || state.reader_owners.contains_key(&owner) {
                // A non-blocking caller asked "is anyone using this store?".
                // The honest answer is yes — this thread is — and callers
                // narrate that as busy. Only the blocking form is a genuine
                // self-upgrade that can never be satisfied.
                if nonblocking {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "cannot upgrade an operation's activity lease; release the shared lease first",
                ));
            }
            if nonblocking && (state.writer || state.readers != 0) {
                return Ok(None);
            }
            while state.writer || state.readers != 0 {
                state = coordinator
                    .changed
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            state.writer = true;
            state.writer_owner = Some(owner);
        }
    }

    Ok(Some(Arc::new(LocalLease {
        coordinator: Arc::clone(coordinator),
        mode,
        owner,
    })))
}

fn open_lock(root: &Path) -> io::Result<File> {
    let path = root.join("activity.lock");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|error| {
            io::Error::new(error.kind(), format!("open {}: {error}", path.display()))
        })?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::other(format!(
            "activity lock {} is not a regular file",
            path.display()
        )));
    }
    // The descriptor is the object we inspected. Applying permissions by
    // pathname would reopen a replacement if the lock name were swapped
    // between open(2) and chmod(2).
    // SAFETY: `file` is the open descriptor this function just created.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn lock_file(file: &File, mode: ActivityMode, nonblocking: bool) -> io::Result<bool> {
    let mut operation = mode.flock_operation();
    if nonblocking {
        operation |= libc::LOCK_NB;
    }
    // SAFETY: `file` is an open descriptor owned by the caller and the
    // operation is one of the flock lock flags above.
    if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if nonblocking
        && matches!(
            error.raw_os_error(),
            Some(errno) if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK
        )
    {
        return Ok(false);
    }
    Err(error)
}

/// A live operation lease.  The OS descriptor is intentionally
/// close-on-exec: the Tog process, not a child tool, owns the protection.
#[derive(Debug)]
pub struct StoreActivity {
    root: PathBuf,
    mode: ActivityMode,
    _file: Arc<File>,
    _local: Arc<LocalLease>,
}

impl Clone for StoreActivity {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            mode: self.mode,
            _file: Arc::clone(&self._file),
            _local: Arc::clone(&self._local),
        }
    }
}

impl StoreActivity {
    pub fn mode(&self) -> ActivityMode {
        self.mode
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn acquire(root: &Path, mode: ActivityMode) -> io::Result<Self> {
        Self::acquire_inner(root, mode, false)?.ok_or_else(|| {
            io::Error::other("activity lock unexpectedly unavailable after blocking acquisition")
        })
    }

    /// Try to take the exclusive lease without waiting for a job.
    ///
    /// A single `flock` attempt is not a reliable answer. `flock` belongs to
    /// the open file description, so a child forked by any thread between
    /// `fork` and `exec` transiently holds a duplicate of a lease descriptor
    /// — including one whose owner has already released it. During that
    /// window an idle store reports itself busy, and callers turn that into
    /// "cleanup skipped", so `gc` quietly does nothing.
    ///
    /// Confirm instead of guessing: a real job holds its lease for the whole
    /// operation, so it is still unavailable after this bounded confirmation
    /// window, while a fork/exec shadow is gone within microseconds. This
    /// never reports a busy store as free — only the reverse, and only for
    /// as long as the window.
    pub(crate) fn try_exclusive(root: &Path) -> io::Result<Option<Self>> {
        Self::try_acquire(root, ActivityMode::Exclusive)
    }

    /// Try to take the shared lease without waiting for an exclusive job
    /// (a sweep, a reset), with the same confirmation as `try_exclusive`.
    /// For a reader that would rather say the store is busy than wait.
    pub(crate) fn try_shared(root: &Path) -> io::Result<Option<Self>> {
        Self::try_acquire(root, ActivityMode::Shared)
    }

    fn try_acquire(root: &Path, mode: ActivityMode) -> io::Result<Option<Self>> {
        const ATTEMPTS: u32 = 10;
        const PAUSE: std::time::Duration = std::time::Duration::from_millis(5);
        for attempt in 0..ATTEMPTS {
            if let Some(activity) = Self::acquire_inner(root, mode, true)? {
                return Ok(Some(activity));
            }
            if attempt + 1 < ATTEMPTS {
                std::thread::sleep(PAUSE);
            }
        }
        Ok(None)
    }

    fn acquire_inner(
        root: &Path,
        mode: ActivityMode,
        nonblocking: bool,
    ) -> io::Result<Option<Self>> {
        let root = root.canonicalize()?;
        let coordinator = coordinator_for(&root);
        let Some(local) = local_lease(&coordinator, mode, nonblocking)? else {
            return Ok(None);
        };
        let file = match open_lock(&root).and_then(|file| {
            let available = lock_file(&file, mode, nonblocking)?;
            if available {
                Ok(Some(file))
            } else {
                Ok(None)
            }
        }) {
            Ok(Some(file)) => file,
            Ok(None) => return Ok(None),
            Err(error) => return Err(error),
        };
        Ok(Some(Self {
            root,
            mode,
            _file: Arc::new(file),
            _local: local,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::testutil::TempDir;

    fn temp_root(label: &str) -> TempDir {
        TempDir::named(&format!("activity-{label}"))
    }

    /// A thread holding the exclusive lease must not be able to wait on
    /// itself by asking for a shared one; the error names the remedy.
    #[test]
    fn a_shared_request_under_this_thread_s_exclusive_lease_is_an_error() {
        let root = temp_root("no-self-wait");
        let exclusive = StoreActivity::acquire(&root.0, ActivityMode::Exclusive).unwrap();
        let error = StoreActivity::acquire(&root.0, ActivityMode::Shared).unwrap_err();
        assert!(
            error.to_string().contains("pass that lease"),
            "unexpected error: {error}"
        );
        drop(exclusive);
        // With the exclusive lease gone the same request succeeds.
        StoreActivity::acquire(&root.0, ActivityMode::Shared).unwrap();
    }

    /// `try_exclusive` answers "is this store in use?". A lease held by the
    /// asking thread is still use, so the answer is busy, not an error.
    #[test]
    fn try_exclusive_reports_busy_rather_than_failing_under_our_own_lease() {
        let root = temp_root("busy-not-error");
        let shared = StoreActivity::acquire(&root.0, ActivityMode::Shared).unwrap();
        assert!(StoreActivity::try_exclusive(&root.0).unwrap().is_none());
        drop(shared);
        assert!(StoreActivity::try_exclusive(&root.0).unwrap().is_some());
    }

    /// The blocking form of the same mistake is unsatisfiable and must say so
    /// instead of deadlocking.
    #[test]
    fn a_blocking_upgrade_of_a_held_shared_lease_is_rejected() {
        let root = temp_root("no-upgrade");
        let _shared = StoreActivity::acquire(&root.0, ActivityMode::Shared).unwrap();
        let error = StoreActivity::acquire(&root.0, ActivityMode::Exclusive).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    /// Independent shared leases coexist; a lease for one store never
    /// satisfies a check for another.
    #[test]
    fn independent_shared_leases_coexist_and_stay_bound_to_their_store() {
        let first = temp_root("store-a");
        let second = temp_root("store-b");
        let a = StoreActivity::acquire(&first.0, ActivityMode::Shared).unwrap();
        let b = StoreActivity::acquire(&second.0, ActivityMode::Shared).unwrap();
        assert_eq!(a.root(), first.0.as_path());
        assert_eq!(b.root(), second.0.as_path());
        assert!(StoreActivity::try_exclusive(&first.0).unwrap().is_none());
        drop(a);
        assert!(StoreActivity::try_exclusive(&first.0).unwrap().is_some());
        // The other store was never affected.
        assert!(StoreActivity::try_exclusive(&second.0).unwrap().is_none());
        drop(b);
    }
}
