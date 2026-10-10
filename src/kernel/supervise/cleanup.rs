//! Signal ownership across a resolver client and mandatory cleanup.

use super::*;

#[derive(Clone, Copy)]
struct CleanupStart {
    owner: u64,
    cursors: [u32; 4],
}

thread_local! {
    // Nested client sessions inherit cancellation since the enclosing
    // cleanup scope began, including its registration-to-spawn interval.
    static CLEANUP_START: Cell<Option<CleanupStart>> = const { Cell::new(None) };
}

pub(super) fn inherit_start(session: &mut Session) {
    CLEANUP_START.with(|start| {
        if let Some(CleanupStart {
            owner,
            cursors: [term, int, hup, quit],
        }) = start.get()
        {
            session.cleanup_owner = Some(owner);
            session.term_cursor.set(term);
            session.int_cursor.set(int);
            session.hup_cursor.set(hup);
            session.quit_cursor.set(quit);
        }
    });
}

impl Session {
    pub(super) fn finish_with_handled_cleanup(&mut self, cleanup_handled: bool) -> u32 {
        if !self.active {
            return 0;
        }
        self.active = false;
        self.clear_child();
        self.reconcile();
        let mut registry = registry();
        if !cleanup_handled && self.unconsumed_terms.get() != 0 {
            registry.term_orphaned.push(self.cleanup_owner);
        }
        pause_boundary("before-deregister");
        let packed = SESSION_TERM.fetch_sub(ONE_SESSION, Ordering::SeqCst);
        let unseen = term_count(packed) != self.term_cursor.get();
        if unseen {
            if !cleanup_handled {
                registry.term_orphaned.push(self.cleanup_owner);
            }
            self.received
                .set(self.received.get() | signal_bit(libc::SIGTERM));
        }
        for (counter, cursor, signal) in [
            (&SESSION_INT, &self.int_cursor, libc::SIGINT),
            (&SESSION_HUP, &self.hup_cursor, libc::SIGHUP),
            (&SESSION_QUIT, &self.quit_cursor, libc::SIGQUIT),
        ] {
            let previous = counter.fetch_sub(ONE_SESSION, Ordering::SeqCst);
            if term_count(previous) != cursor.get() {
                self.received.set(self.received.get() | signal_bit(signal));
            }
        }
        // This scope has completed mandatory cleanup for every signal it
        // observed. Even orphaned cancellation from a nested client/drain
        // session is now handled as an interruption, rather than re-raised.
        if cleanup_handled {
            registry
                .term_orphaned
                .retain(|owner| *owner != self.cleanup_owner);
        }
        let mut reraise = false;
        if live_sessions(packed) == 1 {
            reraise = !registry.term_orphaned.is_empty() || (!cleanup_handled && unseen);
            registry.term_orphaned.clear();
        }
        if reraise {
            pause_boundary("before-reraise");
            // Keep admission closed until inherited delivery. When the caller
            // blocks TERM, RERAISE_THREAD keeps later registrations closed even
            // after raise returns, without changing that caller's signal mask.
            // SAFETY: pthread_self and raise are valid on this live thread.
            RERAISE_THREAD.store(unsafe { libc::pthread_self() } as usize, Ordering::SeqCst);
            unsafe { libc::raise(libc::SIGTERM) };
        }
        drop(registry);
        self.received.get()
    }
}

/// Keep cancellation caught continuously across a supervised client and its
/// mandatory bounded cleanup. Cleanup may start after cancellation. It must
/// not forward signals to its own isolated process group. Ordinary sessions
/// retain their existing orphan-signal behavior.
pub(crate) fn during_cleanup<T>(work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    use std::os::unix::process::ExitStatusExt as _;
    struct Restore(Option<CleanupStart>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CLEANUP_START.with(|start| start.set(self.0));
        }
    }
    let mut session = Session::new()?;
    session.reject_pending_before_spawn()?;
    static NEXT_CLEANUP: AtomicU64 = AtomicU64::new(1);
    let owner = NEXT_CLEANUP.fetch_add(1, Ordering::Relaxed);
    session.cleanup_owner = Some(owner);
    let _restore = Restore(CLEANUP_START.with(|start| {
        start.replace(Some(CleanupStart {
            owner,
            cursors: [
                session.term_cursor.get(),
                session.int_cursor.get(),
                session.hup_cursor.get(),
                session.quit_cursor.get(),
            ],
        }))
    }));
    let result = work();
    let signal = record_stop(session.finish_with_handled_cleanup(true));
    match (result, signal) {
        (Err(error), _) => Err(error),
        (Ok(_), Some(signal)) => Err(io::Error::new(
            io::ErrorKind::Interrupted,
            Interrupted {
                signal,
                status: ExitStatus::from_raw(signal),
            },
        )),
        (Ok(value), None) => Ok(value),
    }
}
