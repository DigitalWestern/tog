//! Common child-process waiting for store-consuming commands.
//!
//! The supervisor is deliberately small, but it owns the complete spawn-to-
//! reap interval. A process-directed TERM is delivered to a self-pipe by an
//! async-signal-safe handler and forwarded by the ordinary Rust event loop to
//! the live direct child. INT/QUIT/HUP are observed so the parent waits and
//! restores its dispositions, while terminal process-group delivery remains
//! the mechanism that reaches the child for those signals.
//!
//! Any of those four arriving while a child runs is a request to stop tog,
//! not a verdict on the child: once the child is reaped, `status`,
//! `status_with_stderr` and `output` return an [`io::ErrorKind::Interrupted`]
//! error carrying [`Interrupted`] instead of the child's status. A caller
//! that turns a child's failure into something softer (a recorded policy
//! exception, a fallback) must let that kind through as an error.
//!
//! The three primitives are unrestricted, so clippy refuses them outside
//! the reviewed kernel sites (`clippy.toml`). Everything else starts a
//! child through `local_status`, `local_status_with_stderr` or
//! `local_output`, which refuse a dependency tool (it goes through
//! `kernel::resolve`'s door).

/// Serializes tests that supervise a child process.
///
/// A single process-wide signal session owns the temporary dispositions and
/// the child-pid slot, so `status`/`output` reject a second concurrent child
/// in the same process rather than waiting for the first (see the session
/// lock below). Production paths run their children sequentially under one
/// lease, but the unit-test harness runs tests in parallel threads inside one
/// binary, so any test that realizes an object through a child must hold this
/// guard. Same convention, and same reason, as `store::STORE_ENV_LOCK`.
///
/// Poison is ignored deliberately: one panicking test must not cascade into
/// every other holder.
#[cfg(test)]
pub(crate) static SUPERVISION_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use crate::kernel::activity::StoreActivity;
use crate::kernel::resolve::confine;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

const SIGNAL_COUNT: usize = 5;
const SIGNALS: [libc::c_int; SIGNAL_COUNT] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    // SIGCHLD wakes the supervisor: it carries no forwarding semantics, it
    // only makes the wait event-driven instead of a timer. Unlike the other
    // signals here it is handled even when inherited as SIG_IGN, because an
    // ignored SIGCHLD makes the kernel auto-reap the child and its exit
    // status is lost (`Session::install`). A SIGCHLD blocked by the
    // inherited mask still cannot reach the handler; `child_events` records
    // that, and the wait falls back to a timeout then.
    libc::SIGCHLD,
];

static SESSION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static NOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);
/// TERMs not yet forwarded to the child; `forward_pending` consumes it.
static TERM_COUNT: AtomicU32 = AtomicU32::new(0);
/// Every terminating signal the session has caught, one bit each (see
/// `signal_bit`). Unlike `TERM_COUNT`, forwarding never clears it, so it
/// still says after the reap that tog was asked to stop.
static RECEIVED: AtomicU32 = AtomicU32::new(0);
/// Set by the SIGCHLD handler and cleared only by the waiter. This is
/// deliberately **not** the self-pipe byte: `forward_pending` drains the pipe
/// between `try_wait` and the poll, so a notification that lived only in the
/// pipe could be swallowed there and leave an infinite poll with nothing left
/// to wake it. The flag survives that drain.
static CHILD_EVENT: AtomicBool = AtomicBool::new(false);
static SIGNAL_BYTE: u8 = 1;

fn session_lock() -> &'static Mutex<()> {
    SESSION_LOCK.get_or_init(|| Mutex::new(()))
}

/// The terminating signals in the order an error names them when more than
/// one arrived: the interrupt a person typed first.
const TERMINATING: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

fn signal_bit(signal: libc::c_int) -> u32 {
    match signal {
        libc::SIGINT => 1,
        libc::SIGHUP => 2,
        libc::SIGQUIT => 4,
        libc::SIGTERM => 8,
        _ => 0,
    }
}

fn signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGINT => "SIGINT",
        libc::SIGTERM => "SIGTERM",
        libc::SIGHUP => "SIGHUP",
        libc::SIGQUIT => "SIGQUIT",
        _ => "a signal",
    }
}

/// Why a supervised call returned [`io::ErrorKind::Interrupted`]: tog itself
/// received `signal` while the child ran. `status` is how the child ended,
/// kept for callers whose own exit code is the child's (`tog run`), where the
/// child decides what an interrupt means.
#[derive(Debug)]
pub struct Interrupted {
    pub signal: libc::c_int,
    pub status: ExitStatus,
}

impl std::fmt::Display for Interrupted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "interrupted by {} (the command it was running ended with {})",
            signal_name(self.signal),
            self.status
        )
    }
}

impl std::error::Error for Interrupted {}

/// The [`Interrupted`] record inside `error`, when it is the one a
/// supervised call returned. Wrapping the error in a new message keeps the
/// kind but drops the record, so callers that need the status look first.
pub fn interrupted(error: &io::Error) -> Option<&Interrupted> {
    error.get_ref()?.downcast_ref::<Interrupted>()
}

/// The child's status even when tog was interrupted while it ran, for
/// commands whose exit code is the child's (`tog run`, `tog x`). The
/// interrupt reached the child through the terminal or by forwarding, and
/// how the child chose to end is then the answer. Every other error passes
/// through unchanged.
pub fn child_status(result: io::Result<ExitStatus>) -> io::Result<ExitStatus> {
    match result {
        Err(error) => match interrupted(&error) {
            Some(interrupted) => Ok(interrupted.status),
            None => Err(error),
        },
        ok => ok,
    }
}

fn errno_location() -> *mut libc::c_int {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: libc returns the calling thread's errno slot.
        unsafe { libc::__errno_location() }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: libc returns the calling thread's errno slot.
        unsafe { libc::__error() }
    }
}

/// Only atomics, a raw write, and errno preservation are permitted here.
extern "C" fn signal_handler(signal: libc::c_int) {
    // SAFETY: errno_location points at this signal-handler thread's errno.
    let saved_errno = unsafe { *errno_location() };
    match signal {
        libc::SIGTERM => {
            TERM_COUNT.fetch_add(1, Ordering::SeqCst);
            RECEIVED.fetch_or(signal_bit(signal), Ordering::SeqCst);
        }
        libc::SIGINT | libc::SIGHUP | libc::SIGQUIT => {
            RECEIVED.fetch_or(signal_bit(signal), Ordering::SeqCst);
        }
        libc::SIGCHLD => {
            CHILD_EVENT.store(true, Ordering::SeqCst);
        }
        _ => {}
    }
    let fd = NOTIFY_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        // SAFETY: SIGNAL_BYTE is a process-lifetime one-byte buffer and fd is
        // published only after the self-pipe has been created. O_NONBLOCK
        // makes a full pipe a harmless coalescing case; the atomics retain
        // the notification in that event.
        unsafe {
            let _ = libc::write(fd, &SIGNAL_BYTE as *const u8 as *const libc::c_void, 1);
        }
    }
    // SAFETY: restore the interrupted thread's errno exactly as found.
    unsafe { *errno_location() = saved_errno };
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl operates on the caller-owned descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl operates on the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl operates on the caller-owned descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn pipe_pair() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    // SAFETY: fds points to two writable c_int slots for libc to initialize.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for fd in fds {
        if let Err(error) = set_cloexec(fd).and_then(|_| set_nonblocking(fd)) {
            // SAFETY: both descriptors were returned by pipe and remain owned
            // by this setup path.
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(error);
        }
    }
    Ok((fds[0], fds[1]))
}

fn close_fd(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: the descriptor is owned by the session.
        unsafe {
            libc::close(fd);
        }
    }
}

struct SavedSignal {
    number: libc::c_int,
    action: libc::sigaction,
    installed: bool,
}

/// One serialized process-local signal session. A separate Tog process
/// has its own session, so this only serializes concurrent sessions within
/// one process.
struct Session {
    _serial: MutexGuard<'static, ()>,
    read_fd: RawFd,
    write_fd: RawFd,
    old_actions: Vec<SavedSignal>,
    old_mask: libc::sigset_t,
    old_mask_saved: bool,
    /// True only when a SIGCHLD handler was actually installed for this
    /// session and SIGCHLD is not blocked by the mask the parent restores.
    /// When false the child transition cannot reach the self-pipe, so the
    /// wait keeps a timeout rather than blocking forever.
    child_events: bool,
    active: bool,
}

impl Session {
    fn new() -> io::Result<Self> {
        // A single process-wide signal session owns the temporary signal
        // dispositions and child-pid slot, so only one child in this process
        // can be supervised at a time. Report that as busy rather than
        // waiting for it. Independent operations must not queue behind a
        // process-global mutex, and contention across the store's locks is
        // always a named outcome: an unbounded wait here would be
        // the same silent self-deadlock shape as a shared helper called under
        // its own exclusive lease, with no error and no timeout to end it.
        // No production path supervises two children at once — every entry
        // point runs its children sequentially through one lease — so this
        // rejects a genuine programming error rather than a normal race.
        let serial = match session_lock().try_lock() {
            Ok(guard) => guard,
            // A poisoned session means a previous supervisor panicked. Its
            // dispositions were restored by `Drop` either way, so adopt the
            // guard instead of refusing every later child in the process.
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "another child is already being supervised in this process; \
                     supervision owns process-wide signal dispositions, so its \
                     children are run one at a time",
                ));
            }
        };
        let (read_fd, write_fd) = pipe_pair()?;
        let mut session = Self {
            _serial: serial,
            read_fd,
            write_fd,
            old_actions: Vec::with_capacity(SIGNAL_COUNT),
            // SAFETY: sigset_t is an opaque C value initialized by
            // sigprocmask below before it is read.
            old_mask: unsafe { std::mem::zeroed() },
            old_mask_saved: false,
            child_events: false,
            active: true,
        };
        if let Err(error) = session.install() {
            session.teardown();
            return Err(error);
        }
        Ok(session)
    }

    fn install(&mut self) -> io::Result<()> {
        // Query, rather than replace, the current mask. We do not change it
        // for the parent after teardown; saving it makes restoration
        // explicit. The temporary block closes the setup interval between
        // publishing the self-pipe and installing the handlers: a pending
        // signal is delivered to the new handler when the old mask is
        // restored below instead of hitting the old disposition or the
        // default action.
        // SAFETY: a null set asks libc to copy the current process mask into
        // the initialized output slot.
        if unsafe { libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut self.old_mask) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.old_mask_saved = true;

        // SAFETY: sigset_t is an opaque C value; sigemptyset initializes it
        // below before anything reads it.
        let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: libc initializes blocked's empty set.
        if unsafe { libc::sigemptyset(&mut blocked) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for number in SIGNALS {
            // SAFETY: blocked is a valid signal set.
            if unsafe { libc::sigaddset(&mut blocked, number) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: blocked is initialized and old_mask was saved above.
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }

        NOTIFY_FD.store(self.write_fd, Ordering::SeqCst);
        CHILD_PID.store(-1, Ordering::SeqCst);
        TERM_COUNT.store(0, Ordering::SeqCst);
        RECEIVED.store(0, Ordering::SeqCst);

        for number in SIGNALS {
            // SAFETY: zeroed is the conventional initialization for the
            // output sigaction which libc fills.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: number is one of the `SIGNALS` constants and old is a
            // writable output slot.
            if unsafe { libc::sigaction(number, std::ptr::null(), &mut old) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let ignored = old.sa_sigaction == libc::SIG_IGN;
            self.old_actions.push(SavedSignal {
                number,
                action: old,
                installed: false,
            });
            // An inherited SIG_IGN is kept for TERM/INT/HUP/QUIT: whoever
            // started tog asked for it not to be interrupted by them. SIGCHLD
            // is the exception. With SIGCHLD ignored (or SA_NOCLDWAIT set,
            // which the replacement below also clears) the kernel reaps the
            // child itself, `try_wait` fails with ECHILD, and the exit status
            // tog exists to report is gone. The handler replaces it for the
            // session only: `prepare_child` hands the child the inherited
            // SIG_IGN back and teardown restores the saved action. One
            // difference remains. While the handler is installed, any other
            // child of this process (say, spawned by another thread) that
            // exits without being waited for becomes a zombie instead of
            // being auto-reaped, and restoring SIG_IGN afterwards does not
            // reap it. The default disposition does exactly that to the
            // same child anyway, so this only makes the inherited-SIG_IGN
            // case behave like the default one during a session. Such a
            // zombie is cleared when tog exits, and production code waits
            // for every child it spawns.
            if ignored && number != libc::SIGCHLD {
                continue;
            }
            if number == libc::SIGCHLD {
                // SAFETY: old_mask was filled by sigprocmask above.
                let blocked_in_restored_mask =
                    unsafe { libc::sigismember(&self.old_mask, libc::SIGCHLD) } == 1;
                self.child_events = !blocked_in_restored_mask;
            }
            // SAFETY: zeroed is followed by sigemptyset and all fields used
            // by sigaction are initialized below.
            let mut replacement: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: replacement is writable and the call initializes its
            // signal mask.
            if unsafe { libc::sigemptyset(&mut replacement.sa_mask) } != 0 {
                return Err(io::Error::last_os_error());
            }
            replacement.sa_flags = 0;
            replacement.sa_sigaction = signal_handler as *const () as usize;
            // SAFETY: replacement contains a valid async-signal-safe handler.
            if unsafe { libc::sigaction(number, &replacement, std::ptr::null_mut()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            self.old_actions
                .last_mut()
                .expect("just pushed signal action")
                .installed = true;
        }
        // Unblock only after every non-ignored disposition is installed and
        // all global session state is initialized. A signal which arrived
        // during setup is now pending for the temporary handler and will be
        // observed by reject_pending_before_spawn or the first wait loop.
        // SAFETY: old_mask was captured before the temporary block.
        if unsafe { libc::sigprocmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut()) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn reject_pending_before_spawn(&self) -> io::Result<()> {
        self.drain_notifications();
        if RECEIVED.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancellation arrived before the child was spawned",
            ));
        }
        Ok(())
    }

    /// The child must never exec with the supervisor's temporary handlers or
    /// a caller's accidentally inherited blocked signal mask. Every signal
    /// goes back to what tog inherited: SIG_IGN stays ignored (including a
    /// SIGCHLD the session handled anyway), and anything else becomes
    /// SIG_DFL, which is what exec would make of an inherited handler. The
    /// post-fork hook is restricted to libc signal operations.
    fn prepare_child(&self, command: &mut Command) {
        let actions: Vec<(libc::c_int, bool)> = self
            .old_actions
            .iter()
            .map(|saved| (saved.number, saved.action.sa_sigaction == libc::SIG_IGN))
            .collect();
        let old_mask = self.old_mask;
        // SAFETY: the closure performs only async-signal-safe libc operations
        // in the post-fork child and owns all copied signal values.
        unsafe {
            command.pre_exec(move || {
                for (number, ignored) in &actions {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    if libc::sigemptyset(&mut action.sa_mask) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    action.sa_flags = 0;
                    action.sa_sigaction = if *ignored {
                        libc::SIG_IGN
                    } else {
                        libc::SIG_DFL
                    };
                    if libc::sigaction(*number, &action, std::ptr::null_mut()) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                if libc::sigprocmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    fn publish_child(&self, child: &Child) -> io::Result<()> {
        let pid = i32::try_from(child.id()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "child pid does not fit in the supervisor pid slot",
            )
        })?;
        if pid <= 0 {
            return Err(io::Error::other("child did not publish a positive pid"));
        }
        // Store the pid before inspecting pending signals. A TERM in the
        // fork/exec interval is therefore either rejected before spawn or
        // forwarded after this publication.
        CHILD_PID.store(pid, Ordering::SeqCst);
        self.forward_pending()
    }

    fn clear_child(&self) {
        CHILD_PID.store(-1, Ordering::SeqCst);
    }

    fn forward_pending(&self) -> io::Result<()> {
        self.drain_notifications();
        if TERM_COUNT.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
        // Read the pid slot before consuming the count. With no live child
        // the cancellation stays pending instead of being swallowed: the
        // next child published in this session still receives it, and a
        // reaped pid is never signalled.
        let pid = CHILD_PID.load(Ordering::SeqCst);
        if pid <= 0 {
            return Ok(());
        }
        let terms = TERM_COUNT.swap(0, Ordering::SeqCst);
        for _ in 0..terms {
            // SAFETY: pid was published from Child::id and remains positive.
            if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
                let error = io::Error::last_os_error();
                // A child that exited between try_wait and forwarding cannot
                // be replaced until it is reaped, so ESRCH is harmless.
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    fn wait_for_event(&self, output_fds: &[RawFd]) -> io::Result<()> {
        let mut descriptors = Vec::with_capacity(output_fds.len() + 1);
        descriptors.push(libc::pollfd {
            fd: self.read_fd,
            events: libc::POLLIN,
            revents: 0,
        });
        descriptors.extend(output_fds.iter().map(|fd| libc::pollfd {
            fd: *fd,
            events: libc::POLLIN,
            revents: 0,
        }));
        loop {
            // A child transition observed since the last check is a wakeup in
            // its own right. Consuming it here — before blocking — closes the
            // window where `forward_pending` drained the pipe byte after the
            // caller's `try_wait` said the child was still alive. Without this
            // the poll below would have nothing left to wake it.
            if CHILD_EVENT.swap(false, Ordering::SeqCst) {
                self.drain_notifications();
                return Ok(());
            }
            // SAFETY: descriptors points at a valid contiguous pollfd array.
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    // Block indefinitely when the child transition can reach
                    // the self-pipe: every event that matters writes it from
                    // the signal handler, so there is nothing left for a timer
                    // to discover. A signal arriving between the check above
                    // and this call still wakes it, because the handler writes
                    // the pipe after setting the flag and nothing drains it in
                    // between. When SIGCHLD is blocked by the inherited
                    // mask, no such wakeup exists and the former timeout is
                    // the only thing that would notice the exit, so keep it.
                    if self.child_events { -1 } else { 100 },
                )
            };
            if result >= 0 {
                self.drain_notifications();
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    fn drain_notifications(&self) {
        let mut bytes = [0u8; 64];
        loop {
            // SAFETY: bytes is a valid writable buffer and read_fd is the
            // session-owned nonblocking pipe end.
            let read = unsafe {
                libc::read(
                    self.read_fd,
                    bytes.as_mut_ptr() as *mut libc::c_void,
                    bytes.len(),
                )
            };
            if read > 0 {
                continue;
            }
            if read == 0 {
                return;
            }
            if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                return;
            }
            return;
        }
    }

    /// Restore everything the session changed and return the terminating
    /// signals it caught. The mask is read after the handlers are blocked,
    /// so a signal is either counted here or arrives once the inherited
    /// disposition is back and acts on tog itself; none falls between.
    fn teardown(&mut self) -> u32 {
        if !self.active {
            return 0;
        }
        // Prevent a signal from running the temporary handler while the
        // global pid/fd and dispositions are being dismantled.
        if self.old_mask_saved {
            // SAFETY: set is initialized before use and contains the
            // temporary handler signals.
            let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
            // SAFETY: libc initializes blocked's empty set.
            if unsafe { libc::sigemptyset(&mut blocked) } == 0 {
                for number in SIGNALS {
                    // SAFETY: blocked is a valid signal set.
                    unsafe {
                        libc::sigaddset(&mut blocked, number);
                    }
                }
                // SAFETY: blocked is valid; the old mask is already saved.
                unsafe {
                    libc::sigprocmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut());
                }
            }
        }
        self.clear_child();
        NOTIFY_FD.store(-1, Ordering::SeqCst);
        TERM_COUNT.store(0, Ordering::SeqCst);
        let received = RECEIVED.swap(0, Ordering::SeqCst);
        for saved in self.old_actions.iter().rev() {
            if saved.installed {
                // SAFETY: saved.action came from sigaction and is restored
                // for the same signal number.
                unsafe {
                    libc::sigaction(saved.number, &saved.action, std::ptr::null_mut());
                }
            }
        }
        if self.old_mask_saved {
            // SAFETY: old_mask came from sigprocmask and is restored verbatim.
            unsafe {
                libc::sigprocmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut());
            }
        }
        close_fd(self.read_fd);
        close_fd(self.write_fd);
        self.read_fd = -1;
        self.write_fd = -1;
        self.active = false;
        received
    }

    /// End the session for a reaped child: `value` when no terminating
    /// signal arrived, the interruption otherwise. A signal that arrives
    /// after a clean exit still counts, since it asked tog to stop too.
    fn conclude<T>(mut self, status: ExitStatus, value: T) -> io::Result<T> {
        let received = self.teardown();
        match TERMINATING
            .into_iter()
            .find(|signal| received & signal_bit(*signal) != 0)
        {
            Some(signal) => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                Interrupted { signal, status },
            )),
            None => Ok(value),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

fn wait(child: &mut Child) -> io::Result<ExitStatus> {
    loop {
        match child.wait() {
            Ok(status) => return Ok(status),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn reap_after_error(child: &mut Child) {
    let _ = child.kill();
    let _ = wait(child);
}

/// Spawn a command with inherited stdio and reap its direct child before
/// returning. The activity argument is borrowed for the whole interval so
/// the caller cannot accidentally end store protection before reaping.
// Reviewed site (tests/architecture.rs): the supervisor itself: spawns under the caller's lease.
#[allow(clippy::disallowed_methods)]
pub fn status(command: &mut Command, activity: &StoreActivity) -> io::Result<ExitStatus> {
    let _ = activity.mode();
    let session = Session::new()?;
    session.reject_pending_before_spawn()?;
    session.prepare_child(command);
    let mut child = command.spawn()?;
    if let Err(error) = session.publish_child(&child) {
        reap_after_error(&mut child);
        return Err(error);
    }
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                session.clear_child();
                return session.conclude(status, status);
            }
            Ok(None) => {}
            Err(error) => {
                reap_after_error(&mut child);
                return Err(error);
            }
        }
        if let Err(error) = session.forward_pending() {
            reap_after_error(&mut child);
            return Err(error);
        }
        if let Err(error) = session.wait_for_event(&[]) {
            reap_after_error(&mut child);
            return Err(error);
        }
    }
}

/// Spawn a command with stdout and stderr piped, drain both while the child
/// runs, and reap the direct child before returning.  Sandbox engines use
/// this form so their setup diagnostics can still be classified without
/// putting a large build log behind a pipe that the child could fill. The
/// returned stderr is bounded to the same prefix used by the sandbox
/// classifier; every byte of both is relayed to the caller's matching
/// stream through a [`Relay`], the signing key's secret replaced.
// Reviewed site (tests/architecture.rs): the supervisor itself: spawns under the caller's lease.
#[allow(clippy::disallowed_methods)]
pub fn status_with_stderr(
    command: &mut Command,
    activity: &StoreActivity,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    let _ = activity.mode();
    let session = Session::new()?;
    session.reject_pending_before_spawn()?;
    session.prepare_child(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Err(error) = session.publish_child(&child) {
        reap_after_error(&mut child);
        return Err(error);
    }
    let mut stderr = child.stderr.take();
    let mut stdout = child.stdout.take();
    for fd in [
        stderr.as_ref().map(AsRawFd::as_raw_fd),
        stdout.as_ref().map(AsRawFd::as_raw_fd),
    ]
    .into_iter()
    .flatten()
    {
        if let Err(error) = set_nonblocking(fd) {
            reap_after_error(&mut child);
            return Err(error);
        }
    }
    let mut stderr_bytes = Vec::new();
    let mut stderr_relay = Relay::new(RelayTo::Stderr);
    let mut stdout_relay = Relay::new(RelayTo::Stdout);
    let mut status = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(next) => {
                    if next.is_some() {
                        // The direct child is reaped. Clear the pid slot now,
                        // not at return: this loop keeps running while the
                        // pipes drain, and a forwarded signal must never
                        // reach a reaped — possibly recycled — pid.
                        session.clear_child();
                    }
                    status = next;
                }
                Err(error) => {
                    reap_after_error(&mut child);
                    return Err(error);
                }
            }
        }
        let drained = drain_relayed(&mut stderr, Some(&mut stderr_bytes), &mut stderr_relay)
            .and_then(|stderr_eof| {
                drain_relayed(&mut stdout, None, &mut stdout_relay)
                    .map(|stdout_eof| (stderr_eof, stdout_eof))
            });
        let (stderr_eof, stdout_eof) = match drained {
            Ok(eofs) => eofs,
            Err(error) => {
                reap_after_error(&mut child);
                return Err(error);
            }
        };
        if stderr_eof {
            stderr = None;
        }
        if stdout_eof {
            stdout = None;
        }
        if let Some(status) = status {
            if stderr.is_none() && stdout.is_none() {
                session.clear_child();
                return session.conclude(status, (status, stderr_bytes));
            }
        }
        if let Err(error) = session.forward_pending() {
            reap_after_error(&mut child);
            return Err(error);
        }
        let output_fds: Vec<RawFd> = [
            stderr.as_ref().map(AsRawFd::as_raw_fd),
            stdout.as_ref().map(AsRawFd::as_raw_fd),
        ]
        .into_iter()
        .flatten()
        .collect();
        if let Err(error) = session.wait_for_event(&output_fds) {
            reap_after_error(&mut child);
            return Err(error);
        }
    }
}

/// Where a [`Relay`] writes.
#[derive(Clone, Copy)]
enum RelayTo {
    Stdout,
    Stderr,
    /// Into `Relay::captured`, for tests.
    #[cfg(test)]
    Captured,
}

/// A child's output passed on to one of tog's own streams with the signing
/// key's secret replaced: a tool's parse error quotes the line it failed
/// on, and a project file can be the key under another name. Output is
/// passed on a line at a time (a newline or a carriage return ends one), so
/// a secret is whole when it is checked however the child's writes were
/// cut, and each line is held until the next one arrives or the child goes
/// quiet, so a secret broken across two lines is checked as one
/// ([`confine::redaction_mask`]). With no signing key there is nothing to
/// replace and every byte is passed on as it arrives.
struct Relay {
    to: RelayTo,
    secrets: &'static [Vec<u8>],
    /// Bytes of a line not yet ended.
    pending: Vec<u8>,
    /// The last whole line, with what is already known to be secret.
    held: Vec<u8>,
    held_mask: Vec<bool>,
    #[cfg(test)]
    captured: Vec<u8>,
}

/// A line longer than this is passed on in pieces rather than held.
const RELAY_LINE_MAX: usize = 64 * 1024;

impl Relay {
    fn new(to: RelayTo) -> Relay {
        Relay::with_secrets(to, confine::signing_key_secrets())
    }

    fn with_secrets(to: RelayTo, secrets: &'static [Vec<u8>]) -> Relay {
        Relay {
            to,
            secrets,
            pending: Vec::new(),
            held: Vec::new(),
            held_mask: Vec::new(),
            #[cfg(test)]
            captured: Vec::new(),
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match self.to {
            #[cfg(test)]
            RelayTo::Captured => self.captured.extend_from_slice(bytes),
            RelayTo::Stdout => {
                let mut out = io::stdout().lock();
                let _ = out.write_all(bytes);
                let _ = out.flush();
            }
            RelayTo::Stderr => {
                let _ = io::stderr().write_all(bytes);
            }
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        if self.secrets.is_empty() {
            self.write(bytes);
            return;
        }
        self.pending.extend_from_slice(bytes);
        while let Some(end) = self.pending.iter().position(|b| matches!(b, b'\n' | b'\r')) {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            self.line(line);
        }
        if self.pending.len() > RELAY_LINE_MAX {
            let piece = std::mem::take(&mut self.pending);
            self.line(piece);
        }
    }

    /// Check `line` together with the held one, pass the held one on, and
    /// hold `line`.
    fn line(&mut self, line: Vec<u8>) {
        let mut joined = std::mem::take(&mut self.held);
        let split = joined.len();
        joined.extend_from_slice(&line);
        let mut mask = confine::redaction_mask(&joined, self.secrets);
        for (bit, known) in mask.iter_mut().zip(&self.held_mask) {
            *bit |= known;
        }
        self.write(&confine::redact(&joined[..split], &mask[..split]));
        self.held = line;
        self.held_mask = mask[split..].to_vec();
    }

    /// The child is quiet: pass the held line on.
    fn idle(&mut self) {
        let held = std::mem::take(&mut self.held);
        let mask = std::mem::take(&mut self.held_mask);
        self.write(&confine::redact(&held, &mask));
    }

    /// The child closed its end: pass everything on.
    fn finish(&mut self) {
        if !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            self.line(rest);
        }
        self.idle();
    }
}

/// Read what `reader` has now into `relay` (and the first 4 KiB into
/// `destination`, the sandbox classifier's prefix). Returns whether the
/// child closed it.
fn drain_relayed<R: Read>(
    reader: &mut Option<R>,
    mut destination: Option<&mut Vec<u8>>,
    relay: &mut Relay,
) -> io::Result<bool> {
    let Some(reader) = reader else {
        return Ok(true);
    };
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                relay.finish();
                return Ok(true);
            }
            Ok(count) => {
                if let Some(destination) = destination.as_deref_mut() {
                    let keep = count.min(4096usize.saturating_sub(destination.len()));
                    destination.extend_from_slice(&buffer[..keep]);
                }
                relay.push(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                relay.idle();
                return Ok(false);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn drain<R: Read>(reader: &mut Option<R>, destination: &mut Vec<u8>) -> io::Result<bool> {
    let Some(reader) = reader else {
        return Ok(false);
    };
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                return Ok(true);
            }
            Ok(count) => destination.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

/// Spawn a command, drain captured stdout/stderr without waiting on a full
/// pipe, and reap its direct child before returning.
// Reviewed site (tests/architecture.rs): the supervisor itself: spawns under the caller's lease.
#[allow(clippy::disallowed_methods)]
pub fn output(command: &mut Command, activity: &StoreActivity) -> io::Result<Output> {
    let _ = activity.mode();
    let session = Session::new()?;
    session.reject_pending_before_spawn()?;
    session.prepare_child(command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let Err(error) = session.publish_child(&child) {
        reap_after_error(&mut child);
        return Err(error);
    }
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    if let Some(pipe) = stdout.as_ref() {
        if let Err(error) = set_nonblocking(pipe.as_raw_fd()) {
            reap_after_error(&mut child);
            return Err(error);
        }
    }
    if let Some(pipe) = stderr.as_ref() {
        if let Err(error) = set_nonblocking(pipe.as_raw_fd()) {
            reap_after_error(&mut child);
            return Err(error);
        }
    }
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut status = None;
    loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(next) => {
                    if next.is_some() {
                        // The direct child is reaped. Clear the pid slot now,
                        // not at return: this loop keeps running while the
                        // pipes drain, and a forwarded signal must never
                        // reach a reaped — possibly recycled — pid.
                        session.clear_child();
                    }
                    status = next;
                }
                Err(error) => {
                    reap_after_error(&mut child);
                    return Err(error);
                }
            }
        }
        let stdout_eof = match drain(&mut stdout, &mut stdout_bytes) {
            Ok(eof) => eof,
            Err(error) => {
                reap_after_error(&mut child);
                return Err(error);
            }
        };
        let stderr_eof = match drain(&mut stderr, &mut stderr_bytes) {
            Ok(eof) => eof,
            Err(error) => {
                reap_after_error(&mut child);
                return Err(error);
            }
        };
        if stdout_eof {
            stdout = None;
        }
        if stderr_eof {
            stderr = None;
        }
        if let Some(status) = status {
            if stdout.is_none() && stderr.is_none() {
                session.clear_child();
                return session.conclude(
                    status,
                    Output {
                        status,
                        stdout: stdout_bytes,
                        stderr: stderr_bytes,
                    },
                );
            }
        }
        if let Err(error) = session.forward_pending() {
            reap_after_error(&mut child);
            return Err(error);
        }
        let mut output_fds = Vec::with_capacity(2);
        if let Some(pipe) = stdout.as_ref() {
            output_fds.push(pipe.as_raw_fd());
        }
        if let Some(pipe) = stderr.as_ref() {
            output_fds.push(pipe.as_raw_fd());
        }
        if let Err(error) = session.wait_for_event(&output_fds) {
            reap_after_error(&mut child);
            return Err(error);
        }
    }
}

/// [`status`] for a host-local helper: a child that needs no network
/// (`cp`, `patch`, an offline extraction). A dependency tool is refused
/// unless its argv is one of the reviewed offline forms
/// (`kernel::resolve::tripwire`); it starts through `kernel::resolve`'s
/// door instead. Nothing is spawned for a refused command.
// Reviewed site (tests/architecture.rs): the supervisor itself: a helper that passed the tripwire.
#[allow(clippy::disallowed_methods)]
pub fn local_status(command: &mut Command, activity: &StoreActivity) -> io::Result<ExitStatus> {
    refuse_resolver(command, activity)?;
    status(command, activity)
}

/// [`status_with_stderr`] for a host-local helper; refuses a dependency
/// tool as [`local_status`] does.
// Reviewed site (tests/architecture.rs): the supervisor itself: a helper that passed the tripwire.
#[allow(clippy::disallowed_methods)]
pub fn local_status_with_stderr(
    command: &mut Command,
    activity: &StoreActivity,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    refuse_resolver(command, activity)?;
    status_with_stderr(command, activity)
}

/// [`output`] for a host-local helper; refuses a dependency tool as
/// [`local_status`] does.
// Reviewed site (tests/architecture.rs): the supervisor itself: a helper that passed the tripwire.
#[allow(clippy::disallowed_methods)]
pub fn local_output(command: &mut Command, activity: &StoreActivity) -> io::Result<Output> {
    refuse_resolver(command, activity)?;
    output(command, activity)
}

fn refuse_resolver(command: &Command, activity: &StoreActivity) -> io::Result<()> {
    match crate::kernel::resolve::tripwire::refusal(command, activity.root()) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::store::Store;
    use crate::kernel::testutil::TempDir;
    use std::path::Path;
    use std::sync::Mutex;

    static TEST_SESSION: Mutex<()> = Mutex::new(());

    fn test_store(label: &str) -> (Store, TempDir) {
        let dir = TempDir::named(&format!("supervise-{label}"));
        let root = dir.0.clone();
        for sub in [
            "objects",
            "meta",
            "cache/sha1",
            "cache/sha256",
            "cache/sha512",
            "tmp",
            "roots",
            "forests",
            "backups",
            "root-locks",
        ] {
            std::fs::create_dir_all(root.join(sub)).unwrap();
        }
        (Store { root }, dir)
    }

    // Reviewed site (tests/architecture.rs): the supervisor's own tests of its primitives.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn status_preserves_a_numeric_exit_across_sequential_children() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _test_session = TEST_SESSION.lock().unwrap();
        let (store, _root) = test_store("status");
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 42"]);
        assert_eq!(status(&mut command, &activity).unwrap().code(), Some(42));
        let mut second = Command::new("/bin/sh");
        second.args(["-c", "exit 0"]);
        assert!(status(&mut second, &activity).unwrap().success());
        drop(activity);
    }

    /// Every `local_*` form refuses a dependency tool before spawning it,
    /// naming the program and the door, and lets a plain helper through to
    /// the supervisor.
    #[test]
    fn local_supervise_refuses_resolver_programs() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _test_session = TEST_SESSION.lock().unwrap();
        let (store, _root) = test_store("local");
        let activity = store.activity(ActivityMode::Shared).unwrap();
        // The resolver named by a path that does not exist: had it been
        // spawned, the error would be NotFound, not the refusal.
        let resolver = || {
            let mut command = Command::new("/nonexistent/tog-test/bin/npm");
            command.args(["install", "--package-lock-only"]);
            command
        };
        let refusals = [
            local_status(&mut resolver(), &activity).unwrap_err(),
            local_status_with_stderr(&mut resolver(), &activity).unwrap_err(),
            local_output(&mut resolver(), &activity).unwrap_err(),
        ];
        for error in refusals {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            let message = error.to_string();
            assert!(message.contains("npm"), "{message}");
            assert!(message.contains("kernel::resolve"), "{message}");
        }
        // No cargo runs on the host: the workspace lookup it once ran is
        // refused unspawned, the store's own Cargo included.
        let lookup = |program: &Path| {
            let mut command = Command::new(program);
            command
                .args([
                    "locate-project",
                    "--workspace",
                    "--message-format",
                    "plain",
                    "--offline",
                ])
                .env_remove("RUSTUP_HOME")
                .env_remove("RUSTUP_TOOLCHAIN");
            command
        };
        let host = local_output(
            &mut lookup(Path::new("/nonexistent/tog-test/bin/cargo")),
            &activity,
        );
        assert_eq!(host.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let cargo = crate::kernel::testutil::store_program(&store.root, "objects/rust/bin/cargo");
        let store_cargo = local_output(&mut lookup(&cargo), &activity);
        assert_eq!(
            store_cargo.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut helper = Command::new("/bin/sh");
        helper.args(["-c", "exit 3"]);
        assert_eq!(
            local_status(&mut helper, &activity).unwrap().code(),
            Some(3)
        );
        drop(activity);
    }

    /// The relay replaces the signing key's secret however the child's
    /// writes were cut and when a line break splits it, and passes every
    /// other byte on unchanged, in order.
    #[test]
    fn the_relay_replaces_the_key_however_the_output_is_cut() {
        const SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        static SECRETS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
        let secrets = SECRETS.get_or_init(|| vec![SEED.as_bytes().to_vec()]);
        let relayed = |pieces: &[&[u8]], idle_between: bool| {
            let mut relay = Relay::with_secrets(RelayTo::Captured, secrets);
            for piece in pieces {
                relay.push(piece);
                if idle_between {
                    relay.idle();
                }
            }
            relay.finish();
            String::from_utf8(relay.captured).unwrap()
        };
        let message = format!("error: bad TOML\n1 | ed25519:{SEED}\n  |\nmore\n");
        let bytes = message.as_bytes();
        // Cut inside the secret, across two reads.
        let out = relayed(&[&bytes[..30], &bytes[30..]], false);
        assert!(!out.contains("33445566"), "{out}");
        assert_eq!(
            out,
            "error: bad TOML\n1 | ed25519:[signing key redacted]\n  |\nmore\n"
        );
        // Cut into single bytes, the child going quiet after each.
        let singles: Vec<&[u8]> = bytes.chunks(1).collect();
        assert_eq!(relayed(&singles, true), out);
        // Split across two lines with a short tail, written at once.
        let split = format!("1 | {}\n  | {}\nend", &SEED[..58], &SEED[58..]);
        let out = relayed(&[split.as_bytes()], false);
        assert_eq!(
            out,
            "1 | [signing key redacted]\n  | [signing key redacted]\nend"
        );
        // Without a key every byte passes as it is.
        let mut plain = Relay::with_secrets(RelayTo::Captured, &[]);
        plain.push(b"partial line, no newline");
        assert_eq!(plain.captured, b"partial line, no newline");
    }

    // Reviewed site (tests/architecture.rs): the supervisor's own tests of its primitives.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn output_drains_both_pipes_before_reaping() {
        let _supervision = crate::kernel::supervise::SUPERVISION_TEST_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _test_session = TEST_SESSION.lock().unwrap();
        let (store, _root) = test_store("output");
        let activity = store.activity(ActivityMode::Shared).unwrap();
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "dd if=/dev/zero bs=131072 count=1 2>/dev/null; printf stderr >&2",
        ]);
        let result = output(&mut command, &activity).unwrap();
        assert_eq!(result.stdout.len(), 131072);
        assert_eq!(result.stderr, b"stderr");
        drop(activity);
    }
}
