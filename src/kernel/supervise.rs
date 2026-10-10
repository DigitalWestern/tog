//! Common child-process waiting for store-consuming commands.
//!
//! The supervisor is deliberately small, but it owns the complete spawn-to-
//! reap interval. A process-directed TERM is counted by an async-signal-safe
//! handler and forwarded by the ordinary Rust event loop to the live direct
//! child. INT/QUIT/HUP are observed so the parent waits for its child,
//! while terminal process-group delivery remains the mechanism that reaches
//! the child for those signals.
//!
//! Any of those four arriving while a child runs is a request to stop tog,
//! not a verdict on the child: once the child is reaped, `status`,
//! `status_with_stderr` and `output` return an [`io::ErrorKind::Interrupted`]
//! error carrying [`Interrupted`] instead of the child's status. A caller
//! that turns a child's failure into something softer (a recorded policy
//! exception, a fallback) must let that kind through as an error.
//!
//! Each call is its own signal session, and any number of them may run at
//! once on different threads. `sigaction` is process-wide, so sessions do
//! not own the dispositions: the first session in the process installs one
//! handler per signal and it stays for the life of the process. The handler
//! counts each signal, and with no session live it acts as the disposition
//! tog inherited would have (`act_as_inherited`), so outside supervision a
//! TERM still kills tog. Every live session sees every TERM and forwards it
//! to its own child. Correctness never depends on a wakeup: the counts live
//! in atomics, a self-pipe only shortens the wait, and the wait is bounded
//! by a short tick (`tick_ms`). Design: `docs/human/ARCHITECTURE.md` "Store
//! concurrency" and the history in #57.
//!
//! The three primitives are unrestricted, so clippy refuses them outside
//! the reviewed kernel sites (`clippy.toml`). Everything else starts a
//! child through `local_status`, `local_status_with_stderr` or
//! `local_output`, which refuse a dependency tool (it goes through
//! `kernel::resolve`'s door).

mod cleanup;
mod pipes;
pub(crate) use cleanup::during_cleanup;

use crate::kernel::activity::StoreActivity;
use crate::kernel::resolve::confine;
use pipes::{drain, note_abandoned_output, wait_readable, DRAIN_AFTER_EXIT};
use std::cell::{Cell, UnsafeCell};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

const SIGNAL_COUNT: usize = 5;
const SIGNALS: [libc::c_int; SIGNAL_COUNT] = [
    libc::SIGTERM,
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    // SIGCHLD wakes a supervisor: it carries no forwarding semantics, it
    // only shortens the wait. Unlike the other signals here it is handled
    // even when inherited as SIG_IGN, because an ignored SIGCHLD makes the
    // kernel auto-reap the child and its exit status is lost
    // (`install_handlers`). A SIGCHLD blocked by the mask still cannot
    // reach the handler; the tick bounds the wait then.
    libc::SIGCHLD,
];

/// One live session, in [`SESSION_TERM`]'s high half.
const ONE_SESSION: u64 = 1 << 32;
/// The high 32 bits count live sessions; the low 32 bits count TERMs
/// received (wrapping: only differences are used). Packing both into one
/// atomic makes the handler's question "was any session live?" and its
/// count one step, and the same for a session registering or leaving, so
/// every TERM falls either before the last session left (that session
/// accounts for it) or after (the handler acts as inherited). No window
/// between the two exists for a TERM to be lost in.
static SESSION_TERM: AtomicU64 = AtomicU64::new(0);
/// Each terminating signal pairs its count with its own live registrations,
/// so a handler paused across registration/departure cannot lose cancellation.
static SESSION_INT: AtomicU64 = AtomicU64::new(0);
static SESSION_HUP: AtomicU64 = AtomicU64::new(0);
static SESSION_QUIT: AtomicU64 = AtomicU64::new(0);
static CHLD_RECEIVED: AtomicU32 = AtomicU32::new(0);
/// The signal that last stopped a session of this process (one command), or
/// 0: a later clean session leaves it. A wrapped error drops its record, and
/// `stop_signal` reads this to tell an interrupt from a store "retry".
static STOPPED_BY: AtomicI32 = AtomicI32::new(0);
/// The global self-pipe, created at the first install and never closed, so
/// the handler never writes into a reused descriptor.
static NOTIFY_READ: AtomicI32 = AtomicI32::new(-1);
static NOTIFY_WRITE: AtomicI32 = AtomicI32::new(-1);
static SIGNAL_BYTE: u8 = 1;

/// The disposition each of [`SIGNALS`] had before tog's handler replaced
/// it. Slot `i` is written once, under [`REGISTRY`], before bit `i` of
/// [`RECORDED`] is set and before the handler for it is installed; after
/// that it is only read, by the handler and by `prepare_child`.
struct InheritedActions(UnsafeCell<[libc::sigaction; SIGNAL_COUNT]>);
// SAFETY: every slot is written once before it is published through
// RECORDED, and only read afterwards.
unsafe impl Sync for InheritedActions {}
// SAFETY: an all-zero sigaction is a valid (SIG_DFL, empty) value.
static INHERITED: InheritedActions =
    InheritedActions(UnsafeCell::new(unsafe { std::mem::zeroed() }));
/// Bit `i` set: `INHERITED[i]` is recorded.
static RECORDED: AtomicU32 = AtomicU32::new(0);
/// Bit `i` set: tog's handler is installed for `SIGNALS[i]`, for good.
static INSTALLED: AtomicU32 = AtomicU32::new(0);
/// One-shot inherited handlers reset only when their inherited action runs.
static RESET_HANDLED: AtomicU32 = AtomicU32::new(0);
/// A final session's orphaned TERM belongs to this thread, even if its mask
/// delays delivery. No new session may register until that delivery finishes.
static RERAISE_THREAD: AtomicUsize = AtomicUsize::new(0);

/// Bookkeeping shared by sessions. Held only for the first install and a
/// session's arrival and departure, never across a child's lifetime, a
/// `poll`, or a blocking syscall: a lock held for a child's lifetime is an
/// unbounded silent wait, which is why the old one-session-per-process
/// rule refused a second session instead of queueing it. The handler never
/// touches it.
struct Registry {
    /// A session left with TERMs it could not forward (its child was
    /// already reaped). The last session to leave re-raises one TERM for
    /// them, so a TERM nobody delivered still stops tog.
    term_orphaned: Vec<Option<u64>>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    term_orphaned: Vec::new(),
});

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    // A panicking session still deregisters in `Drop`; the bookkeeping
    // stays consistent, so poison is ignored.
    REGISTRY.lock().unwrap_or_else(|error| error.into_inner())
}

fn signal_index(signal: libc::c_int) -> Option<usize> {
    SIGNALS.iter().position(|number| *number == signal)
}

fn live_sessions(packed: u64) -> u64 {
    packed >> 32
}

fn term_count(packed: u64) -> u32 {
    packed as u32
}

/// Count a signal without letting low-half rollover change registrations.
fn count_signal(counter: &AtomicU64) -> u64 {
    counter
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |packed| {
            Some((packed & !(u32::MAX as u64)) | u64::from(term_count(packed).wrapping_add(1)))
        })
        .expect("a signal counter update is never refused")
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
/// kind but drops the record unless it uses `error::context`. Retained typed
/// wrappers preserve the record, so child status and signal handling agree.
pub fn interrupted(error: &io::Error) -> Option<&Interrupted> {
    error
        .get_ref()
        .and_then(|payload| payload.downcast_ref::<Interrupted>())
        .or_else(|| crate::kernel::error::inner(error).and_then(interrupted))
}

/// The first terminating signal in `received`, recorded for `stop_signal`.
fn record_stop(received: u32) -> Option<libc::c_int> {
    let found = TERMINATING
        .into_iter()
        .find(|s| received & signal_bit(*s) != 0);
    found.inspect(|signal| STOPPED_BY.store(*signal, Ordering::SeqCst))
}

/// The signal that asked tog to stop, when `error` is how a supervised call
/// reported it: from the [`Interrupted`] record, or, once a caller wrapped
/// the error and dropped the record, from the last interruption a session
/// of this command saw. `main` exits `128 + signal`, the shell's convention.
/// Any other error, including the store's own [`io::ErrorKind::Interrupted`]
/// with no session interrupted, is `None`.
pub fn stop_signal(error: &io::Error) -> Option<libc::c_int> {
    if let Some(record) = interrupted(error) {
        return Some(record.signal);
    }
    if error.kind() != io::ErrorKind::Interrupted {
        return None;
    }
    match STOPPED_BY.load(Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
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

/// Only atomics, a raw write, errno preservation, and `act_as_inherited`
/// are permitted here.
extern "C" fn signal_handler(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: errno_location points at this signal-handler thread's errno.
    let saved_errno = unsafe { *errno_location() };
    // SAFETY: pthread_self is async-signal-safe. Supported targets represent
    // pthread_t as an integer or pointer and never use zero for a live thread.
    let inherited_reraise = signal == libc::SIGTERM
        && RERAISE_THREAD.load(Ordering::SeqCst) == unsafe { libc::pthread_self() } as usize;
    let live = match signal {
        libc::SIGTERM if inherited_reraise => false,
        libc::SIGTERM => live_sessions(count_signal(&SESSION_TERM)) != 0,
        libc::SIGINT | libc::SIGHUP | libc::SIGQUIT => {
            let counter = match signal {
                libc::SIGINT => &SESSION_INT,
                libc::SIGHUP => &SESSION_HUP,
                _ => &SESSION_QUIT,
            };
            live_sessions(count_signal(counter)) != 0
        }
        libc::SIGCHLD => {
            CHLD_RECEIVED.fetch_add(1, Ordering::SeqCst);
            live_sessions(SESSION_TERM.load(Ordering::SeqCst)) != 0
        }
        _ => true,
    };
    if !live {
        act_as_inherited(signal, info, context);
        if inherited_reraise {
            RERAISE_THREAD.store(0, Ordering::SeqCst);
        }
    }
    let fd = NOTIFY_WRITE.load(Ordering::SeqCst);
    if fd >= 0 {
        // SAFETY: SIGNAL_BYTE is a process-lifetime one-byte buffer and fd is
        // the never-closed global self-pipe. O_NONBLOCK makes a full pipe a
        // harmless coalescing case; the counters retain the signal.
        unsafe {
            let _ = libc::write(fd, &SIGNAL_BYTE as *const u8 as *const libc::c_void, 1);
        }
    }
    // SAFETY: restore the interrupted thread's errno exactly as found.
    unsafe { *errno_location() = saved_errno };
}

/// With no session live, do what the disposition tog inherited would have
/// done. `SIG_DFL` for TERM/INT/HUP/QUIT puts the default back and raises
/// the signal again, so it is delivered with its default action (tog dies)
/// as soon as the handler returns. An inherited function is called, with
/// `siginfo` when it asked for it. One-shot handlers become default after
/// their first inherited invocation. The installed action preserves the
/// inherited restart, alternate-stack, deferred-delivery and mask behavior. A
/// default or ignored SIGCHLD needs nothing. `sigaction`, `raise` and a
/// plain call are async-signal-safe.
fn act_as_inherited(signal: libc::c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
    let Some(index) = signal_index(signal) else {
        return;
    };
    if RECORDED.load(Ordering::SeqCst) & (1 << index) == 0 {
        return;
    }
    // SAFETY: the slot was written before RECORDED published it and is never
    // written again.
    let action = unsafe { &(*INHERITED.0.get())[index] };
    let function = if action.sa_flags & libc::SA_RESETHAND != 0
        && RESET_HANDLED.fetch_or(1 << index, Ordering::SeqCst) & (1 << index) != 0
    {
        libc::SIG_DFL
    } else {
        action.sa_sigaction
    };
    match function {
        libc::SIG_IGN => {}
        libc::SIG_DFL => {
            if signal == libc::SIGCHLD {
                return;
            }
            // SAFETY: zeroed is followed by sigemptyset; SIG_DFL is a valid
            // disposition, and raise targets this thread, where the signal
            // stays blocked until the handler returns.
            unsafe {
                let mut default: libc::sigaction = std::mem::zeroed();
                libc::sigemptyset(&mut default.sa_mask);
                default.sa_sigaction = libc::SIG_DFL;
                libc::sigaction(signal, &default, std::ptr::null_mut());
                libc::raise(signal);
            }
        }
        function => {
            if action.sa_flags & libc::SA_SIGINFO != 0 {
                // SAFETY: the inherited action was installed with SA_SIGINFO,
                // so its handler takes the three-argument form.
                let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                    unsafe { std::mem::transmute(function) };
                handler(signal, info, context);
            } else {
                // SAFETY: an action without SA_SIGINFO holds a one-argument
                // handler.
                let handler: extern "C" fn(libc::c_int) = unsafe { std::mem::transmute(function) };
                handler(signal);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
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

/// The global self-pipe, both ends close-on-exec and nonblocking. Linux
/// sets both flags atomically. macOS has no `pipe2`, so a child forked by
/// another thread between `pipe` and `fcntl` can inherit an end, once per
/// process: with the read end it can drain wake bytes (a session waits one
/// tick), with the write end it can send spurious wakes (one `try_wait`
/// each). Neither can lose or forge a signal, because signals live in the
/// counters.
fn create_notify_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    #[cfg(target_os = "linux")]
    {
        // SAFETY: fds points to two writable c_int slots for libc to initialize.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: fds points to two writable c_int slots for libc to initialize.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for fd in fds {
            if let Err(error) = set_cloexec(fd).and_then(|_| set_nonblocking(fd)) {
                // SAFETY: both descriptors were returned by pipe and are
                // owned by this setup path.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                return Err(error);
            }
        }
    }
    Ok((fds[0], fds[1]))
}

/// Install tog's handler for every signal that does not have it yet. Runs
/// under [`REGISTRY`]. Each signal's inherited disposition is recorded
/// first, so from the moment the handler is installed it can act as that
/// disposition; nothing is ever uninstalled, so there is no restore and no
/// rollback. A failed `sigaction` leaves the handlers already installed in
/// place (harmless with no session live) and the next session installs the
/// rest.
fn install_handlers(_registry: &mut Registry) -> io::Result<()> {
    if NOTIFY_WRITE.load(Ordering::SeqCst) < 0 {
        let (read, write) = create_notify_pipe()?;
        NOTIFY_READ.store(read, Ordering::SeqCst);
        NOTIFY_WRITE.store(write, Ordering::SeqCst);
    }
    let mut calls = 0usize;
    for (index, number) in SIGNALS.into_iter().enumerate() {
        let bit = 1u32 << index;
        if INSTALLED.load(Ordering::SeqCst) & bit != 0 {
            continue;
        }
        if RECORDED.load(Ordering::SeqCst) & bit == 0 {
            // SAFETY: zeroed is a valid output slot that sigaction fills.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: a null new action only queries the current one.
            if unsafe { libc::sigaction(number, std::ptr::null(), &mut old) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the slot is unpublished (RECORDED bit clear) and this
            // runs under REGISTRY, so nothing else reads or writes it.
            unsafe { (*INHERITED.0.get())[index] = old };
            RECORDED.fetch_or(bit, Ordering::SeqCst);
        }
        // SAFETY: published above or by an earlier install, never rewritten.
        let inherited = unsafe { (*INHERITED.0.get())[index] };
        // An inherited SIG_IGN is kept for TERM/INT/HUP/QUIT: whoever
        // started tog asked for it not to be interrupted by them. SIGCHLD
        // is the exception. With SIGCHLD ignored (or SA_NOCLDWAIT set,
        // which the replacement below also clears) the kernel reaps the
        // child itself, `try_wait` fails with ECHILD, and the exit status
        // tog exists to report is gone. `prepare_child` hands the child the
        // inherited SIG_IGN back. While the handler is installed, a child
        // of this process that exits without being waited for becomes a
        // zombie instead of being auto-reaped, exactly what the default
        // disposition does to it; production code waits for every child it
        // spawns.
        if inherited.sa_sigaction == libc::SIG_IGN && number != libc::SIGCHLD {
            continue;
        }
        calls += 1;
        failpoint_before_sigaction(calls)?;
        // SAFETY: zeroed is followed by sigemptyset and all fields used by
        // sigaction are initialized below.
        let mut replacement: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: replacement is writable and the call initializes its mask.
        if unsafe { libc::sigemptyset(&mut replacement.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        replacement.sa_mask = inherited.sa_mask;
        replacement.sa_flags = libc::SA_SIGINFO
            | (inherited.sa_flags & (libc::SA_RESTART | libc::SA_ONSTACK | libc::SA_NODEFER));
        // Default dispositions have no inherited handler whose restart
        // behavior must be preserved. The supervisor's own handler can restart.
        if inherited.sa_sigaction == libc::SIG_DFL || inherited.sa_sigaction == libc::SIG_IGN {
            replacement.sa_flags |= libc::SA_RESTART;
        }
        replacement.sa_sigaction = signal_handler as *const () as usize;
        // SAFETY: replacement contains a valid async-signal-safe handler.
        if unsafe { libc::sigaction(number, &replacement, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        INSTALLED.fetch_or(bit, Ordering::SeqCst);
        failpoint_after_sigaction(calls);
    }
    Ok(())
}

/// Test-only knobs, read only in debug builds: `TOG_SUPERVISE_FAILPOINT`
/// is `fail-sigaction-<k>` (the k-th handler install of the process fails,
/// once) or `pause-after-sigaction-<k>` (after the k-th install, print
/// `FAILPOINT PAUSED <k>` and block until `TOG_SUPERVISE_FAILPOINT_FIFO`
/// is written).
#[cfg(debug_assertions)]
fn failpoint(kind: &str) -> Option<usize> {
    let value = std::env::var("TOG_SUPERVISE_FAILPOINT").ok()?;
    value.strip_prefix(kind)?.strip_prefix('-')?.parse().ok()
}

#[cfg(debug_assertions)]
static FAILPOINT_SPENT: AtomicBool = AtomicBool::new(false);

fn failpoint_before_sigaction(_call: usize) -> io::Result<()> {
    #[cfg(debug_assertions)]
    if failpoint("fail-sigaction") == Some(_call) && !FAILPOINT_SPENT.swap(true, Ordering::SeqCst) {
        return Err(io::Error::other(format!(
            "failpoint: sigaction {_call} failed"
        )));
    }
    Ok(())
}

fn failpoint_after_sigaction(_call: usize) {
    #[cfg(debug_assertions)]
    if failpoint("pause-after-sigaction") == Some(_call)
        && !FAILPOINT_SPENT.swap(true, Ordering::SeqCst)
    {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "FAILPOINT PAUSED {_call}");
        let _ = out.flush();
        drop(out);
        if let Some(fifo) = std::env::var_os("TOG_SUPERVISE_FAILPOINT_FIFO") {
            let _ = std::fs::read(fifo);
        }
    }
}

/// Pause exactly at a registration, spawn or departure boundary, in integration tests.
fn pause_boundary(_name: &str) {
    #[cfg(debug_assertions)]
    if std::env::var("TOG_SUPERVISE_FAILPOINT").as_deref() == Ok(_name)
        && !FAILPOINT_SPENT.swap(true, Ordering::SeqCst)
    {
        if _name == "before-reraise" {
            // Exercise a caller whose mask delays the thread-directed replay.
            // SAFETY: the initialized set names one valid signal on this thread.
            unsafe {
                let mut set = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGTERM);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
                    0
                );
            }
        }
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "FAILPOINT PAUSED {_name}");
        let _ = out.flush();
        drop(out);
        if let Some(fifo) = std::env::var_os("TOG_SUPERVISE_FAILPOINT_FIFO") {
            let _ = std::fs::read(fifo);
        }
        if let Ok(name) = std::env::var("TOG_SUPERVISE_BOUNDARY_SIGNAL") {
            let signal = match name.as_str() {
                "INT" => libc::SIGINT,
                "HUP" => libc::SIGHUP,
                "QUIT" => libc::SIGQUIT,
                _ => return,
            };
            // SAFETY: synchronously inject a valid signal at the paused boundary.
            unsafe { libc::raise(signal) };
        }
    }
}

/// How long a wait may go without a wakeup. A lone session is woken by the
/// signal itself; the tick only matters when concurrent sessions take each
/// other's wake bytes, and it bounds the wait when SIGCHLD is blocked. It
/// never decides correctness. Debug builds read `TOG_SUPERVISE_TICK_MS`.
fn tick_ms() -> libc::c_int {
    const DEFAULT: libc::c_int = 20;
    #[cfg(debug_assertions)]
    {
        static TICK: std::sync::OnceLock<libc::c_int> = std::sync::OnceLock::new();
        *TICK.get_or_init(|| {
            std::env::var("TOG_SUPERVISE_TICK_MS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(DEFAULT)
        })
    }
    #[cfg(not(debug_assertions))]
    DEFAULT
}

fn drain_notifications() {
    let fd = NOTIFY_READ.load(Ordering::SeqCst);
    if fd < 0 {
        return;
    }
    let mut bytes = [0u8; 64];
    // SAFETY: bytes is a valid writable buffer and fd is the global,
    // nonblocking, never-closed pipe end.
    while unsafe { libc::read(fd, bytes.as_mut_ptr() as *mut libc::c_void, bytes.len()) } > 0 {}
}

/// One supervised child's signal session: a registration among any number
/// of live ones, with its own cursors into the global counters. Owned by
/// the thread that supervises the child.
struct Session {
    /// The direct child, or -1 before spawn and after the reap. Only this
    /// thread reaps the child and only this thread forwards to it, so a
    /// reaped (possibly recycled) pid is never signalled.
    child_pid: Cell<i32>,
    cleanup_owner: Option<u64>,
    term_cursor: Cell<u32>,
    int_cursor: Cell<u32>,
    hup_cursor: Cell<u32>,
    quit_cursor: Cell<u32>,
    /// `CHLD_RECEIVED` when the current wait round began (`begin_round`).
    chld_seen: Cell<u32>,
    /// TERMs this session saw and has not yet forwarded or turned into a
    /// pre-spawn rejection.
    unconsumed_terms: Cell<u32>,
    /// Every terminating signal this session saw, one bit each
    /// (`signal_bit`). Forwarding never clears it, so it still says after
    /// the reap that tog was asked to stop.
    received: Cell<u32>,
    /// The spawning thread's mask, which the child execs with.
    old_mask: libc::sigset_t,
    active: bool,
}

impl Session {
    fn new() -> io::Result<Self> {
        let mut registry = registry();
        install_handlers(&mut registry)?;
        if RERAISE_THREAD.load(Ordering::SeqCst) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "termination from an earlier operation is still pending",
            ));
        }
        #[cfg(debug_assertions)]
        assert_term_handler_is_tog_s();
        // Each signal's registration and starting cursor are one atomic step,
        // just like TERM. Admission is serialized until all four are published.
        let int_cursor = term_count(SESSION_INT.fetch_add(ONE_SESSION, Ordering::SeqCst));
        let hup_cursor = term_count(SESSION_HUP.fetch_add(ONE_SESSION, Ordering::SeqCst));
        let quit_cursor = term_count(SESSION_QUIT.fetch_add(ONE_SESSION, Ordering::SeqCst));
        let packed = SESSION_TERM.fetch_add(ONE_SESSION, Ordering::SeqCst);
        pause_boundary("after-register");
        let mut session = Self {
            child_pid: Cell::new(-1),
            cleanup_owner: None,
            term_cursor: Cell::new(term_count(packed)),
            int_cursor: Cell::new(int_cursor),
            hup_cursor: Cell::new(hup_cursor),
            quit_cursor: Cell::new(quit_cursor),
            chld_seen: Cell::new(CHLD_RECEIVED.load(Ordering::SeqCst)),
            unconsumed_terms: Cell::new(0),
            received: Cell::new(0),
            // SAFETY: sigset_t is an opaque C value filled by
            // pthread_sigmask below before it is read.
            old_mask: unsafe { std::mem::zeroed() },
            active: true,
        };
        cleanup::inherit_start(&mut session);
        drop(registry);
        // SAFETY: a null set queries this thread's mask into the slot.
        let queried = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut session.old_mask)
        };
        if queried != 0 {
            return Err(io::Error::from_raw_os_error(queried));
        }
        Ok(session)
    }

    /// Fold every signal counted since the last look into this session.
    fn reconcile(&self) {
        let terms = term_count(SESSION_TERM.load(Ordering::SeqCst));
        let new_terms = terms.wrapping_sub(self.term_cursor.get());
        if new_terms != 0 {
            self.term_cursor.set(terms);
            self.unconsumed_terms
                .set(self.unconsumed_terms.get().wrapping_add(new_terms));
            self.received
                .set(self.received.get() | signal_bit(libc::SIGTERM));
        }
        for (counter, cursor, signal) in [
            (&SESSION_INT, &self.int_cursor, libc::SIGINT),
            (&SESSION_HUP, &self.hup_cursor, libc::SIGHUP),
            (&SESSION_QUIT, &self.quit_cursor, libc::SIGQUIT),
        ] {
            let now = term_count(counter.load(Ordering::SeqCst));
            if now != cursor.get() {
                cursor.set(now);
                self.received.set(self.received.get() | signal_bit(signal));
            }
        }
    }

    fn reject_pending_before_spawn(&self) -> io::Result<()> {
        self.reconcile();
        if self.received.get() != 0 {
            // The rejection is what these TERMs did: nothing is left to
            // forward or re-raise.
            self.unconsumed_terms.set(0);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancellation arrived before the child was spawned",
            ));
        }
        Ok(())
    }

    /// The child must never exec with tog's handlers or a caller's
    /// accidentally inherited blocked signal mask. Every signal goes back
    /// to what tog inherited: SIG_IGN stays ignored (including a SIGCHLD
    /// the handler takes anyway), and anything else becomes SIG_DFL, which
    /// is what exec would make of an inherited handler. The post-fork hook
    /// is restricted to libc signal operations on copied values.
    fn prepare_child(&self, command: &mut Command) {
        let recorded = RECORDED.load(Ordering::SeqCst);
        let actions: Vec<(libc::c_int, bool)> = SIGNALS
            .into_iter()
            .enumerate()
            .filter(|(index, _)| recorded & (1 << index) != 0)
            .map(|(index, number)| {
                // SAFETY: published through RECORDED, never rewritten.
                let action = unsafe { (*INHERITED.0.get())[index] };
                (number, action.sa_sigaction == libc::SIG_IGN)
            })
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
        pause_boundary("before-spawn");
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
        // Store the pid before reconciling. A TERM in the fork/exec interval
        // is therefore either rejected before spawn or forwarded now.
        self.child_pid.set(pid);
        self.forward_pending()
    }

    fn clear_child(&self) {
        if self.child_pid.get() > 0 {
            // This is the session's reap boundary. Cancellation already caught
            // belongs to the child's lifetime and carries its exit status,
            // even if it exited before we could forward. Only later TERMs,
            // caught while draining without a child, can become orphans.
            self.reconcile();
            self.unconsumed_terms.set(0);
        }
        self.child_pid.set(-1);
    }

    fn forward_pending(&self) -> io::Result<()> {
        self.reconcile();
        let terms = self.unconsumed_terms.get();
        // With no live child the TERMs stay unconsumed: a child published
        // later in this session still receives them, and one that never
        // comes makes them orphans that `finish` re-raises.
        let pid = self.child_pid.get();
        if terms == 0 || pid <= 0 {
            return Ok(());
        }
        self.unconsumed_terms.set(0);
        for _ in 0..terms {
            // SAFETY: pid was published from Child::id and this thread has
            // not reaped it.
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

    /// Start a wait round: empty the pipe, then note the SIGCHLD count.
    /// Called before `try_wait`, so a child exit after it either moves the
    /// count (`wait_for_event` sees it and does not block) or writes a byte
    /// into the emptied pipe (the poll wakes on it). The same holds for a
    /// TERM after `forward_pending`'s reconcile.
    fn begin_round(&self) {
        drain_notifications();
        self.chld_seen.set(CHLD_RECEIVED.load(Ordering::SeqCst));
    }

    fn wait_for_event(&self, output_fds: &[RawFd]) -> io::Result<()> {
        if CHLD_RECEIVED.load(Ordering::SeqCst) != self.chld_seen.get() {
            return Ok(());
        }
        let mut descriptors = Vec::with_capacity(output_fds.len() + 1);
        descriptors.push(libc::pollfd {
            fd: NOTIFY_READ.load(Ordering::SeqCst),
            events: libc::POLLIN,
            revents: 0,
        });
        descriptors.extend(output_fds.iter().map(|fd| libc::pollfd {
            fd: *fd,
            events: libc::POLLIN,
            revents: 0,
        }));
        // SAFETY: descriptors points at a valid contiguous pollfd array.
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                tick_ms(),
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            // A signal interrupted the wait: that is a wakeup.
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Deregister and return the terminating signals the session saw. A
    /// TERM this session saw but could not forward marks the registry; the
    /// last session to leave re-raises one TERM if any session left such a
    /// TERM, or if a TERM arrived after its own last look. That TERM then
    /// meets the handler with no session live and acts as inherited (by
    /// default, tog dies of it). A TERM every session forwarded does not
    /// re-raise: the child decides what it means.
    fn finish(&mut self) -> u32 {
        self.finish_with_handled_cleanup(false)
    }

    /// End the session for a reaped child: `value` when no terminating
    /// signal arrived, the interruption otherwise. A signal that arrives
    /// after a clean exit still counts, since it asked tog to stop too.
    fn conclude<T>(mut self, status: ExitStatus, value: T) -> io::Result<T> {
        match record_stop(self.finish()) {
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
        let _ = record_stop(self.finish());
    }
}

/// Supervision forwards TERM only while tog's handler holds it. Code that
/// installs its own TERM handler after tog's first session silently ends
/// that, so debug builds check at each registration.
#[cfg(debug_assertions)]
fn assert_term_handler_is_tog_s() {
    let Some(index) = signal_index(libc::SIGTERM) else {
        return;
    };
    if INSTALLED.load(Ordering::SeqCst) & (1 << index) == 0 {
        return;
    }
    // SAFETY: zeroed is a valid output slot; a null new action only queries.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    if unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut current) } == 0 {
        assert_eq!(
            current.sa_sigaction, signal_handler as *const () as usize,
            "something replaced tog's SIGTERM handler after its first supervised child; \
             supervision would stop forwarding TERM"
        );
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
        session.begin_round();
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
/// stream by [`relay`], the signing key's secret replaced.
// Reviewed site (tests/architecture.rs): the supervisor itself: spawns under the caller's lease.
#[allow(clippy::disallowed_methods)]
pub fn status_with_stderr(
    command: &mut Command,
    activity: &StoreActivity,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    status_relayed(
        command,
        activity,
        Sink::Stdout,
        Sink::Stderr,
        confine::signing_key_secrets(),
    )
}

/// [`status_with_stderr`] with where each stream goes as an argument, so a
/// test can collect them.
#[allow(clippy::disallowed_methods)]
fn status_relayed(
    command: &mut Command,
    activity: &StoreActivity,
    stdout_sink: Sink,
    stderr_sink: Sink,
    secrets: &[Vec<u8>],
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
    // One reader per pipe, each blocking on its own stream: a child that
    // floods one while the other's pipe is full cannot stall either. The
    // supervising thread keeps the child and the signals, as `status` does.
    // A reader that fails (a read error, a panic) wakes it through the
    // session's self-pipe, as a signal does ([`RelayWake`]).
    let failed = std::sync::Arc::new(AtomicBool::new(false));
    let deadline = std::sync::Arc::new(std::sync::OnceLock::new());
    let mut readers = Vec::with_capacity(2);
    let started: io::Result<()> = (|| {
        if let Some(pipe) = child.stderr.take() {
            let wake = RelayWake::new(NOTIFY_WRITE.load(Ordering::SeqCst), &failed)?;
            readers.push((
                true,
                spawn_relay(
                    pipe,
                    stderr_sink,
                    secrets,
                    CLASSIFIER_PREFIX,
                    wake,
                    deadline.clone(),
                )?,
            ));
        }
        if let Some(pipe) = child.stdout.take() {
            let wake = RelayWake::new(NOTIFY_WRITE.load(Ordering::SeqCst), &failed)?;
            readers.push((
                false,
                spawn_relay(pipe, stdout_sink, secrets, 0, wake, deadline.clone())?,
            ));
        }
        Ok(())
    })();
    let waited = match started {
        Err(error) => Err(error),
        Ok(()) => loop {
            session.begin_round();
            if failed.load(Ordering::SeqCst) {
                break Err(io::Error::other("a child output relay failed"));
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => {}
                Err(error) => break Err(error),
            }
            if let Err(error) = session.forward_pending() {
                break Err(error);
            }
            // Checked again after `forward_pending`: a reader that failed
            // before this sees the flag, one that fails after it writes a
            // byte the poll below wakes on (`begin_round` emptied the pipe
            // before the first check).
            if failed.load(Ordering::SeqCst) {
                break Err(io::Error::other("a child output relay failed"));
            }
            if let Err(error) = session.wait_for_event(&[]) {
                break Err(error);
            }
        },
    };
    if waited.is_err() {
        reap_after_error(&mut child);
    }
    // The direct child is reaped: no forwarded signal may reach its pid
    // again while the pipes drain. Both readers are joined on every path,
    // before the session and the activity borrow end. A process the child
    // left holding a pipe gets `DRAIN_AFTER_EXIT`, then its reader stops.
    session.clear_child();
    let _ = deadline.set(std::time::Instant::now() + DRAIN_AFTER_EXIT);
    let mut stderr_bytes = Ok(Vec::new());
    let mut relay_error = None;
    let mut abandoned = false;
    for (is_stderr, reader) in readers {
        match join_relay(reader) {
            Ok((bytes, stopped)) => {
                abandoned |= stopped;
                if is_stderr {
                    stderr_bytes = Ok(bytes);
                }
            }
            Err(error) => {
                if relay_error.is_none() {
                    relay_error = Some(io::Error::new(error.kind(), error.to_string()));
                }
                if is_stderr {
                    stderr_bytes = Err(error);
                }
            }
        }
    }
    if abandoned {
        note_abandoned_output(command);
    }
    let status = match (waited, relay_error) {
        (_, Some(error)) => return Err(error),
        (Err(error), None) => return Err(error),
        (Ok(status), None) => status,
    };
    session.conclude(status, (status, stderr_bytes?))
}

/// The bytes of a child's stderr kept for the sandbox failure classifier,
/// by this supervisor and by the sandbox's unmanaged relay alike.
pub(crate) const CLASSIFIER_PREFIX: usize = 4096;

/// Where a relayed stream goes.
enum Sink {
    Stdout,
    Stderr,
    /// Into a buffer, for tests.
    #[cfg(test)]
    Buffer(std::sync::Arc<Mutex<Vec<u8>>>),
    /// A relay that panics on its first write, for the fault test.
    #[cfg(test)]
    Panic,
}

impl Sink {
    fn write(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match self {
            Sink::Stdout => {
                let mut out = io::stdout().lock();
                let _ = out.write_all(bytes);
                let _ = out.flush();
            }
            Sink::Stderr => {
                let _ = io::stderr().write_all(bytes);
            }
            #[cfg(test)]
            Sink::Buffer(buffer) => buffer
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .extend_from_slice(bytes),
            #[cfg(test)]
            Sink::Panic => panic!("injected relay failure"),
        }
    }
}

/// How a relay thread tells the supervising thread it failed: a shared
/// flag, and a byte on its own copy of the session's self-pipe, which the
/// supervision loop polls. Dropped without [`RelayWake::done`] it fires, so
/// a read error and a panic (the drop runs while unwinding) both reach it.
struct RelayWake {
    fd: std::os::fd::OwnedFd,
    failed: std::sync::Arc<AtomicBool>,
    done: bool,
}

impl RelayWake {
    fn new(write_fd: RawFd, failed: &std::sync::Arc<AtomicBool>) -> io::Result<Self> {
        use std::os::fd::FromRawFd;
        // SAFETY: write_fd is the global self-pipe's write end, never closed; the
        // duplicate is owned here and closed when the wake is dropped.
        let fd = unsafe { libc::fcntl(write_fd, libc::F_DUPFD_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: fd was just returned by fcntl and nothing else owns it.
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
            failed: failed.clone(),
            done: false,
        })
    }

    /// The relay finished: nothing to report.
    fn done(mut self) {
        self.done = true;
    }
}

impl Drop for RelayWake {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        self.failed.store(true, Ordering::SeqCst);
        // SAFETY: the byte is a valid one-byte buffer and fd is an open,
        // nonblocking pipe end (a full pipe already holds a wakeup).
        unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &SIGNAL_BYTE as *const u8 as *const libc::c_void,
                1,
            );
        }
    }
}

/// A relay's kept prefix, and whether it stopped at the drain deadline
/// rather than at end of file.
type RelayHandle = std::thread::JoinHandle<io::Result<(Vec<u8>, bool)>>;

/// Set once the direct child is reaped: when a relay stops reading.
type DrainDeadline = std::sync::Arc<std::sync::OnceLock<std::time::Instant>>;

/// Relay `pipe` to `sink` on a thread of its own ([`relay`]), reporting a
/// failure through `wake`.
fn spawn_relay<R: Read + AsRawFd + Send + 'static>(
    pipe: R,
    sink: Sink,
    secrets: &[Vec<u8>],
    keep: usize,
    wake: RelayWake,
    deadline: DrainDeadline,
) -> io::Result<RelayHandle> {
    let scrubber = confine::Scrubber::new(secrets.to_vec());
    std::thread::Builder::new()
        .name("tog-relay".into())
        .spawn(move || {
            let result = relay(pipe, &sink, scrubber, keep, &deadline);
            if result.is_ok() {
                wake.done();
            }
            result
        })
}

fn join_relay(handle: RelayHandle) -> io::Result<(Vec<u8>, bool)> {
    handle
        .join()
        .map_err(|_| io::Error::other("a child output relay panicked"))?
}

/// Pass a child's output stream on to `sink` with the signing key's secret
/// replaced: a tool's parse error quotes the line it failed on, and a
/// project file can be the key under another name. Blocking reads until the
/// child closes its end, or until `deadline` once it is set; the
/// [`confine::Scrubber`] holds back only bytes that could still be part of
/// a secret, never on a pause. Returns the first `keep` bytes passed on,
/// scrubbed like the rest: a caller that quotes them in an error cannot
/// carry the key either. The flag says the deadline, not end of file,
/// stopped it.
fn relay(
    mut pipe: impl Read + AsRawFd,
    sink: &Sink,
    mut scrubber: confine::Scrubber,
    keep: usize,
    deadline: &std::sync::OnceLock<std::time::Instant>,
) -> io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut pass_on = |bytes: Vec<u8>| {
        let room = keep.saturating_sub(kept.len()).min(bytes.len());
        kept.extend_from_slice(&bytes[..room]);
        sink.write(&bytes);
    };
    let mut buffer = [0u8; 16 * 1024];
    // Short waits, so a deadline set while the pipe is quiet is seen.
    const TICK: std::time::Duration = std::time::Duration::from_millis(50);
    let result = loop {
        let wait = match deadline.get() {
            Some(at) => match at.checked_duration_since(std::time::Instant::now()) {
                Some(left) if !left.is_zero() => left.min(TICK),
                _ => break Ok(true),
            },
            None => TICK,
        };
        match wait_readable(pipe.as_raw_fd(), wait) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => break Err(error),
        }
        match pipe.read(&mut buffer) {
            Ok(0) => break Ok(false),
            Ok(count) => pass_on(scrubber.push(&buffer[..count])),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => break Err(error),
        }
    };
    pass_on(scrubber.finish());
    result.map(|stopped| (kept, stopped))
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
    let mut reaped_at = None;
    loop {
        session.begin_round();
        if status.is_none() {
            match child.try_wait() {
                Ok(next) => {
                    if next.is_some() {
                        // The direct child is reaped. Clear the pid slot now,
                        // not at return: this loop keeps running while the
                        // pipes drain, and a forwarded signal must never
                        // reach a reaped — possibly recycled — pid.
                        session.clear_child();
                        reaped_at = Some(std::time::Instant::now());
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
            // A process the child left holding a pipe gets
            // `DRAIN_AFTER_EXIT`; then the pipe is dropped.
            if (stdout.is_some() || stderr.is_some())
                && reaped_at.is_some_and(|at: std::time::Instant| at.elapsed() >= DRAIN_AFTER_EXIT)
            {
                note_abandoned_output(command);
                stdout = None;
                stderr = None;
            }
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

    #[test]
    #[ignore = "isolated signal ownership harness"]
    fn cleanup_orphan_harness() {
        if std::env::var_os("TOG_CLEANUP_ORPHAN_HARNESS").is_none() {
            return;
        }
        let mut other = Session::new().unwrap();
        let mut orphan = Session::new().unwrap();
        // SAFETY: this isolated process has two registered sessions.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        orphan.finish();
        other.reconcile();
        other.unconsumed_terms.set(0);
        during_cleanup(|| Ok(())).unwrap();
        assert!(registry().term_orphaned.contains(&None));
        other.finish();
        panic!("unrelated orphan TERM was erased by cleanup");
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn cleanup_preserves_an_earlier_unrelated_sessions_orphan_term() {
        use std::os::unix::process::ExitStatusExt as _;
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "kernel::supervise::tests::cleanup_orphan_harness",
                "--ignored",
                "--nocapture",
            ])
            .env("TOG_CLEANUP_ORPHAN_HARNESS", "1");
        // SAFETY: reset one disposition between fork and exec.
        unsafe {
            command.pre_exec(|| {
                libc::signal(libc::SIGTERM, libc::SIG_DFL);
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(status.signal(), Some(libc::SIGTERM));
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("orphan ownership harness hung");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn signal_counter_rollover_preserves_the_live_registration_count() {
        for live in [0, 1, 3] {
            let counter = AtomicU64::new((live * ONE_SESSION) | u64::from(u32::MAX));
            let previous = count_signal(&counter);
            assert_eq!(live_sessions(previous), live);
            assert_eq!(term_count(previous), u32::MAX);
            let wrapped = counter.load(Ordering::SeqCst);
            assert_eq!(live_sessions(wrapped), live);
            assert_eq!(term_count(wrapped), 0);
        }
    }
    use crate::kernel::activity::ActivityMode;
    use crate::kernel::store::Store;
    use crate::kernel::testutil::TempDir;
    use std::path::Path;
    use std::sync::Mutex;

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
        (Store::for_test(root), dir)
    }

    // Reviewed site (tests/architecture.rs): the supervisor's own tests of its primitives.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn status_preserves_a_numeric_exit_across_sequential_children() {
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

    const RELAY_SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// Run `script` under `status_relayed` with both streams collected and
    /// `RELAY_SEED` as the secret, on a thread, failing after `limit`. The
    /// stderr prefix it returns for the classifier must be the start of
    /// what was passed on, scrubbed the same way.
    fn relayed(script: &str, limit: std::time::Duration) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let script = script.to_string();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (store, _root) = test_store("relay");
            let activity = store.activity(ActivityMode::Shared).unwrap();
            let stdout = std::sync::Arc::new(Mutex::new(Vec::new()));
            let stderr = std::sync::Arc::new(Mutex::new(Vec::new()));
            let mut command = Command::new("/bin/sh");
            command.args(["-c", &script]);
            let (status, prefix) = status_relayed(
                &mut command,
                &activity,
                Sink::Buffer(stdout.clone()),
                Sink::Buffer(stderr.clone()),
                &[RELAY_SEED.as_bytes().to_vec()],
            )
            .unwrap();
            drop(activity);
            let take = |buffer: std::sync::Arc<Mutex<Vec<u8>>>| buffer.lock().unwrap().clone();
            let _ = sender.send((status, take(stdout), take(stderr), prefix));
        });
        let (status, stdout, stderr, prefix) = receiver
            .recv_timeout(limit)
            .expect("the relayed child did not finish in time");
        assert_eq!(prefix.len(), stderr.len().min(CLASSIFIER_PREFIX));
        assert_eq!(prefix, stderr[..prefix.len()]);
        (status, stdout, stderr)
    }

    /// A relay thread that panics while the child sleeps wakes the
    /// supervising thread, which kills and reaps the child, joins both
    /// readers, and returns the failure, well before the child would end.
    #[test]
    fn a_failing_relay_wakes_the_supervisor_and_the_child_is_reaped() {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (store, _root) = test_store("relay-fail");
            let activity = store.activity(ActivityMode::Shared).unwrap();
            // `exec`: the sleep is the direct child, so killing it closes
            // both pipes at once (a grandchild holding one would add `DRAIN_AFTER_EXIT`).
            let mut command = Command::new("/bin/sh");
            command.args(["-c", "printf 'x\\n' >&2; exec sleep 600"]);
            let started = std::time::Instant::now();
            let result = status_relayed(
                &mut command,
                &activity,
                Sink::Buffer(std::sync::Arc::new(Mutex::new(Vec::new()))),
                Sink::Panic,
                &[],
            );
            drop(activity);
            let _ = sender.send((
                result.map(drop).map_err(|error| error.to_string()),
                started.elapsed(),
            ));
        });
        let (result, elapsed) = receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the supervisor did not wake for a failed relay");
        let error = result.unwrap_err();
        assert!(error.contains("relay panicked"), "{error}");
        assert!(elapsed < std::time::Duration::from_secs(60), "{elapsed:?}");
    }

    #[test]
    fn a_continuously_readable_stream_yields_to_other_supervisor_work() {
        struct ContinuousOutput(usize);
        impl Read for ContinuousOutput {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                if self.0 >= 1024 {
                    return Err(io::Error::other("stream monopolized the supervisor"));
                }
                buffer[0] = b'x';
                Ok(1)
            }
        }
        let mut stream = Some(ContinuousOutput(0));
        let mut captured = Vec::new();
        assert!(!drain(&mut stream, &mut captured).unwrap());
        assert!(!captured.is_empty());
        // Returning permits reaping, signal forwarding, deadline checks,
        // and draining the other output pipe even without EOF/WouldBlock.
        assert!(stream.unwrap().0 < 1024);
    }

    /// A command that leaves a process holding its output open (a compiler
    /// server, an MSBuild node) does not hang tog: once the direct child is
    /// reaped, both supervisors read for `DRAIN_AFTER_EXIT` more, then stop
    /// and keep what they read.
    // Reviewed site (tests/architecture.rs): the supervisor's own tests of its primitives.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn a_leftover_process_holding_the_output_does_not_hang_the_supervisor() {
        let script = "printf 'early\\n' >&2; sleep 60 >&2 & echo $!";
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (store, _root) = test_store("leftover");
            let activity = store.activity(ActivityMode::Shared).unwrap();
            let started = std::time::Instant::now();
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            let captured = output(&mut command, &activity).unwrap();
            let captured_after = started.elapsed();

            let stdout = std::sync::Arc::new(Mutex::new(Vec::new()));
            let stderr = std::sync::Arc::new(Mutex::new(Vec::new()));
            let started = std::time::Instant::now();
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            let (status, prefix) = status_relayed(
                &mut command,
                &activity,
                Sink::Buffer(stdout.clone()),
                Sink::Buffer(stderr.clone()),
                &[],
            )
            .unwrap();
            let relayed_after = started.elapsed();
            drop(activity);
            let relayed_pid = stdout.lock().unwrap().clone();
            let _ = sender.send((
                captured,
                captured_after,
                status,
                prefix,
                relayed_pid,
                relayed_after,
            ));
        });
        let (captured, captured_after, status, prefix, relayed_pid, relayed_after) = receiver
            .recv_timeout(std::time::Duration::from_secs(40))
            .expect("the supervisor waited on the leftover process");
        for pid in [&captured.stdout, &relayed_pid] {
            let pid = String::from_utf8_lossy(pid).trim().to_string();
            let _ = Command::new("kill").arg(&pid).status();
        }
        assert!(captured.status.success());
        assert_eq!(captured.stderr, b"early\n");
        assert!(captured_after >= DRAIN_AFTER_EXIT, "{captured_after:?}");
        assert!(status.success());
        assert_eq!(prefix, b"early\n");
        assert!(relayed_after >= DRAIN_AFTER_EXIT, "{relayed_after:?}");
    }

    /// No piece of the secret 10 characters or longer is in `text`.
    fn holds_no_fragment(text: &[u8]) -> bool {
        let text = String::from_utf8_lossy(text);
        (0..=RELAY_SEED.len() - 10).all(|start| !text.contains(&RELAY_SEED[start..start + 10]))
    }

    /// A secret written in 8-character pieces on guttered lines, the child
    /// pausing between them, never comes out whole or in a 10-character
    /// piece: the scrubber holds back what could still be part of a match
    /// however long the pause.
    #[test]
    fn a_secret_split_across_paused_lines_is_replaced() {
        let mut script = String::from("printf 'error: bad TOML\\n1 | ed25519:' >&2; ");
        for piece in RELAY_SEED.as_bytes().chunks(8) {
            let piece = std::str::from_utf8(piece).unwrap();
            script.push_str(&format!("printf '%s\\n  | ' {piece} >&2; sleep 0.03; "));
        }
        script.push_str("printf 'done\\n' >&2");
        let (status, stdout, stderr) = relayed(&script, std::time::Duration::from_secs(60));
        assert!(status.success());
        assert!(
            holds_no_fragment(&stderr),
            "{}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(String::from_utf8_lossy(&stderr).ends_with("done\n"));
        assert!(stdout.is_empty());
        assert!(String::from_utf8_lossy(&stderr).contains("1 | ed25519:"));
        // Each piece, cut alone, is shorter than a match; together they are
        // the secret, so every one is replaced.
        let text = String::from_utf8_lossy(&stderr);
        assert!(text.contains("[signing key redacted]"), "{text}");
        for piece in RELAY_SEED.as_bytes().chunks(8) {
            assert!(
                !text.contains(std::str::from_utf8(piece).unwrap()),
                "{text}"
            );
        }
    }

    /// A child that floods stderr while writing 128 KiB to stdout finishes:
    /// each pipe has its own reader, so neither waits on the other.
    #[test]
    fn a_child_flooding_both_streams_does_not_hang() {
        let script = "dd if=/dev/zero bs=131072 count=1 2>/dev/null & \
                      dd if=/dev/zero bs=1048576 count=2 >&2 2>/dev/null; wait";
        let (status, stdout, stderr) = relayed(script, std::time::Duration::from_secs(60));
        assert!(status.success());
        assert_eq!(stdout.len(), 131072);
        assert_eq!(stderr.len(), 2 * 1048576);
        let script = "dd if=/dev/zero bs=1048576 count=2 >&2 2>/dev/null & \
                      dd if=/dev/zero bs=131072 count=1 2>/dev/null; wait";
        let (status, stdout, stderr) = relayed(script, std::time::Duration::from_secs(60));
        assert!(status.success());
        assert_eq!(stdout.len(), 131072);
        assert_eq!(stderr.len(), 2 * 1048576);
    }

    /// Ordinary output passes through byte for byte, in order on each
    /// stream, hex and line breaks included.
    #[test]
    fn ordinary_output_arrives_intact() {
        let mut expected = String::new();
        for line in 0..2000 {
            expected.push_str(&format!("line {line}: sha 0123abcd 4567 | ok\n"));
        }
        std::fs::write(std::env::temp_dir().join("tog-relay-intact.txt"), &expected).unwrap();
        let script = format!(
            "cat {0}; cat {0} >&2; printf 'no newline 0123abc'",
            std::env::temp_dir().join("tog-relay-intact.txt").display()
        );
        let (status, stdout, stderr) = relayed(&script, std::time::Duration::from_secs(60));
        assert!(status.success());
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            format!("{expected}no newline 0123abc")
        );
        assert_eq!(String::from_utf8(stderr).unwrap(), expected);
    }

    // Reviewed site (tests/architecture.rs): the supervisor's own tests of its primitives.
    #[allow(clippy::disallowed_methods)]
    #[test]
    fn output_drains_both_pipes_before_reaping() {
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
