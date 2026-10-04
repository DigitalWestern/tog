//! Signal and PTY acceptance coverage for the supervised child lifetime.
//!
//! These are the supervision cases that need a real process tree: a supervisor in its own process, a real child, and real
//! signal delivery. This binary re-executes itself with
//! `TOG_SUPERVISE_SCENARIO` set; the ignored `supervisor_harness` test
//! below then plays the supervisor and prints markers the cases wait for.
//!
//! No case uses a sleep to synchronise with an unobserved event. Progress is
//! observed through markers on the child's inherited stdout, through a FIFO
//! rendezvous, through `waitpid`, and through `/proc/<pid>/stat`; polling
//! loops are bounded and only bound how often an already-decided state is
//! re-read. The one deliberate delay is in
//! `term_across_the_spawn_boundary_is_never_lost`, where a varying delay is
//! the stimulus being swept rather than a wait.

// Tests spawn fixtures and take leases freely (see clippy.toml).
#![allow(clippy::disallowed_methods)]
#![cfg(unix)]

use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tog::kernel::activity::{ActivityMode, StoreActivity};
use tog::kernel::store::Store;
use tog::kernel::supervise;

mod common;

use common::{command, fresh_store, TempDir};

/// Every wait in this file is bounded. A blown deadline fails the case with
/// the output collected so far rather than hanging the suite.
const DEADLINE: Duration = Duration::from_secs(30);
/// How often a bounded loop re-reads a state it is waiting on.
const TICK: Duration = Duration::from_millis(2);

// ---------------------------------------------------------------- utilities

/// A disposable store. Never point `TOG_STORE` at a real store. Its
/// scratch root is also the home and working directory of the nested tog
/// runs and holds the case's FIFOs, so everything goes when the case does.
struct TempStore {
    temp: TempDir,
    root: PathBuf,
}

impl TempStore {
    fn new(label: &str) -> Self {
        let temp = TempDir::new(&format!("supervise-{label}"));
        let root = temp.0.join("store");
        fresh_store(&root);
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
        Self { temp, root }
    }

    fn home(&self) -> &Path {
        self.temp.path()
    }

    /// A rendezvous FIFO under the scratch root.
    fn fifo(&self, name: &str) -> PathBuf {
        let path = self.temp.0.join(name);
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path this test owns.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        path
    }

    /// True when nobody holds the store's activity lease. This is the same
    /// question `gc` asks, so it is also the check that a supervised job
    /// keeps its store protected.
    fn is_free(&self) -> bool {
        let path = self.root.join("activity.lock");
        if !path.exists() {
            return true;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // SAFETY: the descriptor is owned here for the duration of the call.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        if locked {
            // SAFETY: the lock was just acquired on this descriptor.
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        }
        locked
    }

    fn wait_until_free(&self) {
        let deadline = Instant::now() + DEADLINE;
        while !self.is_free() {
            assert!(
                Instant::now() < deadline,
                "the activity lease outlived every process that could hold it"
            );
            std::thread::sleep(TICK);
        }
    }
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: fd is owned by the caller for the duration of these calls.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Accumulating reader over a pipe or PTY master.
struct Markers {
    fd: RawFd,
    owned: bool,
    seen: String,
    eof: bool,
}

impl Markers {
    fn new(fd: RawFd, owned: bool) -> Self {
        set_nonblocking(fd);
        Self {
            fd,
            owned,
            seen: String::new(),
            eof: false,
        }
    }

    fn pump(&mut self) {
        let mut buffer = [0u8; 8192];
        loop {
            // SAFETY: buffer is a valid writable slice and fd is owned for
            // the lifetime of this value.
            let count = unsafe {
                libc::read(
                    self.fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if count > 0 {
                self.seen
                    .push_str(&String::from_utf8_lossy(&buffer[..count as usize]));
                continue;
            }
            if count == 0 {
                self.eof = true;
            }
            return;
        }
    }

    fn poll_once(&self, timeout_ms: libc::c_int) {
        let mut descriptor = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is a single valid pollfd.
        unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    }

    fn wait_for(&mut self, marker: &str) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            self.pump();
            if self.seen.contains(marker) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {marker:?}; output so far:\n{}",
                self.seen
            );
            self.poll_once(50);
        }
    }

    /// Collect whatever a finished process left in the pipe.
    fn settle(&mut self) {
        for _ in 0..10 {
            self.pump();
            if self.eof {
                return;
            }
            self.poll_once(20);
        }
    }

    fn text(&self) -> String {
        self.seen.clone()
    }

    /// The pid the scenario's child announced with `CHILDPID <n>`.
    fn child_pid(&self) -> i32 {
        for line in self.seen.lines() {
            if let Some(rest) = line.trim().strip_prefix("CHILDPID ") {
                if let Ok(pid) = rest.trim().parse() {
                    return pid;
                }
            }
        }
        panic!("no CHILDPID marker in:\n{}", self.seen);
    }
}

impl Drop for Markers {
    fn drop(&mut self) {
        if self.owned && self.fd >= 0 {
            // SAFETY: the descriptor was moved into this value.
            unsafe { libc::close(self.fd) };
        }
    }
}

fn signal(pid: i32, number: libc::c_int) {
    // SAFETY: a plain kill(2) on a process this test created.
    assert_eq!(
        unsafe { libc::kill(pid, number) },
        0,
        "kill({pid}, {number}): {}",
        std::io::Error::last_os_error()
    );
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only probes for the process's existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// The single-character state field of `/proc/<pid>/stat`, read past the
/// parenthesised comm so a process name containing ')' cannot shift it.
#[cfg(target_os = "linux")]
fn proc_state(pid: i32) -> Option<char> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &text[text.rfind(')')? + 1..];
    tail.split_whitespace().next()?.chars().next()
}

#[cfg(target_os = "linux")]
fn wait_for_state(pid: i32, state: char, what: &str) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if proc_state(pid) == Some(state) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: pid {pid} is in state {:?}, wanted {state:?}",
            proc_state(pid)
        );
        std::thread::sleep(TICK);
    }
}

/// A stopped process reads 'T'. A shell that vforks its commands (dash, the
/// `/bin/sh` on Debian and Ubuntu) and takes the stop mid-vfork stays in 'D'
/// until the stopped command execs or exits, so a 'D' parent whose every
/// child is stopped counts as stopped too.
#[cfg(target_os = "linux")]
fn wait_until_stopped(pid: i32, what: &str) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        match proc_state(pid) {
            Some('T') => return,
            Some('D') => {
                let children = proc_children(pid);
                if !children.is_empty()
                    && children.iter().all(|child| proc_state(*child) == Some('T'))
                {
                    return;
                }
            }
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what}: pid {pid} is in state {:?}, wanted 'T'",
            proc_state(pid)
        );
        std::thread::sleep(TICK);
    }
}

/// Wait until no instance of `number` is pending for process `pid`, read
/// from the process-wide `ShdPnd` mask in `/proc/<pid>/status`. A signal
/// sent with kill(2) stays there until a thread takes it for its handler.
#[cfg(target_os = "linux")]
fn wait_until_delivered(pid: i32, number: libc::c_int) {
    let bit = 1u64 << (number - 1);
    let deadline = Instant::now() + DEADLINE;
    loop {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let pending = status
            .lines()
            .find_map(|line| line.strip_prefix("ShdPnd:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .expect("ShdPnd in /proc/<pid>/status");
        if pending & bit == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "signal {number} stayed pending for {pid}"
        );
        std::thread::sleep(TICK);
    }
}

/// Every process whose parent is `pid`, from the ppid field of `/proc/*/stat`.
#[cfg(target_os = "linux")]
fn proc_children(pid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(candidate) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(format!("/proc/{candidate}/stat")) else {
            continue;
        };
        let Some(close) = text.rfind(')') else {
            continue;
        };
        let ppid = text[close + 1..]
            .split_whitespace()
            .nth(1)
            .and_then(|field| field.parse::<i32>().ok());
        if ppid == Some(pid) {
            out.push(candidate);
        }
    }
    out
}

struct Harness {
    process: Child,
    markers: Markers,
    reaped: bool,
}

/// A failing case must not leave a supervisor or its child running: an
/// orphaned grandchild holds the inherited stdout open, which wedges any
/// caller reading this suite's output through a pipe. Killing the whole
/// process group terminates and reaps every process the case started.
impl Drop for Harness {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let pid = self.process.id() as i32;
        // SAFETY: the harness is always its own group leader (setpgid or
        // setsid in pre_exec), so this reaches it and its children only.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = self.process.wait();
    }
}

impl Harness {
    fn pid(&self) -> i32 {
        self.process.id() as i32
    }

    fn finish(&mut self) -> ExitStatus {
        let deadline = Instant::now() + DEADLINE;
        loop {
            match self.process.try_wait().unwrap() {
                Some(status) => {
                    self.reaped = true;
                    return status;
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "supervisor {} did not exit; output so far:\n{}",
                        self.process.id(),
                        self.markers.seen
                    );
                    std::thread::sleep(TICK);
                }
            }
        }
    }
}

/// Spawn this test binary again as a supervisor. With `pty`, the harness gets
/// its own session and the slave as controlling terminal so terminal signals
/// reach its foreground process group; otherwise it gets its own process
/// group and a pipe.
fn spawn_harness(
    scenario: &str,
    store: &TempStore,
    pty: Option<&Pty>,
    fifo: Option<&Path>,
) -> Harness {
    spawn_harness_with(scenario, store, pty, fifo, |_| {})
}

/// `spawn_harness` with a hook that adjusts the command first, for cases
/// whose subject is state the supervisor inherits across exec.
fn spawn_harness_with(
    scenario: &str,
    store: &TempStore,
    pty: Option<&Pty>,
    fifo: Option<&Path>,
    configure: impl FnOnce(&mut Command),
) -> Harness {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    // The supervisor keeps an inherited SIG_IGN for INT and QUIT on
    // purpose, so a harness that inherited one from the suite's launcher
    // (a background job of a non-interactive shell starts every process
    // that way) would never report the interrupts these cases send. The
    // harness starts from the default dispositions whatever launched it.
    // SAFETY: signal(2) between fork and exec, on two signal numbers.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }
    configure(&mut command);
    let (scenario, inner) = match scenario.split_once(':') {
        Some((outer, inner)) => (outer, Some(inner)),
        None => (scenario, None),
    };
    command
        .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
        .env("TOG_SUPERVISE_SCENARIO", scenario)
        .env("TOG_SUPERVISE_STORE", &store.root)
        .env("TOG_SUPERVISE_HOME", store.home())
        .env("RUST_BACKTRACE", "1")
        .env_remove("TOG_STORE");
    if let Some(inner) = inner {
        command.env("TOG_SUPERVISE_INNER", inner);
    }
    if let Some(fifo) = fifo {
        command.env("TOG_SUPERVISE_FIFO", fifo);
    }

    let markers = match pty {
        Some(pty) => {
            let slave = pty.slave;
            // SAFETY: the slave stays open in this process for the whole
            // spawn; each Stdio takes its own duplicate.
            unsafe {
                command
                    .stdin(Stdio::from(OwnedFd::from_raw_fd(libc::dup(slave))))
                    .stdout(Stdio::from(OwnedFd::from_raw_fd(libc::dup(slave))))
                    .stderr(Stdio::from(OwnedFd::from_raw_fd(libc::dup(slave))));
            }
            // SAFETY: setsid and TIOCSCTTY are async-signal-safe and touch
            // only the post-fork child.
            unsafe {
                command.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            None
        }
        None => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
            // SAFETY: setpgid only touches the post-fork child.
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            Some(())
        }
    };
    let mut process = command.spawn().unwrap();
    let markers = match markers {
        Some(()) => Markers::new(process.stdout.take().unwrap().into_raw_fd(), true),
        None => Markers::new(pty.expect("pty harness").master, false),
    };
    Harness {
        process,
        markers,
        reaped: false,
    }
}

/// Release a child blocked on `read < fifo`. A blocking open for write
/// waits for a reader forever, so a child that never reaches its `read`
/// (because a signal killed it first, say) would hang the case instead of
/// failing it. The open is non-blocking, retried until `DEADLINE`: with no
/// reader it fails with ENXIO rather than waiting.
fn release_fifo(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt;
    let deadline = Instant::now() + DEADLINE;
    let mut file = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => break file,
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
                assert!(
                    Instant::now() < deadline,
                    "nothing ever opened {} to read; the child is not waiting on it",
                    path.display()
                );
                std::thread::sleep(TICK);
            }
            Err(error) => panic!("open {}: {error}", path.display()),
        }
    };
    file.write_all(b"go\n").unwrap();
}

// ----------------------------------------------------------------- the PTY

struct Pty {
    master: RawFd,
    slave: RawFd,
}

impl Pty {
    fn open() -> Self {
        let mut master = 0;
        let mut slave = 0;
        // SAFETY: both out-parameters are valid writable slots; null for the
        // name, termios and winsize asks for the defaults.
        let result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "openpty: {}", std::io::Error::last_os_error());
        Self { master, slave }
    }

    fn write_control(&self, byte: u8) {
        // SAFETY: a one-byte write to a descriptor this value owns.
        let written =
            unsafe { libc::write(self.master, &byte as *const u8 as *const libc::c_void, 1) };
        assert_eq!(
            written,
            1,
            "control write: {}",
            std::io::Error::last_os_error()
        );
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        // SAFETY: both descriptors are owned by this value.
        unsafe {
            libc::close(self.slave);
            libc::close(self.master);
        }
    }
}

// ------------------------------------------------------------- the harness

/// Re-executed by the cases below; not a test on its own.
#[test]
#[ignore = "re-executed as the supervisor for the cases in this file"]
fn supervisor_harness() {
    let Ok(scenario) = std::env::var("TOG_SUPERVISE_SCENARIO") else {
        return;
    };
    // A probe run as a supervised child, not a supervisor: it reports the
    // SIGCHLD disposition it was exec'd with and needs no store.
    if scenario == "report-sigchld" {
        say(&format!("CHILD_SIGCHLD {}", sigchld_disposition()));
        std::process::exit(0);
    }
    if scenario == "int-counter" {
        int_counter();
    }
    if scenario == "term-counter" {
        term_counter();
    }
    #[cfg(target_os = "linux")]
    if scenario == "report-fds" {
        for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                say(&format!(
                    "{} {}",
                    entry.file_name().to_string_lossy(),
                    target.display()
                ));
            }
        }
        std::process::exit(0);
    }
    let root = PathBuf::from(std::env::var_os("TOG_SUPERVISE_STORE").unwrap());
    let store = Store::open_at(&root).unwrap();
    let activity = store.activity(ActivityMode::Shared).unwrap();
    let code = run_scenario(&scenario, &activity);
    drop(activity);
    std::process::exit(code);
}

fn shell(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(script);
    command
}

fn say(line: &str) {
    println!("{line}");
    std::io::stdout().flush().unwrap();
}

fn code_of(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Print how a supervised child ended and return it as the harness exit
/// code. A supervisor that was itself signalled while the child ran gets an
/// `Interrupted` error rather than the status, so that case prints
/// `INTERRUPTED <signal>` before the child's `EXIT <code>`.
fn report(result: std::io::Result<ExitStatus>) -> i32 {
    let status = match result {
        Ok(status) => status,
        Err(error) => {
            let interrupted = supervise::interrupted(&error)
                .unwrap_or_else(|| panic!("supervision failed: {error}"));
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
            say(&format!("INTERRUPTED {}", interrupted.signal));
            interrupted.status
        }
    };
    say(&format!("EXIT {}", code_of(status)));
    code_of(status)
}

/// The calling process's SIGCHLD disposition, in the words the markers use.
fn sigchld_disposition() -> &'static str {
    // SAFETY: zeroed is a valid output slot that sigaction fills.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a null new action only queries the current one.
    let queried = unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) };
    assert_eq!(queried, 0, "{}", std::io::Error::last_os_error());
    let nocldwait = action.sa_flags & libc::SA_NOCLDWAIT != 0;
    match action.sa_sigaction {
        libc::SIG_IGN => "ignored",
        libc::SIG_DFL if nocldwait => "default-nocldwait",
        libc::SIG_DFL => "default",
        _ if nocldwait => "handler-nocldwait",
        _ => "handler",
    }
}

extern "C" fn inherited_sigchld_handler(_: libc::c_int) {}

static INTS_SEEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn count_int(_: libc::c_int) {
    INTS_SEEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

static TERMS_SEEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn count_term(_: libc::c_int) {
    TERMS_SEEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

// Acknowledge each delivery after the native handler returns. A shell trap
// can discard a TERM received while its previous trap is still executing,
// even after that trap has printed the acknowledgement.
fn term_counter() -> ! {
    // SAFETY: the initialized action points to an atomic-only handler.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        action.sa_sigaction = count_term as extern "C" fn(libc::c_int) as *const () as usize;
        assert_eq!(
            libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()),
            0
        );
    }
    say(&format!("CHILDPID {}", std::process::id()));
    say("READY");
    let mut reported = 0;
    loop {
        let seen = TERMS_SEEN.load(std::sync::atomic::Ordering::SeqCst);
        if seen != reported {
            say(&format!("GOT {seen}"));
            reported = seen;
        }
        if seen >= 3 {
            std::process::exit(46);
        }
        std::thread::sleep(TICK);
    }
}

/// How long the counting child keeps running after its first INT, so a
/// second delivery (a forwarded copy, which follows the first within
/// milliseconds) lands in the count rather than after the exit.
const INT_GRACE: Duration = Duration::from_millis(500);

/// A supervised child that counts every INT in the handler itself: a
/// shell trap runs once for any number of INTs that arrive before it gets
/// to run, which would hide a duplicate. Prints `INTSEEN <n>` as the count
/// changes; `INT_GRACE` after the first one it prints `INTCOUNT <n>` and
/// exits 48, so the only signal the supervisor ever sees is the INT under
/// test. The token is deliberately not "INT": a PTY echoes the ^C that
/// generated the signal, and an echo must not be counted as delivery.
fn int_counter() -> ! {
    use std::sync::atomic::Ordering;
    // SAFETY: zeroed is followed by sigemptyset; the handler only touches
    // an atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        action.sa_sigaction = count_int as extern "C" fn(libc::c_int) as *const () as usize;
        assert_eq!(
            libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()),
            0
        );
    }
    say(&format!("CHILDPID {}", std::process::id()));
    say("READY");
    let mut reported = 0;
    let mut first_seen: Option<Instant> = None;
    loop {
        let seen = INTS_SEEN.load(Ordering::SeqCst);
        if seen != reported {
            say(&format!("INTSEEN {seen}"));
            reported = seen;
            first_seen.get_or_insert_with(Instant::now);
        }
        if first_seen.is_some_and(|at| at.elapsed() >= INT_GRACE) {
            say(&format!("INTCOUNT {seen}"));
            std::process::exit(48);
        }
        std::thread::sleep(TICK);
    }
}

/// Installs a SIGCHLD handler with `SA_NOCLDWAIT`, which asks the kernel to
/// reap children as they exit just as `SIG_IGN` does. A handler cannot
/// survive exec, so this one is set by the harness itself.
fn set_sigchld_nocldwait() {
    // SAFETY: zeroed is followed by sigemptyset; the handler is a no-op.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_NOCLDWAIT;
        action.sa_sigaction = inherited_sigchld_handler as *const () as usize;
        assert_eq!(
            libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()),
            0
        );
    }
}

/// The binary, run from the case's scratch home against the case's store.
fn tog_command(args: &[&str]) -> Command {
    let home = PathBuf::from(std::env::var_os("TOG_SUPERVISE_HOME").unwrap());
    let store = PathBuf::from(std::env::var_os("TOG_SUPERVISE_STORE").unwrap());
    let mut command = command(&home, &home, &store);
    command.args(args);
    command
}

static RECORDED_SIGNALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn record_one(_: libc::c_int) {
    RECORDED_SIGNALS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Install a handler that only counts `number`, as code that ran before
/// tog's first session might.
fn record_signal(number: libc::c_int) {
    // SAFETY: zeroed is followed by sigemptyset; the handler only touches
    // an atomic.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        action.sa_sigaction = record_one as extern "C" fn(libc::c_int) as *const () as usize;
        assert_eq!(libc::sigaction(number, &action, std::ptr::null_mut()), 0);
    }
}

fn signal_named(name: &str) -> libc::c_int {
    match name {
        "TERM" => libc::SIGTERM,
        "INT" => libc::SIGINT,
        "HUP" => libc::SIGHUP,
        "QUIT" => libc::SIGQUIT,
        other => panic!("unknown signal {other}"),
    }
}

/// A child that leaves a grandchild holding its stdout and stderr open on a
/// `read < fifo`, writes its own pid to `<fifo>.pid`, and exits: it is
/// reaped while `output` still drains its pipes.
fn drained_child(fifo: &str) -> Command {
    shell(&format!(
        r#"(read line < "{fifo}") &
           printf "%d\n" $$ > "{fifo}.pid.tmp"
           mv "{fifo}.pid.tmp" "{fifo}.pid"
           exit 0"#
    ))
}

fn run_scenario(scenario: &str, activity: &StoreActivity) -> i32 {
    match scenario {
        "boundary" => {
            match supervise::status(&mut shell("printf 'BOUNDARY_CHILD\\n'; exit 7"), activity) {
                Ok(status) => say(&format!("BOUNDARY_OK {}", code_of(status))),
                Err(error) => say(&format!("BOUNDARY_ERR {:?}", error.kind())),
            }
            say("DONE");
            0
        }
        "blocked-orphan" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let result = supervise::output(&mut drained_child(&fifo), activity);
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
            let next = supervise::status(&mut shell("printf 'UNEXPECTED_CHILD\\n'"), activity);
            assert_eq!(next.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
            say("PENDING_REFUSED");
            // SAFETY: unblock the signal this scenario's debug failpoint blocked.
            unsafe {
                let mut set = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGTERM);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()),
                    0
                );
            }
            panic!("the pending inherited TERM should terminate the process");
        }
        "oneshot-inherited" => {
            record_signal(libc::SIGTERM);
            // SAFETY: query the action just installed and make it one-shot.
            unsafe {
                let mut action = std::mem::zeroed();
                assert_eq!(
                    libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut action),
                    0
                );
                action.sa_flags |= libc::SA_RESETHAND;
                assert_eq!(
                    libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()),
                    0
                );
            }
            supervise::status(&mut shell("exit 0"), activity).unwrap();
            // SAFETY: signal the current thread with a valid signal number.
            unsafe { libc::raise(libc::SIGTERM) };
            say(&format!(
                "HANDLED {}",
                RECORDED_SIGNALS.load(std::sync::atomic::Ordering::SeqCst)
            ));
            unsafe { libc::raise(libc::SIGTERM) };
            panic!("the one-shot handler should reset to the default");
        }
        "inherited-no-restart" => {
            record_signal(libc::SIGTERM);
            // SAFETY: query the action just installed and disable syscall restart.
            unsafe {
                let mut action = std::mem::zeroed();
                assert_eq!(
                    libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut action),
                    0
                );
                action.sa_flags &= !libc::SA_RESTART;
                assert_eq!(
                    libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()),
                    0
                );
            }
            supervise::status(&mut shell("exit 0"), activity).unwrap();
            let (reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
            let done = std::sync::atomic::AtomicBool::new(false);
            // SAFETY: the calling thread stays live until the signal sender joins.
            let target = unsafe { libc::pthread_self() } as usize;
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    let deadline = Instant::now() + DEADLINE;
                    // Repeated signal injection is the stimulus. It covers a
                    // delivery just before read starts without a timing guess.
                    while !done.load(std::sync::atomic::Ordering::SeqCst) {
                        assert!(Instant::now() < deadline, "read was not interrupted");
                        // SAFETY: target is a live thread and TERM has a recording handler.
                        unsafe { libc::pthread_kill(target as libc::pthread_t, libc::SIGTERM) };
                        std::thread::yield_now();
                    }
                });
                let mut byte = 0u8;
                // SAFETY: reader is owned here and byte is a writable one-byte buffer.
                let count =
                    unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
                let error = std::io::Error::last_os_error();
                done.store(true, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(count, -1);
                assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
            });
            say("READ_INTERRUPTED");
            0
        }
        // Announces its pid, traps TERM, and blocks inside the trap on a FIFO
        // so the case can inspect the world mid-termination.
        "term-during-wait" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let mut command = shell(&format!(
                r#"trap 'printf "CHILD_TERM\n"; read line < "{fifo}"; exit 45' TERM
                   printf "CHILDPID %d\nREADY\n" $$
                   while : ; do sleep 0.05 ; done"#
            ));
            report(supervise::status(&mut command, activity))
        }
        // The same child without a rendezvous, used to sweep the spawn
        // boundary and to receive a group-directed TERM.
        "term-trap" => {
            let mut command = shell(
                r#"trap 'printf "CHILD_TERM\n"; exit 45' TERM
                   printf "CHILDPID %d\nREADY\n" $$
                   while : ; do sleep 0.05 ; done"#,
            );
            match supervise::status(&mut command, activity) {
                Err(error) if supervise::interrupted(&error).is_none() => {
                    say(&format!("ERR {error}"));
                    70
                }
                result => report(result),
            }
        }
        "repeat-term" => {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
                .env("TOG_SUPERVISE_SCENARIO", "term-counter");
            report(supervise::status(&mut command, activity))
        }
        // A child that never sees the signal: INT sent to the supervisor
        // alone is observed, not forwarded, so the child finishes cleanly
        // once the FIFO releases it and the supervisor still reports the
        // interrupt.
        "int-to-supervisor" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let mut command = shell(&format!(
                r#"printf "CHILDPID %d\nREADY\n" $$
                   read line < "{fifo}"
                   exit 0"#
            ));
            let code = report(supervise::status(&mut command, activity));
            // The next child in the same process starts from a clean
            // session: the interrupt was reported once and is not replayed.
            let after = supervise::status(&mut shell("exit 7"), activity).unwrap();
            say(&format!("AFTER {}", code_of(after)));
            code
        }
        // Two sessions at once. Each child waits until the other has
        // started, so both are provably running together; each exits with
        // its own code.
        "concurrent" => {
            let dir = std::env::var("TOG_SUPERVISE_HOME").unwrap();
            let child = |me: &str, other: &str, code: i32| {
                shell(&format!(
                    r#"touch "{dir}/{me}"
                       i=0
                       while [ ! -e "{dir}/{other}" ]; do
                         i=$((i+1)); [ $i -gt 3000 ] && exit 99
                         sleep 0.01
                       done
                       exit {code}"#
                ))
            };
            let (a, b) = std::thread::scope(|scope| {
                let a = scope.spawn(|| supervise::status(&mut child("a", "b", 11), activity));
                let b = scope.spawn(|| supervise::status(&mut child("b", "a", 12), activity));
                (a.join().unwrap(), b.join().unwrap())
            });
            say(&format!(
                "CONCURRENT {} {}",
                code_of(a.unwrap()),
                code_of(b.unwrap())
            ));
            say("DONE");
            0
        }
        // Two live sessions whose children trap TERM; one TERM to the
        // supervisor must reach both.
        "term-two" => {
            let child = |name: &str| {
                shell(&format!(
                    r#"trap 'printf "CHILD_TERM {name}\n"; exit 45' TERM
                       printf "READY {name}\n"
                       while : ; do sleep 0.05 ; done"#
                ))
            };
            let (a, b) = std::thread::scope(|scope| {
                let a = scope.spawn(|| report(supervise::status(&mut child("A"), activity)));
                let b = scope.spawn(|| report(supervise::status(&mut child("B"), activity)));
                (a.join().unwrap(), b.join().unwrap())
            });
            if a == 45 && b == 45 {
                45
            } else {
                1
            }
        }
        // A's child is inside its TERM trap when B registers; B's child
        // must not inherit that TERM.
        "late-session" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let gate = format!("{fifo}-gate");
            std::thread::scope(|scope| {
                let a = scope.spawn(|| {
                    let mut command = shell(&format!(
                        r#"trap 'printf "CHILD_TERM\n"; read line < "{fifo}"; exit 45' TERM
                           printf "READY\n"
                           while : ; do sleep 0.05 ; done"#
                    ));
                    report(supervise::status(&mut command, activity))
                });
                std::fs::read_to_string(&gate).unwrap();
                match supervise::status(&mut shell("exit 0"), activity) {
                    Ok(status) => say(&format!("B EXIT {}", code_of(status))),
                    Err(error) => say(&format!("B ERR {error}")),
                }
                a.join().unwrap();
            });
            say("DONE");
            0
        }
        // How a signal acts once no session is live. TOG_SUPERVISE_INNER is
        // `<TERM|INT|HUP|QUIT>-<default|handler>`: with `handler` the
        // supervisor installs a recording handler before its first session
        // and then signals itself; with `default` it waits for the case to
        // signal it, and should die of it.
        "inherited-after" => {
            let inner = std::env::var("TOG_SUPERVISE_INNER").unwrap();
            let (name, mode) = inner.split_once('-').unwrap();
            let number = signal_named(name);
            if mode == "handler" {
                record_signal(number);
            }
            let status = supervise::status(&mut shell("exit 0"), activity).unwrap();
            say(&format!("SESSION {}", code_of(status)));
            if mode == "handler" {
                // SAFETY: a plain kill(2) of this process.
                unsafe { libc::kill(libc::getpid(), number) };
                let deadline = Instant::now() + DEADLINE;
                while RECORDED_SIGNALS.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                    assert!(Instant::now() < deadline, "the recording handler never ran");
                    std::thread::sleep(TICK);
                }
                say(&format!(
                    "HANDLED {}",
                    RECORDED_SIGNALS.load(std::sync::atomic::Ordering::SeqCst)
                ));
                say("DONE");
                return 0;
            }
            say("READY");
            loop {
                std::thread::park_timeout(Duration::from_millis(50));
            }
        }
        // A child that is reaped while a grandchild still holds its output
        // pipe open, so `output` keeps draining after the reap. Its pid goes
        // to `<fifo>.pid` so the case can tell when it has been reaped.
        "term-after-reap" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let mut command = drained_child(&fifo);
            let result = supervise::output(&mut command, activity);
            say(&format!(
                "RETURNED {:?}",
                result
                    .map(|output| code_of(output.status))
                    .map_err(|error| error.to_string())
            ));
            say("DONE");
            0
        }
        // A as in `term-after-reap` (its TERM can only be orphaned), B with
        // a live child that traps TERM. TOG_SUPERVISE_INNER says nothing;
        // the case decides which session ends first.
        "orphan-two" => {
            let base = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let fifo_a = format!("{base}-a");
            let fifo_b = format!("{base}-b");
            std::thread::scope(|scope| {
                let a = scope.spawn(|| {
                    let result = supervise::output(&mut drained_child(&fifo_a), activity);
                    say(&format!(
                        "A RETURNED {:?}",
                        result
                            .map(|output| code_of(output.status))
                            .map_err(|error| error.to_string())
                    ));
                });
                let b = scope.spawn(|| {
                    let mut command = shell(&format!(
                        r#"trap 'printf "B_TERM\n"; read line < "{fifo_b}"; exit 45' TERM
                           printf "B READY\n"
                           while : ; do sleep 0.05 ; done"#
                    ));
                    let result = supervise::status(&mut command, activity);
                    say(&format!(
                        "B RETURNED {:?}",
                        result.map(code_of).map_err(|error| error.to_string())
                    ));
                });
                a.join().unwrap();
                b.join().unwrap();
            });
            say("DONE");
            0
        }
        // A sees TOG_SUPERVISE_INNER (INT, HUP or QUIT) and ends; then an
        // unrelated child exit, and B, which must spawn normally.
        "old-signal" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let mut command = shell(&format!(
                r#"printf "CHILDPID %d\nREADY\n" $$
                   read line < "{fifo}"
                   exit 0"#
            ));
            report(supervise::status(&mut command, activity));
            let unrelated = Command::new("/bin/sh").args(["-c", "exit 0"]).status();
            assert!(unrelated.unwrap().success());
            match supervise::status(&mut shell("exit 7"), activity) {
                Ok(status) => say(&format!("AFTER {}", code_of(status))),
                Err(error) => say(&format!("AFTER_ERR {error}")),
            }
            say("DONE");
            0
        }
        // Fifteen children on each of two threads at the default tick.
        "concurrent-latency" => {
            std::thread::scope(|scope| {
                for name in ["A", "B"] {
                    scope.spawn(move || {
                        let start = Instant::now();
                        for _ in 0..15 {
                            let status =
                                supervise::status(&mut shell("sleep 0.105"), activity).unwrap();
                            assert!(status.success(), "child did not exit cleanly");
                        }
                        say(&format!("TOTAL {name} {}", start.elapsed().as_millis()));
                    });
                }
            });
            say("DONE");
            0
        }
        // Eight threads of fifty short children with their own exit codes,
        // and a ninth listing the descriptors its children hold.
        "churn" => {
            let count_fds = || std::fs::read_dir("/proc/self/fd").unwrap().count();
            let pipes = || -> std::collections::BTreeSet<String> {
                std::fs::read_dir("/proc/self/fd")
                    .unwrap()
                    .flatten()
                    .filter_map(|entry| std::fs::read_link(entry.path()).ok())
                    .map(|target| target.to_string_lossy().into_owned())
                    .filter(|target| target.starts_with("pipe:"))
                    .collect()
            };
            let inherited_pipes = pipes();
            // Warm-up: the first session creates the process's one pipe.
            supervise::status(&mut shell("exit 0"), activity).unwrap();
            let before = count_fds();
            let own_pipes: std::collections::BTreeSet<_> =
                pipes().difference(&inherited_pipes).cloned().collect();
            assert_eq!(
                own_pipes.len(),
                1,
                "warm-up must create the notification pipe"
            );
            let wrong = std::sync::atomic::AtomicUsize::new(0);
            let leaked = std::sync::Mutex::new(Vec::new());
            std::thread::scope(|scope| {
                for thread in 0..8 {
                    let wrong = &wrong;
                    scope.spawn(move || {
                        for index in 0..50 {
                            let code = (thread * 31 + index) % 250;
                            let status =
                                supervise::status(&mut shell(&format!("exit {code}")), activity)
                                    .unwrap();
                            if code_of(status) != code {
                                wrong.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    });
                }
                scope.spawn(|| {
                    for _ in 0..10 {
                        let mut probe = Command::new(std::env::current_exe().unwrap());
                        probe
                            .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
                            .env("TOG_SUPERVISE_SCENARIO", "report-fds");
                        let listing = supervise::output(&mut probe, activity).unwrap();
                        for line in String::from_utf8_lossy(&listing.stdout).lines() {
                            let Some((fd, target)) = line.split_once(' ') else {
                                continue;
                            };
                            let fd: i32 = fd.parse().unwrap_or(-1);
                            if fd > 2 && own_pipes.contains(target) {
                                leaked.lock().unwrap().push(line.to_string());
                            }
                        }
                    }
                });
            });
            let after = count_fds();
            say(&format!(
                "CHURN wrong={} before={before} after={after} leaked={:?}",
                wrong.load(std::sync::atomic::Ordering::SeqCst),
                leaked.lock().unwrap()
            ));
            say("DONE");
            0
        }
        // The first install fails (TOG_SUPERVISE_FAILPOINT); with
        // TOG_SUPERVISE_INNER `session` a second session follows. Then the
        // supervisor waits for the case's TERM.
        "install-fail" => {
            match supervise::status(&mut shell("exit 0"), activity) {
                Ok(status) => say(&format!("FIRST_OK {}", code_of(status))),
                Err(error) => say(&format!("FIRST_ERR {error}")),
            }
            if std::env::var("TOG_SUPERVISE_INNER").as_deref() == Ok("session") {
                let second = supervise::status(&mut shell("exit 7"), activity).unwrap();
                say(&format!("SECOND {}", code_of(second)));
            }
            say("READY");
            loop {
                std::thread::park_timeout(Duration::from_millis(50));
            }
        }
        // The first install pauses after one of its `sigaction` calls
        // (TOG_SUPERVISE_FAILPOINT); the case sends TERM then.
        "install-pause" => {
            let status = supervise::status(&mut shell("exit 0"), activity).unwrap();
            say(&format!("SURVIVED {}", code_of(status)));
            0
        }
        // Two `int-counter` children at once under a terminal.
        "int-two" => {
            let counter = || {
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
                    .env("TOG_SUPERVISE_SCENARIO", "int-counter");
                command
            };
            let (a, b) = std::thread::scope(|scope| {
                let a = scope.spawn(|| report(supervise::status(&mut counter(), activity)));
                let b = scope.spawn(|| report(supervise::status(&mut counter(), activity)));
                (a.join().unwrap(), b.join().unwrap())
            });
            if a == 48 && b == 48 {
                48
            } else {
                1
            }
        }
        // Fifteen children that each outlive one former poll tick. Event-driven
        // waiting costs each child only its own lifetime; a 100 ms tick rounds
        // every reap up to the next boundary, so the difference accumulates
        // into something a clock can separate without a tight margin.
        "reap-latency" => {
            let start = Instant::now();
            for _ in 0..15 {
                let status = supervise::status(&mut shell("sleep 0.105"), activity).unwrap();
                assert!(status.success(), "child did not exit cleanly");
            }
            say(&format!("TOTAL {}", start.elapsed().as_millis()));
            say("DONE");
            0
        }
        // Three children through one lease: a numeric exit, a clean exit, and
        // a self-signalled exit, each printed as the raw wait status
        // `supervise::status` returned.
        "sequential" => {
            let raw = |status: ExitStatus| {
                format!("code={:?} signal={:?}", status.code(), status.signal())
            };
            let first = supervise::status(&mut shell("exit 42"), activity).unwrap();
            say(&format!("A {}", raw(first)));
            let second = supervise::status(&mut shell("exit 0"), activity).unwrap();
            say(&format!("B {}", raw(second)));
            let third = supervise::status(&mut shell("kill -TERM $$"), activity).unwrap();
            say(&format!("C {}", raw(third)));
            say("DONE");
            0
        }
        // A failed spawn must not leave a session installed: the next child
        // still runs, and a later TERM still kills the supervisor normally.
        "spawn-fail" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let mut missing = Command::new("/nonexistent/tog-supervise-probe");
            match supervise::status(&mut missing, activity) {
                Ok(status) => say(&format!("UNEXPECTED {}", code_of(status))),
                Err(error) => say(&format!("ERR {:?}", error.kind())),
            }
            // The failed spawn must not have left the supervisor without its
            // handlers: this child ignores TERM, so a TERM arriving now can
            // only be survived if the parent is catching and forwarding it.
            // Without a session the parent takes the default action and dies.
            let mut guarded = shell(&format!(
                r#"trap '' TERM
                   printf "GUARDED\n"
                   read line < "{fifo}"
                   exit 9"#
            ));
            let guarded = supervise::status(&mut guarded, activity).unwrap_err();
            let interrupted = supervise::interrupted(&guarded).expect("an interrupted child");
            say(&format!(
                "GUARDED_INTERRUPTED {} GUARDED_EXIT {}",
                interrupted.signal,
                code_of(interrupted.status)
            ));
            let after = supervise::status(&mut shell("exit 7"), activity).unwrap();
            say(&format!("AFTER {}", code_of(after)));
            say("READY");
            loop {
                std::thread::park_timeout(Duration::from_millis(50));
            }
        }
        "fds" => {
            let mut command = shell(r#"ls -l /proc/self/fd; printf "DONE\n""#);
            let status = supervise::status(&mut command, activity).unwrap();
            code_of(status)
        }
        // Characterisation only: SIGPIPE is deliberately not "fixed", so this
        // records what the toolchain actually hands the child.
        "sigpipe" => {
            let mut command = shell(r#"kill -PIPE $$; printf "SURVIVED\n""#);
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!(
                "SIGPIPE code={:?} signal={:?}",
                status.code(),
                status.signal()
            ));
            say("DONE");
            0
        }
        "self-stop" => {
            let mut command = shell(
                r#"printf "CHILDPID %d\nREADY\n" $$
                   kill -STOP $$
                   printf "RESUMED\n"
                   exit 47"#,
            );
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!("EXIT {}", code_of(status)));
            code_of(status)
        }
        // The child is `int-counter`, which counts INT in its signal handler
        // and exits only a grace period later, so a second delivery (a
        // forwarded copy of the terminal's INT) is counted rather than lost
        // to an exit or merged into one shell trap run.
        "int-trap" => {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
                .env("TOG_SUPERVISE_SCENARIO", "int-counter");
            report(supervise::status(&mut command, activity))
        }
        // A job-control shell: its own session owns the terminal, and the
        // supervisor runs in a separate foreground process group. Without
        // this layer the supervisor's group would be orphaned and the kernel
        // would discard terminal stop signals instead of delivering them.
        "shell" => {
            let inner = std::env::var("TOG_SUPERVISE_INNER").unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
                .env("TOG_SUPERVISE_SCENARIO", inner)
                .env_remove("TOG_SUPERVISE_INNER");
            // SAFETY: setpgid only touches the post-fork child.
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = command.spawn().unwrap();
            let pid = child.id() as i32;
            // SAFETY: the shell hands its controlling terminal to the job's
            // process group, exactly as an interactive shell does. SIGTTOU is
            // ignored so reclaiming the terminal later cannot stop the shell.
            unsafe {
                libc::signal(libc::SIGTTOU, libc::SIG_IGN);
                libc::setpgid(pid, pid);
                libc::tcsetpgrp(0, pid);
            }
            say(&format!("SHELLCHILD {pid}"));
            loop {
                let mut status = 0;
                // SAFETY: waitpid on this process's own child, reporting
                // stops and continuations the way a job-control shell does.
                let reported =
                    unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED | libc::WCONTINUED) };
                if reported < 0 {
                    say("SHELL LOST");
                    break;
                }
                if libc::WIFSTOPPED(status) {
                    say(&format!("SHELL STOPPED {}", libc::WSTOPSIG(status)));
                } else if libc::WIFCONTINUED(status) {
                    say("SHELL CONTINUED");
                } else if libc::WIFEXITED(status) {
                    say(&format!("SHELL EXITED {}", libc::WEXITSTATUS(status)));
                    break;
                } else if libc::WIFSIGNALED(status) {
                    say(&format!("SHELL SIGNALED {}", libc::WTERMSIG(status)));
                    break;
                }
            }
            // SAFETY: the shell takes its terminal back before exiting.
            unsafe { libc::tcsetpgrp(0, libc::getpgrp()) };
            std::mem::forget(child);
            0
        }
        "orphan-boundary" => {
            let mut command = shell(
                r#"printf "CHILDPID %d\nREADY\n" $$
                   while : ; do sleep 0.05 ; done"#,
            );
            let status = supervise::status(&mut command, activity).unwrap();
            code_of(status)
        }
        // A nested exclusive command must report busy rather than wait for a
        // lease its own parent holds.
        "nested-gc" => {
            let mut command = tog_command(&["gc", "--dry-run"]);
            // gc narrates on stderr (CLI.md: stdout is for documents), and
            // this harness's marker stream is its stdout, so the busy line
            // is folded into it here.
            let output = supervise::output(&mut command, activity).unwrap();
            say(String::from_utf8_lossy(&output.stderr).trim_end());
            say(&format!("NESTED {}", code_of(output.status)));
            code_of(output.status)
        }
        // A nested read-only command must simply finish.
        "nested-roots" => {
            let mut command = tog_command(&["store", "roots"]);
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!("NESTED {}", code_of(status)));
            code_of(status)
        }
        // SIGCHLD as the supervisor found it: `sigchld-ignored` inherited
        // SIG_IGN across exec, `sigchld-nocldwait` sets a handler with
        // SA_NOCLDWAIT here. Either way the kernel would reap the children
        // itself unless the session takes SIGCHLD over.
        "sigchld-ignored" | "sigchld-nocldwait" => {
            if scenario == "sigchld-nocldwait" {
                set_sigchld_nocldwait();
            }
            say(&format!("INHERITED {}", sigchld_disposition()));
            match supervise::status(&mut shell("exit 42"), activity) {
                Ok(status) => say(&format!("STATUS {}", code_of(status))),
                Err(error) => say(&format!("STATUS_ERR {error}")),
            }
            match supervise::output(&mut shell("printf out; exit 43"), activity) {
                Ok(output) => say(&format!(
                    "OUTPUT {} {}",
                    code_of(output.status),
                    String::from_utf8_lossy(&output.stdout)
                )),
                Err(error) => say(&format!("OUTPUT_ERR {error}")),
            }
            let mut probe = Command::new(std::env::current_exe().unwrap());
            probe
                .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
                .env("TOG_SUPERVISE_SCENARIO", "report-sigchld");
            match supervise::status(&mut probe, activity) {
                Ok(status) => say(&format!("PROBE {}", code_of(status))),
                Err(error) => say(&format!("PROBE_ERR {error}")),
            }
            say(&format!("AFTER {}", sigchld_disposition()));
            say("DONE");
            0
        }
        other => panic!("unknown scenario {other}"),
    }
}

// ------------------------------------------------------------------- cases

/// A parent TERM during an ordinary wait reaches the child, and the
/// store stays protected until the child is actually reaped.
#[test]
fn parent_term_reaches_the_child_and_holds_activity_until_reap() {
    let store = TempStore::new("term-wait");
    let fifo = store.fifo("fifo");
    let mut harness = spawn_harness("term-during-wait", &store, None, Some(&fifo));
    harness.markers.wait_for("READY");
    let child = harness.markers.child_pid();
    assert!(!store.is_free(), "a running job must hold the store lease");

    signal(harness.pid(), libc::SIGTERM);
    harness.markers.wait_for("CHILD_TERM");

    // The child is now inside its TERM handler, blocked on the FIFO: the
    // supervisor has seen TERM, has not reaped, and must not have released
    // the store.
    assert!(
        alive(child),
        "child should still be running its TERM handler"
    );
    assert!(
        !store.is_free(),
        "activity was released while a terminating child was still using the store"
    );

    release_fifo(&fifo);
    harness.markers.wait_for("EXIT 45");
    assert!(
        harness.markers.text().contains("INTERRUPTED 15"),
        "a TERM during the wait was not reported as an interruption:\n{}",
        harness.markers.text()
    );
    let status = harness.finish();
    assert_eq!(
        status.code(),
        Some(45),
        "output:\n{}",
        harness.markers.text()
    );
    store.wait_until_free();
    assert!(!alive(child), "child survived its supervisor");
}

/// TERM anywhere across the spawn boundary is either rejected before
/// launch or delivered to the launched child. It is never lost, and it never
/// leaves a child running behind a supervisor that reported success.
#[test]
fn term_across_the_spawn_boundary_is_never_lost() {
    let store = TempStore::new("race");
    let mut outcomes = std::collections::BTreeMap::new();
    for step in 0..24u64 {
        let mut harness = spawn_harness("term-trap", &store, None, None);
        // The varying delay is the stimulus: it walks the injection point
        // across process start, session install, spawn, and the wait loop.
        std::thread::sleep(Duration::from_micros(step * 900));
        // The harness may already be gone; losing that race is not a failure.
        // SAFETY: plain kill(2) on a process this test created.
        unsafe { libc::kill(harness.pid(), libc::SIGTERM) };
        let status = harness.finish();
        harness.markers.settle();
        let text = harness.markers.text();
        let outcome = match (status.code(), status.signal()) {
            (Some(45), _) => "child handled TERM",
            // The forwarded TERM reached the child before its shell had
            // installed the trap: still delivered, not lost.
            (Some(143), _) => "child killed before its trap",
            (Some(70), _) => "cancelled before spawn",
            (_, Some(libc::SIGTERM)) => "supervisor died before its session",
            other => panic!("unexpected outcome {other:?} at step {step}; output:\n{text}"),
        };
        if matches!(status.code(), Some(45 | 143)) {
            assert!(
                text.contains("INTERRUPTED 15"),
                "step {step}: the child's TERM exit was reported as its own status:\n{text}"
            );
        }
        *outcomes.entry(outcome).or_insert(0u32) += 1;
        if text.contains("CHILDPID ") {
            let child = harness.markers.child_pid();
            assert!(
                !alive(child),
                "step {step}: child {child} outlived its supervisor ({outcome})"
            );
        }
        store.wait_until_free();
    }
    println!("spawn-boundary outcomes: {outcomes:?}");
    assert!(
        outcomes.contains_key("child handled TERM")
            || outcomes.contains_key("child killed before its trap"),
        "the sweep never reached a spawned child: {outcomes:?}"
    );
}

/// Repeated parent TERM stays meaningful; the supervisor does not
/// permanently suppress every TERM after the first.
#[test]
fn repeated_parent_term_is_forwarded_every_time() {
    let store = TempStore::new("repeat");
    let mut harness = spawn_harness("repeat-term", &store, None, None);
    harness.markers.wait_for("READY");
    signal(harness.pid(), libc::SIGTERM);
    harness.markers.wait_for("GOT 1");
    signal(harness.pid(), libc::SIGTERM);
    harness.markers.wait_for("GOT 2");
    signal(harness.pid(), libc::SIGTERM);
    harness.markers.wait_for("GOT 3");
    harness.markers.wait_for("EXIT 46");
    assert!(
        harness.markers.text().contains("INTERRUPTED 15"),
        "{}",
        harness.markers.text()
    );
    assert_eq!(harness.finish().code(), Some(46));
    store.wait_until_free();
}

/// Sequential children through one lease each get their own wait status
/// back from `supervise::status`: a numeric exit as its code, and a
/// signalled child as "signalled", with no code. The 128 + signal mapping
/// at the command boundary is not exercised here: it lives in `tog run`,
/// which needs a synced environment. Session reset across those children is
/// covered by `spawn_failure_restores_dispositions`, which is the case that
/// actually distinguishes an installed session from an absent one.
#[test]
fn sequential_children_report_numeric_and_signal_wait_statuses() {
    let store = TempStore::new("sequential");
    let mut harness = spawn_harness("sequential", &store, None, None);
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(text.contains("A code=Some(42) signal=None"), "{text}");
    assert!(text.contains("B code=Some(0) signal=None"), "{text}");
    assert!(text.contains("C code=None signal=Some(15)"), "{text}");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// The wait is driven by the child transition itself, not by a timer.
/// Under the former 100 ms poll every reap was rounded up to the next tick,
/// so fifteen children that each live just past one tick paid roughly a
/// second of pure waiting on top of their own runtime.
///
/// This is the one case in this file whose subject *is* latency, so it is the
/// one case that reads a clock. The bound is deliberately loose: event-driven
/// waiting spends about 15 x 105 ms = 1.6 s, a 100 ms tick spends about
/// 15 x 200 ms = 3.0 s, and 2.4 s sits clear of both.
#[test]
fn a_child_exit_wakes_the_supervisor_without_waiting_for_a_poll_tick() {
    let store = TempStore::new("reap-latency");
    // A one-minute tick: only the signal's own wake can meet the bound.
    let mut harness = spawn_harness_with("reap-latency", &store, None, None, |command| {
        command.env("TOG_SUPERVISE_TICK_MS", "60000");
    });
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    let total: u128 = text
        .lines()
        .find_map(|line| line.strip_prefix("TOTAL "))
        .unwrap_or_else(|| panic!("no TOTAL marker in {text}"))
        .trim()
        .parse()
        .unwrap();
    assert!(
        total < 2400,
        "fifteen 105 ms children took {total} ms; a 100 ms poll tick rounds \
         every reap up to the next boundary instead of following SIGCHLD"
    );
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// A failed spawn restores the inherited dispositions, so the next
/// child still runs and a later TERM kills the supervisor normally instead
/// of being swallowed by a leftover handler.
#[test]
fn spawn_failure_restores_dispositions() {
    let store = TempStore::new("spawn-fail");
    let fifo = store.fifo("spawn-fail-fifo");
    let mut harness = spawn_harness("spawn-fail", &store, None, Some(&fifo));
    harness.markers.wait_for("GUARDED");
    let text = harness.markers.text();
    assert!(
        text.contains("ERR "),
        "the spawn failure was not reported: {text}"
    );

    // Mid-child: the session is installed, so the supervisor catches TERM,
    // forwards it to a child that ignores it, and keeps waiting.
    signal(harness.pid(), libc::SIGTERM);
    release_fifo(&fifo);
    harness
        .markers
        .wait_for("GUARDED_INTERRUPTED 15 GUARDED_EXIT 9");
    assert!(
        harness.process.try_wait().unwrap().is_none(),
        "the supervisor died of a TERM it had installed a handler for"
    );

    // Session over: the inherited disposition is back, so TERM kills.
    harness.markers.wait_for("AFTER 7");
    harness.markers.wait_for("READY");
    signal(harness.pid(), libc::SIGTERM);
    let status = harness.finish();
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "the supervisor's temporary TERM handler outlived its session: {status:?}"
    );
    store.wait_until_free();
}

/// No child sees the activity lease descriptor.
#[cfg(target_os = "linux")]
#[test]
fn children_do_not_inherit_the_activity_descriptor() {
    let store = TempStore::new("fds");
    let mut harness = spawn_harness("fds", &store, None, None);
    harness.markers.wait_for("DONE");
    harness.finish();
    harness.markers.settle();
    let text = harness.markers.text();
    assert!(
        !text.contains(".lock"),
        "a child inherited a Tog lock descriptor:\n{text}"
    );
    store.wait_until_free();
}

/// SIGPIPE is characterised, not "fixed". The child gets the
/// toolchain's default disposition rather than Tog's inherited ignore.
#[test]
fn sigpipe_reaches_the_child_with_the_toolchain_default() {
    let store = TempStore::new("sigpipe");
    let mut harness = spawn_harness("sigpipe", &store, None, None);
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(
        text.contains("signal=Some(13)"),
        "SIGPIPE was not the default disposition in the child: {text}"
    );
    assert!(
        !text.contains("SURVIVED"),
        "the child inherited an ignored SIGPIPE: {text}"
    );
    harness.finish();
    store.wait_until_free();
}

/// A child that stops itself keeps the supervisor waiting and the
/// store protected; continuing it lets the job finish normally.
#[cfg(target_os = "linux")]
#[test]
fn a_child_that_stops_itself_keeps_the_store_protected() {
    let store = TempStore::new("self-stop");
    let mut harness = spawn_harness("self-stop", &store, None, None);
    harness.markers.wait_for("READY");
    let child = harness.markers.child_pid();
    wait_for_state(child, 'T', "the child to stop itself");
    assert!(
        harness.process.try_wait().unwrap().is_none(),
        "the supervisor returned while its child was stopped"
    );
    assert!(!store.is_free(), "a stopped job released the store");
    signal(child, libc::SIGCONT);
    harness.markers.wait_for("RESUMED");
    harness.markers.wait_for("EXIT 47");
    assert_eq!(harness.finish().code(), Some(47));
    store.wait_until_free();
}

/// Terminal ^Z stops the whole foreground group, the controlling
/// process can observe the stopped job as a shell would, and continuing it
/// resumes both processes.
#[cfg(target_os = "linux")]
#[test]
fn terminal_stop_and_continue_covers_the_whole_group() {
    let store = TempStore::new("pty-tstp");
    let pty = Pty::open();
    // The job-control shell layer matters: a supervisor whose process group
    // is orphaned would have its terminal stop signals discarded by the
    // kernel, and the case would pass for the wrong reason.
    let mut harness = spawn_harness("shell:term-trap", &store, Some(&pty), None);
    harness.markers.wait_for("SHELLCHILD ");
    let supervisor = harness
        .markers
        .text()
        .lines()
        .find_map(|line| line.trim().strip_prefix("SHELLCHILD ")?.trim().parse().ok())
        .expect("the shell announced its job");
    harness.markers.wait_for("READY");
    let child = harness.markers.child_pid();

    pty.write_control(0x1a); // ^Z
                             // The controlling shell observes the stopped job, exactly as an
                             // interactive shell would report "Stopped".
    harness
        .markers
        .wait_for(&format!("SHELL STOPPED {}", libc::SIGTSTP));
    wait_for_state(supervisor, 'T', "the supervisor to stop");
    wait_until_stopped(child, "the child to stop");
    assert!(!store.is_free(), "a stopped job released the store");

    signal(-supervisor, libc::SIGCONT);
    harness.markers.wait_for("SHELL CONTINUED");
    signal(supervisor, libc::SIGTERM);
    harness.markers.wait_for("CHILD_TERM");
    harness.markers.wait_for("SHELL EXITED 45");
    harness.finish();
    store.wait_until_free();
}

/// Terminal INT reaches a trapping child once, through terminal group
/// delivery rather than through forwarding.
#[test]
fn terminal_interrupt_reaches_a_trapping_child_once() {
    let store = TempStore::new("pty-int");
    let pty = Pty::open();
    let mut harness = spawn_harness("int-trap", &store, Some(&pty), None);
    harness.markers.wait_for("READY");

    pty.write_control(0x03); // ^C
                             // The child outlives its INT by a grace period before it reports the
                             // count and exits, so a forwarded copy would have been counted.
    harness.markers.wait_for("EXIT 48");
    let text = harness.markers.text();
    let seen = text.matches("INTSEEN").count();
    assert_eq!(seen, 1, "the child saw INT {seen} times:\n{text}");
    assert!(text.contains("INTCOUNT 1"), "{text}");
    assert!(
        text.contains("INTERRUPTED 2"),
        "a terminal interrupt was reported as the child's own exit:\n{text}"
    );
    assert_eq!(harness.finish().code(), Some(48));
    store.wait_until_free();
}

/// An interrupt counts even when the child never sees it and exits
/// cleanly: INT sent to the supervisor alone is not forwarded, and the
/// supervisor still reports it once the child is reaped instead of passing
/// the clean status on. The next child in the same process runs normally.
#[cfg(target_os = "linux")]
#[test]
fn an_interrupt_the_child_never_sees_is_still_reported() {
    let store = TempStore::new("int-supervisor");
    let fifo = store.fifo("int-supervisor-fifo");
    let mut harness = spawn_harness("int-to-supervisor", &store, None, Some(&fifo));
    harness.markers.wait_for("READY");
    let child = harness.markers.child_pid();
    signal(harness.pid(), libc::SIGINT);
    // Release the child only once the supervisor's handler has taken the
    // signal; a still-pending INT would race the child's exit instead.
    wait_until_delivered(harness.pid(), libc::SIGINT);
    assert!(alive(child), "INT sent to the supervisor reached the child");
    release_fifo(&fifo);
    harness.markers.wait_for("AFTER 7");
    let text = harness.markers.text();
    assert!(text.contains("INTERRUPTED 2"), "{text}");
    assert!(text.contains("EXIT 0"), "{text}");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// A group-directed TERM reaches parent and child. The documented
/// guarantee is only that the child terminates, not exactly-once delivery,
/// so this records the delivery count instead of asserting one.
#[test]
fn group_term_terminates_the_child_without_promising_exactly_once() {
    let store = TempStore::new("group-term");
    let mut harness = spawn_harness("term-trap", &store, None, None);
    harness.markers.wait_for("READY");
    let child = harness.markers.child_pid();
    signal(-harness.pid(), libc::SIGTERM);
    harness.markers.wait_for("EXIT 45");
    let text = harness.markers.text();
    let delivered = text
        .lines()
        .filter(|line| line.trim() == "CHILD_TERM")
        .count();
    println!("group TERM was delivered to the child {delivered} time(s)");
    assert!(delivered >= 1, "{text}");
    assert!(text.contains("INTERRUPTED 15"), "{text}");
    assert_eq!(harness.finish().code(), Some(45));
    assert!(!alive(child));
    store.wait_until_free();
}

/// SIGKILL of the supervisor cannot be caught. The lease is released
/// and the child may survive; the boundary is documented, not defended, so
/// the case records what happened and cleans up after itself.
#[test]
fn supervisor_sigkill_releases_activity_and_may_orphan_the_child() {
    let store = TempStore::new("kill9");
    let mut harness = spawn_harness("orphan-boundary", &store, None, None);
    harness.markers.wait_for("READY");
    let child = harness.markers.child_pid();
    signal(harness.pid(), libc::SIGKILL);
    assert_eq!(harness.finish().signal(), Some(libc::SIGKILL));
    store.wait_until_free();
    println!(
        "after supervisor SIGKILL the child was {}",
        if alive(child) { "orphaned" } else { "gone" }
    );
    // SAFETY: plain kill(2) on a process this test created.
    unsafe { libc::kill(child, libc::SIGKILL) };
}

/// A nested exclusive command reports busy instead of waiting forever
/// on the lease its own parent holds.
#[test]
fn a_nested_exclusive_command_reports_busy() {
    let store = TempStore::new("nested-gc");
    let mut harness = spawn_harness("nested-gc", &store, None, None);
    harness.markers.wait_for("NESTED ");
    harness.finish();
    harness.markers.settle();
    let text = harness.markers.text();
    assert!(
        text.contains("cleanup skipped: a Tog job is using this store"),
        "nested gc did not report busy:\n{text}"
    );
    assert!(
        text.contains("NESTED 0"),
        "nested gc did not exit 0:\n{text}"
    );
    store.wait_until_free();
}

/// A nested read-only command simply completes.
#[test]
fn a_nested_read_only_command_completes() {
    let store = TempStore::new("nested-roots");
    let mut harness = spawn_harness("nested-roots", &store, None, None);
    harness.markers.wait_for("NESTED 0");
    harness.finish();
    store.wait_until_free();
}

/// A supervisor started with SIGCHLD ignored still reports its child's exit
/// status. POSIX lets the kernel reap the children of a process that
/// ignores SIGCHLD, so without the session's own handler `try_wait` finds no
/// child (ECHILD) and the status is lost. The child still execs with the
/// SIG_IGN tog inherited.
#[test]
fn inherited_sigchld_ignore_still_reports_the_exit_status() {
    let store = TempStore::new("sigchld-ignored");
    let mut harness = spawn_harness_with("sigchld-ignored", &store, None, None, |command| {
        // SAFETY: signal only touches the post-fork child, and an ignored
        // disposition survives exec.
        unsafe {
            command.pre_exec(|| {
                if libc::signal(libc::SIGCHLD, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    });
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(text.contains("INHERITED ignored"), "{text}");
    assert!(text.contains("STATUS 42"), "{text}");
    assert!(text.contains("OUTPUT 43 out"), "{text}");
    assert!(
        text.contains("CHILD_SIGCHLD ignored"),
        "the child did not get the inherited SIG_IGN back: {text}"
    );
    assert!(text.contains("PROBE 0"), "{text}");
    // The handler stays once installed (supervision never uninstalls it),
    // so tog's later unsupervised children keep their exit status too.
    assert!(text.contains("AFTER handler"), "{text}");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// The same with a SIGCHLD handler that sets `SA_NOCLDWAIT`, the other way a
/// parent can ask the kernel to reap its children. The child sees SIG_DFL,
/// which is what exec makes of any inherited handler.
#[test]
fn inherited_sigchld_nocldwait_still_reports_the_exit_status() {
    let store = TempStore::new("sigchld-nocldwait");
    let mut harness = spawn_harness("sigchld-nocldwait", &store, None, None);
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(text.contains("INHERITED handler-nocldwait"), "{text}");
    assert!(text.contains("STATUS 42"), "{text}");
    assert!(text.contains("OUTPUT 43 out"), "{text}");
    assert!(text.contains("CHILD_SIGCHLD default"), "{text}");
    assert!(text.contains("PROBE 0"), "{text}");
    assert!(text.contains("AFTER handler"), "{text}");
    assert!(!text.contains("AFTER handler-nocldwait"), "{text}");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// Two sessions in one process each supervise their own child at the same
/// time and each gets its own child's exit code back.
#[test]
fn concurrent_sessions_each_supervise_their_own_child() {
    let store = TempStore::new("concurrent");
    let mut harness = spawn_harness("concurrent", &store, None, None);
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(text.contains("CONCURRENT 11 12"), "{text}");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// One TERM reaches the child of every live session. Each child handled
/// it, so nothing is re-raised: the supervisor exits with their code.
#[test]
fn parent_term_reaches_every_live_child() {
    let store = TempStore::new("term-two");
    let mut harness = spawn_harness("term-two", &store, None, None);
    harness.markers.wait_for("READY A");
    harness.markers.wait_for("READY B");
    signal(harness.pid(), libc::SIGTERM);
    let status = harness.finish();
    harness.markers.settle();
    let text = harness.markers.text();
    assert!(text.contains("CHILD_TERM A"), "{text}");
    assert!(text.contains("CHILD_TERM B"), "{text}");
    assert_eq!(text.matches("INTERRUPTED 15").count(), 2, "{text}");
    assert_eq!(status.code(), Some(45), "{text}");
    store.wait_until_free();
}

/// A session that registers after a TERM was counted does not inherit it.
#[test]
fn a_session_registered_after_term_does_not_inherit_it() {
    let store = TempStore::new("late-session");
    let fifo = store.fifo("late");
    let gate = store.fifo("late-gate");
    let mut harness = spawn_harness("late-session", &store, None, Some(&fifo));
    harness.markers.wait_for("READY");
    signal(harness.pid(), libc::SIGTERM);
    harness.markers.wait_for("CHILD_TERM");
    release_fifo(&gate);
    harness.markers.wait_for("B ");
    release_fifo(&fifo);
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(text.contains("B EXIT 0"), "{text}");
    assert!(text.contains("INTERRUPTED 15"), "{text}");
    assert!(text.contains("EXIT 45"), "{text}");
    assert_eq!(harness.finish().code(), Some(0), "{text}");
    store.wait_until_free();
}

/// After a session ends, each of TERM/INT/HUP/QUIT acts as the disposition
/// tog inherited: the default kills tog, and a handler installed before
/// the first session runs once and tog carries on.
#[test]
fn dispositions_act_as_inherited_whenever_no_session_is_live() {
    for name in ["TERM", "INT", "HUP", "QUIT"] {
        let number = signal_named(name);
        let store = TempStore::new(&format!("inherited-{name}"));
        let mut harness = spawn_harness(
            &format!("inherited-after:{name}-default"),
            &store,
            None,
            None,
        );
        harness.markers.wait_for("READY");
        signal(harness.pid(), number);
        let status = harness.finish();
        assert_eq!(
            status.signal(),
            Some(number),
            "{name}: inherited default, {status:?}; output:\n{}",
            harness.markers.text()
        );
        store.wait_until_free();

        let mut harness = spawn_harness(
            &format!("inherited-after:{name}-handler"),
            &store,
            None,
            None,
        );
        harness.markers.wait_for("DONE");
        let text = harness.markers.text();
        assert!(text.contains("SESSION 0"), "{name}: {text}");
        assert!(text.contains("HANDLED 1"), "{name}: {text}");
        assert_eq!(harness.finish().code(), Some(0), "{name}: {text}");
        store.wait_until_free();
    }
}

/// A TERM that arrives after the child is reaped but while `output` still
/// drains its pipes reaches no child, so it is re-raised when the session
/// ends and tog dies of it, as it would with no session at all.
#[test]
fn term_after_reap_but_before_the_pipes_close_is_not_swallowed() {
    let store = TempStore::new("term-after-reap");
    let fifo = store.fifo("drain");
    let mut harness = spawn_harness("term-after-reap", &store, None, Some(&fifo));
    wait_until_reaped(&fifo);
    signal(harness.pid(), libc::SIGTERM);
    #[cfg(target_os = "linux")]
    wait_until_delivered(harness.pid(), libc::SIGTERM);
    // The grandchild still reads the FIFO; releasing it closes the pipes
    // and ends the session.
    release_fifo(&fifo);
    let status = harness.finish();
    harness.markers.settle();
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "{status:?}; output:\n{}",
        harness.markers.text()
    );
    store.wait_until_free();
}

/// One TERM while two sessions are live: B forwards it to its child, A's
/// child was already reaped. A's copy is an orphan, so whichever session
/// ends last re-raises it and tog dies of TERM, in either order.
#[test]
fn a_term_orphaned_by_one_session_reraises_though_another_consumed_it() {
    for a_first in [true, false] {
        let store = TempStore::new(if a_first { "orphan-a" } else { "orphan-b" });
        let base = store.temp.0.join("orphan");
        let fifo_a = store.fifo("orphan-a");
        let fifo_b = store.fifo("orphan-b");
        let mut harness = spawn_harness("orphan-two", &store, None, Some(&base));
        wait_until_reaped(&fifo_a);
        harness.markers.wait_for("B READY");
        signal(harness.pid(), libc::SIGTERM);
        harness.markers.wait_for("B_TERM");
        if a_first {
            release_fifo(&fifo_a);
            harness.markers.wait_for("A RETURNED");
            release_fifo(&fifo_b);
        } else {
            release_fifo(&fifo_b);
            harness.markers.wait_for("B RETURNED");
            release_fifo(&fifo_a);
        }
        let status = harness.finish();
        harness.markers.settle();
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "a_first={a_first}: {status:?}; output:\n{}",
            harness.markers.text()
        );
        store.wait_until_free();
    }
}

/// A TERM at A's final counter check stays orphaned while B finishes.
#[test]
fn a_term_during_departure_is_not_lost_by_a_nonfinal_session() {
    let store = TempStore::new("orphan-departure");
    let base = store.temp.0.join("orphan");
    let fifo_a = store.fifo("orphan-a");
    let fifo_b = store.fifo("orphan-b");
    let gate = store.fifo("departure");
    let mut harness = spawn_harness_with("orphan-two", &store, None, Some(&base), |command| {
        command
            .env("TOG_SUPERVISE_FAILPOINT", "before-deregister")
            .env("TOG_SUPERVISE_FAILPOINT_FIFO", &gate);
    });
    wait_until_reaped(&fifo_a);
    harness.markers.wait_for("B READY");
    release_fifo(&fifo_a);
    harness
        .markers
        .wait_for("FAILPOINT PAUSED before-deregister");
    signal(harness.pid(), libc::SIGTERM);
    harness.markers.wait_for("B_TERM");
    release_fifo(&gate);
    harness.markers.wait_for("A RETURNED");
    release_fifo(&fifo_b);
    assert_eq!(harness.finish().signal(), Some(libc::SIGTERM));
    store.wait_until_free();
}

/// Every non-TERM interrupt is retained across both session boundaries.
#[test]
fn interrupts_at_registration_and_departure_are_reported() {
    for boundary in ["after-register", "before-deregister"] {
        for name in ["INT", "HUP", "QUIT"] {
            let store = TempStore::new(&format!("boundary-{boundary}-{name}"));
            let gate = store.fifo("boundary");
            let mut harness = spawn_harness_with("boundary", &store, None, None, |command| {
                command
                    .env("TOG_SUPERVISE_FAILPOINT", boundary)
                    .env("TOG_SUPERVISE_FAILPOINT_FIFO", &gate)
                    .env("TOG_SUPERVISE_BOUNDARY_SIGNAL", name);
            });
            harness
                .markers
                .wait_for(&format!("FAILPOINT PAUSED {boundary}"));
            release_fifo(&gate);
            harness.markers.wait_for("DONE");
            let text = harness.markers.text();
            assert!(
                text.contains("BOUNDARY_ERR Interrupted"),
                "{boundary}/{name}: {text}"
            );
            assert_eq!(
                text.contains("BOUNDARY_CHILD"),
                boundary == "before-deregister",
                "{text}"
            );
            assert_eq!(harness.finish().code(), Some(0));
            store.wait_until_free();
        }
    }
}

/// A caller blocking TERM cannot pass a pending replay to a later child.
#[test]
fn a_blocked_orphaned_term_closes_admission_until_inherited_delivery() {
    let store = TempStore::new("blocked-orphan");
    let fifo = store.fifo("drain");
    let gate = store.fifo("reraise");
    let mut harness = spawn_harness_with("blocked-orphan", &store, None, Some(&fifo), |command| {
        command
            .env("TOG_SUPERVISE_FAILPOINT", "before-reraise")
            .env("TOG_SUPERVISE_FAILPOINT_FIFO", &gate);
    });
    wait_until_reaped(&fifo);
    signal(harness.pid(), libc::SIGTERM);
    #[cfg(target_os = "linux")]
    wait_until_delivered(harness.pid(), libc::SIGTERM);
    release_fifo(&fifo);
    harness.markers.wait_for("FAILPOINT PAUSED before-reraise");
    release_fifo(&gate);
    let status = harness.finish();
    harness.markers.settle();
    let text = harness.markers.text();
    assert!(text.contains("PENDING_REFUSED"), "{text}");
    assert!(!text.contains("UNEXPECTED_CHILD"), "{text}");
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{text}");
    store.wait_until_free();
}

#[test]
fn an_inherited_one_shot_handler_resets_after_its_first_delivery() {
    let store = TempStore::new("oneshot");
    let mut harness = spawn_harness("oneshot-inherited", &store, None, None);
    let status = harness.finish();
    harness.markers.settle();
    assert!(harness.markers.text().contains("HANDLED 1"));
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    store.wait_until_free();
}

#[test]
fn an_inherited_handler_without_restart_still_interrupts_a_read() {
    let store = TempStore::new("no-restart");
    let mut harness = spawn_harness("inherited-no-restart", &store, None, None);
    let status = harness.finish();
    harness.markers.settle();
    assert!(harness.markers.text().contains("READ_INTERRUPTED"));
    assert_eq!(status.code(), Some(0));
    store.wait_until_free();
}

/// An INT, HUP or QUIT one session saw is not reported again to a session
/// that registers after it ended.
#[cfg(target_os = "linux")]
#[test]
fn an_old_signal_is_not_reported_to_a_later_session() {
    for name in ["INT", "HUP", "QUIT"] {
        let number = signal_named(name);
        let store = TempStore::new(&format!("old-{name}"));
        let fifo = store.fifo("old");
        let mut harness = spawn_harness("old-signal", &store, None, Some(&fifo));
        harness.markers.wait_for("READY");
        signal(harness.pid(), number);
        wait_until_delivered(harness.pid(), number);
        release_fifo(&fifo);
        harness.markers.wait_for("DONE");
        let text = harness.markers.text();
        assert!(
            text.contains(&format!("INTERRUPTED {number}")),
            "{name}: {text}"
        );
        assert!(text.contains("AFTER 7"), "{name}: {text}");
        assert_eq!(harness.finish().code(), Some(0), "{name}: {text}");
        store.wait_until_free();
    }
}

/// Two threads reaping fifteen short children each stay within the bound a
/// lone session meets: the tick only bounds how late a wake byte another
/// session took is noticed.
#[test]
fn concurrent_reap_latency_is_bounded_by_the_tick() {
    let store = TempStore::new("concurrent-latency");
    let mut harness = spawn_harness("concurrent-latency", &store, None, None);
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    for name in ["A", "B"] {
        let total: u128 = text
            .lines()
            .find_map(|line| line.trim().strip_prefix(&format!("TOTAL {name} ")))
            .unwrap_or_else(|| panic!("no TOTAL {name} in {text}"))
            .trim()
            .parse()
            .unwrap();
        assert!(total < 2400, "thread {name} took {total} ms:\n{text}");
    }
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// Four hundred children across eight threads all report their own exit
/// code, the process ends with the descriptors it started with, and no
/// child holds an end of the supervisor's pipes.
#[cfg(target_os = "linux")]
#[test]
fn session_churn_loses_no_exit_and_leaks_no_descriptor() {
    let store = TempStore::new("churn");
    let mut harness = spawn_harness_with("churn", &store, None, None, |command| {
        // Deliberately inherit a launcher pipe above stderr. The leak check
        // must distinguish this descriptor from the supervisor's own pipe.
        // SAFETY: fcntl only duplicates the post-fork child's stdout.
        unsafe {
            command.pre_exec(|| {
                if libc::fcntl(1, libc::F_DUPFD, 100) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    });
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    let line = text
        .lines()
        .find(|line| line.starts_with("CHURN "))
        .unwrap_or_else(|| panic!("no CHURN line in {text}"));
    assert!(line.contains("wrong=0 "), "{line}");
    let field = |name: &str| -> usize {
        line.split_whitespace()
            .find_map(|part| part.strip_prefix(&format!("{name}=")))
            .unwrap()
            .parse()
            .unwrap()
    };
    assert_eq!(field("before"), field("after"), "{line}");
    assert!(line.ends_with("leaked=[]"), "{line}");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// A first install that fails at its k-th `sigaction` returns an error,
/// leaves TERM acting as inherited, and the next session installs the rest
/// and supervises normally.
#[test]
fn a_failed_first_install_leaves_signals_behaving_as_inherited() {
    for call in 1..=5 {
        for then in ["term", "session"] {
            let store = TempStore::new(&format!("install-fail-{call}-{then}"));
            let mut harness = spawn_harness_with(
                &format!("install-fail:{then}"),
                &store,
                None,
                None,
                |command| {
                    command.env("TOG_SUPERVISE_FAILPOINT", format!("fail-sigaction-{call}"));
                },
            );
            harness.markers.wait_for("READY");
            let text = harness.markers.text();
            assert!(text.contains("FIRST_ERR"), "{call}/{then}: {text}");
            if then == "session" {
                assert!(text.contains("SECOND 7"), "{call}/{then}: {text}");
            }
            signal(harness.pid(), libc::SIGTERM);
            let status = harness.finish();
            assert_eq!(
                status.signal(),
                Some(libc::SIGTERM),
                "{call}/{then}: {status:?}; output:\n{text}"
            );
            store.wait_until_free();
        }
    }
}

/// A TERM that arrives part-way through the first install, with no session
/// registered yet, acts as inherited: tog dies of it.
#[test]
fn a_term_during_first_install_acts_as_inherited() {
    for call in 1..=5 {
        let store = TempStore::new(&format!("install-pause-{call}"));
        let fifo = store.fifo("pause");
        let mut harness = spawn_harness_with("install-pause", &store, None, None, |command| {
            command
                .env(
                    "TOG_SUPERVISE_FAILPOINT",
                    format!("pause-after-sigaction-{call}"),
                )
                .env("TOG_SUPERVISE_FAILPOINT_FIFO", &fifo);
        });
        harness
            .markers
            .wait_for(&format!("FAILPOINT PAUSED {call}"));
        signal(harness.pid(), libc::SIGTERM);
        let status = harness.finish();
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "{call}: {status:?}; output:\n{}",
            harness.markers.text()
        );
        store.wait_until_free();
    }
}

/// Terminal INT reaches each of two concurrent children exactly once,
/// through the terminal's group delivery.
#[test]
fn terminal_interrupt_reaches_every_concurrent_child() {
    let store = TempStore::new("pty-int-two");
    let pty = Pty::open();
    let mut harness = spawn_harness("int-two", &store, Some(&pty), None);
    let deadline = Instant::now() + DEADLINE;
    while harness.markers.text().matches("READY").count() < 2 {
        assert!(
            Instant::now() < deadline,
            "both children never started:\n{}",
            harness.markers.text()
        );
        harness.markers.pump();
        harness.markers.poll_once(50);
    }
    pty.write_control(0x03); // ^C
    let status = harness.finish();
    harness.markers.settle();
    let text = harness.markers.text();
    assert_eq!(text.matches("INTCOUNT 1").count(), 2, "{text}");
    assert_eq!(text.matches("INTSEEN").count(), 2, "{text}");
    assert_eq!(text.matches("INTERRUPTED 2").count(), 2, "{text}");
    assert_eq!(status.code(), Some(48), "{text}");
    store.wait_until_free();
}

/// The pid a `drained_child` wrote, once its supervisor has reaped it.
fn wait_until_reaped(fifo: &Path) -> i32 {
    let pidfile = PathBuf::from(format!("{}.pid", fifo.display()));
    let deadline = Instant::now() + DEADLINE;
    loop {
        if let Ok(text) = std::fs::read_to_string(&pidfile) {
            let pid: i32 = text.trim().parse().unwrap();
            if !alive(pid) {
                return pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the drained child was never reaped"
        );
        std::thread::sleep(TICK);
    }
}
