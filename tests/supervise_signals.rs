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

#![cfg(unix)]

use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tog::kernel::activity::{ActivityMode, StoreActivity};
use tog::kernel::store::Store;
use tog::kernel::supervise;

/// Every wait in this file is bounded. A blown deadline fails the case with
/// the output collected so far rather than hanging the suite.
const DEADLINE: Duration = Duration::from_secs(30);
/// How often a bounded loop re-reads a state it is waiting on.
const TICK: Duration = Duration::from_millis(2);

// ---------------------------------------------------------------- utilities

fn unique(label: &str) -> String {
    format!(
        "tog-supervise-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// A disposable store. Never point `TOG_STORE` at a real store.
struct TempStore {
    root: PathBuf,
}

impl TempStore {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(unique(label));
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
        Self {
            root: root.canonicalize().unwrap(),
        }
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

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = tog::kernel::store::remove_tree(&self.root);
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
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    let (scenario, inner) = match scenario.split_once(':') {
        Some((outer, inner)) => (outer, Some(inner)),
        None => (scenario, None),
    };
    command
        .args(["--exact", "supervisor_harness", "--ignored", "--nocapture"])
        .env("TOG_SUPERVISE_SCENARIO", scenario)
        .env("TOG_SUPERVISE_STORE", &store.root)
        .env("RUST_BACKTRACE", "1")
        .env_remove("TOG_STORE");
    if let Some(inner) = inner {
        command.env("TOG_SUPERVISE_INNER", inner);
    }
    if let Some(fifo) = fifo {
        command.env("TOG_SUPERVISE_FIFO", fifo);
    }
    let markers;
    match pty {
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
            markers = None;
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
            markers = Some(());
        }
    }
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

/// A rendezvous FIFO that is removed even when its case fails.
struct Fifo(PathBuf);

impl Fifo {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(unique(label));
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: c_path is a valid NUL-terminated path this test owns.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Fifo {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Release a child blocked on `read < fifo`.
fn release_fifo(path: &Path) {
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
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
    let root = PathBuf::from(std::env::var_os("TOG_SUPERVISE_STORE").unwrap());
    let store = Store {
        root: root.canonicalize().unwrap(),
    };
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

fn tog_command(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tog"));
    command.args(args).env(
        "TOG_STORE",
        std::env::var_os("TOG_SUPERVISE_STORE").unwrap(),
    );
    command
}

fn run_scenario(scenario: &str, activity: &StoreActivity) -> i32 {
    match scenario {
        // Announces its pid, traps TERM, and blocks inside the trap on a FIFO
        // so the case can inspect the world mid-termination.
        "term-during-wait" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let mut command = shell(&format!(
                r#"trap 'printf "CHILD_TERM\n"; read line < "{fifo}"; exit 45' TERM
                   printf "CHILDPID %d\nREADY\n" $$
                   while : ; do sleep 0.05 ; done"#
            ));
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!("EXIT {}", code_of(status)));
            code_of(status)
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
                Ok(status) => {
                    say(&format!("EXIT {}", code_of(status)));
                    code_of(status)
                }
                Err(error) => {
                    say(&format!("ERR {error}"));
                    70
                }
            }
        }
        "repeat-term" => {
            let mut command = shell(
                r#"count=0
                   trap 'count=$((count+1)); printf "GOT %d\n" $count; [ $count -ge 3 ] && exit 46' TERM
                   printf "CHILDPID %d\nREADY\n" $$
                   while : ; do sleep 0.05 ; done"#,
            );
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!("EXIT {}", code_of(status)));
            code_of(status)
        }
        // A second supervisory session while one is live. The holder's child
        // announces itself on the FIFO, so the second attempt is made while
        // the first child is provably still running.
        "session-busy" => {
            let fifo = std::env::var("TOG_SUPERVISE_FIFO").unwrap();
            let mut outcome = String::new();
            std::thread::scope(|scope| {
                let holder = scope.spawn(|| {
                    supervise::status(
                        &mut shell(&format!("printf 'HOLDING\\n' > {fifo}; sleep 1")),
                        activity,
                    )
                    .unwrap()
                });
                // Opening the FIFO for read blocks until the held child writes,
                // so this is a rendezvous with the child's own progress rather
                // than a delay.
                std::fs::read_to_string(&fifo).unwrap();
                outcome = match supervise::status(&mut shell("exit 0"), activity) {
                    Ok(status) => format!("ACCEPTED {}", code_of(status)),
                    Err(error) => format!("REJECTED {:?}", error.kind()),
                };
                assert!(holder.join().unwrap().success());
            });
            say(&outcome);
            say("DONE");
            0
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
        // a self-signalled exit.
        "sequential" => {
            let first = supervise::status(&mut shell("exit 42"), activity).unwrap();
            say(&format!("A {}", code_of(first)));
            let second = supervise::status(&mut shell("exit 0"), activity).unwrap();
            say(&format!("B {}", code_of(second)));
            let third = supervise::status(&mut shell("kill -TERM $$"), activity).unwrap();
            say(&format!(
                "C {} raw_signal={:?}",
                code_of(third),
                third.signal()
            ));
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
            let guarded = supervise::status(&mut guarded, activity).unwrap();
            say(&format!("GUARDED_EXIT {}", code_of(guarded)));
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
        // The token is deliberately not "INT": a PTY echoes the ^C that
        // generated the signal, and an echo must not be counted as delivery.
        "int-trap" => {
            let mut command = shell(
                r#"trap 'printf "INTSEEN\n"; exit 48' INT
                   printf "CHILDPID %d\nREADY\n" $$
                   while : ; do sleep 0.05 ; done"#,
            );
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!("EXIT {}", code_of(status)));
            code_of(status)
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
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!("NESTED {}", code_of(status)));
            code_of(status)
        }
        // A nested read-only command must simply finish.
        "nested-roots" => {
            let mut command = tog_command(&["store", "roots"]);
            let status = supervise::status(&mut command, activity).unwrap();
            say(&format!("NESTED {}", code_of(status)));
            code_of(status)
        }
        // Captured output larger than a pipe buffer must not deadlock.
        "large-output" => {
            let mut command = shell("dd if=/dev/zero bs=1048576 count=4 2>/dev/null");
            let output = supervise::output(&mut command, activity).unwrap();
            say(&format!("BYTES {}", output.stdout.len()));
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
    let fifo = Fifo::new("fifo");
    let mut harness = spawn_harness("term-during-wait", &store, None, Some(fifo.path()));
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

    release_fifo(fifo.path());
    harness.markers.wait_for("EXIT 45");
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
    assert_eq!(harness.finish().code(), Some(46));
    store.wait_until_free();
}

/// Sequential children through one lease preserve numeric exits, and a
/// signalled child maps to 128 + signal at the command boundary while the raw
/// wait status still says "signalled". Session reset across those children is
/// covered by `spawn_failure_restores_dispositions`, which is the case that
/// actually distinguishes an installed session from an absent one.
#[test]
fn sequential_children_preserve_numeric_and_signal_exits() {
    let store = TempStore::new("sequential");
    let mut harness = spawn_harness("sequential", &store, None, None);
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(text.contains("A 42"), "{text}");
    assert!(text.contains("B 0"), "{text}");
    assert!(text.contains("C 143 raw_signal=Some(15)"), "{text}");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}

/// Supervision owns process-wide signal dispositions, so a second
/// concurrent session in one process is refused as busy instead of waiting on
/// a process-global mutex.
///
/// The rejection is deliberate: unit tests that supervise children from
/// sibling threads serialize on `SUPERVISION_TEST_LOCK`. If supervision ever
/// becomes per-operation, delete this case.
#[test]
fn a_second_supervisory_session_is_refused_rather_than_queued() {
    let store = TempStore::new("session-busy");
    let fifo = Fifo::new("session-busy-fifo");
    let mut harness = spawn_harness("session-busy", &store, None, Some(fifo.path()));
    harness.markers.wait_for("DONE");
    let text = harness.markers.text();
    assert!(
        text.contains("REJECTED WouldBlock"),
        "a concurrent session should report busy, got: {text}"
    );
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
    let mut harness = spawn_harness("reap-latency", &store, None, None);
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
    let fifo = Fifo::new("spawn-fail-fifo");
    let mut harness = spawn_harness("spawn-fail", &store, None, Some(fifo.path()));
    harness.markers.wait_for("GUARDED");
    let text = harness.markers.text();
    assert!(
        text.contains("ERR "),
        "the spawn failure was not reported: {text}"
    );

    // Mid-child: the session is installed, so the supervisor catches TERM,
    // forwards it to a child that ignores it, and keeps waiting.
    signal(harness.pid(), libc::SIGTERM);
    release_fifo(fifo.path());
    harness.markers.wait_for("GUARDED_EXIT 9");
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
    harness.markers.wait_for("EXIT 48");
    let text = harness.markers.text();
    let seen = text.matches("INTSEEN").count();
    assert_eq!(seen, 1, "the child saw INT {seen} times:\n{text}");
    assert_eq!(harness.finish().code(), Some(48));
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

/// Captured output larger than a pipe buffer is drained while the child
/// runs, so waiting for the child cannot deadlock.
#[test]
fn captured_output_larger_than_a_pipe_buffer_does_not_deadlock() {
    let store = TempStore::new("large-output");
    let mut harness = spawn_harness("large-output", &store, None, None);
    harness.markers.wait_for("BYTES 4194304");
    assert_eq!(harness.finish().code(), Some(0));
    store.wait_until_free();
}
