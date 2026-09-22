//! Output conventions (CLI.md): stdout is for results, stderr is for
//! narration. `--quiet` drops narration, `--verbose` adds decisions and the
//! command line of every subprocess tog starts, and color appears only
//! on a terminal, only on stderr, only on the words that carry state.
//!
//! Quiet is implemented at the file-descriptor level: fd 2 is pointed at
//! /dev/null after one private copy of the original stderr is kept for
//! errors. That silences every module's `eprintln!` and every subprocess
//! (uv, npm, cargo, ...) without threading a flag through them, and it
//! guarantees the one thing quiet must never hide: the error. A panic is
//! an error, so the panic hook writes through that saved copy too.

use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default)]
struct Settings {
    quiet: bool,
    verbose: bool,
    color: bool,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();
/// The saved original stderr when quiet redirected fd 2.
static ERROR_FD: OnceLock<i32> = OnceLock::new();

const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn settings() -> Settings {
    SETTINGS.get().copied().unwrap_or_default()
}

/// Apply the global options once, before any command runs. Repeated calls
/// keep the first settings.
pub fn init(quiet: bool, verbose: bool, no_color: bool) -> io::Result<()> {
    if SETTINGS.get().is_some() {
        return Ok(());
    }
    let color = !no_color && std::env::var_os("NO_COLOR").is_none() && io::stderr().is_terminal();
    let _ = SETTINGS.set(Settings {
        quiet,
        verbose: verbose && !quiet,
        color,
    });
    if quiet {
        silence_stderr()?;
    }
    install_panic_hook();
    Ok(())
}

/// A panic must reach the user whatever `--quiet` did to fd 2: the default
/// hook writes to fd 2, which quiet points at /dev/null, so the process
/// would exit 101 having printed nothing.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // A download may be holding the cursor's row. Clear it first, or
        // the panic prints onto the tail of the progress line.
        erase_progress_line();
        if ERROR_FD.get().is_none() {
            default(info);
            return;
        }
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|text| (*text).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panicked".to_string());
        let where_ = match info.location() {
            Some(location) => format!(" at {}:{}", location.file(), location.line()),
            None => String::new(),
        };
        write_error_channel(&format!(
            "tog: {}: {payload}{where_}\ntog: this is a bug in tog; please report it with the command you ran\n",
            paint("internal error", RED)
        ));
    }));
}

fn silence_stderr() -> io::Result<()> {
    let null = std::fs::OpenOptions::new().write(true).open("/dev/null")?;
    // SAFETY: plain fd duplication on fds this process owns; the saved copy
    // is marked close-on-exec so children never inherit the real stderr.
    unsafe {
        let saved = libc::dup(io::stderr().as_raw_fd());
        if saved < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(saved, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::dup2(null.as_raw_fd(), io::stderr().as_raw_fd()) < 0 {
            return Err(io::Error::last_os_error());
        }
        let _ = ERROR_FD.set(saved);
    }
    Ok(())
}

pub fn quiet() -> bool {
    settings().quiet
}

/// Run `job` with fd 1 pointed at fd 2, so whatever it or any child it
/// spawns prints reaches stderr, then put fd 1 back. `tog env` syncs
/// before it prints and its stdout is evaled by a shell: a package
/// manager's summary there would be executed as commands.
pub fn with_stdout_on_stderr<T>(job: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    with_fd_pointed_at(io::stdout().as_raw_fd(), io::stderr().as_raw_fd(), job)
}

/// The mechanism, over any two descriptors so it can be tested against a
/// pipe. Rust's own stdout buffer is flushed first, so nothing written
/// before the swap comes out after it on the wrong side.
fn with_fd_pointed_at<T>(
    fd: i32,
    target: i32,
    job: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    io::stdout().flush()?;
    // SAFETY: plain duplication of descriptors this process owns. The
    // saved copy is close-on-exec so no child inherits the real stdout,
    // and it is closed here on every path.
    let saved = unsafe { libc::dup(fd) };
    if saved < 0 {
        return Err(io::Error::last_os_error());
    }
    let swapped = unsafe {
        libc::fcntl(saved, libc::F_SETFD, libc::FD_CLOEXEC) >= 0 && libc::dup2(target, fd) >= 0
    };
    if !swapped {
        let error = io::Error::last_os_error();
        unsafe { libc::close(saved) };
        return Err(error);
    }
    let result = job();
    io::stdout().flush()?;
    let restored = unsafe { libc::dup2(saved, fd) } >= 0;
    let restore_error = io::Error::last_os_error();
    unsafe { libc::close(saved) };
    match (result, restored) {
        (Ok(_), false) => Err(restore_error),
        (result, _) => result,
    }
}

pub fn verbose() -> bool {
    settings().verbose
}

pub fn color() -> bool {
    settings().color
}

fn paint(word: &str, code: &str) -> String {
    if color() {
        format!("{code}{word}{RESET}")
    } else {
        word.to_string()
    }
}

/// Write to the real stderr even under `--quiet`.
fn write_error_channel(text: &str) {
    match ERROR_FD.get() {
        Some(&fd) => {
            // SAFETY: fd is a valid, open descriptor this module saved and
            // never closes; ManuallyDrop keeps File from closing it.
            let mut file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
            let _ = file.write_all(text.as_bytes());
        }
        None => {
            let _ = io::stderr().write_all(text.as_bytes());
        }
    }
}

/// A failure the command could not recover from. Always visible.
pub fn error(message: &str) {
    write_error_channel(&format!("tog: {}: {message}\n", paint("error", RED)));
}

/// The same failure for a `--json` command: one JSON object on stderr, so
/// stdout carries the document or nothing at all and a script never parses
/// prose. Never colored: this line is read by a program.
pub fn error_json(message: &str) {
    let object = serde_json::json!({ "error": message });
    write_error_channel(&format!("{object}\n"));
}

/// The prefix of an advisory's first line, before color is applied. Kept
/// plain so a caller can compare, store or re-color the text.
pub(crate) const WARNING_PREFIX: &str = "tog: warning: ";
/// The prefix of the fix line. The same 14 columns as `WARNING_PREFIX`, so
/// `fix:` right-aligns under `warning:`.
pub(crate) const FIX_PREFIX: &str = "tog:     fix: ";

/// Something the user should know that did not stop the command, and the
/// one command that resolves it. Suppressed by `--quiet` like all
/// narration.
///
/// `fix` is a command to paste into a shell: no leading "run", no trailing
/// period, no explanation — the explanation is the message. An advisory
/// with nothing for the user to do is not a warning; it is progress, so
/// print it with `note`.
pub fn warning(message: &str, fix: &str) {
    if quiet() {
        return;
    }
    eprint!("{}", warning_lines(message, fix));
}

/// Both lines as text, newlines included, for a caller that writes to a
/// handle of its own (the maintenance narration holds a locked stderr) and
/// must still look like every other advisory.
pub fn warning_lines(message: &str, fix: &str) -> String {
    debug_assert!(
        !fix.trim().is_empty(),
        "a warning names the command that resolves it: {message}"
    );
    debug_assert!(
        !fix.starts_with("run ") && !fix.starts_with("Run "),
        "the fix line is a command, not a sentence about one: {fix}"
    );
    format!("{}{}", advisory_line(message), fix_line(fix))
}

/// The first of the two lines, colored for the current terminal.
pub(crate) fn advisory_line(message: &str) -> String {
    format!("tog: {}: {message}\n", paint("warning", YELLOW))
}

/// The second of the two lines, colored for the current terminal. Green,
/// like `synced`: it is the way out, not the problem.
pub(crate) fn fix_line(command: &str) -> String {
    format!("tog:     {}: {command}\n", paint("fix", GREEN))
}

/// Progress narration.
pub fn note(message: &str) {
    if quiet() {
        return;
    }
    eprintln!("tog: {message}");
}

/// The line each ecosystem prints when its projection is in place.
pub fn synced(what: &str, target: &std::path::Path) {
    if quiet() {
        return;
    }
    eprintln!("{}: {what} -> {}", paint("synced", GREEN), target.display());
}

/// How often a download redraws its progress line. Slow enough that a
/// fast local mirror cannot flood a terminal, fast enough to look live.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

/// Bytes as a human reads them: three significant figures and a unit, so
/// the line does not change width every redraw.
pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
        ("B", 1),
    ];
    for (unit, scale) in UNITS {
        if bytes >= scale {
            if scale == 1 {
                return format!("{bytes} B");
            }
            return format!("{:.1} {unit}", bytes as f64 / scale as f64);
        }
    }
    "0 B".to_string()
}

/// The one-line body of a download's progress report. Pure, so the shape
/// is testable without a terminal.
pub(crate) fn progress_line(what: &str, done: u64, total: Option<u64>) -> String {
    match total {
        Some(total) if total > 0 => {
            let percent = (done.min(total) as f64 / total as f64 * 100.0).round() as u64;
            format!(
                "downloading {what}  {} / {} ({percent}%)",
                human_bytes(done),
                human_bytes(total)
            )
        }
        _ => format!("downloading {what}  {}", human_bytes(done)),
    }
}

/// A download's progress on stderr, redrawn in place and erased when it
/// ends. Narration, so `--quiet` silences it; a redrawn line is noise in a
/// log file, so a stderr that is not a terminal gets nothing either. The
/// value is inert in both cases, so callers need no branch.
pub struct Progress {
    what: String,
    total: Option<u64>,
    done: u64,
    drawn: bool,
    live: bool,
    next: Instant,
}

impl Progress {
    /// Start reporting a download of `what` (the artifact's name), with its
    /// total size when the server declared one.
    pub fn start(what: &str, total: Option<u64>) -> Self {
        Self {
            what: what.to_string(),
            total,
            done: 0,
            drawn: false,
            live: !quiet() && io::stderr().is_terminal(),
            next: Instant::now(),
        }
    }

    /// Account for `bytes` more, redrawing at most once per interval.
    ///
    /// Every write is ignored on failure: a closed or full stderr must not
    /// take down a download that is otherwise fine, and `eprint!` panics
    /// where `write!` returns.
    pub fn advance(&mut self, bytes: u64) {
        self.done = self.done.saturating_add(bytes);
        if !self.live {
            return;
        }
        let now = Instant::now();
        if now < self.next {
            return;
        }
        self.next = now + PROGRESS_INTERVAL;
        // \x1b[K clears the rest of the row, so a shorter line never leaves
        // the tail of a longer one behind.
        let mut stderr = io::stderr();
        let _ = write!(
            stderr,
            "\rtog: {}\x1b[K",
            progress_line(&self.what, self.done, self.total)
        );
        let _ = stderr.flush();
        self.drawn = true;
        LINE_HELD.store(true, Ordering::Relaxed);
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.live && self.drawn {
            erase_progress_line();
        }
    }
}

/// Is a progress line currently occupying the cursor's row? The panic hook
/// reads this so a crash mid-download does not print its message onto the
/// tail of `downloading cpython-3.12.14.tar.gz  12.0 MiB / 28.3 MiB (42%)`.
static LINE_HELD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
use std::sync::atomic::Ordering;

/// Return the cursor to a clean row if a progress line is holding it.
/// Idempotent, and a no-op when nothing was drawn.
fn erase_progress_line() {
    if !LINE_HELD.swap(false, Ordering::Relaxed) {
        return;
    }
    let mut stderr = io::stderr();
    let _ = write!(stderr, "\r\x1b[K");
    let _ = stderr.flush();
}

/// An argv rendered as a shell line the user can paste back.
pub fn shell_line<S: AsRef<str>>(argv: &[S]) -> String {
    argv.iter()
        .map(|word| shell_word(word.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decision-level detail, only under `--verbose`.
pub fn trace(message: &str) {
    if verbose() {
        eprintln!("tog: {} {message}", paint("[verbose]", DIM));
    }
}

/// The command line of a subprocess tog is about to start, only under
/// `--verbose`; the bug-report mode's most useful line.
pub fn trace_command(command: &std::process::Command) {
    if !verbose() {
        return;
    }
    let mut line = shell_word(&command.get_program().to_string_lossy());
    for arg in command.get_args() {
        line.push(' ');
        line.push_str(&shell_word(&arg.to_string_lossy()));
    }
    let cwd = command
        .get_current_dir()
        .map(|dir| format!(" (in {})", dir.display()))
        .unwrap_or_default();
    trace(&format!("run: {line}{cwd}"));
}

fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@+,".contains(c))
    {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child spawned inside the job inherits the redirected descriptor,
    /// and the descriptor is put back afterwards, on the error path too.
    #[test]
    fn a_job_and_its_children_print_to_the_redirected_descriptor() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_end, write_end) = (fds[0], fds[1]);
        let child = || {
            std::process::Command::new("sh")
                .args(["-c", "echo redirected-marker"])
                .status()
                .map(|_| ())
        };
        with_fd_pointed_at(io::stdout().as_raw_fd(), write_end, child).unwrap();
        let error = with_fd_pointed_at(io::stdout().as_raw_fd(), write_end, || {
            child()?;
            Err::<(), _>(io::Error::other("job failed"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "job failed");
        unsafe { libc::close(write_end) };
        let mut captured = String::new();
        // SAFETY: the read end is ours; File takes ownership and closes it.
        let mut reader = unsafe { File::from_raw_fd(read_end) };
        io::Read::read_to_string(&mut reader, &mut captured).unwrap();
        // The test harness writes its own progress to fd 1 meanwhile, so
        // the pipe holds those lines too; the two markers are what matters.
        assert_eq!(
            captured.matches("redirected-marker\n").count(),
            2,
            "{captured}"
        );
        // fd 1 is stdout again: a child sees a descriptor that is not the
        // (now closed) pipe.
        let after = std::process::Command::new("sh")
            .args(["-c", "echo after >&1"])
            .stdout(std::process::Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&after.stdout), "after\n");
    }

    #[test]
    fn shell_words_quote_only_when_needed() {
        assert_eq!(shell_word("uv"), "uv");
        assert_eq!(shell_word("--python-version=3.12"), "--python-version=3.12");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn progress_lines_name_the_artifact_and_scale_the_bytes() {
        assert_eq!(
            progress_line("cpython-3.12.tar.gz", 1024 * 1024, Some(4 * 1024 * 1024)),
            "downloading cpython-3.12.tar.gz  1.0 MiB / 4.0 MiB (25%)"
        );
        // No Content-Length: bytes so far, no percentage to invent.
        assert_eq!(
            progress_line("flask-3.0.0.whl", 2048, None),
            "downloading flask-3.0.0.whl  2.0 KiB"
        );
        // A declared total of zero cannot be divided by.
        assert_eq!(
            progress_line("empty.tar", 0, Some(0)),
            "downloading empty.tar  0 B"
        );
        // Overshoot (a server that under-declares) clamps at 100%.
        assert!(progress_line("x", 30, Some(10)).ends_with("(100%)"));
        assert_eq!(human_bytes(1), "1 B");
        assert_eq!(human_bytes(3 << 30), "3.0 GiB");
    }

    /// Progress is narration on a terminal. Under `cargo test` stderr is a
    /// pipe, so `live` must be false, nothing may be drawn, and no progress
    /// line may be left holding the cursor for the panic hook to clear.
    /// The byte count is kept regardless, because the caller reads it.
    #[test]
    fn progress_is_silent_when_stderr_is_not_a_terminal() {
        assert!(
            !io::stderr().is_terminal(),
            "the test harness is expected to capture stderr"
        );
        LINE_HELD.store(false, Ordering::Relaxed);
        let mut progress = Progress::start("artifact.tar.gz", Some(10));
        assert!(
            !progress.live,
            "a piped stderr must not get a progress line"
        );
        progress.advance(4);
        progress.advance(6);
        assert!(!progress.drawn, "a piped stderr was drawn to");
        assert!(
            !LINE_HELD.load(Ordering::Relaxed),
            "nothing was drawn, so no line is held"
        );
        assert_eq!(progress.done, 10);
        drop(progress);
        assert!(!LINE_HELD.load(Ordering::Relaxed));
    }

    /// The panic hook clears the row a live download is holding, so a crash
    /// mid-transfer does not print onto the tail of the progress line.
    #[test]
    fn a_held_progress_line_is_erased_once() {
        LINE_HELD.store(true, Ordering::Relaxed);
        erase_progress_line();
        assert!(!LINE_HELD.load(Ordering::Relaxed));
        // Idempotent: the hook and Drop can both run.
        erase_progress_line();
        assert!(!LINE_HELD.load(Ordering::Relaxed));
    }

    #[test]
    fn shell_lines_quote_each_word() {
        assert_eq!(
            shell_line(&["uv", "pip", "install", "a b"]),
            "uv pip install 'a b'"
        );
        assert_eq!(shell_line::<&str>(&[]), "");
    }

    /// Every warning is two lines: what happened, then the one command that
    /// resolves it, with `fix:` right-aligned under `warning:`.
    #[test]
    fn a_warning_is_followed_by_the_command_that_resolves_it() {
        // `init` was never called, so color is off and the text is plain.
        assert!(!color(), "the test process has no terminal");
        assert_eq!(
            warning_lines(
                "node_modules was a real directory; moved aside",
                "tog gc --project"
            ),
            "tog: warning: node_modules was a real directory; moved aside\n\
             tog:     fix: tog gc --project\n"
        );
        assert_eq!(
            WARNING_PREFIX.len(),
            FIX_PREFIX.len(),
            "the two labels must line up"
        );
        assert_eq!(advisory_line("x"), format!("{WARNING_PREFIX}x\n"));
        assert_eq!(
            fix_line("tog --fresh"),
            format!("{FIX_PREFIX}tog --fresh\n")
        );
    }

    #[test]
    fn defaults_are_plain_and_loud() {
        // Before init: no quiet, no verbose, no color (settings default).
        let s = Settings::default();
        assert!(!s.quiet && !s.verbose && !s.color);
    }
}
