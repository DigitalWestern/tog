//! Output conventions (CLI.md): stdout is for results, stderr is for
//! narration. `--quiet` drops narration, `--verbose` adds decisions and the
//! command line of every subprocess blanket starts, and color appears only
//! on a terminal, only on stderr, only on the words that carry state.
//!
//! Quiet is implemented at the file-descriptor level: fd 2 is pointed at
//! /dev/null after one private copy of the original stderr is kept for
//! errors. That silences every module's `eprintln!` and every subprocess
//! (uv, npm, cargo, ...) without threading a flag through them, and it
//! guarantees the one thing quiet must never hide: the error.

use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::OnceLock;

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
    Ok(())
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
    write_error_channel(&format!("blanket: {}: {message}\n", paint("error", RED)));
}

/// Something the user should know but that did not stop the command.
/// Suppressed by `--quiet` like all narration.
pub fn warning(message: &str) {
    if quiet() {
        return;
    }
    eprintln!("blanket: {}: {message}", paint("warning", YELLOW));
}

/// Progress narration.
pub fn note(message: &str) {
    if quiet() {
        return;
    }
    eprintln!("blanket: {message}");
}

/// The line each ecosystem prints when its projection is in place.
pub fn synced(what: &str, target: &std::path::Path) {
    if quiet() {
        return;
    }
    eprintln!("{}: {what} -> {}", paint("synced", GREEN), target.display());
}

/// Decision-level detail, only under `--verbose`.
pub fn trace(message: &str) {
    if verbose() {
        eprintln!("blanket: {} {message}", paint("[verbose]", DIM));
    }
}

/// The command line of a subprocess blanket is about to start, only under
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

    #[test]
    fn shell_words_quote_only_when_needed() {
        assert_eq!(shell_word("uv"), "uv");
        assert_eq!(shell_word("--python-version=3.12"), "--python-version=3.12");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("it's"), "'it'\\''s'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn defaults_are_plain_and_loud() {
        // Before init: no quiet, no verbose, no color (settings default).
        let s = Settings::default();
        assert!(!s.quiet && !s.verbose && !s.color);
    }
}
