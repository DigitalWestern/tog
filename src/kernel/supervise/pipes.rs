//! Bounded pipe reads and post-reap output draining.

use std::io::{self, Read};
use std::os::fd::RawFd;
use std::process::Command;

/// How long output is still read once the direct child is reaped. A process
/// the command left running (a compiler server, an MSBuild node) can hold
/// the pipe open for good, and tog must not wait on it.
pub(super) const DRAIN_AFTER_EXIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Say that a command's leftover process kept its output open, once.
pub(super) fn note_abandoned_output(command: &Command) {
    crate::kernel::ui::note(&format!(
        "{} exited, but a process it started still holds its output open; stopped reading \
         {} s after it exited",
        command.get_program().to_string_lossy(),
        DRAIN_AFTER_EXIT.as_secs()
    ));
}

/// Wait up to `timeout` for `fd` to be readable (or closed). `false` when
/// the time ran out first.
pub(super) fn wait_readable(fd: RawFd, timeout: std::time::Duration) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: descriptor is one valid pollfd for the duration of the call.
    match unsafe { libc::poll(&mut descriptor, 1, millis) } {
        0 => Ok(false),
        count if count > 0 => Ok(true),
        _ => {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

pub(super) fn drain<R: Read>(
    reader: &mut Option<R>,
    destination: &mut Vec<u8>,
) -> io::Result<bool> {
    let Some(reader) = reader else {
        return Ok(false);
    };
    let mut buffer = [0u8; 16 * 1024];
    // Bound each turn so a continuously writable grandchild cannot starve
    // reaping, the other stream, signal forwarding, or drain deadlines.
    for _ in 0..4 {
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
    Ok(false)
}
