//! The body of `tog __resolution-relay`: the first process inside the
//! resolution door's sandbox (kernel layer).
//!
//! bubblewrap starts it as `/run/tog/tog __resolution-relay [--exec-log-fd
//! <n>] /run/tog/proxy.sock 127.0.0.1:8119 -- <tool argv>` in a fresh
//! network and PID namespace. It is the only way out of that namespace:
//!
//! 1. It makes itself non-dumpable, so nothing of the same user can trace
//!    it or read its memory and borrow its unfiltered sockets.
//! 2. It opens the bound Unix socket (the proxy) as an `O_PATH` descriptor
//!    before the tool starts, listens on the fixed loopback address inside
//!    the namespace and, for each accepted TCP connection, connects the
//!    proxy through that descriptor and copies bytes both ways until either
//!    side closes.
//! 3. It starts the tool in a fresh anonymous session keyring, with the
//!    door's seccomp filter installed in the
//!    child before `exec`, receives the filter's notification listener over
//!    a socket pair, and answers every `execve` notification while
//!    recording it in the exec log.
//! 4. When the tool exits it sends `SIGKILL` to every other process in the
//!    namespace, repeating until none is left, and exits with the tool's
//!    status (a signal `n` becomes `128 + n`).
//!
//! The exec log is JSON lines written to an inherited pipe descriptor that
//! only the relay holds (the tool never inherits it). Besides one line per
//! exec it carries the tool's status and the quiescence result, so the door
//! reads the tool's outcome from the relay rather than from bubblewrap's
//! exit code, and a relay that failed says why.

use crate::kernel::resolve::seccomp::ExecEvent;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

/// The loopback address the relay listens on inside the namespace. Fixed,
/// so every proxy URL a tool is given is the same from run to run.
pub const LISTEN_ADDRESS: &str = "127.0.0.1:8119";
/// Where the proxy's Unix socket is bound inside the sandbox.
pub const PROXY_SOCKET: &str = "/run/tog/proxy.sock";
/// Where the running tog executable is bound inside the sandbox.
pub const TOG_EXECUTABLE: &str = "/run/tog/tog";
/// The hidden verb.
pub const VERB: &str = "__resolution-relay";
/// The descriptor number the exec log arrives on inside the sandbox.
pub const EXEC_LOG_FD: i32 = 3;

/// What the relay was asked to do, parsed from its command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayArgs {
    pub socket: PathBuf,
    pub listen: SocketAddr,
    pub exec_log_fd: Option<i32>,
    pub argv: Vec<OsString>,
}

/// How the tool ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Code(i32),
    Signal(i32),
}

impl ToolStatus {
    /// The exit code tog uses for a child everywhere: its code, or 128 + n
    /// for a signal `n`.
    pub fn exit_code(self) -> i32 {
        match self {
            ToolStatus::Code(code) => code,
            ToolStatus::Signal(signal) => 128 + signal,
        }
    }

    pub fn success(self) -> bool {
        self == ToolStatus::Code(0)
    }
}

impl std::fmt::Display for ToolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolStatus::Code(code) => write!(f, "exit status {code}"),
            ToolStatus::Signal(signal) => write!(f, "killed by signal {signal}"),
        }
    }
}

/// One line of the exec log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRecord {
    Exec {
        pid: i32,
        parent: i32,
        path: Option<String>,
    },
    Tool(ToolStatus),
    /// Every other process in the namespace is gone; `killed` counts the
    /// `SIGKILL`s it took.
    Quiesced {
        killed: usize,
    },
    Error {
        message: String,
    },
}

impl From<ExecEvent> for RelayRecord {
    fn from(event: ExecEvent) -> Self {
        RelayRecord::Exec {
            pid: event.pid,
            parent: event.parent,
            path: event.path,
        }
    }
}

/// Parse the relay's own arguments (everything after the verb). The listen
/// address must be loopback: the relay is a bridge inside a private
/// namespace, never a listener anyone else can reach.
pub fn parse_args(
    socket: &str,
    listen: &str,
    exec_log_fd: Option<i32>,
    argv: &[String],
) -> io::Result<RelayArgs> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidInput, message);
    let listen: SocketAddr = listen
        .parse()
        .map_err(|_| invalid(format!("{VERB}: {listen:?} is not an address and port")))?;
    if !listen.ip().is_loopback() {
        return Err(invalid(format!(
            "{VERB}: {listen} is not a loopback address"
        )));
    }
    if argv.is_empty() {
        return Err(invalid(format!("{VERB}: no tool to run after --")));
    }
    if matches!(exec_log_fd, Some(fd) if fd < 3) {
        return Err(invalid(format!(
            "{VERB}: the exec log cannot be a standard descriptor"
        )));
    }
    Ok(RelayArgs {
        socket: PathBuf::from(socket),
        listen,
        exec_log_fd,
        argv: argv.iter().map(OsString::from).collect(),
    })
}

/// Parse an exec log. A line that does not parse is an error: the pipe is
/// written only by the relay, so a malformed line means something else wrote
/// it or the relay broke.
pub fn parse_log(bytes: &[u8]) -> io::Result<Vec<RelayRecord>> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_slice(line).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the resolution relay's log has a malformed line: {error}"),
                )
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(not(target_os = "linux"))]
pub fn run(_args: RelayArgs) -> io::Result<i32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{VERB} runs only inside the Linux resolution sandbox"),
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::kernel::resolve::seccomp::{self, Compiled};
    use std::fs::File;
    use std::io::Write as _;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// The exec log: one writer shared by the notification thread and the
    /// main thread, so lines never interleave.
    #[derive(Clone)]
    pub(super) struct RelayLog(Arc<Mutex<Option<File>>>);

    impl RelayLog {
        fn adopt(fd: Option<i32>) -> io::Result<RelayLog> {
            let file = match fd {
                None => None,
                Some(fd) => {
                    // SAFETY: fcntl on an integer descriptor; a bad one
                    // fails with EBADF, reported below.
                    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "{VERB}: exec log descriptor {fd}: {}",
                                io::Error::last_os_error()
                            ),
                        ));
                    }
                    // SAFETY: the descriptor was handed to this process for
                    // the relay alone; ownership moves into the File.
                    Some(unsafe { File::from_raw_fd(fd) })
                }
            };
            Ok(RelayLog(Arc::new(Mutex::new(file))))
        }

        /// Append one record. A failed write is dropped: tog has gone away,
        /// and the tool's outcome no longer has a reader.
        fn write(&self, record: &RelayRecord) {
            let Ok(mut line) = serde_json::to_vec(record) else {
                return;
            };
            line.push(b'\n');
            let mut guard = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
            if let Some(file) = guard.as_mut() {
                let _ = file.write_all(&line);
            }
        }
    }

    pub fn run(args: RelayArgs) -> io::Result<i32> {
        let log = RelayLog::adopt(args.exec_log_fd)?;
        let result = relay(&args, &log);
        if let Err(error) = &result {
            log.write(&RelayRecord::Error {
                message: error.to_string(),
            });
        }
        result
    }

    fn relay(args: &RelayArgs, log: &RelayLog) -> io::Result<i32> {
        // SAFETY: prctl with integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let listener = TcpListener::bind(args.listen).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{VERB}: listen on {}: {error}", args.listen),
            )
        })?;
        let proxy = ProxySocket::hold(&args.socket)?;
        std::thread::spawn(move || accept_loop(listener, &proxy));
        let status = run_tool(&args.argv, log)?;
        log.write(&RelayRecord::Tool(status));
        let killed = quiesce()?;
        log.write(&RelayRecord::Quiesced { killed });
        Ok(status.exit_code())
    }

    /// The proxy's socket, held open (`O_PATH`) from before the tool
    /// starts. Every connection goes through the held descriptor, so a
    /// tool that renamed `/run/tog` or planted a symlink there could not
    /// steer the unfiltered relay at another socket.
    pub(super) struct ProxySocket {
        _held: OwnedFd,
        via: String,
    }

    impl ProxySocket {
        pub(super) fn hold(path: &Path) -> io::Result<ProxySocket> {
            use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)
                .map_err(|error| {
                    io::Error::new(error.kind(), format!("{VERB}: {}: {error}", path.display()))
                })?;
            if !file.metadata()?.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{VERB}: {} is not the proxy's socket", path.display()),
                ));
            }
            let held = OwnedFd::from(file);
            let via = format!("/proc/self/fd/{}", held.as_raw_fd());
            Ok(ProxySocket { _held: held, via })
        }

        pub(super) fn connect(&self) -> io::Result<UnixStream> {
            UnixStream::connect(&self.via)
        }
    }

    fn accept_loop(listener: TcpListener, proxy: &ProxySocket) {
        for client in listener.incoming() {
            let Ok(client) = client else { continue };
            match proxy.connect() {
                Ok(upstream) => splice(client, upstream),
                // The tool sees its connection closed, which is what a
                // proxy that is gone looks like.
                Err(_) => drop(client),
            }
        }
    }

    /// Copy both directions on their own threads, closing each write half
    /// when its reader ends so the far side sees end-of-stream.
    fn splice(client: TcpStream, upstream: UnixStream) {
        let (Ok(client_reader), Ok(upstream_reader)) = (client.try_clone(), upstream.try_clone())
        else {
            return;
        };
        std::thread::spawn(move || {
            let _ = io::copy(&mut &client_reader, &mut &upstream);
            let _ = upstream.shutdown(Shutdown::Write);
        });
        std::thread::spawn(move || {
            let _ = io::copy(&mut &upstream_reader, &mut &client);
            let _ = client.shutdown(Shutdown::Write);
        });
    }

    /// Start the tool under the filter and wait for it. The notification
    /// thread starts first: the tool's own `execve` is a notification, and
    /// `spawn` does not return until that exec has happened.
    fn run_tool(argv: &[OsString], log: &RelayLog) -> io::Result<ToolStatus> {
        let (ours, theirs) = UnixStream::pair()?;
        let first = argv[0].to_string_lossy().into_owned();
        let sink = log.clone();
        std::thread::spawn(move || {
            if let Ok(listener) = receive_fd(&ours) {
                seccomp::serve_notifications(listener, Some(first), |event| {
                    sink.write(&event.into())
                });
            }
        });
        let mut child = spawn_tool(argv, Compiled::native(), theirs.as_raw_fd())?;
        drop(theirs);
        let status = child.wait()?;
        Ok(match (status.code(), status.signal()) {
            (Some(code), _) => ToolStatus::Code(code),
            (None, Some(signal)) => ToolStatus::Signal(signal),
            (None, None) => ToolStatus::Code(1),
        })
    }

    // Reviewed site (tests/architecture.rs): the relay runs inside the resolution sandbox, where no store is mounted writable and there is no lease to borrow.
    #[allow(clippy::disallowed_methods)]
    fn spawn_tool(
        argv: &[OsString],
        filter: Compiled,
        channel: RawFd,
    ) -> io::Result<std::process::Child> {
        let mut command = std::process::Command::new(&argv[0]);
        // bubblewrap adds PWD while processing --chdir; the tool's
        // environment is exactly what the door set.
        command.args(&argv[1..]).env_remove("PWD");
        // SAFETY: the closure makes only async-signal-safe syscalls
        // (keyctl, prctl, seccomp, sendmsg, close) on data prepared before
        // fork.
        unsafe {
            command.pre_exec(move || {
                // A fresh anonymous session keyring: the tool does not
                // possess the one tog was started with. The filter then
                // refuses every keyring call.
                if libc::syscall(
                    libc::SYS_keyctl,
                    libc::KEYCTL_JOIN_SESSION_KEYRING,
                    std::ptr::null::<libc::c_char>(),
                ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                let listener = filter.install()?;
                let sent = send_fd(channel, listener);
                libc::close(listener);
                sent
            });
        }
        command.spawn().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("{VERB}: start {}: {error}", Path::new(&argv[0]).display()),
            )
        })
    }

    /// Room for one `SCM_RIGHTS` header and one descriptor, aligned.
    const CONTROL_WORDS: usize = 8;

    /// Send `fd` over the connected socket `channel` as `SCM_RIGHTS`.
    ///
    /// # Safety
    ///
    /// Async-signal-safe: stack buffers and one `sendmsg`.
    unsafe fn send_fd(channel: RawFd, fd: RawFd) -> io::Result<()> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0u64; CONTROL_WORDS];
        // SAFETY: msghdr is plain old data.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        // SAFETY: CMSG_SPACE is arithmetic.
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as _;
        // SAFETY: the control buffer is larger than one header plus an int,
        // so the first header and its data lie inside it.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), fd);
        }
        // SAFETY: `message` and everything it points at live on this stack.
        if unsafe { libc::sendmsg(channel, &message, libc::MSG_NOSIGNAL) } != 1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Receive one descriptor sent by `send_fd`, close-on-exec.
    fn receive_fd(channel: &UnixStream) -> io::Result<OwnedFd> {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0u64; CONTROL_WORDS];
        // SAFETY: msghdr is plain old data.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        // SAFETY: `message` describes buffers on this stack.
        let read =
            unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if read <= 0 {
            return Err(io::Error::other(format!(
                "{VERB}: the tool's filter listener never arrived"
            )));
        }
        // SAFETY: the kernel filled `message`; CMSG_FIRSTHDR checks the
        // length before handing out a header.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null()
                || (*header).cmsg_level != libc::SOL_SOCKET
                || (*header).cmsg_type != libc::SCM_RIGHTS
            {
                return Err(io::Error::other(format!(
                    "{VERB}: the tool's filter listener arrived malformed"
                )));
            }
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>());
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }

    /// Rounds of `SIGKILL` before quiescence is declared failed. A process
    /// stuck in uninterruptible sleep can take a moment to die.
    const QUIESCE_ROUNDS: usize = 500;

    /// Kill every process in the namespace except its init (pid 1, which
    /// bubblewrap runs) and the relay, until none is left alive. Zombies are
    /// dead already and are not counted.
    fn quiesce() -> io::Result<usize> {
        let me = std::process::id() as i32;
        let mut killed = 0;
        for _ in 0..QUIESCE_ROUNDS {
            let mut alive = 0;
            for pid in namespace_pids()? {
                if pid == 1 || pid == me || is_zombie(pid) {
                    continue;
                }
                alive += 1;
                // SAFETY: kill with integer arguments; a pid that exited
                // meanwhile fails with ESRCH, which is the goal.
                if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                    killed += 1;
                }
            }
            reap_children();
            if alive == 0 {
                return Ok(killed);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(io::Error::other(format!(
            "{VERB}: processes in the sandbox survived SIGKILL"
        )))
    }

    fn namespace_pids() -> io::Result<Vec<i32>> {
        let mut pids = Vec::new();
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            if let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    fn is_zombie(pid: i32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            // Gone between the listing and the read.
            return true;
        };
        let state = stat
            .rfind(')')
            .and_then(|at| stat[at + 1..].split_whitespace().next());
        matches!(state, Some("Z") | Some("X") | Some("x"))
    }

    /// Reap any child of the relay a kill left behind, so it does not stay
    /// a zombie the next round has to skip.
    fn reap_children() {
        loop {
            let mut status = 0;
            // SAFETY: waitpid on any child, non-blocking.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                return;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Connections go to the socket held when the relay started, even
        /// after its path is renamed away and a symlink to another socket
        /// takes its place.
        #[test]
        fn the_proxy_socket_is_the_one_held_at_start() {
            let dir = crate::kernel::testutil::TempDir::named("relay-held");
            // A short path: sun_path is 108 bytes.
            let short = std::path::PathBuf::from(format!("/tmp/tog-held-{}", std::process::id()));
            let _ = std::fs::remove_file(&short);
            std::os::unix::fs::symlink(&dir.0, &short).unwrap();
            let real = std::os::unix::net::UnixListener::bind(short.join("p.sock")).unwrap();
            let other = std::os::unix::net::UnixListener::bind(short.join("o.sock")).unwrap();
            let held = ProxySocket::hold(&short.join("p.sock")).unwrap();
            std::fs::rename(short.join("p.sock"), short.join("moved.sock")).unwrap();
            std::os::unix::fs::symlink(short.join("o.sock"), short.join("p.sock")).unwrap();
            let mut stream = held.connect().unwrap();
            stream.write_all(b"x").unwrap();
            real.set_nonblocking(true).unwrap();
            other.set_nonblocking(true).unwrap();
            assert!(real.accept().is_ok(), "the held socket got the connection");
            assert!(other.accept().is_err(), "the planted one did not");
            assert!(
                ProxySocket::hold(&short.join("p.sock")).is_err(),
                "a symlink is refused"
            );
            std::fs::remove_file(&short).unwrap();
        }

        /// The tool runs under the real filter with the real notification
        /// path, outside any sandbox: every exec it makes is logged, the
        /// first with the path the relay passed, and it sees the filter's
        /// verdicts.
        #[test]
        fn the_tool_runs_filtered_and_every_exec_is_logged() {
            let (reader, writer) = UnixStream::pair().unwrap();
            let fd = writer.as_raw_fd();
            // The log takes ownership of a duplicate; the pair end closes
            // with `writer`.
            // SAFETY: dup of a live descriptor.
            let log_fd = unsafe { libc::dup(fd) };
            let log = RelayLog::adopt(Some(log_fd)).unwrap();
            let argv: Vec<OsString> = [
                "/bin/sh",
                "-c",
                "/usr/bin/true && /usr/bin/env true && exit 3",
            ]
            .iter()
            .map(OsString::from)
            .collect();
            let status = run_tool(&argv, &log).unwrap();
            assert_eq!(status, ToolStatus::Code(3));
            drop(log);
            drop(writer);
            reader
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let _ = std::io::Read::read_to_end(&mut &reader, &mut bytes);
            let records = parse_log(&bytes).unwrap();
            let paths: Vec<Option<String>> = records
                .iter()
                .filter_map(|record| match record {
                    RelayRecord::Exec { path, .. } => Some(path.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(paths.first(), Some(&Some("/bin/sh".to_string())));
            assert!(
                paths.contains(&Some("/usr/bin/true".to_string())),
                "{paths:?}"
            );
            assert!(
                paths.contains(&Some("/usr/bin/env".to_string())),
                "{paths:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_arguments_are_checked() {
        let argv = vec!["/bin/true".to_string()];
        let parsed = parse_args("/run/tog/proxy.sock", LISTEN_ADDRESS, Some(3), &argv).unwrap();
        assert_eq!(parsed.listen, LISTEN_ADDRESS.parse().unwrap());
        assert_eq!(parsed.argv, vec![OsString::from("/bin/true")]);
        for (listen, fd, argv, reason) in [
            ("0.0.0.0:8119", None, &argv[..], "not a loopback"),
            ("localhost:8119", None, &argv[..], "not an address"),
            (LISTEN_ADDRESS, Some(2), &argv[..], "standard descriptor"),
            (LISTEN_ADDRESS, None, &[][..], "no tool"),
        ] {
            let error = parse_args("/s", listen, fd, argv).unwrap_err();
            assert!(error.to_string().contains(reason), "{error}");
        }
    }

    #[test]
    fn the_log_round_trips_and_refuses_a_foreign_line() {
        let records = vec![
            RelayRecord::Exec {
                pid: 2,
                parent: 1,
                path: Some("/usr/bin/true".into()),
            },
            RelayRecord::Tool(ToolStatus::Signal(9)),
            RelayRecord::Quiesced { killed: 4 },
        ];
        let mut bytes = Vec::new();
        for record in &records {
            bytes.extend(serde_json::to_vec(record).unwrap());
            bytes.push(b'\n');
        }
        assert_eq!(parse_log(&bytes).unwrap(), records);
        assert_eq!(ToolStatus::Signal(9).exit_code(), 137);
        bytes.extend_from_slice(b"hello\n");
        assert!(parse_log(&bytes).is_err());
    }
}
