//! The resolution door's seccomp filter and its exec log (kernel layer).
//!
//! The relay installs this filter in the tool's process after `fork` and
//! before `exec`, so the tool and every process it starts inherit it while
//! the relay itself stays outside it. It closes the ways out of the network
//! namespace that a Unix socket or a kernel side channel would offer:
//!
//! - The architecture is checked first. A syscall made through another
//!   table (a 32-bit `int 0x80` on x86-64, where `socket` has another
//!   number and `socketcall` multiplexes it) kills the process, and so does
//!   a syscall number with the x32 bit set.
//! - `socket` is an allow-list: `AF_INET` and `AF_INET6` (the network
//!   namespace holds only loopback and the relay), and `AF_NETLINK` with
//!   `NETLINK_ROUTE` only (glibc's `getaddrinfo` and Go read interface
//!   addresses through it, and it sees only the sandbox's namespace).
//!   Every other family fails with `EAFNOSUPPORT`: `AF_UNIX`, `AF_VSOCK`
//!   (which reaches the host across a network namespace), and any family
//!   a later kernel adds. `socketpair` is allowed for `AF_UNIX` stream
//!   and seqpacket pairs only (child-process pipes use them): a connected
//!   stream or seqpacket socket cannot be pointed anywhere else (the kernel
//!   answers `EISCONN` or `EOPNOTSUPP`). A datagram pair is refused with
//!   `EAFNOSUPPORT`, because `connect` or a `sendto` with an address
//!   re-aims a datagram socket at any filesystem-named datagram socket
//!   visible in the read-only root, such as systemd's journal socket.
//! - `add_key`, `request_key` and `keyctl` fail with `EPERM`, so the tool
//!   cannot read a key from this user's keyrings.
//! - `io_uring_setup`, `io_uring_enter` and `io_uring_register` fail with
//!   `EPERM`: a ring submits socket operations the filter never sees.
//! - `ptrace`, `process_vm_readv`, `process_vm_writev` and `pidfd_getfd`
//!   fail with `EPERM`, so the tool cannot borrow the unfiltered relay's
//!   sockets or memory.
//! - `execve` and `execveat` go to the relay as user notifications. The
//!   relay records `{pid, parent, path}` for the exec log and lets the call
//!   continue. The log is diagnostics: it never allows or denies anything.
//!
//! The program is plain classic BPF built here, so its logic is data a unit
//! test can run for both supported architectures on any host.

use std::io;

/// `AUDIT_ARCH_X86_64` from `linux/audit.h`: `EM_X86_64 | 64BIT | LE`.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
/// `AUDIT_ARCH_AARCH64` from `linux/audit.h`: `EM_AARCH64 | 64BIT | LE`.
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
/// `__X32_SYSCALL_BIT`: an x86-64 syscall number with this bit is the x32
/// ABI, which shares the x86-64 arch value and has its own numbers.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// Classic BPF opcodes (linux/filter.h, linux/bpf_common.h).
/// `BPF_LD | BPF_W | BPF_ABS` (0x00 | 0x00 | 0x20).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x05 | 0x10;
const BPF_JMP_JGE_K: u16 = 0x05 | 0x30;
const BPF_RET_K: u16 = 0x06;
/// `BPF_ALU | BPF_AND | BPF_K` (0x04 | 0x50 | 0x00).
const BPF_ALU_AND_K: u16 = 0x04 | 0x50;

// Filter return values (linux/seccomp.h).
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_USER_NOTIF: u32 = 0x7fc0_0000;
const RET_ERRNO: u32 = 0x0005_0000;

// Offsets into `struct seccomp_data`: nr (i32), arch (u32), ip (u64),
// args[6] (u64 each). Both supported architectures are little-endian, so
// an argument's low 32 bits sit at its own offset.
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const DATA_ARG0_LOW: u32 = 16;
const DATA_ARG1_LOW: u32 = 24;
const DATA_ARG2_LOW: u32 = 32;

const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const AF_NETLINK: u32 = 16;
const NETLINK_ROUTE: u32 = 0;
/// `SOCK_TYPE_MASK`: a socket type argument's low bits name the type; the
/// bits above carry `SOCK_NONBLOCK` and `SOCK_CLOEXEC`.
const SOCK_TYPE_MASK: u32 = 0xf;
const SOCK_STREAM: u32 = 1;
const SOCK_SEQPACKET: u32 = 5;
const EPERM: u32 = 1;
const EAFNOSUPPORT: u32 = 97;

/// One classic BPF instruction, laid out like `struct sock_filter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const fn stmt(code: u16, k: u32) -> Insn {
    Insn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code, jt, jf, k }
}

/// The syscall table the filter is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// The syscall numbers the filter names, per architecture. Fixed here
/// rather than taken from `libc` so the program for either architecture
/// can be built and tested on any host; a test pins the native row against
/// `libc`.
#[derive(Clone, Copy, Debug)]
pub struct Numbers {
    pub socket: u32,
    pub socketpair: u32,
    pub add_key: u32,
    pub request_key: u32,
    pub keyctl: u32,
    pub execve: u32,
    pub execveat: u32,
    pub ptrace: u32,
    pub process_vm_readv: u32,
    pub process_vm_writev: u32,
    pub io_uring_setup: u32,
    pub io_uring_enter: u32,
    pub io_uring_register: u32,
    pub pidfd_getfd: u32,
}

impl Arch {
    /// The architecture this tog was built for.
    pub fn native() -> Arch {
        #[cfg(target_arch = "aarch64")]
        {
            Arch::Aarch64
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            Arch::X86_64
        }
    }

    pub fn audit_arch(self) -> u32 {
        match self {
            Arch::X86_64 => AUDIT_ARCH_X86_64,
            Arch::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    pub fn numbers(self) -> Numbers {
        match self {
            Arch::X86_64 => Numbers {
                socket: 41,
                socketpair: 53,
                add_key: 248,
                request_key: 249,
                keyctl: 250,
                execve: 59,
                execveat: 322,
                ptrace: 101,
                process_vm_readv: 310,
                process_vm_writev: 311,
                io_uring_setup: 425,
                io_uring_enter: 426,
                io_uring_register: 427,
                pidfd_getfd: 438,
            },
            Arch::Aarch64 => Numbers {
                socket: 198,
                socketpair: 199,
                add_key: 217,
                request_key: 218,
                keyctl: 219,
                execve: 221,
                execveat: 281,
                ptrace: 117,
                process_vm_readv: 270,
                process_vm_writev: 271,
                io_uring_setup: 425,
                io_uring_enter: 426,
                io_uring_register: 427,
                pidfd_getfd: 438,
            },
        }
    }
}

/// The filter program for `arch`. Order matters and is fixed: the arch
/// check first (before any number is read, since numbers mean nothing in
/// another table), then the x32 bit on x86-64, then one equality test per
/// named syscall, then the `socket` and `socketpair` argument checks,
/// which reload the accumulator and so must come last. Everything else is
/// allowed.
pub fn program(arch: Arch) -> Vec<Insn> {
    let n = arch.numbers();
    let mut program = vec![
        stmt(BPF_LD_W_ABS, DATA_ARCH),
        jump(BPF_JMP_JEQ_K, arch.audit_arch(), 1, 0),
        stmt(BPF_RET_K, RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, DATA_NR),
    ];
    if arch == Arch::X86_64 {
        program.push(jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1));
        program.push(stmt(BPF_RET_K, RET_KILL_PROCESS));
    }
    let denied = RET_ERRNO | EPERM;
    for (number, action) in [
        (n.io_uring_setup, denied),
        (n.io_uring_enter, denied),
        (n.io_uring_register, denied),
        (n.ptrace, denied),
        (n.process_vm_readv, denied),
        (n.process_vm_writev, denied),
        (n.pidfd_getfd, denied),
        (n.add_key, denied),
        (n.request_key, denied),
        (n.keyctl, denied),
        (n.execve, RET_USER_NOTIF),
        (n.execveat, RET_USER_NOTIF),
    ] {
        program.push(jump(BPF_JMP_JEQ_K, number, 0, 1));
        program.push(stmt(BPF_RET_K, action));
    }
    let refused = RET_ERRNO | EAFNOSUPPORT;
    // Relative jumps (counted from the next instruction): `socket` goes
    // two past it, to its domain check; `socketpair` nine past it, over
    // the allow and the eight instructions of the socket check, to its own.
    program.push(jump(BPF_JMP_JEQ_K, n.socket, 2, 0));
    program.push(jump(BPF_JMP_JEQ_K, n.socketpair, 9, 0));
    program.push(stmt(BPF_RET_K, RET_ALLOW));
    // socket(domain, type, protocol)
    program.push(stmt(BPF_LD_W_ABS, DATA_ARG0_LOW));
    program.push(jump(BPF_JMP_JEQ_K, AF_INET, 5, 0));
    program.push(jump(BPF_JMP_JEQ_K, AF_INET6, 4, 0));
    program.push(jump(BPF_JMP_JEQ_K, AF_NETLINK, 0, 2));
    program.push(stmt(BPF_LD_W_ABS, DATA_ARG2_LOW));
    program.push(jump(BPF_JMP_JEQ_K, NETLINK_ROUTE, 1, 0));
    program.push(stmt(BPF_RET_K, refused));
    program.push(stmt(BPF_RET_K, RET_ALLOW));
    // socketpair(domain, type, ...): AF_UNIX stream or seqpacket only.
    // A datagram pair (and SOCK_RAW, which AF_UNIX treats as datagram)
    // could be re-aimed at a named socket.
    program.push(stmt(BPF_LD_W_ABS, DATA_ARG0_LOW));
    program.push(jump(BPF_JMP_JEQ_K, AF_UNIX, 0, 4));
    program.push(stmt(BPF_LD_W_ABS, DATA_ARG1_LOW));
    program.push(stmt(BPF_ALU_AND_K, SOCK_TYPE_MASK));
    program.push(jump(BPF_JMP_JEQ_K, SOCK_STREAM, 2, 0));
    program.push(jump(BPF_JMP_JEQ_K, SOCK_SEQPACKET, 1, 0));
    program.push(stmt(BPF_RET_K, refused));
    program.push(stmt(BPF_RET_K, RET_ALLOW));
    program
}

/// The native program in the kernel's own layout, built before `fork` so
/// the child that installs it allocates nothing.
#[cfg(target_os = "linux")]
pub struct Compiled {
    filters: Vec<libc::sock_filter>,
}

#[cfg(target_os = "linux")]
impl Compiled {
    pub fn native() -> Compiled {
        Compiled {
            filters: program(Arch::native())
                .into_iter()
                .map(|insn| libc::sock_filter {
                    code: insn.code,
                    jt: insn.jt,
                    jf: insn.jf,
                    k: insn.k,
                })
                .collect(),
        }
    }

    /// Install the filter in the calling process and return the listener
    /// descriptor for its exec notifications. `PR_SET_NO_NEW_PRIVS` comes
    /// first, as an unprivileged process must set it.
    ///
    /// # Safety
    ///
    /// Async-signal-safe: meant for the child between `fork` and `exec`. It
    /// makes two syscalls and allocates nothing.
    pub unsafe fn install(&self) -> io::Result<libc::c_int> {
        // SAFETY: prctl with integer arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let program = libc::sock_fprog {
            len: self.filters.len() as libc::c_ushort,
            filter: self.filters.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: `program` points at `self.filters`, which outlives the
        // call; the kernel copies the program before returning.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &program as *const libc::sock_fprog,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd as libc::c_int)
    }
}

/// One exec the filter reported: the process that called `execve` or
/// `execveat` (a pid in the sandbox's PID namespace), its parent, and the
/// path it asked for, or `None` when the relay could not read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecEvent {
    pub pid: i32,
    pub parent: i32,
    pub path: Option<String>,
}

/// Serve exec notifications on `listener` until it fails or every process
/// under the filter is gone. Each notification is answered with "continue"
/// before it is recorded, so a slow sink never holds up the tool. `first`
/// names the program the relay itself started: the first exec happens in
/// the relay's non-dumpable fork, whose memory cannot be read, and that
/// path is the one the relay passed.
#[cfg(target_os = "linux")]
pub fn serve_notifications(
    listener: std::os::fd::OwnedFd,
    first: Option<String>,
    mut sink: impl FnMut(ExecEvent),
) {
    use std::os::fd::AsRawFd;
    let fd = listener.as_raw_fd();
    let mut first = first;
    loop {
        match wait_readable(fd) {
            Ok(true) => {}
            Ok(false) | Err(_) => return,
        }
        // SAFETY: seccomp_notif is plain old data; RECV requires it zeroed.
        let mut notif: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is a seccomp listener and `notif` is writable.
        if unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_RECV, &mut notif) } != 0 {
            match io::Error::last_os_error().raw_os_error() {
                // The caller died before the notification was read, or a
                // signal interrupted the wait: keep serving.
                Some(libc::ENOENT) | Some(libc::EINTR) => continue,
                _ => return,
            }
        }
        let pid = notif.pid as i32;
        let address = if notif.data.nr as u32 == Arch::native().numbers().execveat {
            notif.data.args[1]
        } else {
            notif.data.args[0]
        };
        let read = read_c_string(pid, address);
        // The read is meaningful only if the notification is still live:
        // otherwise the pid may already be another process.
        // SAFETY: `fd` is a seccomp listener and `id` is readable.
        let still_valid =
            unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_ID_VALID, &notif.id) } == 0;
        let mut response = libc::seccomp_notif_resp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };
        // SAFETY: `fd` is a seccomp listener and `response` is readable.
        // ENOENT (the caller died meanwhile) needs no handling.
        unsafe { libc::ioctl(fd, libc::SECCOMP_IOCTL_NOTIF_SEND, &mut response) };
        let path = match (read, still_valid) {
            (Some(path), true) => Some(path),
            _ => first.take(),
        };
        first = None;
        sink(ExecEvent {
            pid,
            parent: parent_of(pid).unwrap_or(0),
            path,
        });
    }
}

/// Block until the listener has a notification (`true`) or has hung up
/// because no process uses the filter any more (`false`).
#[cfg(target_os = "linux")]
fn wait_readable(fd: libc::c_int) -> io::Result<bool> {
    loop {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let ready = unsafe { libc::poll(&mut poll, 1, -1) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if poll.revents & libc::POLLIN != 0 {
            return Ok(true);
        }
        if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Ok(false);
        }
    }
}

/// Longest exec path the log records; `PATH_MAX`.
#[cfg(target_os = "linux")]
const PATH_LIMIT: usize = 4096;

/// Read a NUL-terminated string at `address` in process `pid`, one page at
/// a time so a string ending just before an unmapped page still reads.
#[cfg(target_os = "linux")]
fn read_c_string(pid: i32, address: u64) -> Option<String> {
    let mut bytes = Vec::new();
    let mut at = address;
    while bytes.len() < PATH_LIMIT {
        let to_page_end = 4096 - (at % 4096) as usize;
        let want = to_page_end.min(PATH_LIMIT - bytes.len());
        let mut chunk = vec![0u8; want];
        let local = libc::iovec {
            iov_base: chunk.as_mut_ptr().cast(),
            iov_len: want,
        };
        let remote = libc::iovec {
            iov_base: at as *mut libc::c_void,
            iov_len: want,
        };
        // SAFETY: both iovecs describe `want` bytes; the local one is our
        // own buffer, the remote one is only read by the kernel.
        let read = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if read <= 0 {
            return None;
        }
        let read = read as usize;
        if let Some(end) = chunk[..read].iter().position(|byte| *byte == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.extend_from_slice(&chunk[..read]);
        at += read as u64;
    }
    None
}

/// The parent pid from `/proc/<pid>/stat`: the field after the command
/// name, which is parenthesized and may itself contain `)`.
#[cfg(target_os = "linux")]
pub(crate) fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A classic-BPF interpreter for the subset the program uses, run
    /// against a synthetic `seccomp_data`. Pins the program's logic for
    /// both architectures without installing anything.
    fn run(program: &[Insn], nr: u32, arch: u32, arg0: u64) -> u32 {
        run_with(program, nr, arch, [arg0, 0, 0])
    }

    fn run_with(program: &[Insn], nr: u32, arch: u32, args: [u64; 3]) -> u32 {
        let [arg0, arg1, arg2] = args;
        let mut data = [0u8; 64];
        data[24..32].copy_from_slice(&arg1.to_le_bytes());
        data[32..40].copy_from_slice(&arg2.to_le_bytes());
        data[0..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        data[16..24].copy_from_slice(&arg0.to_le_bytes());
        let mut accumulator = 0u32;
        let mut pc = 0usize;
        loop {
            let insn = program[pc];
            match insn.code {
                BPF_LD_W_ABS => {
                    let at = insn.k as usize;
                    accumulator = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    pc += 1 + if accumulator == insn.k {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                BPF_JMP_JGE_K => {
                    pc += 1 + if accumulator >= insn.k {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                }
                BPF_ALU_AND_K => {
                    accumulator &= insn.k;
                    pc += 1;
                }
                BPF_RET_K => return insn.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    fn check_arch(arch: Arch) {
        let program = program(arch);
        let native = arch.audit_arch();
        let n = arch.numbers();
        let getpid = match arch {
            Arch::X86_64 => 39,
            Arch::Aarch64 => 172,
        };
        assert_eq!(run(&program, getpid, native, 0), RET_ALLOW);
        assert_eq!(
            run(&program, n.socket, native, AF_UNIX as u64),
            RET_ERRNO | EAFNOSUPPORT
        );
        // The domain is an int: the kernel reads the low 32 bits only, so
        // high garbage does not hide AF_UNIX from the check.
        assert_eq!(
            run(&program, n.socket, native, (7u64 << 32) | AF_UNIX as u64),
            RET_ERRNO | EAFNOSUPPORT
        );
        assert_eq!(run(&program, n.socket, native, AF_INET as u64), RET_ALLOW);
        assert_eq!(run(&program, n.socket, native, AF_INET6 as u64), RET_ALLOW);
        // Every other family is refused, AF_VSOCK (40) first among them,
        // and any family a later kernel adds.
        for family in [
            0u64,
            3,
            4,
            5,
            9,
            17,
            29,
            38,
            40,
            44,
            45,
            46,
            200,
            u32::MAX as u64,
        ] {
            assert_eq!(
                run(&program, n.socket, native, family),
                RET_ERRNO | EAFNOSUPPORT,
                "family {family}"
            );
        }
        let netlink = AF_NETLINK as u64;
        assert_eq!(
            run_with(
                &program,
                n.socket,
                native,
                [netlink, 0, NETLINK_ROUTE as u64]
            ),
            RET_ALLOW
        );
        for protocol in [
            2u64, /* USERSOCK */
            4,    /* SOCK_DIAG */
            9,    /* AUDIT */
            15,   /* KOBJECT_UEVENT */
        ] {
            assert_eq!(
                run_with(&program, n.socket, native, [netlink, 0, protocol]),
                RET_ERRNO | EAFNOSUPPORT,
                "netlink protocol {protocol}"
            );
        }
        let unix = AF_UNIX as u64;
        let (nonblock, cloexec) = (0o4000u64, 0o2000000u64);
        let stream = SOCK_STREAM as u64;
        let seqpacket = SOCK_SEQPACKET as u64;
        let dgram = 2u64;
        for kind in [
            stream,
            seqpacket,
            stream | cloexec | nonblock,
            seqpacket | cloexec,
        ] {
            assert_eq!(
                run_with(&program, n.socketpair, native, [unix, kind, 0]),
                RET_ALLOW,
                "socketpair type {kind:#x}"
            );
        }
        // A datagram pair could be re-aimed at a named socket; SOCK_RAW (3)
        // is a datagram socket to AF_UNIX, SOCK_RDM (4) is refused too, and
        // high garbage does not turn a datagram type into an allowed one.
        for kind in [
            0u64,
            dgram,
            dgram | cloexec,
            dgram | cloexec | nonblock,
            3,
            4,
            6,
            10,
            0xf,
            (7u64 << 32) | dgram,
        ] {
            assert_eq!(
                run_with(&program, n.socketpair, native, [unix, kind, 0]),
                RET_ERRNO | EAFNOSUPPORT,
                "socketpair type {kind:#x}"
            );
        }
        for family in [AF_INET as u64, AF_INET6 as u64, 40] {
            for kind in [stream, seqpacket, dgram] {
                assert_eq!(
                    run_with(&program, n.socketpair, native, [family, kind, 0]),
                    RET_ERRNO | EAFNOSUPPORT,
                    "socketpair family {family} type {kind}"
                );
            }
        }
        for number in [
            n.add_key,
            n.request_key,
            n.keyctl,
            n.io_uring_setup,
            n.io_uring_enter,
            n.io_uring_register,
            n.ptrace,
            n.process_vm_readv,
            n.process_vm_writev,
            n.pidfd_getfd,
        ] {
            assert_eq!(run(&program, number, native, 0), RET_ERRNO | EPERM);
        }
        assert_eq!(run(&program, n.execve, native, 0), RET_USER_NOTIF);
        assert_eq!(run(&program, n.execveat, native, 0), RET_USER_NOTIF);
        // Any other table: killed before a number is looked at, including
        // numbers that would be allowed natively.
        for foreign in [0x4000_0003u32 /* i386 */, 0x4000_0028 /* arm */] {
            for nr in [getpid, n.socket, 102 /* i386 socketcall */] {
                assert_eq!(run(&program, nr, foreign, 1), RET_KILL_PROCESS);
            }
        }
    }

    #[test]
    fn x86_64_program_denies_each_named_syscall_and_kills_a_foreign_arch() {
        check_arch(Arch::X86_64);
        let program = program(Arch::X86_64);
        let n = Arch::X86_64.numbers();
        for nr in [X32_SYSCALL_BIT | 39, X32_SYSCALL_BIT | n.socket, u32::MAX] {
            assert_eq!(
                run(&program, nr, AUDIT_ARCH_X86_64, AF_UNIX as u64),
                RET_KILL_PROCESS,
                "x32 number {nr:#x}"
            );
        }
    }

    #[test]
    fn aarch64_program_denies_each_named_syscall_and_kills_a_foreign_arch() {
        check_arch(Arch::Aarch64);
        // No x32 ABI there: a large number is simply not named.
        let program = program(Arch::Aarch64);
        assert_eq!(
            run(&program, X32_SYSCALL_BIT | 39, AUDIT_ARCH_AARCH64, 0),
            RET_ALLOW
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_native_numbers_are_the_libc_numbers() {
        let n = Arch::native().numbers();
        assert_eq!(n.socket as libc::c_long, libc::SYS_socket);
        assert_eq!(n.socketpair as libc::c_long, libc::SYS_socketpair);
        assert_eq!(n.add_key as libc::c_long, libc::SYS_add_key);
        assert_eq!(n.request_key as libc::c_long, libc::SYS_request_key);
        assert_eq!(n.keyctl as libc::c_long, libc::SYS_keyctl);
        assert_eq!(n.execve as libc::c_long, libc::SYS_execve);
        assert_eq!(n.execveat as libc::c_long, libc::SYS_execveat);
        assert_eq!(n.ptrace as libc::c_long, libc::SYS_ptrace);
        assert_eq!(
            n.process_vm_readv as libc::c_long,
            libc::SYS_process_vm_readv
        );
        assert_eq!(
            n.process_vm_writev as libc::c_long,
            libc::SYS_process_vm_writev
        );
        assert_eq!(n.io_uring_setup as libc::c_long, libc::SYS_io_uring_setup);
        assert_eq!(n.io_uring_enter as libc::c_long, libc::SYS_io_uring_enter);
        assert_eq!(
            n.io_uring_register as libc::c_long,
            libc::SYS_io_uring_register
        );
        assert_eq!(n.pidfd_getfd as libc::c_long, libc::SYS_pidfd_getfd);
    }

    /// The filter installed for real, in a forked child that reports each
    /// syscall's errno through its exit code. No sandbox is needed: this
    /// is the kernel's verdict on the same program the relay installs.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_installed_filter_allows_only_inet_and_route_sockets_and_refuses_keyrings() {
        let compiled = Compiled::native();
        // SAFETY: the child runs only async-signal-safe syscalls and exits
        // with _exit; the parent waits for it.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // SAFETY: see above.
            unsafe {
                let code = (|| {
                    if compiled.install().is_err() {
                        return 10;
                    }
                    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                    if fd >= 0 || *libc::__errno_location() != libc::EAFNOSUPPORT {
                        return 11;
                    }
                    let mut pair = [0; 2];
                    if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) != 0
                    {
                        return 12;
                    }
                    let dgram =
                        libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, pair.as_mut_ptr());
                    if dgram == 0 || *libc::__errno_location() != libc::EAFNOSUPPORT {
                        return 19;
                    }
                    if libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                        0,
                        pair.as_mut_ptr(),
                    ) != 0
                    {
                        return 20;
                    }
                    if libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, pair.as_mut_ptr())
                        != 0
                    {
                        return 21;
                    }
                    if libc::syscall(libc::SYS_io_uring_setup, 1, std::ptr::null_mut::<u8>()) >= 0
                        || *libc::__errno_location() != libc::EPERM
                    {
                        return 13;
                    }
                    let inet = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                    if inet < 0 {
                        return 14;
                    }
                    let vsock = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
                    if vsock >= 0 || *libc::__errno_location() != libc::EAFNOSUPPORT {
                        return 15;
                    }
                    let route = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
                    if route < 0 {
                        return 16;
                    }
                    let audit = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_AUDIT);
                    if audit >= 0 || *libc::__errno_location() != libc::EAFNOSUPPORT {
                        return 17;
                    }
                    if libc::syscall(
                        libc::SYS_keyctl,
                        0,  /* KEYCTL_GET_KEYRING_ID */
                        -3, /* session */
                        0,
                    ) >= 0
                        || *libc::__errno_location() != libc::EPERM
                    {
                        return 18;
                    }
                    0
                })();
                libc::_exit(code);
            }
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "failed step");
    }
}
