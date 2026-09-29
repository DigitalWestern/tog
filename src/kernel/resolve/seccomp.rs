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
//! - `socket(AF_UNIX, ...)` fails with `EAFNOSUPPORT`. `socketpair` stays
//!   allowed: child-process pipes use it, and a pair cannot reach a named
//!   socket.
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

const AF_UNIX: u32 = 1;
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
/// named syscall, then `socket`'s domain check, which reloads the
/// accumulator and so must come last. Everything else is allowed.
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
        (n.execve, RET_USER_NOTIF),
        (n.execveat, RET_USER_NOTIF),
    ] {
        program.push(jump(BPF_JMP_JEQ_K, number, 0, 1));
        program.push(stmt(BPF_RET_K, action));
    }
    program.push(jump(BPF_JMP_JEQ_K, n.socket, 0, 3));
    program.push(stmt(BPF_LD_W_ABS, DATA_ARG0_LOW));
    program.push(jump(BPF_JMP_JEQ_K, AF_UNIX, 0, 1));
    program.push(stmt(BPF_RET_K, RET_ERRNO | EAFNOSUPPORT));
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
        let mut data = [0u8; 64];
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
                BPF_RET_K => return insn.k,
                other => panic!("unexpected opcode {other:#x}"),
            }
        }
    }

    const AF_INET: u64 = 2;

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
        assert_eq!(run(&program, n.socket, native, AF_INET), RET_ALLOW);
        for number in [
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
    fn the_installed_filter_refuses_unix_sockets_and_io_uring_but_not_pairs() {
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
                    if libc::syscall(libc::SYS_io_uring_setup, 1, std::ptr::null_mut::<u8>()) >= 0
                        || *libc::__errno_location() != libc::EPERM
                    {
                        return 13;
                    }
                    let inet = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                    if inet < 0 {
                        return 14;
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
