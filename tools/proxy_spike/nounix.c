// nounix: run a program under the resolution door's seccomp filter (PR 0
// evidence spike, docs/agent/DESIGNS.md §6 "Unix sockets").
//
//   cc -O2 -o nounix tools/proxy_spike/nounix.c
//   nounix [--allow-unix] -- <program> [args...]
//
// The filter is the one PR 3 installs in the tool's process before exec,
// inherited by every descendant:
//   - seccomp_data.arch must be AUDIT_ARCH_X86_64, else SECCOMP_RET_KILL_PROCESS
//     (no 32-bit int 0x80 table, where socketcall(2) multiplexes socket);
//   - syscall numbers with the x32 bit set fail with ENOSYS;
//   - socket(AF_UNIX, ...) fails with EAFNOSUPPORT (socketpair stays allowed);
//   - io_uring_setup, io_uring_enter, io_uring_register fail with EPERM;
//   - ptrace, process_vm_readv, process_vm_writev fail with EPERM.
// --allow-unix drops the AF_UNIX rule only, for an A/B comparison.
//
// x86-64 Linux only: this is a measurement helper, not the shipped filter.
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __x86_64__
#error "nounix measures the x86-64 filter only"
#endif

#define X32_SYSCALL_BIT 0x40000000u
#define DENY(errno_value) BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ((errno_value) & SECCOMP_RET_DATA))
#define ALLOW BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

int main(int argc, char **argv) {
    int first = 1;
    int allow_unix = 0;
    if (first < argc && strcmp(argv[first], "--allow-unix") == 0) {
        allow_unix = 1;
        first++;
    }
    if (first < argc && strcmp(argv[first], "--") == 0) {
        first++;
    }
    if (first >= argc) {
        fprintf(stderr, "usage: nounix [--allow-unix] -- program [args...]\n");
        return 2;
    }
    struct sock_filter filter[] = {
        /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        /* 2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* 4 */ BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
        /* 5 */ DENY(ENOSYS),
        /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 7, 0),
        /* 7 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 6, 0),
        /* 8 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 5, 0),
        /* 9 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ptrace, 4, 0),
        /* 10 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_readv, 3, 0),
        /* 11 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_process_vm_writev, 2, 0),
        /* 12 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 2, 0),
        /* 13 */ ALLOW,
        /* 14 */ DENY(EPERM),
        /* 15 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        /* 16 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 1),
        /* 17 */ DENY(EAFNOSUPPORT),
        /* 18 */ ALLOW,
    };
    if (allow_unix) {
        // Turn the AF_UNIX denial into an allow; every other rule stays.
        filter[17] = (struct sock_filter)ALLOW;
    }
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("nounix: PR_SET_NO_NEW_PRIVS");
        return 126;
    }
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
        perror("nounix: seccomp");
        return 126;
    }
    execvp(argv[first], &argv[first]);
    fprintf(stderr, "nounix: exec %s: %s\n", argv[first], strerror(errno));
    return 127;
}
