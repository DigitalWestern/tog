/* A probe the Linux resolution-door tests (tests/sandbox_deny.rs) run as
 * the "tool" inside the door. Each command tries one thing and prints one
 * line saying what happened; the tests read the lines.
 *
 *   tcp <ip> <port>          connect, print what the peer sent first
 *   unix <path>              socket(AF_UNIX) + connect
 *   wait-unix <path>         wait up to 10 s for <path>, then as `unix`
 *   dns <host>               getaddrinfo
 *   socketpair               socketpair(AF_UNIX) and a round trip
 *   socketpair-seqpacket     the same with SOCK_SEQPACKET
 *   socketpair-dgram         the same with SOCK_DGRAM
 *   io_uring                 io_uring_setup
 *   int80                    the i386 socket syscall through int $0x80
 *   ptrace-parent            ptrace, /proc/<ppid>/mem, process_vm_readv
 *   daemon <path> <seconds>  double-fork a setsid child that rewrites
 *                            <path> every 10 ms, then exit at once
 *   read <path>              print the file's first line
 *   family <n>               socket(<n>, SOCK_STREAM, 0) for any family
 *   vsock <cid> <port>       socket(AF_VSOCK) + connect
 *   keyring                  keyctl, add_key and request_key on the
 *                            session and user keyrings
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <linux/vm_sockets.h>
#include <time.h>
#include <unistd.h>

static int tcp(const char *ip, const char *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { printf("tcp socket errno=%d\n", errno); return 0; }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(port));
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        printf("tcp connect errno=%d\n", errno);
        return 0;
    }
    char buffer[64] = {0};
    ssize_t got = read(fd, buffer, sizeof buffer - 1);
    if (got < 0) { printf("tcp read errno=%d\n", errno); return 0; }
    buffer[strcspn(buffer, "\n")] = 0;
    printf("tcp ok %s\n", buffer);
    return 0;
}

static int unix_connect(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { printf("unix socket errno=%d\n", errno); return 0; }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        printf("unix connect errno=%d\n", errno);
        return 0;
    }
    printf("unix connected\n");
    return 0;
}

static int wait_unix(const char *path) {
    for (int i = 0; i < 1000 && access(path, F_OK) != 0; i++) usleep(10000);
    return unix_connect(path);
}

static int dns(const char *host) {
    struct addrinfo *result = NULL;
    int rc = getaddrinfo(host, "443", NULL, &result);
    if (rc != 0) { printf("dns fail %d\n", rc); return 0; }
    printf("dns ok\n");
    return 0;
}

static int pair(int type) {
    int fds[2];
    if (socketpair(AF_UNIX, type, 0, fds) != 0) {
        printf("socketpair errno=%d\n", errno);
        return 0;
    }
    char byte = 'x';
    if (write(fds[0], &byte, 1) != 1 || read(fds[1], &byte, 1) != 1) {
        printf("socketpair io errno=%d\n", errno);
        return 0;
    }
    printf("socketpair ok\n");
    return 0;
}

static int io_uring(void) {
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
    char params[120] = {0};
    long rc = syscall(SYS_io_uring_setup, 1, params);
    if (rc < 0) printf("io_uring errno=%d\n", errno);
    else printf("io_uring ok\n");
    return 0;
}

static int int80(void) {
#if defined(__x86_64__)
    /* i386 socketcall/socket: number 359 is socket(2) on i386. */
    long rc;
    long domain = AF_UNIX, type = SOCK_STREAM, protocol = 0;
    __asm__ volatile("int $0x80"
                     : "=a"(rc)
                     : "a"(359L), "b"(domain), "c"(type), "d"(protocol)
                     : "memory");
    printf("int80 survived rc=%ld\n", rc);
#else
    printf("int80 unsupported\n");
#endif
    return 0;
}

static int ptrace_parent(void) {
    pid_t parent = getppid();
    errno = 0;
    long rc = ptrace(PTRACE_ATTACH, parent, NULL, NULL);
    printf("ptrace rc=%ld errno=%d\n", rc, rc < 0 ? errno : 0);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", (int)parent);
    int fd = open(path, O_RDONLY);
    printf("mem fd=%d errno=%d\n", fd, fd < 0 ? errno : 0);
    char buffer[8];
    struct iovec local = {buffer, sizeof buffer};
    struct iovec remote = {(void *)0x400000, sizeof buffer};
    ssize_t got = process_vm_readv(parent, &local, 1, &remote, 1, 0);
    printf("vm rc=%zd errno=%d\n", got, got < 0 ? errno : 0);
    return 0;
}

/* The namespace's pid 1 must be the relay: not writable through
 * /proc/1/mem, and not stoppable from inside. */
static int pid1(void) {
    int fd = open("/proc/1/mem", O_RDWR);
    printf("pid1 mem fd=%d errno=%d\n", fd, fd < 0 ? errno : 0);
    kill(1, SIGSTOP);
    usleep(100000);
    char state = '?';
    FILE *stat = fopen("/proc/1/stat", "r");
    if (stat) {
        char line[512];
        if (fgets(line, sizeof line, stat)) {
            char *close = strrchr(line, ')');
            if (close && close[1] == ' ') state = close[2];
        }
        fclose(stat);
    }
    printf("pid1 state=%c\n", state);
    return 0;
}

static int daemonize(const char *path, const char *seconds) {
    pid_t first = fork();
    if (first < 0) { printf("fork errno=%d\n", errno); return 1; }
    if (first > 0) {
        printf("daemon started\n");
        fflush(stdout);
        return 0;
    }
    setsid();
    if (fork() != 0) _exit(0);
    fclose(stdout);
    time_t end = time(NULL) + atoi(seconds);
    unsigned long counter = 0;
    while (time(NULL) < end) {
        FILE *file = fopen(path, "w");
        if (file) { fprintf(file, "{\"rewritten\":%lu}\n", counter++); fclose(file); }
        usleep(10000);
    }
    _exit(0);
}

static int read_first(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) { printf("read errno=%d\n", errno); return 0; }
    char line[256] = {0};
    if (!fgets(line, sizeof line, file)) line[0] = 0;
    line[strcspn(line, "\n")] = 0;
    printf("read %s\n", line);
    return 0;
}

static int family(const char *number) {
    int fd = socket(atoi(number), SOCK_STREAM, 0);
    if (fd < 0) printf("family errno=%d\n", errno);
    else printf("family ok\n");
    return 0;
}

static int vsock(const char *cid, const char *port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { printf("vsock socket errno=%d\n", errno); return 0; }
    struct sockaddr_vm addr = {0};
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = (unsigned)atoi(cid);
    addr.svm_port = (unsigned)atoi(port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        printf("vsock connect errno=%d\n", errno);
        return 0;
    }
    printf("vsock connected\n");
    return 0;
}

static int keyring(void) {
    /* KEYCTL_GET_KEYRING_ID = 0; KEY_SPEC_SESSION_KEYRING = -3,
       KEY_SPEC_USER_KEYRING = -4. */
    long session = syscall(SYS_keyctl, 0, -3, 0);
    int session_errno = session < 0 ? errno : 0;
    long user = syscall(SYS_keyctl, 0, -4, 0);
    int user_errno = user < 0 ? errno : 0;
    long added = syscall(SYS_add_key, "user", "tog-probe", "x", 1, -3);
    int added_errno = added < 0 ? errno : 0;
    long requested = syscall(SYS_request_key, "user", "tog-probe", NULL, 0);
    int requested_errno = requested < 0 ? errno : 0;
    printf("keyring session=%d user=%d add=%d request=%d\n", session_errno, user_errno,
           added_errno, requested_errno);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 2) return 2;
    const char *cmd = argv[1];
    if (!strcmp(cmd, "tcp") && argc == 4) return tcp(argv[2], argv[3]);
    if (!strcmp(cmd, "unix") && argc == 3) return unix_connect(argv[2]);
    if (!strcmp(cmd, "wait-unix") && argc == 3) return wait_unix(argv[2]);
    if (!strcmp(cmd, "dns") && argc == 3) return dns(argv[2]);
    if (!strcmp(cmd, "socketpair")) return pair(SOCK_STREAM);
    if (!strcmp(cmd, "socketpair-seqpacket")) return pair(SOCK_SEQPACKET);
    if (!strcmp(cmd, "socketpair-dgram")) return pair(SOCK_DGRAM);
    if (!strcmp(cmd, "io_uring")) return io_uring();
    if (!strcmp(cmd, "int80")) return int80();
    if (!strcmp(cmd, "ptrace-parent")) return ptrace_parent();
    if (!strcmp(cmd, "pid1")) return pid1();
    if (!strcmp(cmd, "daemon") && argc == 4) return daemonize(argv[2], argv[3]);
    if (!strcmp(cmd, "read") && argc == 3) return read_first(argv[2]);
    if (!strcmp(cmd, "family") && argc == 3) return family(argv[2]);
    if (!strcmp(cmd, "vsock") && argc == 4) return vsock(argv[2], argv[3]);
    if (!strcmp(cmd, "keyring")) return keyring();
    fprintf(stderr, "door_probe: unknown command %s\n", cmd);
    return 2;
}
