/* net-probe: what an agent can try against the kernel (WEEK2_PLAN §3). Test image only, never a
 * release image, and outside the crate, whose `unsafe_code = "forbid"` rules out raw syscalls.
 *
 * `net-probe sweep` is C-NET's socket sweep (RV4 #6). The other subcommands are single attempts
 * for C-NET, C-LOCK, C-PROC, C-CRED and C-CTL. Each prints `ok`, or the errno it failed with, as
 * `STAGE:ERRNO` where a call has stages:
 *   net-probe park                    pause forever: a container to exec into
 *   net-probe connect ADDR PORT PROTO a TCP or UDP connect, with one byte sent on UDP
 *   net-probe socket FAMILY TYPE      one socket(2)
 *   net-probe unix PATH               a connect to a Unix socket
 *   net-probe tcp ADDR PORT           stdin to the peer, its reply to stdout
 *   net-probe open PATH r|w|c         open(2) for reading, writing, or creating a new file
 *   net-probe read PATH               open(2), then read(2)
 *   net-probe stat PATH               stat(2)
 *   net-probe symlink TARGET PATH     symlink(2)
 *   net-probe unlink PATH             unlink(2)
 *   net-probe rename FROM TO          rename(2)
 *   net-probe ptrace PID              PTRACE_ATTACH
 *   net-probe cat PATH                the file's text
 *   net-probe pids                    every process this namespace shows
 *
 * The sweep tries to create a socket of every family and three types, by every route to the
 * kernel a static x86_64 binary has:
 *   native      the syscall instruction, as libc does;
 *   int80       the i386 socket(2) through `int 0x80`;
 *   socketcall  the i386 socketcall(2) through `int 0x80`;
 *   x32         the syscall instruction with the x32 bit set.
 * The profile refuses a foreign ABI by killing the caller, so each attempt runs in its own child.
 *
 * One line per attempt: `ROUTE FAMILY TYPE RESULT`, where RESULT is `ok`, a decimal errno, or
 * `signal:N`. Any `ok` but AF_UNIX on the native route is a socket the agent must not have.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define FAMILIES 64
#define X32_SYSCALL_BIT 0x40000000L
#define NR_SOCKET_X86_64 41L
#define NR_SOCKET_I386 359L
#define NR_SOCKETCALL_I386 102L
#define SOCKETCALL_SOCKET 1L

/* The socketcall arguments: 32-bit pointers, so they live below 4 GiB. */
static unsigned int *low_args;

static long raw_syscall(long nr, long a, long b, long c) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "0"(nr), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}

static long raw_int80(long nr, long a, long b, long c) {
    long result;
    __asm__ volatile("int $0x80"
                     : "=a"(result)
                     : "0"(nr), "b"(a), "c"(b), "d"(c)
                     : "r8", "r9", "r10", "r11", "memory");
    return (long)(int)result; /* The i386 ABI returns in eax. */
}

static long try_native(int family, int type) {
    return raw_syscall(NR_SOCKET_X86_64, family, type, 0);
}

static long try_int80(int family, int type) {
    return raw_int80(NR_SOCKET_I386, family, type, 0);
}

static long try_socketcall(int family, int type) {
    low_args[0] = (unsigned int)family;
    low_args[1] = (unsigned int)type;
    low_args[2] = 0;
    return raw_int80(NR_SOCKETCALL_I386, SOCKETCALL_SOCKET, (long)low_args, 0);
}

static long try_x32(int family, int type) {
    return raw_syscall(X32_SYSCALL_BIT | NR_SOCKET_X86_64, family, type, 0);
}

static void attempt(const char *route, long (*route_call)(int, int), int family, int type) {
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        exit(2);
    }
    if (child == 0) {
        long result = route_call(family, type);
        _exit(result >= 0 ? 0 : (int)-result);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        perror("waitpid");
        exit(2);
    }
    if (WIFSIGNALED(status)) {
        printf("%s %d %d signal:%d\n", route, family, type, WTERMSIG(status));
    } else if (WEXITSTATUS(status) == 0) {
        printf("%s %d %d ok\n", route, family, type);
    } else {
        printf("%s %d %d %d\n", route, family, type, WEXITSTATUS(status));
    }
}

static int result(int status) {
    if (status < 0) {
        printf("%d\n", errno);
    } else {
        printf("ok\n");
    }
    return 0;
}

/* A connected socket, or -1 after printing where it failed. */
static int connected(const char *address, int port, int type) {
    struct sockaddr_in v4 = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    struct sockaddr_in6 v6 = {.sin6_family = AF_INET6, .sin6_port = htons((unsigned short)port)};
    int family = strchr(address, ':') ? AF_INET6 : AF_INET;
    int fd = socket(family, type, 0);
    if (fd < 0) {
        printf("socket:%d\n", errno);
        return -1;
    }
    struct timeval deadline = {.tv_sec = 3};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &deadline, sizeof deadline);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &deadline, sizeof deadline);
    int status;
    if (family == AF_INET) {
        inet_pton(AF_INET, address, &v4.sin_addr);
        status = connect(fd, (struct sockaddr *)&v4, sizeof v4);
    } else {
        inet_pton(AF_INET6, address, &v6.sin6_addr);
        status = connect(fd, (struct sockaddr *)&v6, sizeof v6);
    }
    if (status < 0) {
        printf("connect:%d\n", errno);
        close(fd);
        return -1;
    }
    return fd;
}

static int do_connect(const char *address, int port, const char *proto) {
    int udp = strcmp(proto, "udp") == 0;
    int fd = connected(address, port, udp ? SOCK_DGRAM : SOCK_STREAM);
    if (fd < 0) {
        return 0;
    }
    if (udp && send(fd, "x", 1, 0) < 0) {
        printf("send:%d\n", errno);
        return 0;
    }
    printf("ok\n");
    return 0;
}

static int do_tcp(const char *address, int port) {
    int fd = connected(address, port, SOCK_STREAM);
    if (fd < 0) {
        return 0;
    }
    char buffer[4096];
    ssize_t count;
    while ((count = read(0, buffer, sizeof buffer)) > 0) {
        if (write(fd, buffer, (size_t)count) != count) {
            printf("write:%d\n", errno);
            return 0;
        }
    }
    shutdown(fd, SHUT_WR);
    while ((count = read(fd, buffer, sizeof buffer)) > 0) {
        fwrite(buffer, 1, (size_t)count, stdout);
    }
    return 0;
}

static int do_unix(const char *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strncpy(address.sun_path, path, sizeof address.sun_path - 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket:%d\n", errno);
        return 0;
    }
    return result(connect(fd, (struct sockaddr *)&address, sizeof address));
}

static int do_read(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("open:%d\n", errno);
        return 0;
    }
    char byte;
    return result(read(fd, &byte, 1) < 0 ? -1 : 0);
}

static int do_cat(const char *path) {
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        printf("open:%d\n", errno);
        return 0;
    }
    int character;
    while ((character = fgetc(file)) != EOF) {
        putchar(character);
    }
    return 0;
}

static int do_pids(void) {
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        printf("open:%d\n", errno);
        return 0;
    }
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (isdigit((unsigned char)entry->d_name[0])) {
            printf("%s\n", entry->d_name);
        }
    }
    return 0;
}

static int do_open(const char *path, const char *mode) {
    int flags = O_RDONLY;
    if (mode[0] == 'w') {
        flags = O_WRONLY;
    } else if (mode[0] == 'c') {
        flags = O_WRONLY | O_CREAT | O_EXCL;
    }
    return result(open(path, flags, 0600));
}

static int sweep(void);

int main(int argc, char **argv) {
    const char *command = argc > 1 ? argv[1] : "sweep";
#define IS(name, count) (strcmp(command, name) == 0 && argc == (count) + 2)
    if (IS("sweep", 0)) {
        return sweep();
    }
    if (IS("park", 0)) {
        for (;;) {
            pause();
        }
    }
    if (IS("connect", 3)) {
        return do_connect(argv[2], atoi(argv[3]), argv[4]);
    }
    if (IS("socket", 2)) {
        return result(socket(atoi(argv[2]), atoi(argv[3]), 0));
    }
    if (IS("unix", 1)) {
        return do_unix(argv[2]);
    }
    if (IS("tcp", 2)) {
        return do_tcp(argv[2], atoi(argv[3]));
    }
    if (IS("open", 2)) {
        return do_open(argv[2], argv[3]);
    }
    if (IS("read", 1)) {
        return do_read(argv[2]);
    }
    if (IS("stat", 1)) {
        struct stat info;
        return result(stat(argv[2], &info));
    }
    if (IS("symlink", 2)) {
        return result(symlink(argv[2], argv[3]));
    }
    if (IS("unlink", 1)) {
        return result(unlink(argv[2]));
    }
    if (IS("rename", 2)) {
        return result(rename(argv[2], argv[3]));
    }
    if (IS("ptrace", 1)) {
        return result((int)ptrace(PTRACE_ATTACH, atoi(argv[2]), NULL, NULL));
    }
    if (IS("cat", 1)) {
        return do_cat(argv[2]);
    }
    if (IS("pids", 0)) {
        return do_pids();
    }
    fprintf(stderr, "net-probe: unknown command\n");
    return 2;
}

static int sweep(void) {
    static const struct {
        const char *name;
        long (*call)(int, int);
    } routes[] = {
        {"native", try_native},
        {"int80", try_int80},
        {"socketcall", try_socketcall},
        {"x32", try_x32},
    };
    static const int types[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_RAW};
    /* Children are killed by the thousand, by design. Where core_pattern is a pipe, as on CI's
     * runners, a core dump for each takes the sweep past any deadline. */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    low_args = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (low_args == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    for (size_t route = 0; route < sizeof routes / sizeof routes[0]; route++) {
        for (int family = 0; family < FAMILIES; family++) {
            for (size_t type = 0; type < sizeof types / sizeof types[0]; type++) {
                attempt(routes[route].name, routes[route].call, family, types[type]);
            }
        }
    }
    return 0;
}
