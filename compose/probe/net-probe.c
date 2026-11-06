/* net-probe: the C-NET socket sweep (WEEK2_PLAN §3, RV4 #6). Test image only, never a release
 * image, and outside the crate, whose `unsafe_code = "forbid"` rules out raw syscalls.
 *
 * It tries to create a socket of every family and three types, by every route to the kernel a
 * static x86_64 binary has:
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
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
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

int main(void) {
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
