#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 3;
    close(fd);
    // Nonexistent target: exercise failed request telemetry without modifying a process.
    syscall(SYS_ptrace, PTRACE_POKEDATA, 2147483647, 0, 0);
    return 0;
}
