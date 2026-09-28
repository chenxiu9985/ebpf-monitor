#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3 || getuid() == 0) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return 3;
    char *cold = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (cold == MAP_FAILED) return 4;
    close(fd);
    // A file-backed page with no PTE: the syscall can fault it in, BPF cannot.
    if (madvise(cold, 4096, MADV_DONTNEED)) return 5;
    errno = 0;
    long denied = syscall(SYS_openat, AT_FDCWD, cold, O_RDONLY, 0);
    int denied_error = errno;
    if (denied >= 0) close((int)denied);
    munmap(cold, 4096);
    errno = 0;
    long invalid = syscall(SYS_openat, AT_FDCWD, (void *)1, O_RDONLY, 0);
    int invalid_error = errno;
    if (invalid >= 0) close((int)invalid);
    errno = 0;
    int normal = open(argv[2], O_RDONLY);
    int normal_error = errno;
    if (normal >= 0) close(normal);
    printf("{\"pid\":%d,\"uid\":%u,\"cold_errno\":%d,\"invalid_errno\":%d,\"normal_errno\":%d}\n",
           getpid(), (unsigned)getuid(), denied_error, invalid_error, normal_error);
    return denied == -1 && denied_error == EACCES && invalid == -1 &&
           invalid_error == EFAULT && normal == -1 && normal_error == EACCES ? 0 : 6;
}
