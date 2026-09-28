#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    if (!strcmp(argv[1], "open")) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) return errno == EPERM ? 77 : 78;
        close(fd);
    }
    int marker = open(argv[3], O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (marker < 0) return 3;
    if (write(marker, "SIDE_EFFECT\n", 12) != 12) { close(marker); return 4; }
    close(marker);
    return 0;
}
