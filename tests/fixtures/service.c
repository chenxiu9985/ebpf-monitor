#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    pid_t pid = fork();
    if (pid < 0) return 3;
    if (!pid) {
        execl("/bin/sh", "sh", "-c", "\"$1\" \"$2\"; :", "fixture", argv[1], argv[2], (char *)0);
        _exit(4);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) return 5;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 6;
}
