#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
static volatile long child_value = 7;
static void *thread_exec(void *arg) {
    (void)arg;
    char *argv[] = {"true", NULL};
    execve("/usr/bin/true", argv, environ);
    _exit(90);
}
int main(int argc, char **argv) {
    if(argc < 2) return 2;
    if(!strcmp(argv[1],"openat2")) {
        if(argc != 3) return 2;
        struct open_how how = {.flags=O_RDONLY};
        int fd = syscall(SYS_openat2, AT_FDCWD, argv[2], &how, sizeof(how));
        if(fd<0) return 3;
        close(fd); return 0;
    }
    if(!strcmp(argv[1],"execveat")) {
        int fd = open("/usr/bin/true",O_PATH);
        if(fd<0) return 3;
        char *args[] = {"true",NULL};
        syscall(SYS_execveat, fd, "", args, environ, AT_EMPTY_PATH);
        return 4;
    }
    if(!strcmp(argv[1],"thread-exec")) {
        pthread_t thread;
        if(pthread_create(&thread,NULL,thread_exec,NULL)) return 3;
        for(;;) pause();
    }
    if(!strcmp(argv[1],"exec-fail")) {
        char *args[] = {"missing",NULL};
        execve("/nonexistent/ebpf-monitor-fixture",args,environ);
        return errno==ENOENT ? 0 : 3;
    }
    if(!strcmp(argv[1],"ptrace")) {
        pid_t child = fork();
        if(child<0) return 3;
        if(!child) {
            if(ptrace(PTRACE_TRACEME,0,0,0)) _exit(4);
            raise(SIGSTOP);
            _exit(child_value==42 ? 0 : 5);
        }
        int status;
        if(waitpid(child,&status,0)<0 || !WIFSTOPPED(status)) return 6;
        if(ptrace(PTRACE_POKEDATA,child,(void *)&child_value,(void *)42)) { kill(child,SIGKILL); waitpid(child,&status,0); return 7; }
        if(ptrace(PTRACE_CONT,child,0,0)) { kill(child,SIGKILL); waitpid(child,&status,0); return 8; }
        if(waitpid(child,&status,0)<0) return 9;
        return WIFEXITED(status) ? WEXITSTATUS(status) : 10;
    }
    return 2;
}
