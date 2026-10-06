/* Existing service, optional cron-like helper, no policy-acknowledgement wait. */
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
int main(int argc,char **argv) {
    if (argc!=5) return 2;
    const char *trigger=getenv("EBPF_START_FILE");
    if (!trigger) return 3;
    while (access(trigger,F_OK)) usleep(10000);
    pid_t child=fork();
    if (child<0) return 4;
    if (!child) {
        if (getenv("EBPF_HELPER")) {
            pid_t helper=fork();
            if (helper<0) _exit(5);
            if (helper) { int status; waitpid(helper,&status,0); _exit(WIFEXITED(status)?WEXITSTATUS(status):6); }
        }
        char path[]="/bin/sh",name[]="sh",option[]="-c";
        char command[]="\"$1\" \"$2\" \"$3\" \"$4\"; :",label[]="automatic-fixture";
        char *args[]={name,option,command,label,argv[1],argv[2],argv[3],argv[4],0};
        execve(path,args,environ); _exit(7);
    }
    int status;
    if (waitpid(child,&status,0)<0) return 8;
    return WIFEXITED(status)?WEXITSTATUS(status):9;
}
