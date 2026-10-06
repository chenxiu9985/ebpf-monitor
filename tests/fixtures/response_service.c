/* Controlled successful capture path: exec argument strings reside on stack. */
#include <sys/wait.h>
#include <unistd.h>
extern char **environ;
int main(int argc,char **argv) {
    if (argc!=3) return 2;
    pid_t child=fork();
    if (child<0) return 3;
    if (!child) {
        char path[]="/bin/sh", name[]="sh", option[]="-c";
        char command[]="\"$1\" \"$2\"; :", label[]="fixture";
        char *args[]={name,option,command,label,argv[1],argv[2],0};
        execve(path,args,environ); _exit(4);
    }
    int status;
    if (waitpid(child,&status,0)<0) return 5;
    return WIFEXITED(status)?WEXITSTATUS(status):6;
}
