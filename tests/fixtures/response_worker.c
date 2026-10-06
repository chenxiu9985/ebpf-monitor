#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
static unsigned long long clock_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (unsigned long long)t.tv_sec*1000000000ULL+t.tv_nsec;
}
static void opens(const char *path,const char *phase,unsigned gap) {
    for (int i=0;i<10;i++) {
        unsigned long long before=clock_ns(); errno=0;
        int fd=open(path,O_RDONLY|O_CLOEXEC), saved=errno;
        if (fd>=0) close(fd);
        printf("{\"phase\":\"%s\",\"before_ns\":%llu,\"after_ns\":%llu,\"retval\":%d,\"errno\":%d}\n",phase,before,clock_ns(),fd,saved);
        fflush(stdout);
        if (gap) usleep(gap);
    }
}
int main(int argc,char **argv) {
    if (argc!=2) return 2;
    const char *ready=getenv("EBPF_READY_FILE");
    unsigned gap=getenv("EBPF_GAP_US")?(unsigned)strtoul(getenv("EBPF_GAP_US"),0,10):0;
    unsigned long long first_before=clock_ns(); errno=0;
    int inherited=open(argv[1],O_RDONLY|O_CLOEXEC), first_errno=errno;
    printf("{\"phase\":\"initial\",\"before_ns\":%llu,\"after_ns\":%llu,\"retval\":%d,\"errno\":%d}\n",first_before,clock_ns(),inherited,first_errno); fflush(stdout);
    opens(argv[1],"initial",gap);
    if (!ready) { if (inherited>=0) close(inherited); return 0; }
    unsigned long long until=clock_ns()+10000000000ULL;
    while (access(ready,F_OK) && clock_ns()<until) usleep(1000);
    if (access(ready,F_OK)) return 3;
    opens(argv[1],"after_confirmation",0);
    char byte; ssize_t read_result=inherited>=0?read(inherited,&byte,1):-1;
    printf("{\"phase\":\"existing_fd_read\",\"retval\":%ld}\n",(long)read_result); fflush(stdout);
    if (inherited>=0) close(inherited);
    usleep(3200000);
    opens(argv[1],"after_expiry",0);
    return 0;
}
