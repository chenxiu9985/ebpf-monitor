#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static unsigned long long clock_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (unsigned long long)t.tv_sec*1000000000ULL+t.tv_nsec;
}
int main(int argc,char **argv) {
    if (argc!=4) return 2;
    unsigned duration=(unsigned)strtoul(argv[3],0,10);
    unsigned long long begin=clock_ns(); int retained=-1;
    do {
        for (int index=1;index<=2;index++) {
            unsigned long long before=clock_ns(); errno=0;
            int fd=open(argv[index],O_RDONLY|O_CLOEXEC),saved=errno;
            printf("{\"phase\":\"open\",\"object\":%d,\"tgid\":%ld,\"before_ns\":%llu,\"after_ns\":%llu,\"retval\":%d,\"errno\":%d}\n",
                index,(long)getpid(),before,clock_ns(),fd,saved); fflush(stdout);
            if (fd>=0) {
                if (index==1 && retained<0) retained=fd;
                else close(fd);
            }
        }
        if (!duration) break;
        usleep(20000);
    } while (clock_ns()-begin<(unsigned long long)duration*1000000ULL);
    char byte; errno=0; ssize_t n=retained>=0?read(retained,&byte,1):-1;
    printf("{\"phase\":\"existing_fd_read\",\"retval\":%ld,\"after_ns\":%llu}\n",(long)n,clock_ns());
    if (retained>=0) close(retained);
    return 0;
}
