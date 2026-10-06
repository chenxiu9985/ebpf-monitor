#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
static const char *thread_path;
static int mapped(const char *path) {
    int fd=open(path,O_RDONLY);
    if (fd<0) return 3;
    void *memory=mmap(0,4096,PROT_READ,MAP_PRIVATE,fd,0);
    if (memory==MAP_FAILED) { close(fd); return 4; }
    munmap(memory,4096); close(fd); return 0;
}
static void *thread_map(void *unused) { (void)unused; return (void *)(long)mapped(thread_path); }
int main(int argc,char **argv) {
    if (argc!=5) return 2;
    if (mapped(argv[1]) || mapped(argv[2]) || mapped(argv[3])) return 3;
    int fd=open(argv[1],O_RDONLY);
    if (fd<0) return 4;
    void *bad=mmap(0,0,PROT_READ,MAP_PRIVATE,fd,0);
    if (bad!=MAP_FAILED) return 5;
    int original=fd; close(fd);
    fd=open(argv[4],O_RDONLY);
    if (fd<0 || fd!=original) return 6;
    void *other=mmap(0,4096,PROT_READ,MAP_PRIVATE,fd,0);
    if (other==MAP_FAILED) return 7;
    munmap(other,4096); close(fd);
    thread_path=argv[1]; pthread_t thread;
    if (pthread_create(&thread,0,thread_map,0)) return 8;
    void *ret=0; if (pthread_join(thread,&ret) || ret) return 9;
    puts("mapping fixture passed (owned files; no code-injection claim)"); return 0;
}
