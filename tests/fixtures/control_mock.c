/* Tests the real C protocol handler with simulated BPF maps; not LSM evidence. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "events.h"
#define BPF_NOEXIST 1
#define BPF_ANY 0
struct monitor_bpf { struct { int identities, dynamic_policies, protected_objects, service_objects; } maps; };
static int bpf_map__fd(int fd) { return fd; }
static struct dynamic_policy simulated;
static struct instance_key simulated_key;
static bool occupied;
struct simulated_asset { int fd; struct file_key key; unsigned id; };
static struct simulated_asset assets[256];
static int bpf_map_lookup_elem(int fd,const void *key,void *value) {
    if (fd>=3) {
        for (unsigned i=0;i<256;i++) if (assets[i].fd==fd && !memcmp(&assets[i].key,key,sizeof(struct file_key))) {
            *(unsigned *)value=assets[i].id; return 0;
        }
        errno=ENOENT; return -1;
    }
    const struct instance_key *instance=key;
    if (fd==1 && instance->tgid==42 && instance->start_ns==100) {
        *(struct execution_identity *)value=(struct execution_identity){.token=900,.uid=1000,.cgroup_id=789,
            .service_id=getenv("MOCK_NO_SERVICE")?0:1,.service_token=800,.service_start_ns=90}; return 0;
    }
    if (fd==2 && occupied && !memcmp(instance,&simulated_key,sizeof(*instance))) {
        *(struct dynamic_policy *)value=simulated; return 0;
    }
    errno=ENOENT; return -1;
}
static int bpf_map_update_elem(int fd,const void *key,const void *value,int flag) {
    (void)flag;
    if (fd>=3) {
        unsigned slot=256;
        for (unsigned i=0;i<256;i++) {
            if (assets[i].fd==fd && !memcmp(&assets[i].key,key,sizeof(struct file_key))) { slot=i; break; }
            if (!assets[i].fd) slot=i;
        }
        if (slot==256) { errno=ENOSPC; return -1; }
        assets[slot]=(struct simulated_asset){.fd=fd,.key=*(const struct file_key *)key,.id=*(const unsigned *)value}; return 0;
    }
    if (occupied) { errno=EEXIST; return -1; }
    simulated_key=*(const struct instance_key *)key; simulated=*(const struct dynamic_policy *)value;
    occupied=true; return 0;
}
static int bpf_map_delete_elem(int fd,const void *key) {
    if (fd>=3) {
        for (unsigned i=0;i<256;i++) if (assets[i].fd==fd && !memcmp(&assets[i].key,key,sizeof(struct file_key))) {
            assets[i].fd=0; return 0;
        }
        errno=ENOENT; return -1;
    }
    occupied=false; return 0;
}
static char session[256]="test-session";
static const char *socket_path="unused-event-socket";
static unsigned long long now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
    return (unsigned long long)t.tv_sec*1000000000ULL+t.tv_nsec;
}
static unsigned long long kernel_device(dev_t dev) { return ((unsigned long long)major(dev)<<20)|minor(dev); }
static void base(FILE *f,const char *kind,unsigned long long time) { fprintf(f,"{\"event_type\":\"%s\",\"monotonic_ns\":%llu",kind,time); }
static void queue_message(char *data,size_t len) { (void)len; free(data); }
static void quote(FILE *f,const char *s) { fprintf(f,"\"%s\"",s); }
#include "../../collector/registry.h"
#include "../../collector/control.h"
static int check_registry(void) {
    for (unsigned i=0;i<registry_used;i++) if (registry[i].fd>=0) {
        unsigned id=0;
        if (bpf_map_lookup_elem(registry[i].kind==1?3:4,&registry[i].key,&id) || !id) return -1;
    }
    for (unsigned i=0;i<256;i++) if (assets[i].fd) {
        bool found=false;
        for (unsigned j=0;j<registry_used;j++) if (registry[j].fd>=0 &&
            assets[i].fd==(registry[j].kind==1?3:4) && !memcmp(&assets[i].key,&registry[j].key,sizeof(struct file_key))) found=true;
        for (unsigned j=0;j<registry_retired_used;j++) if (assets[i].fd==(registry_retired[j].kind==1?3:4) &&
            !memcmp(&assets[i].key,&registry_retired[j].key,sizeof(struct file_key))) found=true;
        if (!found) return -1;
    }
    return 0;
}
int main(int argc,char **argv) {
    if (argc!=3) return 2;
    struct stat st;
    if (stat(argv[2],&st)) return 3;
    control_object=argv[2]; control_path=argv[1];
    control_object_fd=open(argv[2],O_PATH|O_CLOEXEC);
    control_inode=st.st_ino; control_device=kernel_device(st.st_dev);
    control_target_uid=1000; control_peer_uid=getuid(); control_cgroup_id=1;
    control_fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK,0);
    struct sockaddr_un address={.sun_family=AF_UNIX}; strcpy(address.sun_path,argv[1]);
    if (bind(control_fd,(struct sockaddr *)&address,sizeof(address)) || listen(control_fd,4)) return 4;
    control_bound=true;
    /* Reference the startup function as well to compile all protocol code. */
    int (*read_reference)(void)=registry_read; (void)read_reference;
    int (*refresh_reference)(struct monitor_bpf *,bool)=registry_refresh; (void)refresh_reference;
    void (*close_reference)(void)=registry_close; (void)close_reference;
    int (*open_reference)(void)=control_open; (void)open_reference;
    struct monitor_bpf skel={.maps={.identities=1,.dynamic_policies=2,.protected_objects=3,.service_objects=4}};
    control_manifest=getenv("AUTO_MANIFEST");
    if (control_manifest && (registry_read() || registry_refresh(&skel,true))) return 5;
    unsigned long long until=now_ns()+10000000000ULL;
    while (now_ns()<until) { if (registry_refresh(&skel,false)) registry_objects=0; if (control_manifest && check_registry()) return 6; control_poll(&skel,getppid()); usleep(1000); }
    control_expire(&skel,true); control_close(); registry_close(); return 0;
}
