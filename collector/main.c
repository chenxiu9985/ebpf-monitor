// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
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
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "events.h"
#include "monitor.skel.h"
#include "transport.h"

static unsigned long long seq;
static char boot_id[80], host_id[128], session[256];
static volatile sig_atomic_t stopping, reload_requested;
static const char *open_path, *exec_path, *cgroup_path;
static unsigned policy_uid, policy_version;
static bool have_uid;
// Explicit diagnostic modes omit event output and must never be used for monitoring.
static const char *benchmark_stage;
static unsigned long long benchmark_events;
static unsigned batch_ms = 10;
static unsigned drain_timeout_ms = 10000;
static bool active_bpf_lsm(void) {
    char data[1024];
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) return false;
    bool found = false;
    if (fgets(data, sizeof(data), f)) {
        char *saveptr = NULL;
        for (char *token = strtok_r(data, ",\r\n", &saveptr); token; token = strtok_r(NULL, ",\r\n", &saveptr))
            if (!strcmp(token, "bpf")) found = true;
    }
    fclose(f); return found;
}
static unsigned long long now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec*1000000000ULL+t.tv_nsec;
}
static void signal_handler(int sig) {
    if (sig == SIGHUP) reload_requested = 1;
    else stopping = 1;
}
static void quote(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p=(const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') fprintf(f, "\\%c", *p);
        else if (*p < 32) fprintf(f, "\\u%04x", *p);
        else if (*p >= 128) {
            unsigned n = *p >= 0xc2 && *p <= 0xdf ? 2 : *p >= 0xe0 && *p <= 0xef ? 3 : *p >= 0xf0 && *p <= 0xf4 ? 4 : 0;
            bool valid = n != 0;
            for (unsigned i=1; valid && i<n; i++) if (!p[i] || (p[i]&0xc0)!=0x80) valid=false;
            if(valid && ((*p==0xe0 && p[1]<0xa0) || (*p==0xed && p[1]>=0xa0) || (*p==0xf0 && p[1]<0x90) || (*p==0xf4 && p[1]>=0x90))) valid=false;
            if(valid) { fwrite(p,1,n,f); p+=n-1; }
            else fputs("\\ufffd",f);
        }
        else fputc(*p, f);
    }
    fputc('"', f);
}
static void identity(FILE *f, const char *key, unsigned pid, unsigned long long start_ns) {
    fprintf(f, ",\"%s\":", key);
    char tmp[384];
    snprintf(tmp, sizeof(tmp), "%s:%s:%u:%llu", host_id, boot_id, pid, start_ns);
    quote(f, tmp);
}
static void base(FILE *f, const char *type, unsigned long long timestamp) {
    fprintf(f, "{\"schema_version\":1,\"event_id\":\"%s:%llu\",\"event_type\":", session, ++seq);
    quote(f, type);
    fprintf(f, ",\"monotonic_ns\":%llu,\"host_id\":", timestamp); quote(f, host_id);
    fputs(",\"boot_id\":", f); quote(f, boot_id);
}
static const char *event_name(unsigned type) {
    switch(type) {
    case EV_FORK: return "process_fork";
    case EV_EXEC: return "process_exec";
    case EV_EXIT: return "thread_exit";
    case EV_OPEN: return "file_open";
    case EV_PTRACE: return "ptrace";
    case EV_EXEC_FAIL: return "process_exec_failed";
    case EV_RENAME: return "file_rename";
    case EV_UNLINK: return "file_unlink";
    case EV_DENY: return "policy_denied";
    default: return "unknown";
    }
}
static int on_event(void *ctx, void *data, size_t len) {
    (void)ctx;
    if (len < __builtin_offsetof(struct event, path)) { queue_lost++; return 0; }
    const struct event *wire=data;
    if (len != sizeof(struct event) && len != event_wire_size(wire->type)) { queue_lost++; return 0; }
    benchmark_events++;
    if (benchmark_stage && !strcmp(benchmark_stage,"consume")) return 0;
    struct event expanded = {};
    const struct event *e=data;
    if (len != sizeof(expanded)) { memcpy(&expanded,data,len); e=&expanded; }
    char *json=NULL; size_t size=0;
    FILE *f=open_memstream(&json, &size);
    if (!f) { queue_lost++; return 0; }
    base(f, event_name(e->type), e->timestamp_ns);
    identity(f, "process_key", e->tgid, e->start_ns);
    identity(f, "parent_process_key", e->ppid, e->parent_start_ns);
    if (e->target_host_pid) identity(f, "target_process_key", e->target_host_pid, e->target_start_ns);
    fprintf(f, ",\"process_dead\":%s", e->process_dead?"true":"false");
    fprintf(f, ",\"tgid\":%u,\"tid\":%u,\"ppid\":%u,\"process_start_ns\":%llu,\"uid\":%u,\"euid\":%u,\"cgroup_id\":%llu",
        e->tgid,e->tid,e->ppid,(unsigned long long)e->start_ns,e->uid,e->euid,(unsigned long long)e->cgroup_id);
    fprintf(f, ",\"retval\":%lld,\"result_state\":\"%s\",\"quality_flags\":%u,\"flags\":%llu,\"dirfd\":%d,\"request\":%u,\"target_pid\":%u,\"inode\":%llu,\"device\":%llu,\"policy_version\":%u,\"operation\":%u",
        (long long)e->retval,e->retval<0?"failed":"succeeded",e->quality,(unsigned long long)e->flags,e->dirfd,e->request,e->target_pid,
        (unsigned long long)e->inode,(unsigned long long)e->device,e->policy_version,e->operation);
    fputs(",\"comm\":", f); quote(f,e->comm);
    if(e->type==EV_OPEN) {
        fputs(",\"path_source\":", f);
        quote(f,(e->quality & Q_KERNEL_OPEN_PATH)?"kernel_filename":(e->path[0]?"syscall_entry":"unavailable"));
    }
    fputs(",\"path\":", f); quote(f,e->path);
    fputs(",\"path2\":", f); quote(f,e->path2);
    fputs(",\"argv_summary\":", f); quote(f,e->argv_summary);
    fputs(",\"env\":{\"LD_PRELOAD\":", f); quote(f,e->preload);
    fputs(",\"LD_LIBRARY_PATH\":", f); quote(f,e->library_path);
    fputs("}", f);
    if (e->type==EV_EXEC) { fputs(",\"exe\":",f); quote(f,e->path); }
    fputs("}",f);
    if (fclose(f)) { free(json); queue_lost++; return 0; }
    if (benchmark_stage) free(json);
    else queue_message(json,size);
    return 0;
}
static void metric(struct monitor_bpf *skel, const char *type) {
    unsigned long long sums[CNT_TOTAL]={0};
    int cpus=libbpf_num_possible_cpus();
    if (cpus<=0) return;
    __u64 *values=calloc((size_t)cpus,sizeof(*values));
    if (!values) return;
    for (__u32 key=0;key<CNT_TOTAL;key++) {
        if (!bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),&key,values))
            for(int i=0;i<cpus;i++) sums[key]+=values[i];
    }
    free(values);
    char *json=NULL; size_t len=0; FILE *f=open_memstream(&json,&len);
    if (!f) return;
    base(f,type,now_ns());
    __u32 zero=0, host_tgid=0;
    bpf_map_lookup_elem(bpf_map__fd(skel->maps.collector_identity), &zero, &host_tgid);
    fprintf(f,",\"pid_namespace_is_host\":%s",host_tgid==(unsigned)getpid()?"true":"false");
    fprintf(f,",\"metrics\":{\"events_attempted\":%llu,\"ring_lost\":%llu,\"map_fail\":%llu,\"unpaired\":%llu,\"denied\":%llu,\"queue_lost\":%llu,\"queue_depth\":%u,\"transport_disconnects\":%llu},\"enforcement_enabled\":%s,\"policy_version\":%u,\"shutdown_ack_required\":%s}",
        sums[0],sums[1],sums[2],sums[3],sums[4],queue_lost,used,transport_disconnects,policy_version?"true":"false",policy_version,
        socket_path && !strcmp(type,"monitor_stop") ? "true" : "false");
    fclose(f); fprintf(stderr,"%s\n",json); queue_message(json,len);
}
static unsigned long long kernel_device(dev_t dev) {
    return ((unsigned long long)major(dev)<<20)|minor(dev);
}
static int update_policy(struct monitor_bpf *skel) {
    struct enforcement_policy p={0}; struct stat st;
    if (!cgroup_path || !have_uid || (!open_path && !exec_path)) return -EINVAL;
    if (stat(cgroup_path,&st) || !S_ISDIR(st.st_mode)) return -EINVAL;
    // cgroup-v2 inode identifies the exact cgroup (no recursive subtree matching).
    p.cgroup_id=st.st_ino; p.uid=policy_uid; p.version=policy_version+1;
    if(open_path) {
        if(stat(open_path,&st) || !S_ISREG(st.st_mode)) return -EINVAL;
        p.open_inode=st.st_ino; p.open_device=kernel_device(st.st_dev);
    }
    if(exec_path) {
        if(stat(exec_path,&st) || !S_ISREG(st.st_mode)) return -EINVAL;
        p.exec_inode=st.st_ino; p.exec_device=kernel_device(st.st_dev);
    }
    __u32 zero=0, slot=p.version%2;
    if(bpf_map_update_elem(bpf_map__fd(skel->maps.policies),&slot,&p,BPF_ANY)) return -errno;
    if(bpf_map_update_elem(bpf_map__fd(skel->maps.active_policy),&zero,&slot,BPF_ANY)) return -errno;
    policy_version=p.version; return 0;
}
static int read_id(const char *path,char *buf,size_t len) {
    FILE *f=fopen(path,"r"); if(!f) return -1;
    bool ok=fgets(buf,(int)len,f)!=NULL; fclose(f);
    if(ok) buf[strcspn(buf,"\r\n")]=0;
    return ok?0:-1;
}
static void usage(void) {
    puts("collector [--socket PATH --exclude-pid ANALYZER_PID] [--duration SECONDS] [--enforce-cgroup /sys/fs/cgroup/NAME --enforce-uid UID --deny-open FILE --deny-exec FILE]\nAudit is default. SIGHUP re-resolves explicit enforcement targets; failure preserves old policy. SIGINT/SIGTERM detach all links. JSONL is written to stdout when --socket is omitted.");
    puts("--benchmark-stage kernel|consume|encode: diagnostic only; skip ring output, discard before encoding, or discard after encoding. Cannot be combined with socket or enforcement.");
    puts("--batch-ms 0..50: ring drain interval (default 10 ms); 0 restores adaptive event notifications.");
    puts("--full-event-records: retain padded ring records for same-binary performance comparison.");
    puts("--drain-timeout-ms 1..60000: shared shutdown drain/commit-ack deadline (default 10000 ms). Requires a v3 analyzer with --socket.");
}
int main(int argc,char **argv) {
    static const struct option opts[]={
        {"socket",1,0,'s'},{"duration",1,0,'d'}, {"exclude-pid",1,0,'p'}, {"enforce-cgroup",1,0,'c'},
        {"benchmark-stage",1,0,'b'},
        {"batch-ms",1,0,'m'},
        {"full-event-records",0,0,'F'},
        {"drain-timeout-ms",1,0,'t'},
        {"enforce-uid",1,0,'u'},{"deny-open",1,0,'o'},{"deny-exec",1,0,'x'},{"help",0,0,'h'},{0,0,0,0}};
    unsigned duration=0, excluded_pid=0; int opt,err=0; bool full_records=false;
    while((opt=getopt_long(argc,argv,"",opts,NULL))!=-1) {
        char *end=NULL;
        switch(opt) {
        case 'F': full_records=true; break;
        case 't': {
            unsigned long value=strtoul(optarg,&end,10);
            if(!*optarg || *end || value<1 || value>60000) return 2;
            drain_timeout_ms=(unsigned)value; break;
        }
        case 'm': {
            unsigned long value=strtoul(optarg,&end,10);
            if(!*optarg || *end || value>50) return 2;
            batch_ms=(unsigned)value; break;
        }
        case 'b': benchmark_stage=optarg; if(strcmp(optarg,"kernel") && strcmp(optarg,"consume") && strcmp(optarg,"encode")) return 2; break;
        case 's': socket_path=optarg; break;
        case 'd': duration=(unsigned)strtoul(optarg,&end,10); if(!*optarg||*end) return 2; break;
        case 'p': excluded_pid=(unsigned)strtoul(optarg,&end,10); if(!*optarg||*end||!excluded_pid) return 2; break;
        case 'c': cgroup_path=optarg; break;
        case 'u': policy_uid=(unsigned)strtoul(optarg,&end,10); if(!*optarg||*end) return 2; have_uid=true; break;
        case 'o': open_path=optarg; break;
        case 'x': exec_path=optarg; break;
        case 'h': usage(); return 0;
        default: usage(); return 2;
        }
    }
    if(optind!=argc) return 2;
    if(socket_path && !excluded_pid) {
        fputs("--socket requires --exclude-pid ANALYZER_PID to avoid tracing the analyzer's own log writes.\n",stderr);
        return 2;
    }
    bool enforce=cgroup_path||have_uid||open_path||exec_path;
    if(benchmark_stage && (socket_path || enforce)) {
        fputs("Diagnostic benchmark modes cannot analyze or enforce.\n",stderr); return 2;
    }
    if(benchmark_stage) fprintf(stderr,"{\"diagnostic_only\":true,\"benchmark_stage\":\"%s\"}\n",benchmark_stage);
    if(enforce && (!cgroup_path||!have_uid||(!open_path&&!exec_path))) { usage(); return 2; }
    if(enforce && strncmp(cgroup_path,"/sys/fs/cgroup/",15)) { fputs("Enforcement requires an explicit cgroup-v2 child directory.\n",stderr); return 2; }
    if(enforce && !active_bpf_lsm()) {
        fputs("Enforcement unavailable: cannot confirm bpf in /sys/kernel/security/lsm. CONFIG_BPF_LSM alone is insufficient. No programs loaded.\n",stderr);
        return 3;
    }
    if(read_id("/proc/sys/kernel/random/boot_id",boot_id,sizeof(boot_id)) || read_id("/etc/machine-id",host_id,sizeof(host_id))) return 1;
    snprintf(session,sizeof(session),"%s:%s:%ld-%llu",host_id,boot_id,(long)getpid(),now_ns());
    signal(SIGINT,signal_handler); signal(SIGTERM,signal_handler); signal(SIGHUP,signal_handler); signal(SIGPIPE,SIG_IGN);
    struct monitor_bpf *skel=monitor_bpf__open();
    if(!skel) return 1;
    skel->rodata->ignore_tgid=getpid();
    skel->rodata->analyzer_tgid=excluded_pid;
    struct stat namespace_stat;
    if(stat("/proc/self/ns/pid", &namespace_stat)) { err=-errno; goto done; }
    skel->rodata->collector_pidns=namespace_stat.st_ino;
    skel->rodata->benchmark_no_output=benchmark_stage && !strcmp(benchmark_stage,"kernel");
    skel->rodata->batch_notifications=batch_ms != 0;
    skel->rodata->full_event_records=full_records;
    if(!enforce) {
        bpf_program__set_autoload(skel->progs.deny_open,false);
        bpf_program__set_autoload(skel->progs.deny_exec,false);
    }
    if((err=monitor_bpf__load(skel))) goto done;
    if(enforce && (err=update_policy(skel))) goto done;
    if((err=monitor_bpf__attach(skel))) goto done;
    struct ring_buffer *ring=ring_buffer__new(bpf_map__fd(skel->maps.events),on_event,NULL,NULL);
    if(!ring) { err=-errno; goto done; }
    skel->bss->capturing=true;
    int marker_fd=open("/dev/null", O_RDONLY|O_CLOEXEC);
    if(marker_fd>=0) close(marker_fd);
    metric(skel,"monitor_start");
    unsigned long long begin=now_ns(),last=begin;
    while(!stopping && !transport_error && (!duration || now_ns()-begin<(unsigned long long)duration*1000000000ULL)) {
        if(reload_requested) {
            reload_requested=0;
            int rc=enforce?update_policy(skel):-EINVAL;
            fprintf(stderr,"{\"policy_reload\":\"%s\",\"version\":%u,\"error\":%d}\n",rc?"failed":"applied",policy_version,rc);
        }
        err=ring_buffer__poll(ring,batch_ms ? (int)batch_ms : 50);
        if(err<0 && err!=-EINTR) break;
        // NO_WAKEUP requires an explicit consume even when epoll timed out.
        if(batch_ms) {
            err=ring_buffer__consume(ring);
            if(err<0) break;
        }
        err=0; flush_queue();
        if(now_ns()-last>=1000000000ULL) { metric(skel,"monitor_health"); last=now_ns(); }
    }
    metric(skel,"monitor_health");
    // Stop recording before links are detached individually. Calls spanning this
    // boundary are outside the completed observation window, not missing pairs.
    skel->bss->capturing=false;
    monitor_bpf__detach(skel);
    transport_begin_shutdown(drain_timeout_ms);
    int shutdown_rc=transport_drain();
    int consume_rc=ring_buffer__consume(ring);
    if(consume_rc<0 && !err) err=consume_rc;
    unsigned long long before_stop=seq;
    metric(skel,"monitor_stop");
    char stop_id[384];
    snprintf(stop_id,sizeof(stop_id),"%s:%llu",session,seq);
    if(!shutdown_rc) shutdown_rc=seq==before_stop ? -ENOMEM : transport_finish(stop_id);
    if(shutdown_rc && !err) err=shutdown_rc;
    if(benchmark_stage) fprintf(stderr,"{\"benchmark_events\":%llu}\n",benchmark_events);
    fprintf(stderr,"{\"shutdown_unsent\":%u,\"shutdown_queue_lost\":%llu,\"transport_disconnects\":%llu,\"shutdown_acknowledged\":%s,\"shutdown_error\":%d}\n",
        used,queue_lost,transport_disconnects,socket_path && !shutdown_rc ? "true":"false",shutdown_rc);
    ring_buffer__free(ring);
done:
    if(err) fprintf(stderr,"collector failed: %d (%s)\n",err,strerror(-err));
    monitor_bpf__destroy(skel);
    transport_cleanup();
    return err?1:0;
}
