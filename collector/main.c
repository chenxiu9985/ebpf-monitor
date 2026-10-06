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
static const char *registry_service_path(unsigned id);
static bool dynamic_enabled, registry_only;
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
    fprintf(f, "{\"schema_version\":2,\"event_id\":\"%s:%llu\",\"event_type\":", session, ++seq);
    quote(f, type);
    fprintf(f, ",\"monotonic_ns\":%llu,\"host_id\":", timestamp); quote(f, host_id);
    fputs(",\"boot_id\":", f); quote(f, boot_id);
    fputs(",\"session_id\":", f); quote(f, session);
    fprintf(f,",\"clock_domain\":\"CLOCK_MONOTONIC\",\"collector_receive_ns\":%llu",now_ns());
    fputs(",\"source_hook\":",f);
    const char *hook="selected_syscall_entry_exit";
    if (!strncmp(type,"monitor_",8)) hook="collector";
    else if (!strcmp(type,"process_exec")) hook="sched/sched_process_exec";
    else if (!strcmp(type,"process_fork")) hook="raw_tp/sched_process_fork";
    else if (!strcmp(type,"thread_exit")) hook="raw_tp/sched_process_exit";
    else if (!strcmp(type,"file_open")) hook="syscalls/open_family+security_file_open+do_filp_open";
    else if (!strcmp(type,"file_mapping")) hook="syscalls/mmap+security_mmap_file";
    else if (!strcmp(type,"policy_denied")) hook="lsm/file_open_or_bprm_check_security";
    quote(f,hook);
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
    case EV_MAP: return "file_mapping";
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
    fprintf(f,",\"exec_token\":%llu,\"parent_exec_token\":%llu,\"dynamic_policy_id\":%llu",
        (unsigned long long)e->exec_token,(unsigned long long)e->parent_exec_token,(unsigned long long)e->dynamic_policy_id);
    if (e->service_id) {
        fprintf(f,",\"service_id\":%u,\"service_source\":%u,\"service_token\":%llu,\"service_tgid\":%u,\"service_start_ns\":%llu",
            e->service_id,e->service_source,(unsigned long long)e->service_token,e->service_tgid,(unsigned long long)e->service_start_ns);
        identity(f,"service_process_key",e->service_tgid,e->service_start_ns);
        fputs(",\"service_exe\":",f); quote(f,registry_service_path(e->service_id));
    }
    fprintf(f,",\"protected_object_id\":%u",e->protected_object_id);
    fprintf(f,",\"operation_start_ns\":%llu,\"process_start_clock_domain\":\"CLOCK_BOOTTIME\"",(unsigned long long)e->operation_start_ns);
    fprintf(f,",\"source_detail\":\"%s\"",e->type==EV_MAP?"syscalls/mmap+security_mmap_file":"selected_kernel_hooks");
    fprintf(f,",\"field_quality\":{\"path\":%u,\"environment\":%u,\"argv\":%u}",e->path_quality,e->env_quality,e->argv_quality);
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
    fprintf(f,",\"metrics\":{\"events_attempted\":%llu,\"ring_lost\":%llu,\"map_fail\":%llu,\"unpaired\":%llu,\"denied\":%llu,\"filtered\":%llu,\"queue_lost\":%llu,\"queue_depth\":%u,\"transport_disconnects\":%llu},\"enforcement_enabled\":%s,\"policy_version\":%u,\"shutdown_ack_required\":%s}",
        sums[0],sums[1],sums[2],sums[3],sums[4],sums[5],queue_lost,used,transport_disconnects,(policy_version || dynamic_enabled)?"true":"false",policy_version,
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
#include "registry.h"
#include "control.h"
static void usage(void) {
    puts("collector [--socket PATH --exclude-pid ANALYZER_PID] [--duration SECONDS] [--enforce-cgroup /sys/fs/cgroup/NAME --enforce-uid UID --deny-open FILE --deny-exec FILE]\nAudit is default. SIGHUP re-resolves explicit enforcement targets; failure preserves old policy. SIGINT/SIGTERM detach all links. JSONL is written to stdout when --socket is omitted.");
    puts("--benchmark-stage kernel|consume|encode: diagnostic only; skip ring output, discard before encoding, or discard after encoding. Cannot be combined with socket or enforcement.");
    puts("--batch-ms 0..50: ring drain interval (default 10 ms); 0 restores adaptive event notifications.");
    puts("--full-event-records: retain padded ring records for same-binary performance comparison.");
    puts("--capture-mappings: x86 mmap object/result evidence for instances with observed loading environment; default off.");
    puts("--asset-manifest FILE: enroll authorized service/object identities in audit or shadow; does not enable LSM denial.");
    puts("--control-socket PATH --control-manifest FILE: automatic response for registered assets; UID/cgroup are kernel-discovered.");
    puts("--control-socket PATH --control-object FILE --control-cgroup CGROUP --control-target-uid UID [--control-peer-uid UID]: enable restricted dynamic file_open control; requires active BPF LSM.");
    puts("--drain-timeout-ms 1..60000: shared shutdown drain/commit-ack deadline (default 10000 ms). Requires a v3 analyzer with --socket.");
}
int main(int argc,char **argv) {
    static const struct option opts[]={
        {"socket",1,0,'s'},{"duration",1,0,'d'}, {"exclude-pid",1,0,'p'}, {"enforce-cgroup",1,0,'c'},
        {"benchmark-stage",1,0,'b'},
        {"batch-ms",1,0,'m'},
        {"full-event-records",0,0,'F'},
        {"drain-timeout-ms",1,0,'t'},
        {"capture-mappings",0,0,'M'},
        {"control-socket",1,0,1001},{"control-object",1,0,1002},{"control-cgroup",1,0,1003},
        {"asset-manifest",1,0,1007},{"control-manifest",1,0,1006},{"control-target-uid",1,0,1004},{"control-peer-uid",1,0,1005},
        {"enforce-uid",1,0,'u'},{"deny-open",1,0,'o'},{"deny-exec",1,0,'x'},{"help",0,0,'h'},{0,0,0,0}};
    unsigned duration=0, excluded_pid=0; int opt,err=0; bool full_records=false, mappings=false;
    control_peer_uid=getuid();
    while((opt=getopt_long(argc,argv,"",opts,NULL))!=-1) {
        char *end=NULL;
        switch(opt) {
        case 'M': mappings=true; break;
        case 1007: control_manifest=optarg; registry_only=true; break;
        case 1006: control_manifest=optarg; break;
        case 1001: control_path=optarg; break;
        case 1002: control_object=optarg; break;
        case 1003: control_cgroup=optarg; break;
        case 1004: case 1005: {
            unsigned long value=strtoul(optarg,&end,10);
            if (!*optarg || *end || value>4294967295UL || *optarg=='-') return 2;
            if (opt==1004) { control_target_uid=value; control_have_uid=true; }
            else control_peer_uid=value;
            break;
        }
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
    bool dynamic=control_path||control_object||control_cgroup||control_have_uid||(control_manifest && !registry_only);
    if (registry_only && (control_path || control_object || control_cgroup || control_have_uid)) return 2;
    if (control_manifest && (control_object || control_cgroup || control_have_uid)) return 2;
    if(dynamic && (!control_path||!socket_path||!excluded_pid||
        (!control_manifest && (!control_object||!control_cgroup||!control_have_uid)))) return 2;
    dynamic_enabled=dynamic;
    if (control_manifest && registry_read()) { fputs("Invalid authorization manifest.\n",stderr); registry_close(); return 2; }
    if(benchmark_stage && (socket_path || enforce || dynamic || control_manifest)) {
        fputs("Diagnostic benchmark modes cannot analyze or enforce.\n",stderr); return 2;
    }
    if(benchmark_stage) fprintf(stderr,"{\"diagnostic_only\":true,\"benchmark_stage\":\"%s\"}\n",benchmark_stage);
    if(enforce && (!cgroup_path||!have_uid||(!open_path&&!exec_path))) { usage(); return 2; }
    if(enforce && strncmp(cgroup_path,"/sys/fs/cgroup/",15)) { fputs("Enforcement requires an explicit cgroup-v2 child directory.\n",stderr); return 2; }
    if((enforce || dynamic) && !active_bpf_lsm()) {
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
    skel->rodata->capture_mappings=mappings;
    skel->rodata->automatic_response=control_manifest!=NULL;
    if(!mappings) {
        bpf_program__set_autoload(skel->progs.enter_mmap,false);
        bpf_program__set_autoload(skel->progs.exit_mmap,false);
        bpf_program__set_autoload(skel->progs.mapping_object,false);
    }
    if(!enforce && !dynamic) {
        bpf_program__set_autoload(skel->progs.deny_open,false);
    }
    if(!enforce) {
        bpf_program__set_autoload(skel->progs.deny_exec,false);
    }
    if((err=monitor_bpf__load(skel))) goto done;
    if (control_manifest && (err=registry_refresh(skel,true))) goto done;
    if(enforce && (err=update_policy(skel))) goto done;
    if((err=monitor_bpf__attach(skel))) goto done;
    if(dynamic) {
        err=control_open();
        if(err) goto done;
        control_bound=true;
    }
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
        // Any failed reconciliation stops automatic policy application, never silently
        // claiming successful registry refresh. The next refresh can recover.
        if (registry_refresh(skel,false)) registry_objects=0;
        control_poll(skel,excluded_pid);
        if(now_ns()-last>=1000000000ULL) { metric(skel,"monitor_health"); last=now_ns(); }
    }
    metric(skel,"monitor_health");
    control_expire(skel,true);
    control_close();
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
    control_close();
    registry_close();
    if(err) fprintf(stderr,"collector failed: %d (%s)\n",err,strerror(-err));
    monitor_bpf__destroy(skel);
    transport_cleanup();
    return err?1:0;
}
