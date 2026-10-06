// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";
const volatile __u32 ignore_tgid = 0;
const volatile __u32 analyzer_tgid = 0;
const volatile __u32 collector_pidns = 0;
// Explicit benchmark only: preserve construction/pairing but skip ring delivery.
const volatile bool benchmark_no_output = false;
const volatile bool batch_notifications = false;
const volatile bool full_event_records = false;
const volatile bool capture_mappings = false;
const volatile bool automatic_response = false;
// Controlled by userspace only after every hook and the reader are ready.
volatile bool capturing = false;
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32); } collector_identity SEC(".maps");
static __always_inline bool ignored(__u32 pid) {
    struct task_struct *task = (void *)bpf_get_current_task();
    struct pid *thread_pid = BPF_CORE_READ(task, group_leader, thread_pid);
    unsigned level = BPF_CORE_READ(thread_pid, level);
    if (level > 32) return false;
    struct upid number = {};
    bpf_core_read(&number, sizeof(number), &thread_pid->numbers[level]);
    if (BPF_CORE_READ(number.ns, ns.inum) != collector_pidns) return false;
    if ((__u32)number.nr == ignore_tgid) {
        __u32 zero = 0;
        bpf_map_update_elem(&collector_identity, &zero, &pid, BPF_ANY);
        return true;
    }
    return analyzer_tgid && (__u32)number.nr == analyzer_tgid;
}
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 16*1024*1024); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, MAX_PENDING);
    __type(key, __u64); __type(value, struct pending); } pending_calls SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct pending); } scratch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, CNT_TOTAL);
    __type(key, __u32); __type(value, __u64); } stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 2);
    __type(key, __u32); __type(value, struct enforcement_policy); } policies SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, __u32); } active_policy SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384);
    __type(key, struct instance_key); __type(value, struct execution_identity); } identities SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 128);
    __type(key, struct instance_key); __type(value, struct dynamic_policy); } dynamic_policies SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 128);
    __type(key, struct file_key); __type(value, __u32); } protected_objects SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 128);
    __type(key, struct file_key); __type(value, __u32); } service_objects SEC(".maps");

static __always_inline void count(__u32 key) {
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v) __sync_fetch_and_add(v, 1);
}
static __always_inline __u64 start(struct task_struct *t) {
    struct task_struct *leader = BPF_CORE_READ(t, group_leader);
    return BPF_CORE_READ(leader, start_boottime);
}
static __always_inline void source_event(struct event *e, struct execution_identity *id) {
    e->service_id=id->service_id; e->service_source=id->service_source;
    e->service_tgid=id->service_tgid; e->service_start_ns=id->service_start_ns;
    e->service_token=id->service_token;
}
static __always_inline void register_service(struct task_struct *task, struct instance_key *key,
                                             struct execution_identity *id, __u32 source) {
    if (!automatic_response) return;
    struct file *exe=BPF_CORE_READ(task, mm, exe_file);
    if (!exe) return;
    struct file_key file={.device=BPF_CORE_READ(exe,f_inode,i_sb,s_dev),
                          .inode=BPF_CORE_READ(exe,f_inode,i_ino)};
    __u32 *registered=bpf_map_lookup_elem(&service_objects,&file);
    if (!registered) return;
    id->service_id=*registered; id->service_source=source;
    id->service_tgid=key->tgid; id->service_start_ns=key->start_ns;
    id->service_token=id->token;
}
static __always_inline void fill(struct event *e, struct task_struct *t, __u32 type) {
    struct task_struct *parent = BPF_CORE_READ(t, real_parent);
    e->timestamp_ns = bpf_ktime_get_ns();
    e->operation_start_ns=e->timestamp_ns;
    e->start_ns = start(t);
    e->thread_start_ns = BPF_CORE_READ(t, start_boottime);
    e->tgid = BPF_CORE_READ(t, tgid);
    e->tid = BPF_CORE_READ(t, pid);
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->parent_start_ns = start(parent);
    e->uid = BPF_CORE_READ(t, cred, uid.val);
    e->euid = BPF_CORE_READ(t, cred, euid.val);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type = type;
    struct instance_key key = {.start_ns=e->start_ns, .tgid=e->tgid};
    struct execution_identity *identity = bpf_map_lookup_elem(&identities, &key);
    if (identity) {
        e->exec_token = identity->token;
        source_event(e,identity);
        // The control handler compares these kernel-observed values with the request.
        identity->uid=e->uid; identity->cgroup_id=e->cgroup_id;
    }
    key.start_ns=e->parent_start_ns; key.tgid=e->ppid;
    identity=bpf_map_lookup_elem(&identities,&key);
    if (identity) e->parent_exec_token=identity->token;
    bpf_core_read_str(e->comm, sizeof(e->comm), &t->comm);
}
static __always_inline struct event *fresh(__u32 type) {
    if (!capturing) return 0;
    // Filter once before clearing/filling the large event. finish() separately
    // filters exit hooks; output() receives only already-filtered events.
    if (ignored(bpf_get_current_pid_tgid() >> 32)) return 0;
    __u32 zero = 0;
    struct pending *p = bpf_map_lookup_elem(&scratch, &zero);
    if (!p) return 0;
    volatile __u64 *words = (volatile __u64 *)p;
    #pragma unroll
    for (int i = 0; i < sizeof(*p) / sizeof(__u64); i++) words[i] = 0;
    fill(&p->event, (void *)bpf_get_current_task(), type);
    return &p->event;
}
static __always_inline void output(struct event *e) {
    if (!capturing) return;
    count(CNT_EVENTS);
    if (benchmark_no_output) return;
    unsigned size = full_event_records ? sizeof(*e) : event_wire_size(e->type);
    if (bpf_ringbuf_output(&events, e, size, batch_notifications ? BPF_RB_NO_WAKEUP : 0)) count(CNT_RING_LOST);
}
static __always_inline void readstr(char *dst, const void *src, struct event *e, __u32 *field_quality) {
    long n = bpf_probe_read_user_str(dst, PATH_LEN, src);
    if (n < 0) { e->quality |= Q_READ_ERROR; *field_quality |= Q_READ_ERROR; }
    else if (n == PATH_LEN) { e->quality |= Q_TRUNCATED; *field_quality |= Q_TRUNCATED; }
}
static __always_inline void save(struct event *e) {
    __u64 key = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&pending_calls, &key, e, BPF_ANY)) count(CNT_MAP_FAIL);
}
static __always_inline int finish(__s64 retval, __u32 expected) {
    if (!capturing) return 0;
    __u64 key = bpf_get_current_pid_tgid();
    if (ignored(key >> 32)) return 0;
    struct pending *p = bpf_map_lookup_elem(&pending_calls, &key);
    if (!p || p->event.type != expected) { count(CNT_UNPAIRED); return 0; }
    p->event.retval = retval;
    p->event.timestamp_ns = bpf_ktime_get_ns();
    if (expected == EV_EXEC) p->event.type = EV_EXEC_FAIL;
    output(&p->event);
    bpf_map_delete_elem(&pending_calls, &key);
    return 0;
}

SEC("raw_tp/sched_process_fork")
int on_fork(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *child = (void *)ctx->args[1];
    if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid)) return 0;
    struct event *e = fresh(EV_FORK);
    if (!e) return 0;
    struct instance_key key = {.start_ns=start(child), .tgid=BPF_CORE_READ(child,tgid)};
    // A child gets its own token; an existing parent's policy is never inherited.
    struct execution_identity identity = {.token=bpf_ktime_get_ns(),
        .uid=BPF_CORE_READ(child,cred,uid.val), .cgroup_id=bpf_get_current_cgroup_id()};
    if (automatic_response) {
        struct task_struct *parent=(void *)ctx->args[0];
        struct instance_key parent_key={.start_ns=start(parent), .tgid=BPF_CORE_READ(parent,tgid)};
        struct execution_identity *known=bpf_map_lookup_elem(&identities,&parent_key);
        if (!known) {
            struct execution_identity enrolled={.token=bpf_ktime_get_ns(),
                .uid=BPF_CORE_READ(parent,cred,uid.val), .cgroup_id=bpf_get_current_cgroup_id()};
            register_service(parent,&parent_key,&enrolled,2);
            if (enrolled.service_id && bpf_map_update_elem(&identities,&parent_key,&enrolled,BPF_NOEXIST)) count(CNT_MAP_FAIL);
            known=bpf_map_lookup_elem(&identities,&parent_key);
        } else if (!known->service_id ||
                   (known->service_tgid==parent_key.tgid && known->service_start_ns==parent_key.start_ns)) {
            // Revalidate the originating service at a new fork; retain inherited
            // historical sources on helpers rather than inventing helper execs.
            register_service(parent,&parent_key,known,2);
        }
        if (known) {
            identity.service_id=known->service_id; identity.service_source=known->service_source;
            identity.service_tgid=known->service_tgid; identity.service_start_ns=known->service_start_ns;
            identity.service_token=known->service_token;
        }
    }
    if (bpf_map_update_elem(&identities,&key,&identity,BPF_NOEXIST)) count(CNT_MAP_FAIL);
    fill(e, child, EV_FORK);
    output(e); return 0;
}
static __always_inline int exec_enter(const char *filename, const char *const *argv, const char *const *envp) {
    struct event *e = fresh(EV_EXEC);
    if (!e) return 0;
    readstr(e->path, filename, e, &e->path_quality);
    const char *arg0 = 0;
    if (bpf_probe_read_user(&arg0, sizeof(arg0), argv)) { e->quality |= Q_READ_ERROR; e->argv_quality |= Q_READ_ERROR; }
    else if (arg0) readstr(e->argv_summary, arg0, e, &e->argv_quality);
    // Scan a bounded prefix. A missing key after the limit is UNKNOWN, not absent.
    bool ended = false;
    for (int i=0; i<64; i++) {
        const char *v = 0;
        char key[17] = {};
        if (bpf_probe_read_user(&v, sizeof(v), &envp[i])) { e->quality |= Q_READ_ERROR; e->env_quality |= Q_READ_ERROR; break; }
        if (!v) { ended = true; break; }
        if (bpf_probe_read_user_str(key, sizeof(key), v) < 0) { e->quality |= Q_READ_ERROR; e->env_quality |= Q_READ_ERROR; continue; }
        if (__builtin_memcmp(key, "LD_PRELOAD=", 11) == 0)
            readstr(e->preload, v+11, e, &e->env_quality);
        else if (__builtin_memcmp(key, "LD_LIBRARY_PATH=", 16) == 0)
            readstr(e->library_path, v+16, e, &e->env_quality);
    }
    if (!ended) { e->quality |= Q_ENV_INCOMPLETE; e->env_quality |= Q_ENV_INCOMPLETE; }
    save(e); return 0;
}
SEC("tp/syscalls/sys_enter_execve")
int enter_exec(struct trace_event_raw_sys_enter *ctx) {
    return exec_enter((void *)ctx->args[0], (void *)ctx->args[1], (void *)ctx->args[2]);
}
SEC("tp/syscalls/sys_enter_execveat")
int enter_execat(struct trace_event_raw_sys_enter *ctx) {
    return exec_enter((void *)ctx->args[1], (void *)ctx->args[2], (void *)ctx->args[3]);
}
SEC("tp/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u64 current = bpf_get_current_pid_tgid();
    __u64 key = (current & 0xffffffff00000000ULL) | (__u32)ctx->old_pid;
    struct pending *p = bpf_map_lookup_elem(&pending_calls, &key);
    struct event *e = fresh(EV_EXEC);
    if (!e) return 0;
    struct instance_key instance = {.start_ns=e->start_ns, .tgid=e->tgid};
    if (p && p->event.start_ns != e->start_ns) {
        struct instance_key previous = {.start_ns=p->event.start_ns, .tgid=p->event.tgid};
        bpf_map_delete_elem(&identities,&previous);
        bpf_map_delete_elem(&dynamic_policies,&previous);
    }
    struct execution_identity identity = {.token=bpf_ktime_get_ns(), .uid=e->uid, .cgroup_id=e->cgroup_id};
    struct execution_identity *previous_id=bpf_map_lookup_elem(&identities,&instance);
    if (previous_id) {
        identity.service_id=previous_id->service_id; identity.service_source=previous_id->service_source;
        identity.service_tgid=previous_id->service_tgid; identity.service_start_ns=previous_id->service_start_ns;
        identity.service_token=previous_id->service_token;
    }
    register_service((void *)bpf_get_current_task(),&instance,&identity,1);
    source_event(e,&identity);
    if (p) identity.mappings = p->event.preload[0] || p->event.library_path[0];
    if (bpf_map_update_elem(&identities,&instance,&identity,BPF_ANY)) {
        count(CNT_MAP_FAIL); e->quality |= Q_MISSING; e->exec_token=0;
    } else e->exec_token=identity.token;
    bpf_map_delete_elem(&dynamic_policies,&instance);
    if (p) {
        e->operation_start_ns=p->event.operation_start_ns;
        __builtin_memcpy(e->preload, p->event.preload, ENV_LEN);
        __builtin_memcpy(e->library_path, p->event.library_path, ENV_LEN);
        __builtin_memcpy(e->argv_summary, p->event.argv_summary, PATH_LEN);
        e->quality |= p->event.quality;
        e->path_quality=p->event.path_quality;
        e->env_quality=p->event.env_quality;
        e->argv_quality=p->event.argv_quality;
    } else { e->quality |= Q_MISSING; e->env_quality |= Q_MISSING; e->argv_quality |= Q_MISSING; }
    __u32 off = ctx->__data_loc_filename & 0xffff;
    long n = bpf_probe_read_kernel_str(e->path, PATH_LEN, (void *)ctx + off);
    if (n < 0) { e->quality |= Q_READ_ERROR; e->path_quality |= Q_READ_ERROR; }
    else if (n == PATH_LEN) { e->quality |= Q_TRUNCATED; e->path_quality |= Q_TRUNCATED; }
    output(e);
    bpf_map_delete_elem(&pending_calls, &key);
    return 0;
}
SEC("tp/syscalls/sys_exit_execve")
int exit_exec(struct trace_event_raw_sys_exit *ctx) { return ctx->ret < 0 ? finish(ctx->ret, EV_EXEC) : 0; }
SEC("tp/syscalls/sys_exit_execveat")
int exit_execat(struct trace_event_raw_sys_exit *ctx) { return ctx->ret < 0 ? finish(ctx->ret, EV_EXEC) : 0; }
SEC("raw_tp/sched_process_exit")
int on_exit(struct bpf_raw_tracepoint_args *ctx) {
    (void)ctx;
    __u64 key = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending_calls, &key);
    struct task_struct *t = (void *)bpf_get_current_task();
    // do_exit decrements signal->live before this tracepoint (Linux 6.8).
    struct event *e = fresh(EV_EXIT);
    if (e) {
        e->retval = BPF_CORE_READ(t, exit_code);
        e->process_dead = BPF_CORE_READ(t, signal, live.counter) == 0;
        output(e);
        if (e->process_dead) {
            struct instance_key instance = {.start_ns=e->start_ns, .tgid=e->tgid};
            bpf_map_delete_elem(&identities,&instance);
            bpf_map_delete_elem(&dynamic_policies,&instance);
        }
    }
    return 0;
}
static __always_inline int open_enter(const char *path, int dirfd, __u64 flags) {
    struct event *e = fresh(EV_OPEN);
    if (!e) return 0;
    readstr(e->path, path, e, &e->path_quality); e->dirfd = dirfd; e->flags = flags;
    save(e); return 0;
}
SEC("tp/syscalls/sys_enter_open")
int enter_open(struct trace_event_raw_sys_enter *ctx) { return open_enter((void *)ctx->args[0], -100, ctx->args[1]); }
SEC("tp/syscalls/sys_enter_openat")
int enter_openat(struct trace_event_raw_sys_enter *ctx) { return open_enter((void *)ctx->args[1], ctx->args[0], ctx->args[2]); }
SEC("tp/syscalls/sys_enter_openat2")
int enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    __u64 flags = 0;
    int rc = bpf_probe_read_user(&flags, sizeof(flags), (void *)ctx->args[2]);
    open_enter((void *)ctx->args[1], ctx->args[0], flags);
    if (rc) {
        __u64 key = bpf_get_current_pid_tgid();
        struct pending *p = bpf_map_lookup_elem(&pending_calls, &key);
        if (p) p->event.quality |= Q_READ_ERROR;
    }
    return 0;
}
SEC("tp/syscalls/sys_exit_open")
int exit_open(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_OPEN); }
SEC("tp/syscalls/sys_exit_openat")
int exit_openat(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_OPEN); }
SEC("tp/syscalls/sys_exit_openat2")
int exit_openat2(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_OPEN); }
// x86-64 mmap only. The security hook supplies the file object, the syscall exit
// supplies success/failure; a hook invocation alone never means success.
SEC("tp/syscalls/sys_enter_mmap")
int enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    if (!capture_mappings || !capturing) return 0;
    struct task_struct *task = (void *)bpf_get_current_task();
    struct instance_key key = {.start_ns=start(task), .tgid=BPF_CORE_READ(task,tgid)};
    struct execution_identity *identity=bpf_map_lookup_elem(&identities,&key);
    if (!identity || !identity->mappings) { count(CNT_FILTERED); return 0; }
    struct event *e=fresh(EV_MAP);
    if (!e) return 0;
    e->flags=ctx->args[3]; e->operation=ctx->args[2]; e->dirfd=ctx->args[4];
    save(e); return 0;
}
SEC("kprobe/security_mmap_file")
int BPF_KPROBE(mapping_object, struct file *file) {
    __u64 key=bpf_get_current_pid_tgid();
    struct pending *p=bpf_map_lookup_elem(&pending_calls,&key);
    if (p && p->event.type==EV_MAP && file) {
        p->event.inode=BPF_CORE_READ(file,f_inode,i_ino);
        p->event.device=BPF_CORE_READ(file,f_inode,i_sb,s_dev);
    }
    return 0;
}
SEC("tp/syscalls/sys_exit_mmap")
int exit_mmap(struct trace_event_raw_sys_exit *ctx) {
    __u64 key=bpf_get_current_pid_tgid();
    struct pending *p=bpf_map_lookup_elem(&pending_calls,&key);
    if (!p || p->event.type!=EV_MAP) return 0;
    if (!p->event.inode) p->event.quality |= Q_MISSING;
    return finish(ctx->ret,EV_MAP);
}
SEC("kprobe/security_file_open")
int BPF_KPROBE(file_identity, struct file *file) {
    __u64 key = bpf_get_current_pid_tgid();
    struct pending *p = bpf_map_lookup_elem(&pending_calls, &key);
    if (p && p->event.type == EV_OPEN) {
        p->event.inode = BPF_CORE_READ(file, f_inode, i_ino);
        p->event.device = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    }
    return 0;
}
// getname() has copied the pathname before permission checks in path_openat().
// Read that kernel-owned copy, not a userspace pointer re-read at syscall exit.
// This is the requested pathname, not a canonical/resolved filesystem path.
SEC("kprobe/do_filp_open")
int BPF_KPROBE(open_kernel_path, int dfd, struct filename *name) {
    __u64 key = bpf_get_current_pid_tgid();
    struct pending *p = bpf_map_lookup_elem(&pending_calls, &key);
    if (!p || p->event.type != EV_OPEN) return 0;
    const char *path = BPF_CORE_READ(name, name);
    char copied[PATH_LEN] = {};
    long n = bpf_probe_read_kernel_str(copied, sizeof(copied), path);
    if (n > 0) {
        __builtin_memcpy(p->event.path, copied, sizeof(copied));
        p->event.quality |= Q_KERNEL_OPEN_PATH;
        if (n == PATH_LEN) { p->event.quality |= Q_TRUNCATED; p->event.path_quality |= Q_TRUNCATED; }
        // Preserve previous read/truncation failures as historical evidence.
    } else {
        p->event.quality |= Q_READ_ERROR;
        p->event.path_quality |= Q_READ_ERROR;
    }
    return 0;
}
SEC("tp/syscalls/sys_enter_ptrace")
int enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = fresh(EV_PTRACE);
    if (!e) return 0;
    e->request = ctx->args[0]; e->target_pid = ctx->args[1];
    e->quality |= Q_MISSING; // Target is a namespace PID; do not invent host identity.
    save(e); return 0;
}
SEC("tp/syscalls/sys_exit_ptrace")
int exit_ptrace(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_PTRACE); }
static __always_inline int ptrace_target(struct task_struct *target) {
    __u64 key = bpf_get_current_pid_tgid();
    struct pending *p = bpf_map_lookup_elem(&pending_calls, &key);
    if (p && p->event.type == EV_PTRACE) {
        p->event.target_host_pid = BPF_CORE_READ(target, tgid);
        p->event.target_start_ns = start(target);
        p->event.quality &= ~Q_MISSING;
    }
    return 0;
}
SEC("kprobe/ptrace_check_attach")
int BPF_KPROBE(ptrace_checked_target, struct task_struct *target) { return ptrace_target(target); }
SEC("kprobe/security_ptrace_access_check")
int BPF_KPROBE(ptrace_attach_target, struct task_struct *target) { return ptrace_target(target); }
static __always_inline int rename_enter(const char *old, const char *new) {
    struct event *e = fresh(EV_RENAME);
    if (!e) return 0;
    readstr(e->path, old, e, &e->path_quality); readstr(e->path2, new, e, &e->path_quality); save(e); return 0;
}
SEC("tp/syscalls/sys_enter_rename")
int enter_rename(struct trace_event_raw_sys_enter *ctx) { return rename_enter((void *)ctx->args[0], (void *)ctx->args[1]); }
SEC("tp/syscalls/sys_enter_renameat")
int enter_renameat(struct trace_event_raw_sys_enter *ctx) { return rename_enter((void *)ctx->args[1], (void *)ctx->args[3]); }
SEC("tp/syscalls/sys_enter_renameat2")
int enter_renameat2(struct trace_event_raw_sys_enter *ctx) { return rename_enter((void *)ctx->args[1], (void *)ctx->args[3]); }
SEC("tp/syscalls/sys_exit_rename")
int exit_rename(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_RENAME); }
SEC("tp/syscalls/sys_exit_renameat")
int exit_renameat(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_RENAME); }
SEC("tp/syscalls/sys_exit_renameat2")
int exit_renameat2(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_RENAME); }
static __always_inline int unlink_enter(const char *path) {
    struct event *e = fresh(EV_UNLINK);
    if (!e) return 0;
    readstr(e->path, path, e, &e->path_quality); save(e); return 0;
}
SEC("tp/syscalls/sys_enter_unlink")
int enter_unlink(struct trace_event_raw_sys_enter *ctx) { return unlink_enter((void *)ctx->args[0]); }
SEC("tp/syscalls/sys_enter_unlinkat")
int enter_unlinkat(struct trace_event_raw_sys_enter *ctx) { return unlink_enter((void *)ctx->args[1]); }
SEC("tp/syscalls/sys_exit_unlink")
int exit_unlink(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_UNLINK); }
SEC("tp/syscalls/sys_exit_unlinkat")
int exit_unlinkat(struct trace_event_raw_sys_exit *ctx) { return finish(ctx->ret, EV_UNLINK); }

static __always_inline int enforce(struct file *file, __u32 operation, int ret) {
    if (ret) return ret;
    __u32 zero = 0;
    __u32 *active = bpf_map_lookup_elem(&active_policy, &zero);
    if (!active) return 0;
    __u32 slot = *active;
    struct enforcement_policy *p = bpf_map_lookup_elem(&policies, &slot);
    if (!p || !p->cgroup_id || p->cgroup_id != bpf_get_current_cgroup_id()) return 0;
    if ((__u32)bpf_get_current_uid_gid() != p->uid) return 0;
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u64 dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    if (operation == 1 && (!p->open_inode || ino != p->open_inode || dev != p->open_device)) return 0;
    if (operation == 2 && (!p->exec_inode || ino != p->exec_inode || dev != p->exec_device)) return 0;
    count(CNT_DENIED);
    struct event *e = fresh(EV_DENY);
    if (e) {
        e->inode = ino; e->device = dev; e->retval = -1;
        e->operation = operation; e->policy_version = p->version;
        output(e);
    }
    return -1;
}
SEC("lsm/file_open")
int BPF_PROG(deny_open, struct file *file, int ret) {
    // Preserve previous LSM and static policy denials, then check dynamic scope.
    int prior=enforce(file,1,ret);
    if (prior) return prior;
    struct task_struct *task=(void *)bpf_get_current_task();
    struct instance_key key={.start_ns=start(task), .tgid=BPF_CORE_READ(task,tgid)};
    struct dynamic_policy *p=bpf_map_lookup_elem(&dynamic_policies,&key);
    if (!p || bpf_ktime_get_ns() >= p->expires_ns) return 0;
    struct execution_identity *identity=bpf_map_lookup_elem(&identities,&key);
    if (!identity || !p->token || identity->token != p->token) return 0;
    if (p->cgroup_id != bpf_get_current_cgroup_id() || (__u32)bpf_get_current_uid_gid()!=p->uid) return 0;
    struct file_key object={.inode=BPF_CORE_READ(file,f_inode,i_ino), .device=BPF_CORE_READ(file,f_inode,i_sb,s_dev)};
    __u32 object_id=1;
    if (p->object_set) {
        __u32 *registered=bpf_map_lookup_elem(&protected_objects,&object);
        if (!registered) return 0;
        object_id=*registered;
    } else if (object.inode!=p->inode || object.device!=p->device) return 0;
    count(CNT_DENIED);
    struct event *e=fresh(EV_DENY);
    if (e) {
        e->inode=object.inode; e->device=object.device; e->protected_object_id=object_id; e->retval=-1;
        e->operation=1; e->policy_version=p->version; e->dynamic_policy_id=p->policy_id;
        output(e);
    }
    return -1;
}
SEC("lsm/bprm_check_security")
int BPF_PROG(deny_exec, struct linux_binprm *bprm, int ret) {
    struct file *file = BPF_CORE_READ(bprm, file);
    return enforce(file, 2, ret);
}
