#ifndef MONITOR_EVENTS_H
#define MONITOR_EVENTS_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#define PATH_LEN 256
#define ENV_LEN 256
#define MAX_PENDING 2048
enum event_type { EV_FORK=1, EV_EXEC, EV_EXIT, EV_OPEN, EV_PTRACE,
                  EV_EXEC_FAIL, EV_RENAME, EV_UNLINK, EV_DENY };
enum quality_flag { Q_TRUNCATED=1, Q_READ_ERROR=2, Q_MISSING=4,
                    Q_ENV_INCOMPLETE=8, Q_KERNEL_OPEN_PATH=16 };
enum counters { CNT_EVENTS, CNT_RING_LOST, CNT_MAP_FAIL, CNT_UNPAIRED,
                CNT_DENIED, CNT_TOTAL };
struct event {
    __u64 timestamp_ns, start_ns, parent_start_ns, cgroup_id;
    __u64 thread_start_ns, target_start_ns, inode, device;
    __s64 retval;
    __u64 flags;
    __u32 type, tgid, tid, ppid, uid, euid, target_pid;
    __u32 request, quality, operation, policy_version, process_dead, target_host_pid;
    __s32 dirfd;
    char comm[16], path[PATH_LEN], path2[PATH_LEN];
    char preload[ENV_LEN], library_path[ENV_LEN];
    char argv_summary[PATH_LEN];
};
struct pending { struct event event; };
// Non-exec records do not use the trailing argument/environment buffers.
static __inline __attribute__((always_inline)) unsigned event_wire_size(unsigned type) {
    switch (type) {
    case EV_OPEN: return __builtin_offsetof(struct event, path2);
    case EV_FORK: case EV_EXIT: case EV_PTRACE:
        return __builtin_offsetof(struct event, path);
    default: return sizeof(struct event);
    }
}
struct enforcement_policy {
    __u64 cgroup_id, open_inode, open_device, exec_inode, exec_device;
    __u32 uid, version;
};
#endif
