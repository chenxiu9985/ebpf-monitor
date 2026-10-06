/* Restricted seqpacket control endpoint. No path or arbitrary action from peer. */
#ifndef MONITOR_CONTROL_H
#define MONITOR_CONTROL_H
#include <poll.h>
#define CONTROL_CAPACITY 1024
static const char *control_path, *control_object, *control_cgroup;
static unsigned control_target_uid, control_peer_uid;
static bool control_have_uid;
static int control_fd=-1, control_object_fd=-1;
static __u64 control_inode, control_device, control_cgroup_id, control_serial;
static unsigned long long rate_window;
static unsigned rate_count, control_used;
static bool control_bound;
struct control_request {
    char id[65], session_id[256], evidence[65];
    unsigned version, tgid, uid, object, ttl, protocol;
    unsigned long long start_ns, token, cgroup;
};
struct control_entry {
    struct control_request request;
    struct instance_key key;
    struct dynamic_policy policy;
    unsigned long long before, after;
    const char *state;
    const char *reason;
};
static struct control_entry control_entries[CONTROL_CAPACITY];
static bool control_atom(const char *s) {
    if (!*s) return false;
    for (; *s; s++) if (!((*s>='a' && *s<='z') || (*s>='A' && *s<='Z') ||
            (*s>='0' && *s<='9') || *s==':' || *s=='-' || *s=='_')) return false;
    return true;
}
static bool control_numbers(const char *input) {
    char copy[1025]; strcpy(copy,input);
    char *save=NULL; unsigned index=0;
    for (char *value=strtok_r(copy," \t\r\n",&save); value; value=strtok_r(NULL," \t\r\n",&save),index++) {
        if (index==1 || index==5 || index>=7) {
            if (!*value || strspn(value,"0123456789")!=strlen(value)) return false;
            errno=0; char *end=NULL;
            unsigned long long number=strtoull(value,&end,10);
            if (errno || *end || ((index==1 || index==5 || index==7 || (index>=10 && index<=12)) && number>4294967295ULL)) return false;
        }
    }
    return index==13 || index==14;
}
static void control_record(struct control_entry *entry) {
    char *json=NULL; size_t len=0;
    FILE *f=open_memstream(&json,&len);
    if (!f) return;
    base(f,"monitor_control",now_ns());
    fprintf(f,",\"request_id\":\"%s\",\"state\":\"%s\",\"reason\":\"%s\",\"policy_id\":%llu,\"update_before_ns\":%llu,\"update_after_ns\":%llu,\"expires_ns\":%llu,\"inode\":%llu,\"device\":%llu,\"exec_token\":%llu,\"tgid\":%u,\"process_start_ns\":%llu,\"uid\":%u,\"cgroup_id\":%llu,\"object_id\":%u}",
        entry->request.id,entry->state,entry->reason?entry->reason:"state_transition",(unsigned long long)entry->policy.policy_id,
        entry->before,entry->after,(unsigned long long)entry->policy.expires_ns,
        (unsigned long long)entry->policy.inode,(unsigned long long)entry->policy.device,
        entry->request.token,entry->request.tgid,entry->request.start_ns,entry->policy.uid,
        (unsigned long long)entry->policy.cgroup_id,entry->request.object);
    fclose(f); fprintf(stderr,"%s\n",json); queue_message(json,len);
}
static void control_reply(int fd, const char *id, const char *state, const char *reason, struct control_entry *entry) {
    char reply[1024];
    int len=snprintf(reply,sizeof(reply),"{\"control_version\":%u,\"request_id\":\"%s\",\"state\":\"%s\",\"reason\":\"%s\",\"policy_id\":%llu,\"update_before_ns\":%llu,\"update_after_ns\":%llu,\"expires_ns\":%llu,\"inode\":%llu,\"device\":%llu,\"uid\":%u,\"cgroup_id\":%llu,\"object_id\":%u}",
        control_manifest?2U:1U,id,state,reason,entry?(unsigned long long)entry->policy.policy_id:0,
        entry?entry->before:0,entry?entry->after:0,entry?(unsigned long long)entry->policy.expires_ns:0,
        entry?(unsigned long long)entry->policy.inode:0,entry?(unsigned long long)entry->policy.device:0,
        entry?entry->policy.uid:0,entry?(unsigned long long)entry->policy.cgroup_id:0,entry?entry->request.object:0);
    if (len>0 && len<(int)sizeof(reply)) (void)send(fd,reply,(size_t)len,MSG_NOSIGNAL|MSG_DONTWAIT);
}
static void control_expire(struct monitor_bpf *skel, bool revoke_all) {
    for (unsigned i=0;i<control_used;i++) {
        struct control_entry *entry=&control_entries[i];
        if (strcmp(entry->state,"applied")) continue;
        const char *state=NULL;
        struct execution_identity identity;
        if (revoke_all) state="revoked";
        else if (now_ns()>=entry->policy.expires_ns) state="expired";
        else if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.identities),&entry->key,&identity) ||
                 identity.token!=entry->request.token) state="revoked";
        if (!state) continue;
        struct dynamic_policy current;
        if (!bpf_map_lookup_elem(bpf_map__fd(skel->maps.dynamic_policies),&entry->key,&current) &&
            current.policy_id==entry->policy.policy_id)
            if (bpf_map_delete_elem(bpf_map__fd(skel->maps.dynamic_policies),&entry->key)) state="unknown";
        entry->state=state; control_record(entry);
    }
}
static void control_reject_scoped(int fd, const struct control_request *request, const char *reason) {
    // Once scope is accepted, terminal failures have the same immutable ID
    // contract as success. A changed retry cannot retarget a rejected request.
    struct control_entry *entry=&control_entries[control_used++];
    *entry=(struct control_entry){.request=*request,.state="rejected",.reason=reason};
    control_record(entry); control_reply(fd,request->id,"rejected",reason,entry);
}
static int control_open(void) {
    struct stat object, group;
    if (!control_path) return 0;
    if (!socket_path ||
            !strcmp(socket_path,control_path)) return -EINVAL;
    if (!control_manifest) {
    if (!control_object || !control_cgroup || !control_have_uid || strncmp(control_cgroup,"/sys/fs/cgroup/",15)) return -EINVAL;
    char resolved[4096];
    if (!realpath(control_cgroup,resolved) || strncmp(resolved,"/sys/fs/cgroup/",15) || !resolved[15]) return -EINVAL;
    if (strlen(control_path)>=sizeof(((struct sockaddr_un *)0)->sun_path)) return -ENAMETOOLONG;
    /* Holding a descriptor prevents deletion followed by inode reuse. Recheck
       the configured pathname on APPLY; replacements are rejected. */
    control_object_fd=open(control_object,O_PATH|O_CLOEXEC);
    if (control_object_fd<0 || fstat(control_object_fd,&object) || !S_ISREG(object.st_mode) ||
            stat(control_cgroup,&group) || !S_ISDIR(group.st_mode)) return -EINVAL;
    control_inode=object.st_ino; control_device=kernel_device(object.st_dev); control_cgroup_id=group.st_ino;
    }
    if (strlen(control_path)>=sizeof(((struct sockaddr_un *)0)->sun_path)) return -ENAMETOOLONG;
    control_fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (control_fd<0) return -errno;
    struct sockaddr_un address={.sun_family=AF_UNIX};
    strcpy(address.sun_path,control_path);
    mode_t mask=umask(0077);
    int rc=bind(control_fd,(struct sockaddr *)&address,sizeof(address));
    umask(mask);
    if (rc) return -errno; /* Never unlink a pre-existing endpoint. */
    control_bound=true;
    if (chown(control_path,control_peer_uid,(gid_t)-1) || chmod(control_path,0600) || listen(control_fd,4)) return -errno;
    return 0;
}
static void control_close(void) {
    if (control_fd>=0) { close(control_fd); control_fd=-1; }
    if (control_bound) { unlink(control_path); control_bound=false; }
    if (control_object_fd>=0) { close(control_object_fd); control_object_fd=-1; }
}
static void control_poll(struct monitor_bpf *skel, unsigned analyzer_pid) {
    if (control_fd<0) return;
    control_expire(skel,false);
    int fd=accept4(control_fd,NULL,NULL,SOCK_CLOEXEC|SOCK_NONBLOCK);
    if (fd<0) return;
    struct ucred credentials={0}; socklen_t size=sizeof(credentials);
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&credentials,&size) ||
            (unsigned)credentials.pid!=analyzer_pid || credentials.uid!=control_peer_uid) { close(fd); return; }
    struct pollfd wait={.fd=fd,.events=POLLIN};
    if (poll(&wait,1,20)<=0) { close(fd); return; }
    char data[1025]={0}, verb[9]={0}, tail;
    ssize_t length=recv(fd,data,1024,MSG_TRUNC);
    struct control_request request={0};
    if (length<=0 || length>1024 || memchr(data,0,(size_t)length) || !control_numbers(data) ||
        ((control_manifest ? sscanf(data,"V4 %u %8s %64s %255s %u %64s %u %llu %llu %u %u %u %llu %c",
           &request.protocol,verb,request.id,request.session_id,&request.version,request.evidence,&request.tgid,
           &request.start_ns,&request.token,&request.uid,&request.object,&request.ttl,&request.cgroup,&tail) :
           sscanf(data,"V4 %u %8s %64s %255s %u %64s %u %llu %llu %u %u %u %c",
           &request.protocol,verb,request.id,request.session_id,&request.version,request.evidence,&request.tgid,
           &request.start_ns,&request.token,&request.uid,&request.object,&request.ttl,&tail)) != (control_manifest?13:12)) ||
        request.protocol!=(control_manifest?2U:1U) ||
        !control_atom(request.id) || !control_atom(request.session_id) || !control_atom(request.evidence)) {
        control_reply(fd,"invalid","rejected","invalid_request",NULL); close(fd); return;
    }
    unsigned long long now=now_ns();
    if (now-rate_window>=1000000000ULL) { rate_window=now; rate_count=0; }
    if (++rate_count>20) { control_reply(fd,request.id,"rejected","rate_limit",NULL); close(fd); return; }
    if (strcmp(request.session_id,session) || request.object!=(control_manifest?0U:1U) || !request.version ||
        (control_manifest?!request.cgroup:request.uid!=control_target_uid) || !request.tgid || !request.start_ns || !request.token ||
        request.ttl<1 || request.ttl>30000 || (strcmp(verb,"APPLY") && strcmp(verb,"QUERY") && strcmp(verb,"REVOKE"))) {
        control_reply(fd,request.id,"rejected","scope_or_version",NULL); close(fd); return;
    }
    struct control_entry *entry=NULL;
    for (unsigned i=0;i<control_used;i++) if (!strcmp(control_entries[i].request.id,request.id)) { entry=&control_entries[i]; break; }
    if (entry && memcmp(&entry->request,&request,sizeof(request))) {
        control_reply(fd,request.id,"rejected","request_id_conflict",NULL); close(fd); return;
    }
    if (entry && !strcmp(verb,"REVOKE") && !strcmp(entry->state,"applied")) {
        struct dynamic_policy current;
        if (!bpf_map_lookup_elem(bpf_map__fd(skel->maps.dynamic_policies),&entry->key,&current) &&
            current.policy_id==entry->policy.policy_id &&
            bpf_map_delete_elem(bpf_map__fd(skel->maps.dynamic_policies),&entry->key)) {
            control_reply(fd,request.id,"unknown","map_delete_failed",entry); close(fd); return;
        }
        entry->state="revoked"; control_record(entry);
    }
    if (entry) { control_reply(fd,request.id,entry->state,entry->reason?entry->reason:"idempotent",entry); close(fd); return; }
    if (strcmp(verb,"APPLY")) { control_reply(fd,request.id,"unknown","request_not_found",NULL); close(fd); return; }
    if (control_used==CONTROL_CAPACITY) { control_reply(fd,request.id,"rejected","request_capacity",NULL); close(fd); return; }
    struct stat object;
    if (!control_manifest && (stat(control_object,&object) || object.st_ino!=control_inode || kernel_device(object.st_dev)!=control_device)) {
        control_reject_scoped(fd,&request,"object_replaced"); close(fd); return;
    }
    struct instance_key key={.start_ns=request.start_ns,.tgid=request.tgid};
    struct execution_identity identity;
    if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.identities),&key,&identity) || identity.token!=request.token) {
        control_reject_scoped(fd,&request,"execution_identity"); close(fd); return;
    }
    if (control_manifest && (!registry_healthy || !registry_objects || identity.uid!=request.uid || identity.cgroup_id!=request.cgroup ||
            !identity.service_id || !identity.service_token || !identity.service_start_ns ||
            !*registry_service_path(identity.service_id))) {
        control_reject_scoped(fd,&request,"runtime_scope_or_service"); close(fd); return;
    }
    struct control_entry candidate={.request=request,.key=key,.state="applied",.reason="map_update_confirmed"};
    candidate.policy=(struct dynamic_policy){.token=request.token,.expires_ns=now_ns()+request.ttl*1000000ULL,
        .inode=control_manifest?0:control_inode,.device=control_manifest?0:control_device,.cgroup_id=control_manifest?identity.cgroup_id:control_cgroup_id,.policy_id=++control_serial,
        .uid=request.uid,.version=request.version,.object_set=control_manifest?1:0};
    candidate.before=now_ns();
    int rc=bpf_map_update_elem(bpf_map__fd(skel->maps.dynamic_policies),&key,&candidate.policy,BPF_NOEXIST);
    candidate.after=now_ns();
    if (rc) { control_reject_scoped(fd,&request,"map_full_or_active_policy"); close(fd); return; }
    control_entries[control_used]=candidate; entry=&control_entries[control_used++];
    control_record(entry); control_reply(fd,request.id,"applied","map_update_confirmed",entry); close(fd);
}
#endif
