/* Frozen authorized paths; inode identities refresh without accepting peer paths. */
#ifndef MONITOR_REGISTRY_H
#define MONITOR_REGISTRY_H
#define REGISTRY_MAX 128
static const char *control_manifest;
struct registered_asset {
    char path[PATH_LEN];
    unsigned id, kind; /* 1 protected object, 2 service executable */
    int fd;
    struct file_key key;
};
static struct registered_asset registry[REGISTRY_MAX];
static unsigned registry_used, registry_objects;
static bool registry_healthy=true;
static struct registered_asset registry_retired[REGISTRY_MAX];
static unsigned registry_retired_used;
static unsigned long long registry_last;
static const char *registry_service_path(unsigned id) {
    for (unsigned i=0;i<registry_used;i++)
        if (registry[i].kind==2 && registry[i].id==id) return registry[i].path;
    return "";
}
static void registry_close(void) {
    for (unsigned i=0;i<registry_used;i++) if (registry[i].fd>=0) {
        close(registry[i].fd); registry[i].fd=-1;
    }
    for (unsigned i=0;i<registry_retired_used;i++) close(registry_retired[i].fd);
}
static int registry_read(void) {
    if (!control_manifest) return 0;
    FILE *f=fopen(control_manifest,"r");
    if (!f) return -errno;
    char *line=NULL; size_t capacity=0; ssize_t length;
    int rc=0; unsigned counts[3]={0};
    while ((length=getline(&line,&capacity,f))>=0) {
        if (registry_used==REGISTRY_MAX || memchr(line,0,(size_t)length)) { rc=-EINVAL; break; }
        line[strcspn(line,"\r\n")]=0;
        char *kind=line, *number=strchr(line,'\t');
        if (!number) { rc=-EINVAL; break; }
        *number++=0; char *path=strchr(number,'\t');
        if (!path) { rc=-EINVAL; break; }
        *path++=0;
        unsigned type=!strcmp(kind,"object")?1:!strcmp(kind,"service")?2:0;
        errno=0; char *end=NULL; unsigned long id=strtoul(number,&end,10);
        if (!type || !*number || strspn(number,"0123456789")!=strlen(number) || errno || *end ||
            id!=counts[type]+1 || id>64 || path[0]!='/' || strlen(path)>=PATH_LEN || strchr(path,'\t')) {
            rc=-EINVAL; break;
        }
        for (unsigned i=0;i<registry_used;i++) if (registry[i].kind==type && !strcmp(registry[i].path,path)) rc=-EINVAL;
        if (rc) break;
        struct registered_asset *asset=&registry[registry_used++];
        asset->kind=type; asset->id=id; asset->fd=-1; strcpy(asset->path,path); counts[type]++;
    }
    if (ferror(f)) rc=-EIO;
    if (!counts[1] || !counts[2]) rc=-EINVAL;
    free(line); fclose(f); return rc;
}
static void registry_record(bool failed) {
    char *json=NULL; size_t length=0;
    FILE *f=open_memstream(&json,&length);
    if (!f) return;
    base(f,"monitor_registry",now_ns());
    fprintf(f,",\"registry_error\":%s,\"refresh_interval_ms\":250,\"objects\":[",failed?"true":"false");
    bool first=true;
    for (unsigned i=0;i<registry_used;i++) {
        struct registered_asset *asset=&registry[i];
        if (asset->kind!=1) continue;
        if (!first) fputc(',',f);
        first=false;
        fprintf(f,"{\"object_id\":%u,\"active\":%s,\"device\":%llu,\"inode\":%llu,\"path\":",
            asset->id,asset->fd>=0?"true":"false",(unsigned long long)asset->key.device,(unsigned long long)asset->key.inode);
        quote(f,asset->path); fputc('}',f);
    }
    fputs("]}",f); fclose(f); fprintf(stderr,"%s\n",json); queue_message(json,length);
}
static int registry_refresh(struct monitor_bpf *skel, bool force) {
    if (!control_manifest || (!force && now_ns()-registry_last<250000000ULL)) return 0;
    registry_last=now_ns(); bool changed=force, failed=false;
    for (unsigned i=0;i<registry_used;i++) {
        struct registered_asset *asset=&registry[i];
        int fd=open(asset->path,O_PATH|O_CLOEXEC); struct stat st;
        bool valid=fd>=0 && !fstat(fd,&st) && S_ISREG(st.st_mode);
        struct file_key key={0};
        if (valid) key=(struct file_key){.device=kernel_device(st.st_dev),.inode=st.st_ino};
        if ((valid && asset->fd>=0 && !memcmp(&key,&asset->key,sizeof(key))) || (!valid && asset->fd<0)) {
            if (fd>=0) close(fd);
            continue;
        }
        int map=bpf_map__fd(asset->kind==1?skel->maps.protected_objects:skel->maps.service_objects);
        if (asset->fd>=0 && registry_retired_used==REGISTRY_MAX) {
            if (fd>=0) close(fd);
            failed=true; continue;
        }
        /* Publish replacement first; keep previous descriptor and entry on failure. */
        if (valid && bpf_map_update_elem(map,&key,&asset->id,BPF_ANY)) {
            close(fd); failed=true; continue;
        }
        if (asset->fd>=0) {
            registry_retired[registry_retired_used++]=*asset;
        }
        if (!valid && fd>=0) close(fd);
        asset->fd=valid?fd:-1; asset->key=key; changed=true;
    }
    /* Two authorized aliases may refer to the same inode. Do not remove a live alias. */
    unsigned pending=0;
    for (unsigned i=0;i<registry_retired_used;i++) {
        struct registered_asset old=registry_retired[i];
        bool live=false;
        for (unsigned j=0;j<registry_used;j++) if (registry[j].kind==old.kind && registry[j].fd>=0 &&
                !memcmp(&old.key,&registry[j].key,sizeof(struct file_key))) live=true;
        if (!live) {
            int map=bpf_map__fd(old.kind==1?skel->maps.protected_objects:skel->maps.service_objects);
            if (bpf_map_delete_elem(map,&old.key) && errno!=ENOENT) {
                failed=true; registry_retired[pending++]=old; continue;
            }
        }
        close(old.fd);
    }
    registry_retired_used=pending;
    registry_objects=0;
    for (unsigned i=0;i<registry_used;i++) if (registry[i].kind==1 && registry[i].fd>=0) registry_objects++;
    if (changed || failed || registry_healthy==failed) registry_record(failed);
    registry_healthy=!failed;
    return failed?-EIO:0;
}
#endif
