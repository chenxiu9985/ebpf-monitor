#define _GNU_SOURCE
#include "../../collector/transport.h"

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    socket_path = argv[1];
    unsigned timeout = (unsigned)strtoul(argv[2], NULL, 10);
    unsigned count = (unsigned)strtoul(argv[3], NULL, 10);
    transport_begin_shutdown(timeout);
    char padding[2049]; memset(padding, 'x', sizeof(padding)-1); padding[sizeof(padding)-1]=0;
    for (unsigned i=0; i<count; i++) {
        char *json = NULL;
        int size = asprintf(&json,
            "{\"schema_version\":1,\"event_id\":\"fixture:%u\",\"event_type\":\"file_open\",\"monotonic_ns\":%u,\"process_key\":\"fixture-process\",\"path\":\"%s\",\"padding\":\"%s\"}",
            i,i+1,i+1==count ? "/etc/shadow" : "/etc/hostname",padding);
        if (size<0) return 2;
        queue_message(json, (size_t)size);
        if (i==0 && sock>=0) {
            int small=1024;
            setsockopt(sock,SOL_SOCKET,SO_SNDBUF,&small,sizeof(small));
        }
    }
    char *stop=NULL;
    int length=asprintf(&stop,"{\"schema_version\":1,\"event_id\":\"fixture:stop\",\"event_type\":\"monitor_stop\",\"monotonic_ns\":%u,\"shutdown_ack_required\":true}",count+2);
    if(length<0) return 2;
    queue_message(stop,(size_t)length);
    int rc=transport_finish("fixture:stop");
    printf("{\"error\":%d,\"unsent\":%u,\"lost\":%llu,\"disconnects\":%llu}\n",rc,used,queue_lost,transport_disconnects);
    transport_cleanup();
    return rc ? 1 : 0;
}
