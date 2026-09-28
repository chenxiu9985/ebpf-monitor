#define main collector_main
#include "../../collector/main.c"
#undef main

int main(int argc, char **argv) {
    bool compact = argc > 1 && !strcmp(argv[1], "compact");
    strcpy(host_id,"fixture"); strcpy(boot_id,"boot"); strcpy(session,"codec");
    for (unsigned type=EV_FORK; type<=EV_DENY; type++) {
        struct event e={};
        e.type=type; e.tgid=42; e.ppid=41; e.uid=1000; e.euid=1000;
        e.start_ns=100; e.parent_start_ns=90; e.timestamp_ns=200;
        e.retval=-13; e.request=5; e.target_host_pid=43; e.target_start_ns=95;
        e.flags=524288; e.dirfd=-100; e.inode=1234; e.device=5678;
        e.process_dead=type==EV_EXIT;
        strcpy(e.comm,"test\"\\name");
        if (type==EV_OPEN || event_wire_size(type)==sizeof(e)) strcpy(e.path,"/tmp/quoted\"file");
        if (event_wire_size(type)==sizeof(e)) {
            strcpy(e.path2,"/tmp/target"); strcpy(e.preload,"/tmp/test.so");
            strcpy(e.library_path,"/lib"); strcpy(e.argv_summary,"test argument");
        }
        if (type==EV_OPEN) e.quality=18;
        on_event(NULL,&e,compact?event_wire_size(type):sizeof(e));
    }
    return transport_finish(NULL) != 0;
}
