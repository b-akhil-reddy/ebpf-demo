#include "example1.bpf.h"

// tells to which hookpoint the program must be attached
SEC("raw_tracepoint/sys_enter")
int syscall_invoked(void *context){
    u64 temp = bpf_get_current_uid_gid();
    u64 uid = temp & 0xFFFFFFFF;
    u64 gid = temp << 32 | uid;
    temp = bpf_get_current_pid_tgid();
    u64 pid = temp & 0xFFFFFFFF;
    u64 tgid = temp << 32 | pid;
    bpf_printk("syscall invoked\tpid: %11d\tuid: %11d\tgid: %11d", pid, uid, gid);
    return 0;
}