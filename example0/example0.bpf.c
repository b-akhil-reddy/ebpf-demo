#include "example0.bpf.h"

// tells to which hookpoint the program must be attached
SEC("raw_tracepoint/sys_enter")
int syscall_invoked(void *context){
    bpf_printk("syscall invoked");
    return 0;
}