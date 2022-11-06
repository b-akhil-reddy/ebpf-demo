#include "example0.bpf.h"

// tells to which hookpoint the program must be attached
SEC("kprobe/sys_socket")
int socket_created(void *context){
    bpf_printk("socket created");
    return 0;
}