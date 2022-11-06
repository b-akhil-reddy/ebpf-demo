#include "example2.bpf.h"

BPF_PERF_OUTPUT(datastore);
SEC("kprobe/sys_socket")
int send_command_name(void *context){
    char data[40]={'\0'};
    bpf_get_current_comm(&data,sizeof(data));
    bpf_perf_event_output(context, &datastore, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}