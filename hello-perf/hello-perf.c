//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    u32 pid;
    u8 msg[8];
    u8 comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

// required for -type event
const struct event *unused __attribute__((unused));

SEC("kprobe/sys_execve")
int hello(void *ctx) {
    struct event data = {};
    char message[12] = "Hello World";

    u64 id   = bpf_get_current_pid_tgid();
    data.pid = id;

	bpf_get_current_comm(&data.comm, TASK_COMM_LEN);
    bpf_probe_read_kernel(&data.msg, sizeof(data.msg), message);
    bpf_perf_event_output(ctx, &output, BPF_F_INDEX_MASK, &data, sizeof(data));

    return 0;
}
