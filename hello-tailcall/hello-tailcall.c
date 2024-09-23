//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") prog_array = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1024,
};

SEC("raw_tracepoint/sys_enter")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    const char fmt_str[] = "This is syscall %d!";

    if (opcode > 100) {
        return 0;
    }

    bpf_tail_call(ctx, &prog_array, opcode);

    bpf_trace_printk(fmt_str, sizeof(fmt_str), opcode);

    return 0;
}

SEC("raw_tracepoint/sys_enter")
int hello_execve(struct bpf_raw_tracepoint_args *ctx) {
    const char fmt_str[] = "Executing a program";
    bpf_trace_printk(fmt_str, sizeof(fmt_str));

    return 0;
}

SEC("raw_tracepoint/sys_enter")
int hello_ignore(struct bpf_raw_tracepoint_args *ctx) {
    return 0;
}

SEC("raw_tp/sys_enter")
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    char *fmt_str;

    if (opcode == 222) {
        fmt_str = "Creating a timer";
        bpf_trace_printk(fmt_str, sizeof(fmt_str));
    } else if (opcode == 226) {
        fmt_str = "Deleting a timer";
        bpf_trace_printk(fmt_str, sizeof(fmt_str));
    } else {
        fmt_str = "Some other timer operation";
        bpf_trace_printk(fmt_str, sizeof(fmt_str));
    }
    return 0;
}