//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/sys_execve")
int hello() {
    const char fmt_str[] = "Hello world!";

    bpf_trace_printk(fmt_str, sizeof(fmt_str));

    return 0;
}
