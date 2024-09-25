#include <stddef.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef unsigned long u64;
// const u64 pid_filter = 0;

// This is the tracepoint arguments of the kill functions
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
// warning: make sure int/long types matches the field sizes!
struct syscalls_enter_kill_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    u32 __syscall_nr;
    u64 pid;
    u32 sig;
};

SEC("tp/syscalls/sys_enter_execve")
int handle_syscall(void *ctx)
{
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    // if (pid_filter && pid != pid_filter) {
    //     return 0;
    // }

    // bpf_printk("BPF triggered sys_enter_write from PID %d.", pid);

    return XDP_PASS;
}

SEC("tp/syscalls/sys_enter_kill")
int handle_kill(struct syscalls_enter_kill_args *ctx)
{
    u64 tpid     = ctx->pid;
    int sig        = ctx->sig;
    int syscall_nr = ctx->__syscall_nr;

    bpf_printk("syscall %d signal %ld for pid %d", syscall_nr, sig, tpid);

    if (sig == 42) {
        bpf_printk("Signal 42 received for pid=%d", tpid);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
