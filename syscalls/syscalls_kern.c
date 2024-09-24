#include <stddef.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("tp/syscalls/sys_enter_execve")
int handle_syscall(void *ctx)
{
pid_t pid = bpf_get_current_pid_tgid() >> 32;
if (pid_filter && pid != pid_filter)
return 0;
bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);
    bpf_printk("hello syscall");

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
