//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

typedef unsigned int u32;
typedef long long unsigned int u64;

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

SEC("kprobe/sys_execve")
int hello() {
	u32 key     = 0;
	u64 initval = 1, *valp;

    u8 comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, TASK_COMM_LEN);

    u32 uid, gid;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    gid = bpf_get_current_uid_gid() >> 32;

    // u64 pid = bpf_get_current_pid_tgid() >> 32;

    struct task_struct* task;
    task = (struct task_struct*)bpf_get_current_task();
    if(!task) {
        const char task_fmt[] = "Could not retrieve task...";
        bpf_trace_printk(task_fmt, sizeof(task_fmt));

        return 0;
    }

    const char task_fmt[] = "sys_execve: pid:%d ppid:%d comm:%s";
    u64 pid = BPF_CORE_READ(task, pid);
    u64 ppid = BPF_CORE_READ(task, real_parent, pid);
    bpf_trace_printk(task_fmt, sizeof(task_fmt), pid, ppid, comm);

    const char task_fmt_uids[] = "sys_execve: uid:%d gid:%d";
    bpf_trace_printk(task_fmt_uids, sizeof(task_fmt_uids), uid, gid);

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

    return 0;
}
