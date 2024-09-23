#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "events.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY); 
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct shared_data);
} shared_map SEC(".maps");

SEC("xdp")
int ringbuf(struct xdp_md *ctx)
{
    struct event *e;
    struct shared_data *data;
    __u32 key = 0;

    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    data = bpf_map_lookup_elem(&shared_map, &key);
    if (data) {
        e->shared_num = data->counter;
    }

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
