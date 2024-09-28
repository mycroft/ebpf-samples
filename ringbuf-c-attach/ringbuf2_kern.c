#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "events.h"

int counter = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// this 1 entry map is shared between userland and kernel land to
// pass values from userland to kerneland.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 << 24);
    __type(key, __u32);
    __type(value, struct shared_data);
} shared_map SEC(".maps");

SEC("xdp")
int ringbuf2(struct xdp_md *ctx)
{
    struct event *e;
    struct shared_data *shared_data;
    __u32 key = 0;

    void *data     = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr *eth;
    struct iphdr *ip;

    eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // not an IP packet
        return XDP_PASS;
    }

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    bpf_printk("counter:%d 0x%x -> 0x%x", counter, ip->saddr, ip->daddr);

    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return XDP_PASS;
    }

    e->ip_protocol = ip->protocol;
    e->ip_saddr = ip->saddr;
    e->ip_daddr = ip->daddr;
    e->counter = counter ++;

    shared_data = bpf_map_lookup_elem(&shared_map, &key);
    if (shared_data) {
        e->shared_num = shared_data->counter;
    }

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
