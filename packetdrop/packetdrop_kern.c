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
	__uint(max_entries, 256 * 1024);
} snoop_events SEC(".maps");

SEC("xdp")
int packetdrop(struct xdp_md *ctx)
{
	int pid;
	unsigned long int id;
    struct event *e;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    size_t iplen = bpf_ntohs(iph->tot_len);

    bpf_printk("totlen: %d\n", bpf_ntohs(iph->tot_len));

    // if (data + sizeof(struct ethhdr) + iplen > data_end)
    //     return XDP_ABORTED;

    // This is a ping packet
    if (iph->protocol == IPPROTO_ICMP) {
        bpf_printk("Got ICMP packet\n");
    }

    if (iph->protocol == IPPROTO_TCP)
        bpf_printk("Got TCP packet\n");

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&snoop_events, sizeof(struct event), 0);
	if (!e) {
        bpf_printk("Failed reserving event\n");
        return XDP_PASS;
    }

    id = bpf_get_current_pid_tgid();
	pid = id >> 32;

    e->pid = pid;
    e->num = 42;
    
    size_t len = ctx->data_end - ctx->data;

    e->len = len;
    if (e->len > sizeof(e->bytes)) {
        e->len = sizeof(e->bytes);
    }

    bpf_probe_read_kernel(e->bytes, e->len, data);

    bpf_printk("sent data: %d (size:%ld)\n", pid, len);

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
