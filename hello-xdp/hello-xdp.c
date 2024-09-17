//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>

char __license[] SEC("license") = "Dual MIT/GPL";

int counter = 0;

SEC("xdp")
int hello(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        const char fmt[] = "!ETH_P_IP";
        bpf_trace_printk(fmt, sizeof(fmt));
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return XDP_PASS;
	}

    struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}

    counter++;

    const char fmt[] = "Packet p:%x s:%x d:%x";
    bpf_trace_printk(fmt, sizeof(fmt), ip->protocol, ip->saddr, ip->daddr);

    return XDP_PASS;
}
