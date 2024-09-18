//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include "xdp-ringbuf.h"

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long int u64;

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u16 ip_protocol;
	u32 ip_saddr;
	u32 ip_daddr;
	u64 counter;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");


// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

int counter = 0;

SEC("xdp")
int hello(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct event *task_info;

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

	if (ip->protocol != IPPROTO_ICMP) {
		return XDP_PASS;
	}

	struct icmphdr *icmp = (void *)(ip + 1);
	if ((void *)(icmp + 1) > data_end) {
		return XDP_PASS;
	}

	if (icmp->type == ICMP_ECHO) {
		return XDP_PASS;
	}

#define ICMP_ECHO_LEN 64

	if (data + sizeof(*eth) + sizeof(*ip) + ICMP_ECHO_LEN > data_end) {
		const char fmt[] = "blah";
		bpf_trace_printk(fmt, sizeof(fmt));
		return XDP_PASS;
	}

	if (bpf_ntohs(ip->tot_len) - sizeof(*ip) != ICMP_ECHO_LEN)
		return XDP_PASS;

	task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}

	icmp->un.echo.sequence = bpf_get_prandom_u32() % 32;
	icmp->checksum = 0;
	icmp->checksum = icmp_csum(icmp, ICMP_ECHO_LEN);

	ip->ttl = bpf_get_prandom_u32() % 32;
	ip->check = iph_csum(ip);

	task_info->ip_protocol = ip->protocol;
	task_info->ip_saddr = ip->saddr;
	task_info->ip_daddr = ip->daddr;

	task_info->counter = counter ++;

	bpf_ringbuf_submit(task_info, 0);

    return XDP_PASS;
}
