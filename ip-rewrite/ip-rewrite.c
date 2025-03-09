//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

#include "ip-rewrite.h"

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

int handle_packet(struct __sk_buff *skb) {
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return TC_ACT_OK;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

    struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return TC_ACT_OK;
	}

	struct tcphdr *tcp = (void *)(ip + 1);
	if ((void *)(tcp +1) > data_end) {
		return TC_ACT_OK;
	}

	// if (ip->protocol != IPPROTO_TCP) {
	// 	return TC_ACT_OK;
	// }

	if (ip->saddr == 0x0800000a) {
    	__be32 new_dst = bpf_htonl(0x0a000054);
		__s64 sum = bpf_csum_diff((void *)&ip->daddr, 4, (void *)&new_dst, 4, 0);
		if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), (void *)&new_dst, 4, 0) < 0) {
			return TC_ACT_SHOT; // Drop packet if modification fails
		}
		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, sum, 0);
		return TC_ACT_OK;

	} else if (ip->daddr == 0x5400000a) {
    	__be32 new_dst = bpf_htonl(0x0a000008);
		__s64 sum = bpf_csum_diff((void *)&ip->daddr, 4, (void *)&new_dst, 4, 0);
		if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), (void *)&new_dst, 4, 0) < 0) {
			return TC_ACT_SHOT; // Drop packet if modification fails
		}
		bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, sum, 0);
		return TC_ACT_OK;
	} else {
		return TC_ACT_OK;
	}
	const char fmt[] = "packet s:%x -> d:%x";
	bpf_trace_printk(fmt, sizeof(fmt), ip->saddr, ip->daddr);

	return TC_ACT_OK;
}


SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

    struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_PASS;
	}

	struct tcphdr *tcp = (void *)(ip + 1);
	if ((void *)(tcp +1) > data_end) {
		return XDP_PASS;
	}

	// if (ip->protocol != IPPROTO_TCP) {
	// 	return XDP_PASS;
	// }

	if (ip->saddr == 0x0800000a) {
		ip->saddr = 0x5400000a;
	} else if (ip->daddr == 0x5400000a) {
		ip->daddr = 0x0800000a;
	} else {
		return XDP_PASS;
	}

	const char fmt2[] = "saddr:%x daddr:%x";
	bpf_trace_printk(fmt2, sizeof(fmt2), ip->saddr, ip->daddr);

	ip->check = iph_csum(ip);

	return XDP_PASS;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx) {
	return handle_packet(ctx);
}

SEC("xdp")
int hello(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	// struct event *task_info;


	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
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

	const char fmt[] = "incoming";
	bpf_trace_printk(fmt, sizeof(fmt));


	if (ip->saddr == 0x0800000a) {
		ip->saddr = 0x5400000a;
	} else if (ip->daddr == 0x5400000a) {
		ip->daddr = 0x0800000a;
	}

	const char fmt2[] = "saddr:%x daddr:%x";
	bpf_trace_printk(fmt2, sizeof(fmt2), ip->saddr, ip->daddr);

	ip->check = iph_csum(ip);

	// task_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	// if (!task_info) {
	// 	return 0;
	// }

	// icmp->un.echo.sequence = bpf_htons(bpf_get_prandom_u32() % 32);
	// icmp->checksum = 0;
	// icmp->checksum = icmp_csum(icmp, ICMP_ECHO_LEN);

	// ip->ttl = bpf_get_prandom_u32() % 32;
	// ip->check = iph_csum(ip);

	// task_info->ip_protocol = ip->protocol;
	// task_info->ip_saddr = ip->saddr;
	// task_info->ip_daddr = ip->daddr;

	// task_info->counter = counter ++;

	// bpf_ringbuf_submit(task_info, 0);

    return XDP_PASS;
}
