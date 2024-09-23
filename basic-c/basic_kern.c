#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int basic(struct xdp_md *ctx)
{
    bpf_printk("hello xdp");

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
