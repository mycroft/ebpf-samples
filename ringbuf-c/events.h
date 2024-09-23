#ifndef EVENTS_H_
#define EVENTS_H_

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct event {
	__u16 ip_protocol;
	__u32 ip_saddr;
	__u32 ip_daddr;
	__u64 counter;
    __u32 shared_num;
};

struct shared_data {
    __u32 counter;
};

#endif