# attaching bpf progs

## When userland loads the program by itself

```sh
-sh-5.2# bpftool prog show name ringbuf2
157: xdp  name ringbuf2  tag 339b573cf2f134f6  gpl
	loaded_at 2024-09-28T11:35:44+0200  uid 0
	xlated 448B  jited 265B  memlock 4096B  map_ids 21,24,22
	btf_id 372
	pids ringbuf2_user(127840)

-sh-5.2# bpftool map show name shared_map
71: array  name shared_map  flags 0x0
	key 4B  value 4B  max_entries 16777216  memlock 134217976B
	btf_id 372
	pids ringbuf2_user(127840)
```



## When loading manually

## To load

```sh
-sh-5.2# bpftool prog load ringbuf2_kern.o /sys/fs/bpf/ringbuf2_kern
-sh-5.2# ip link set lo xdp pinned /sys/fs/bpf/ringbuf2_kern

-sh-5.2# bpftool prog show name ringbuf2
285: xdp  name ringbuf2  tag 339b573cf2f134f6  gpl
	loaded_at 2024-09-28T11:40:14+0200  uid 0
	xlated 448B  jited 268B  memlock 4096B  map_ids 79,82,80
	btf_id 394

-sh-5.2# bpftool map show name shared_map
80: array  name shared_map  flags 0x0
	key 4B  value 4B  max_entries 16777216  memlock 134217976B
	btf_id 394

-sh-5.2# bpftool map show name events
106: ringbuf  name events  flags 0x0
	key 0B  value 0B  max_entries 16777216  memlock 16855304B

-sh-5.2# ip link show lo
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 xdpgeneric qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    prog/xdp id 285 name ringbuf2 tag 339b573cf2f134f6 jited


```

# sudo bpftool prog load my_ebpf_program.o /sys/fs/bpf/my_ebpf_program