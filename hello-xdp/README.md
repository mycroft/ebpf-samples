# hello-xdp

## showing module in bpfprog

```sh
$ make run
...
sudo ./hello-xdp lo
2024/09/17 11:16:15 Attached XDP program to iface "lo" (index 1)
2024/09/17 11:16:15 Press Ctrl-C to exit and remove the program

$ sudo bpftool prog
...
126: xdp  name hello  tag 040a2cbd8c13fb45  gpl
	loaded_at 2024-09-17T11:16:15+0200  uid 0
	xlated 384B  jited 231B  memlock 4096B  map_ids 61
	btf_id 302
	pids hello-xdp(285510)
...

$ sudo bpftool prog show id 126 --pretty
{
    "id": 126,
    "type": "xdp",
    "name": "hello",
    "tag": "040a2cbd8c13fb45",
    "gpl_compatible": true,
    "loaded_at": 1726564575,
    "uid": 0,
    "orphaned": false,
    "bytes_xlated": 384,
    "jited": true,
    "bytes_jited": 231,
    "bytes_memlock": 4096,
    "map_ids": [61
    ],
    "btf_id": 302,
    "pids": [{
            "pid": 285510,
            "comm": "hello-xdp"
        }
    ]
}

$
```


## building module using clang directly

```sh
$ clang -target bpf -g -O2 -c hello-xdp.c -o hello-xdp.o
$ file hello-xdp.o
hello-xdp.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), with debug_info, not stripped
$ llvm-objdump -S hello-xdp.o

hello-xdp.o:	file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <hello>:
;     void *data_end = (void *)(long)ctx->data_end;
       0:	61 12 04 00 00 00 00 00	r2 = *(u32 *)(r1 + 0x4)
; 	void *data     = (void *)(long)ctx->data;
       1:	61 11 00 00 00 00 00 00	r1 = *(u32 *)(r1 + 0x0)
; 	if ((void *)(eth + 1) > data_end) {
       2:	bf 13 00 00 00 00 00 00	r3 = r1
       3:	07 03 00 00 0e 00 00 00	r3 += 0xe
       4:	2d 23 29 00 00 00 00 00	if r3 > r2 goto +0x29 <LBB0_5>
; 	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
       5:	71 13 0c 00 00 00 00 00	r3 = *(u8 *)(r1 + 0xc)
       6:	71 14 0d 00 00 00 00 00	r4 = *(u8 *)(r1 + 0xd)
       7:	67 04 00 00 08 00 00 00	r4 <<= 0x8
       8:	4f 34 00 00 00 00 00 00	r4 |= r3
       9:	15 04 0a 00 08 00 00 00	if r4 == 0x8 goto +0xa <LBB0_3>
      10:	b7 01 00 00 50 00 00 00	r1 = 0x50
...

$ sudo bpftool prog load ./hello-xdp.o /sys/fs/bpf/hello-xdp
$ sudo bpftool prog list
161: xdp  name hello  tag 040a2cbd8c13fb45  gpl
	loaded_at 2024-09-17T11:28:27+0200  uid 0
	xlated 384B  jited 231B  memlock 4096B  map_ids 76,77
	btf_id 346

$ sudo rm /sys/fs/bpf/hello-xdp
```

