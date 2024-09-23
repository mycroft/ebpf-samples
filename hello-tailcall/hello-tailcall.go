package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -tags linux bpf hello-tailcall.c -- -I../headers

func main() {
	ignoredSyscalls := []int{
		0,   // read
		1,   // write
		16,  // ioctl
		21,  // access
		25,  // mremap
		26,  // msync
		27,  // mincore
		47,  // recvmsg
		232, // epoll_wait
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	objs.bpfMaps.ProgArray.Update(uint32(59), objs.HelloExecve, ebpf.UpdateAny)

	objs.bpfMaps.ProgArray.Update(uint32(222), objs.HelloTimer, ebpf.UpdateAny)
	objs.bpfMaps.ProgArray.Update(uint32(223), objs.HelloTimer, ebpf.UpdateAny)
	objs.bpfMaps.ProgArray.Update(uint32(224), objs.HelloTimer, ebpf.UpdateAny)
	objs.bpfMaps.ProgArray.Update(uint32(225), objs.HelloTimer, ebpf.UpdateAny)
	objs.bpfMaps.ProgArray.Update(uint32(226), objs.HelloTimer, ebpf.UpdateAny)

	for _, ignored := range ignoredSyscalls {
		objs.bpfMaps.ProgArray.Update(uint32(ignored), objs.HelloIgnore, ebpf.UpdateAny)
	}

	kp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.Hello,
	})
	if err != nil {
		panic(err)
	}
	defer kp.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
	}
}
