PROJECT=xdp-ringbuf

all: clean build

init:
	go mod init $(PROJECT)
	go get github.com/cilium/ebpf

build:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	go generate
	go build

clean:
	rm -f *.o $(PROJECT)

run: build
	sudo ./$(PROJECT) lo

.PHONY: all build clean init run
