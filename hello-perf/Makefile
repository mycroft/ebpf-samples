all: clean build

build:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	go generate
	go build

clean:
	rm -f *.o hello-perf

run: build
	sudo ./hello-perf

.PHONY: all build clean run
