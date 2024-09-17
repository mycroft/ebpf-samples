all: clean build

build:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	go generate
	go build

clean:
	rm -f *.o hello-map

run: build
	sudo ./hello-map

.PHONY: all build clean run
