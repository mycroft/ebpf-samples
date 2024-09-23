all: clean build

build:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	go generate
	go build

clean:
	rm -f *.o hello-tailcall

run: build
	sudo ./hello-tailcall

.PHONY: all build clean run
