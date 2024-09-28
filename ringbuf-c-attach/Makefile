TARGET=ringbuf2

USER_TARGET = ${TARGET:=_user}
BPF_TARGET = ${TARGET:=_kern}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

all: clean kern $(USER_TARGET)

kern: $(BPF_OBJ)
	llvm-strip -g $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(BPF_TARGET).skel.h

load:
	sudo bpftool prog load ringbuf2_kern.o /sys/fs/bpf/ringbuf2_kern
	sudo ip link set lo xdp pinned /sys/fs/bpf/ringbuf2_kern
	sudo bpftool prog show name ringbuf2
	sudo bpftool map pin name events /sys/fs/bpf/events

unload:
	sudo ip link set lo xdp off
	sudo rm /sys/fs/bpf/ringbuf2_kern

$(USER_TARGET): %: %.c  
	gcc -Wall $(CFLAGS) -Ilibbpf/src -Ilibbpf/src/include/uapi -Llibbpf/src -o $@ $< -lbpf -lelf -lz

$(BPF_OBJ): %.o: %.c
	clang -g -O2 -target bpf -c $< -o $@

clean:
	rm -f $(BPF_OBJ) $(USER_TARGET) $(BPF_TARGET).skel.h

run: $(USER_TARGET) kern
	sudo ./$(USER_TARGET)

.PHONY: all kern clean run load unload