TARGET = packetdrop

# For xdp_liz, make and also make user. The others don't have userspace programs

USER_TARGET = ${TARGET:=_user}
BPF_TARGET = ${TARGET:=_kern}
BPF_C = ${BPF_TARGET:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

all: clean kern user

kern:
	clang -g -O2 -target bpf -c packetdrop_kern.c -o packetdrop_kern.o
	llvm-strip -g packetdrop_kern.o
	bpftool gen skeleton packetdrop_kern.o > packetdrop_kern.skel.h

load: kern
	bpftool net detach xdpgeneric dev lo
	rm -f /sys/fs/bpf/$(TARGET)
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/$(TARGET) dev lo 

unload:
	bpftool net detach xdpgeneric dev lo
	rm -f /sys/fs/bpf/$(TARGET)

user: $(USER_TARGET)

$(USER_TARGET): %: %.c  
	gcc -Wall $(CFLAGS) -Ilibbpf/src -Ilibbpf/src/include/uapi -Llibbpf/src -o $@  \
	 $< -lbpf -lelf -lz

#clang -g -O2 -target bpf -D__TARGET_ARCH_x86		      \
#	     -I.output -c ringbuf-output.bpf.c -o .output/ringbuf-output.bpf.o
#llvm-strip -g .output/ringbuf-output.bpf.o

$(BPF_OBJ): %.o: %.c
	clang -S \
	    -target bpf \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

clean:
	rm -f $(BPF_OBJ)
	rm -f ${BPF_OBJ:.o=.ll}
	rm -f ${USER_TARGET}

.PHONY=kern xdp user clean