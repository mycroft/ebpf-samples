#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

#include <bpf/bpf.h>

#include "events.h"

#include "ringbuf2_kern.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    printf("Event received. shared:%d counter:%lld protocol:%d 0x%08x -> 0x%08x\n",
        e->shared_num,
        e->counter,
        e->ip_protocol,
        e->ip_saddr,
        e->ip_daddr
    );

    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    struct ringbuf2_kern *skel;
    struct ring_buffer *ringbuf = NULL;
    int prog_id;

    if (argc != 2) {
        fprintf(stderr, "ERROR: usage: %s prog_id\n", argv[0]);
        return 1;
    }

    int prog_id = strtol(argv[1], NULL, 10);
    if (errno == EINVAL) {
        fprintf(stderr, "ERROR: invalid strtol conversion\n");
        return 1;
    }

    int prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: could not get program fd by in\n");
        return 1;
    }


    skel = ringbuf2_kern__open();
    if (!skel) {
        fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
        return 1;
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        return 1;
    }

    fprintf(stderr, "prog_fd: %d map_fd: %d\n", prog_fd, map_fd);

    // Create a ring buffer manager
    ringbuf = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!ringbuf) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    // Poll the ring buffer
    while (true) {
        ret = ring_buffer__poll(ringbuf, 100 /* timeout, ms */);
        if (ret == -EINTR) {
            break;
        }
        if (ret < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", ret);
            break;
        }
    }

    exit(0);
}
