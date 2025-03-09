#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <bpf/libbpf.h>

#include <unistd.h>

#include "packetdrop_kern.skel.h"
#include "events.h"

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	printf("EXEC pid is :%d %d %ld\n", e->pid, e->num, e->len);

    for (int i = 0; i < e->len; i += 1) {
        printf("%02x ", e->bytes[i]);
    }
    printf("\n");

	return 0;
}

int main(int argc, char **argv)
{
    struct packetdrop_kern *skel;
    int ret = 0;

    skel = packetdrop_kern__open();
    if (!skel) {
        fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
        return 0;
    }

    ret = packetdrop_kern__load(skel);
    if (ret) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(skel->obj, "snoop_events");
    if (!ringbuf_map) {
        fprintf(stderr, "Failed getting finding ringbuf in skel\n");
        goto cleanup;
    }

    int ringbuf_map_fd = bpf_map__fd(ringbuf_map);
    if (ringbuf_map_fd < 0) {
        fprintf(stderr, "Failed retrieve ringbuf fd\n");
        goto cleanup;
    }

    struct ring_buffer *event = NULL;
    event = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);
	if (!event) {
		printf("Failed to create ring buffer\n");
		return 0;
	}

    bpf_program__attach_xdp(skel->progs.packetdrop, 1);

    while (1) {
        ret = ring_buffer__poll(event, 100 /* timeout, ms */);
        if (ret < 0) {
            fprintf(stderr, "Error while polling ringbuf");
            break;
        }
    }
    

cleanup:
    packetdrop_kern__destroy(skel);
    return ret;
}