#include <stdio.h>
#include <unistd.h>

#include <bpf/bpf.h>

#include "hide_process_kern.skel.h"

int main(int argc, char **argv)
{
    int ret;
    struct hide_process_kern *skel;

    skel = hide_process_kern__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Could not open ebpf skeleton.\n");
        return 1;
    }

    ret = hide_process_kern__load(skel);
    if (ret) {
        perror("hide_process_kern__load");
        fprintf(stderr, "ERROR: Could not load ebpf program.\n");
        goto cleanup;
    }

    hide_process_kern__attach(skel);

    while (1) {
        sleep(1);
    }

cleanup:
    hide_process_kern__destroy(skel);
    printf("leaving!\n");

    return 0;
}


//     char *interface_name = "lo";
//     struct ringbuf_kern *skel;
//     int ret = 0;
//     struct ring_buffer *ringbuf = NULL;

//     if (argc > 1) {
//         interface_name = argv[argc - 1];
//     }


//     if (ifindex == 0) {
//         fprintf(stderr, "ERROR: failed to retrieve interface index of %s", interface_name);
//         return 1;
//     }

//     skel = ringbuf_kern__open();
//     if (!skel) {
//         fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
//         return 1;
//     }

//     ret = ringbuf_kern__load(skel);
//     if (ret) {
//         fprintf(stderr, "Failed to load BPF skeleton\n");
//         goto cleanup;
//     }

//     bpf_program__attach_xdp(skel->progs.ringbuf, ifindex);

//     // Get a file descriptor for the ring buffer map
//     int map_fd = bpf_object__find_map_fd_by_name(skel->obj, "events");
//     if (map_fd < 0) {
//         fprintf(stderr, "Failed to find ring buffer map\n");
//         return 1;
//     }

//     // Create a ring buffer manager
//     ringbuf = ring_buffer__new(map_fd, handle_event, NULL, NULL);
//     if (!ringbuf) {
//         fprintf(stderr, "Failed to create ring buffer\n");
//         return 1;
//     }

//     int shared_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "shared_map");

//     struct shared_data data = {
//         .counter = 0
//     };

//     __u32 key = 0;
//     bpf_map_update_elem(shared_map_fd, &key, &data, BPF_ANY);

//     // Poll the ring buffer
//     while (true) {
//         ret = ring_buffer__poll(ringbuf, 100 /* timeout, ms */);
//         if (ret == -EINTR) {
//             break;
//         }
//         if (ret < 0) {
//             fprintf(stderr, "Error polling ring buffer: %d\n", ret);
//             break;
//         }

//         if (ret > 0) {
//             data.counter += ret;
//             bpf_map_update_elem(shared_map_fd, &key, &data, BPF_ANY);
//         }
//     }

//     ring_buffer__free(ringbuf);


// cleanup:
//     return ret;
