#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

#include "basic_kern.skel.h"

int main(int argc, char **argv)
{
    char *interface_name = "lo";
    struct basic_kern *skel;
    int ret = 0;

    if (argc > 1) {
        interface_name = argv[argc - 1];
    }

    unsigned int ifindex = if_nametoindex(interface_name);
    
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: failed to retrieve interface index of %s", interface_name);
        return 1;
    }

    skel = basic_kern__open();
    if (!skel) {
        fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
        return 1;
    }

    ret = basic_kern__load(skel);
    if (ret) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    bpf_program__attach_xdp(skel->progs.packetdrop, ifindex);

    FILE *trace_pipe = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (trace_pipe == NULL) {
        fprintf(stderr, "Error opening trace_pipe");
        goto cleanup;
    }

    while(1) {
        char line[65535];

        if (fgets(line, sizeof(line), trace_pipe) != NULL) {
            fprintf(stdout, "%s", line);
            continue;
        }

        if(feof(trace_pipe)) {
            usleep(100);
            clearerr(trace_pipe);
        } else {
            fprintf(stderr, "Error while reading file");
            break;
        }
    }

cleanup:
    basic_kern__destroy(skel);
    return ret;
}
