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

    while (1) {
        sleep(1);
    }

cleanup:
    basic_kern__destroy(skel);
    return ret;
}
