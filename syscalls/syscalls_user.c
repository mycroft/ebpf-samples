#include <stdio.h>
#include <unistd.h>
#include <net/if.h>

#include "syscalls_kern.skel.h"

int main(int argc, char **argv)
{
    struct syscalls_kern *skel;
    int ret = 0;

    skel = syscalls_kern__open();
    if (!skel) {
        fprintf(stderr, "ERROR: failed to open BPF skeleton\n");
        return 1;
    }

    ret = syscalls_kern__load(skel);
    if (ret) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    ret = syscalls_kern__attach(skel);
    if (ret) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    while (1) {
        sleep(1);
    }
    // bpf_program__attach_xdp(skel->progs.basic, ifindex);

    // FILE *trace_pipe = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    // if (trace_pipe == NULL) {
    //     fprintf(stderr, "Error opening trace_pipe");
    //     goto cleanup;
    // }

    // while(1) {
    //     char line[65535];

    //     if (fgets(line, sizeof(line), trace_pipe) != NULL) {
    //         fprintf(stdout, "%s", line);
    //         continue;
    //     }

    //     if(feof(trace_pipe)) {
    //         usleep(100);
    //         clearerr(trace_pipe);
    //     } else {
    //         fprintf(stderr, "Error while reading file");
    //         break;
    //     }
    // }

cleanup:
    syscalls_kern__destroy(skel);
    return ret;
}
