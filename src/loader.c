#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <error.h>
#include <errno.h>

#include <bpf.h>
#include <libbpf.h>
#include <linux/if_link.h>

#include <net/if.h>
#include <arpa/inet.h>

const struct option longopts[] =
{
    {"interface", required_argument, NULL, 'i'},
    {"obj", required_argument, NULL, 'o'},
    {NULL, 0, NULL, 0}
};

__u8 cont = 1;

void sighndl(int tmp)
{
    cont = 0;
}

char *dev = NULL;
char *objfile = NULL;

void parsecmdline(int argc, char *argv[])
{
    int c = -1;

    while ((c = getopt_long(argc, argv, "i:o:", longopts, NULL)) != -1)
    {
        switch (c)
        {
            case 'i':
                dev = optarg;

                break;

            case 'o':
                objfile = optarg;

                break;

            case '?':
                fprintf(stderr, "Missing argument value.\n");

                break;
        }
    }
}

int main(int argc, char *argv[])
{
    // Parse command line.
    parsecmdline(argc, argv);

    // Check if we have an interface specified.
    if (dev == NULL)
    {
        fprintf(stderr, "Missing interface argument.\n");

        return EXIT_FAILURE;
    }

    // Check to see if the interface exists and get its index.
    int ifidx = if_nametoindex(dev);

    if (ifidx < 0)
    {
        fprintf(stderr, "Interface index less than 0 (Not Found).\n");

        return EXIT_FAILURE;
    }

    // If we don't have an object path, set to default.
    if (objfile == NULL)
    {
        objfile = "/etc/tcpopts/xdp.o";
    }

    struct bpf_object *obj = NULL;
    int bpffd = -1;

    // Load BPF/XDP program.
    bpf_prog_load(objfile, BPF_PROG_TYPE_XDP, &obj, &bpffd);

    if (bpffd < 0)
    {
        fprintf(stderr, "Error loading BPF program.\n");

        return EXIT_FAILURE;
    }

    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    // Attach XDP program with DRV mode.
    int err = bpf_set_link_xdp_fd(ifidx, bpffd, flags);

    if (err)
    {
        fprintf(stdout, "DRV mode not supported. Trying SKB instead.\n");

        // Attempt to try SKB mode.
        flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;

        err = bpf_set_link_xdp_fd(ifidx, bpffd, flags);

        if (err)
        {
            fprintf(stderr, "Error attaching XDP program in DRV or SKB mode :: %s (%d).\n", strerror(-err), -err);

            return EXIT_FAILURE;
        }
    }

    // Setup signal.
    signal(SIGINT, sighndl);

    // Loop (we sleep every second to avoid CPU consumption).
    while (cont)
    {
        sleep(1);
    }

    // Detach XDP program.
    bpf_set_link_xdp_fd(ifidx, -1, flags);
    
    return EXIT_SUCCESS;
}