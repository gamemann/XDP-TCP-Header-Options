#include <linux/bpf.h>
#include <bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "xdp_prog.h"

//#define PRINT

#ifdef PRINT
#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})
#endif

SEC("xdp_prog")
int prog(struct xdp_md *ctx)
{
    // Initialize data and data_end along with needed headers along with checks.
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (eth + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    if (eth->h_proto != htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof (struct ethhdr);

    if (iph + 1 > (struct iphdr *)data_end)
    {
        return XDP_DROP;
    }

    if (iph->protocol != IPPROTO_UDP)
    {
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

    if (tcph + 1 > (struct tcphdr *)data_end)
    {
        return XDP_DROP;
    }

    // These variables will indicates the timestamp values in memory if found (otherwise NULL).
    __u32 *senderts = NULL;
    __u32 *recvts = NULL;

    // Check to see if we have additional TCP header options.
    if (tcph->doff > 5)
    {
        #ifdef PRINT
            bpf_printk("[TCPOPTS] Have TCP header options. Header length => %d. Beginning to parse options.\n", tcph->doff * 5);
        #endif

        __u16 off = 0;
        __u8 *opts = data + sizeof(struct ethhdr) + (iph->ihl * 4) + 20;

        if (opts + 1 > (__u8 *)data_end)
        {
            return XDP_PASS;
        }

        __u16 optdata = 0;

        while (optdata <= 40)
        {
            // Initialize the byte we're parsing and ensure it isn't outside of data_end.
            __u8 *val = opts + optdata;

            if (val + 1 > (__u8 *)data_end || val < (__u8 *)data)
            {
                break;
            }

            #ifdef PRINT
                bpf_printk("[TCPOPTS] Received %d as type code.\n", *val);
            #endif

            // 0x01 indicates a NOP which must be skipped.
            if (*val == 0x01)
            {
                #ifdef PRINT
                    bpf_printk("[TCPOPTS] Skipping NOP.\n");
                #endif

                optdata++;

                continue;
            }
            // 0x00 indicates end of TCP header options, so break loop.
            else if (*val == 0x00)
            {
                break;
            }
            // 0x08 indicates timestamps.
            else if (*val == 0x08)
            {
                // Adjust offset by two since +1 = option length and +2 = start of timestamps data.
                off = optdata + 2;

                #ifdef PRINT
                    bpf_printk("[TCPOPTS] Found start of timestamps! Offset => %d.\n", off);
                #endif

                break;
            }
            // We need to increase by the option's length field for other options.
            else
            {
                #ifdef PRINT
                    bpf_printk("[TCPOPTS] Found another TCP option! Adjusting by its length.\n");
                #endif

                // Increase by option length (which is val + 1 since the option length is the second field).
                __u8 *len = val + 1;
                
                // Check to make sure the length pointer doesn't go outside of data_end and data (the packet).
                if (len + 1 > (__u8 *)data_end || len < (__u8 *)data)
                {
                    break;
                }

                #ifdef PRINT
                    bpf_printk("[TCPOPTS] Found option length => %d! Option type => %d.\n", *len, *val);
                #endif

                // This check shouldn't be needed, but just for safe measure, perform another check before incrementing optdata by the option's length.
                if (len <= (__u8 *)data_end && len >= (__u8 *)data)
                {
                    optdata += (*len > 0) ? *len : 1;
                }
                else
                {
                    // Avoid an infinite loop.
                    optdata++;
                }
                
                continue;
            }

            // We shouldn't get here, but increment to prevent an infinite loop either way.
            optdata++;
        }

        // If the offset is above 0, that means we've found the timestamps.
        if (off > 0)
        {
            // We'll need to make sure 8 bytes after the offset is not outside of the packet since the two timestamps variables are 32 bits (8 bytes).
            if (opts + off + 8 <= (__u8 *)data_end && opts + off + 8 >= (__u8 *)data)
            {
                // Sender timestamp should be the first 32-bit value.
                senderts = (__u32 *)opts + off;

                // Receive timestamp should be the second 32-bit value.
                recvts = (__u32 *)opts + off + 4;

                #ifdef PRINT
                    bpf_printk("[TCPOPTS] Sender TS Value => %lu. Receive TS Value => %lu.\n", *senderts, *recvts);
                #endif
            }
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";