// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#define IPPROTO_TCP 6
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} first_seen_map SEC(".maps");

#ifndef THRESHOLD
#define THRESHOLD 100
#endif

#ifndef WINDOW_NS
#define WINDOW_NS 1000000000ULL
#endif

SEC("xdp")
int xdp_ddos_protect(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    if (!tcp->syn || tcp->ack)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now    = bpf_ktime_get_ns();

    __u64 *first = bpf_map_lookup_elem(&first_seen_map, &src_ip);
    if (!first) {
        __u64 zero = now;
        bpf_map_update_elem(&first_seen_map, &src_ip, &zero, BPF_ANY);
        first = &zero;
    } else if (now - *first > WINDOW_NS) {
        __u64 zero = 0;
        bpf_map_update_elem(&rate_limit_map, &src_ip, &zero, BPF_ANY);
        bpf_map_update_elem(&first_seen_map, &src_ip, &now, BPF_ANY);
        return XDP_PASS;
    }

    __u64 *count = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
    __u64 new_count = (count ? *count : 0) + 1;
    bpf_map_update_elem(&rate_limit_map, &src_ip, &new_count, BPF_ANY);

    if (new_count > THRESHOLD) {
        if ((new_count % 1000) == 0)
            bpf_printk("XDP: BLOCK src=%pI4 pkts=%llu\n", &src_ip, new_count);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
