#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit_map SEC(".maps");

SEC("xdp")
int xdp_ddos_protection(struct xdp_md *ctx) {
    // парсинг Ethernet/IP, lookup в map, return XDP_DROP/XDP_PASS
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
