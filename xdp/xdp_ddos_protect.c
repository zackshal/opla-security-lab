// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#ifndef THRESHOLD
#define THRESHOLD 100
#endif
#ifndef WINDOW_NS
#define WINDOW_NS 1000000000ULL
#endif
#ifndef MAX_SOURCES
#define MAX_SOURCES 4096
#endif
#if MAX_SOURCES < 1 || MAX_SOURCES > 65536
#error "MAX_SOURCES must be 1..65536"
#endif
#if THRESHOLD < 1 || WINDOW_NS < 1
#error "THRESHOLD and WINDOW_NS must be positive"
#endif
struct window {
    struct bpf_spin_lock lock;
    __u32 count;
    __u64 start_ns;
    __u64 scan_start_ns;
    __u64 blocked_until_ns;
    __u16 ports[8];
    __u32 port_count;
    __u32 scan_reported;
};
struct scan_policy { __u32 mode; __u32 trusted[2]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scan_policy);
} xdp_policy SEC(".maps");
#define SCAN_WINDOW_NS 60000000000ULL
#define SCAN_BLOCK_NS 30000000000ULL
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOURCES);
    __type(key, __u32);
    __type(value, struct window);
} syn_windows SEC(".maps");
// Накопительные счётчики нужны для графиков: оконный count для этого не подходит.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 7);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");
static __always_inline void inc(__u32 key)
{
    __u64 *n = bpf_map_lookup_elem(&xdp_stats, &key);
    if (n) (*n)++;
}
struct vlan_header { __be16 tci; __be16 proto; };
SEC("xdp")
int xdp_ddos_protect(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    __be16 proto = eth->h_proto;
    void *cursor = eth + 1;
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct vlan_header *vlan = cursor;
            if ((void *)(vlan + 1) > end) return XDP_DROP;
            proto = vlan->proto;
            cursor = vlan + 1;
        }
    }
    if (proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = cursor;
    if ((void *)(ip + 1) > end) return XDP_DROP;
    if (ip->version != 4 || ip->ihl < 5) return XDP_DROP;
    if (ip->protocol != 6) return XDP_PASS;
    // Для учебного HTTP-сервера фрагментированный TCP запрещён целиком.
    if (ip->frag_off & bpf_htons(0x3fff)) { inc(4); return XDP_DROP; }
    __u32 ihl = ip->ihl * 4;
    __u32 total = bpf_ntohs(ip->tot_len);
    // Сравниваем длины без прибавления total к указателю пакета.
    __u64 available = (char *)end - (char *)ip;
    if (total < ihl + sizeof(struct tcphdr) || total > available)
        return XDP_DROP;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > end || tcp->doff < 5 ||
        ihl + tcp->doff * 4 > total) return XDP_DROP;
    if (!tcp->syn || tcp->ack) return XDP_PASS;
    inc(0);
    __u32 src = ip->saddr;
    __u16 port = tcp->dest;
    __u32 zero = 0, scan_mode = 0;
    struct scan_policy *policy = bpf_map_lookup_elem(&xdp_policy, &zero);
    if (policy && src != policy->trusted[0] && src != policy->trusted[1])
        scan_mode = policy->mode;
    __u64 now = bpf_ktime_get_ns();
    struct window *w = bpf_map_lookup_elem(&syn_windows, &src);
    if (!w) {
        struct window fresh = { .start_ns = now };
        // Другой CPU мог добавить адрес между lookup и update.
        bpf_map_update_elem(&syn_windows, &src, &fresh, BPF_NOEXIST);
        w = bpf_map_lookup_elem(&syn_windows, &src);
        if (!w) { inc(3); inc(2); return XDP_DROP; }
    }
    int drop, scan_drop = 0, scan_event = 0;
    bpf_spin_lock(&w->lock);
    if (scan_mode == 1 || scan_mode == 2) {
        if (w->blocked_until_ns && now >= w->blocked_until_ns) {
            w->blocked_until_ns = 0;
            w->scan_start_ns = now;
            w->port_count = 0;
            w->scan_reported = 0;
        }
        if (!w->scan_start_ns || (now >= w->scan_start_ns &&
            now - w->scan_start_ns >= SCAN_WINDOW_NS)) {
            w->scan_start_ns = now;
            w->port_count = 0;
            w->scan_reported = 0;
        }
        int seen = 0;
#pragma unroll
        for (int i = 0; i < 8; i++) {
            if (i < w->port_count && w->ports[i] == port) seen = 1;
        }
        if (!seen && w->port_count < 8) {
            __u32 slot = w->port_count;
            if (slot < 8) w->ports[slot] = port;
            w->port_count++;
        }
        if (w->port_count >= 8 && !w->scan_reported) {
            w->scan_reported = 1;
            scan_event = 1;
        }
        if (scan_mode == 2 && w->port_count >= 8 && !w->blocked_until_ns)
            w->blocked_until_ns = now + SCAN_BLOCK_NS;
        scan_drop = scan_mode == 2 && now < w->blocked_until_ns;
    }
    if (now >= w->start_ns && now - w->start_ns >= WINDOW_NS) {
        w->start_ns = now;
        w->count = 0;
    }
    // Насыщение предотвращает переполнение при очень длинном окне.
    if (w->count < 0xffffffffU) w->count++;
    drop = w->count > THRESHOLD;
    bpf_spin_unlock(&w->lock);
    if (scan_event) inc(5);
    if (scan_drop) { inc(6); inc(2); return XDP_DROP; }
    if (drop) { inc(2); return XDP_DROP; }
    inc(1);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
