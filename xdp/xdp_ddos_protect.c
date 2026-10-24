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
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOURCES);
    __type(key, __u32);
    __type(value, struct window);
} syn_windows SEC(".maps");
// Накопительные счётчики нужны для графиков: оконный count для этого не подходит.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
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
    __u64 now = bpf_ktime_get_ns();
    struct window *w = bpf_map_lookup_elem(&syn_windows, &src);
    if (!w) {
        struct window fresh = { .start_ns = now };
        // Другой CPU мог добавить адрес между lookup и update.
        bpf_map_update_elem(&syn_windows, &src, &fresh, BPF_NOEXIST);
        w = bpf_map_lookup_elem(&syn_windows, &src);
        if (!w) { inc(3); inc(2); return XDP_DROP; }
    }
    int drop;
    bpf_spin_lock(&w->lock);
    if (now >= w->start_ns && now - w->start_ns >= WINDOW_NS) {
        w->start_ns = now;
        w->count = 0;
    }
    // Насыщение предотвращает переполнение при очень длинном окне.
    if (w->count < 0xffffffffU) w->count++;
    drop = w->count > THRESHOLD;
    bpf_spin_unlock(&w->lock);
    if (drop) { inc(2); return XDP_DROP; }
    inc(1);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
