/* Execute the actual parser and limiter with deterministic maps and clock.
 * This checks packet behavior, not kernel verifier compatibility. */
#include <linux/bpf.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct test_ctx { unsigned long data; unsigned long data_end; };
#define xdp_md test_ctx
#include "../xdp/xdp_ddos_protect.c"
static struct window state;
static int exists, full;
static __u64 counters[5], clock_ns;
void *bpf_map_lookup_elem(void *map,const void *key) {
    if (map==&xdp_stats) return &counters[*(const __u32 *)key];
    return exists ? &state : NULL;
}
long bpf_map_update_elem(void *map,const void *key,const void *value,unsigned long long flags) {
    (void)map;(void)key;(void)flags;
    if (full || exists) return -1;
    memcpy(&state,value,sizeof(state));exists=1;return 0;
}
unsigned long long bpf_ktime_get_ns(void) { return clock_ns; }
void bpf_spin_lock(struct bpf_spin_lock *lock) { (void)lock; }
void bpf_spin_unlock(struct bpf_spin_lock *lock) { (void)lock; }
static unsigned char frame[256];
static struct test_ctx ctx;
static struct iphdr *ip;
static struct tcphdr *tcp;
static void reset(void) {
    memset(frame,0,sizeof(frame)); memset(&state,0,sizeof(state));
    memset(counters,0,sizeof(counters));exists=full=0;clock_ns=1;
    struct ethhdr *eth=(void *)frame;eth->h_proto=bpf_htons(ETH_P_IP);
    ip=(void *)(eth+1);ip->version=4;ip->ihl=5;ip->protocol=6;ip->tot_len=bpf_htons(40);
    tcp=(void *)(ip+1);tcp->syn=1;tcp->doff=5;
    ctx.data=(unsigned long)frame;ctx.data_end=ctx.data+54;
}
int main(void) {
    reset();
    for (int i=0;i<100;i++) assert(xdp_ddos_protect(&ctx)==XDP_PASS);
    assert(xdp_ddos_protect(&ctx)==XDP_DROP);
    assert(counters[0]==101 && counters[1]==100 && counters[2]==1);
    clock_ns+=WINDOW_NS;
    assert(xdp_ddos_protect(&ctx)==XDP_PASS && state.count==1);
    for (int i=1;i<100;i++) assert(xdp_ddos_protect(&ctx)==XDP_PASS);
    assert(xdp_ddos_protect(&ctx)==XDP_DROP);
    reset();tcp->ack=1;assert(xdp_ddos_protect(&ctx)==XDP_PASS && counters[0]==0);
    reset();full=1;assert(xdp_ddos_protect(&ctx)==XDP_DROP && counters[3]==1);
    reset();ctx.data_end-=1;assert(xdp_ddos_protect(&ctx)==XDP_DROP);
    reset();ip->ihl=4;assert(xdp_ddos_protect(&ctx)==XDP_DROP);
    reset();ip->frag_off=bpf_htons(1);assert(xdp_ddos_protect(&ctx)==XDP_DROP && counters[4]==1);
    reset();ip->frag_off=bpf_htons(0x2000);assert(xdp_ddos_protect(&ctx)==XDP_DROP);
    reset();tcp->doff=4;assert(xdp_ddos_protect(&ctx)==XDP_DROP);
    reset();ip->ihl=6;ip->tot_len=bpf_htons(44);ctx.data_end+=4;
    memmove((char *)ip+24,tcp,20);tcp=(void *)((char *)ip+24);
    assert(xdp_ddos_protect(&ctx)==XDP_PASS && counters[0]==1);
    reset();
    memmove(frame+18,frame+14,40);
    ((struct ethhdr *)frame)->h_proto=bpf_htons(ETH_P_8021Q);
    struct vlan_header *tag=(void *)(frame+14);tag->proto=bpf_htons(ETH_P_IP);
    ctx.data_end+=4;assert(xdp_ddos_protect(&ctx)==XDP_PASS && counters[0]==1);
    reset();((struct ethhdr *)frame)->h_proto=bpf_htons(ETH_P_IPV6);
    assert(xdp_ddos_protect(&ctx)==XDP_PASS && counters[0]==0);
    puts("PASS: threshold, window boundary, ACK, map capacity, truncation, IHL, TCP length, fragments, VLAN, IPv6 scope");
}
