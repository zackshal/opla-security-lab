#ifndef OPLA_TEST_HELPERS
#define OPLA_TEST_HELPERS
#define SEC(name) __attribute__((unused))
#define __uint(name,value) int *name
#define __type(name,value) value *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
void *bpf_map_lookup_elem(void *,const void *);
long bpf_map_update_elem(void *,const void *,const void *,unsigned long long);
unsigned long long bpf_ktime_get_ns(void);
void bpf_spin_lock(struct bpf_spin_lock *);
void bpf_spin_unlock(struct bpf_spin_lock *);
#endif
