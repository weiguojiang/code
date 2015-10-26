/*
 * Copyright (c) 2007-2014 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef OVS_DP_COMMON_H
#define OVS_DP_COMMON_H 1
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "ovs_debug.h"

#include "ovs_con_def.h"

#include "se_alloc.h"
#include "ovs_list.h"


#define OVS_STATS
#define u64_stats_update_begin(a)
#define u64_stats_update_end(a)


#define CHECKSUM_PARTIAL 3
#define CSUM_MANGLED_0  (( __sum16)0xffff)



#define ENODEV 19
#define ENOMEM 12
#define EFBIG 27
#define EINVAL 22
#define EEXIST 17
#define ENOENT 2
#define EBUSY 16

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))
#define for_each_possible_cpu(i) 

#define BUG_ON(n)  //just for TOSE


#define rcu_dereference
#define __force
#define __always_unused


#define u64_stats_init(syncp)  do { } while (0)
//#define spin_lock
#define NUMA_NO_NODE -1
#define jiffies 0
//#define for_each_node(n) 



#define vlan_tx_tag_get(skb) ((skb)->vlan_tci)
#define vlan_tx_tag_present(skb) ((skb)->vlan_tci)
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)




#define max(n,m) ({ typeof(n) _max1 = (n); typeof(m) _max2 = (size); (void) (&_max1 == &_max2); _max1 > _max2 ? _max1 : _max2; })



//typedef unsigned gfp_t;


#ifdef _IS_LINUX_
  // typedef _Bool bool;
   #define CVMX_SHARED
   #include <stddef.h>
   #define unlikely
   #define likely
   #define mbuf sk_buff

   static inline char *m_prepend(struct mbuf *m, unsigned int len)
   {
      return NULL;
   }

   static inline char *m_adj(struct mbuf *m, uint16_t len)
   {
      return NULL;
   }

   static inline uint16_t m_copyfrombuf(struct mbuf *m, uint16_t off, const void *src, uint16_t len)
   {
      return 0;
   }

   #define cvmx_spinlock_t int
   #define cvmx_rwlock_wp_lock_t int
   #define cvmx_spinlock_lock(a)
   #define cvmx_spinlock_unlock(a)

   #define cvmx_rwlock_wp_read_lock(a)
   #define cvmx_rwlock_wp_read_unlock(a)
   #define cvmx_rwlock_wp_write_lock(a)
   #define cvmx_rwlock_wp_write_unlock(a)
   #define cvmx_rwlock_wp_init(a)

   static inline void *kmalloc(size_t size, int flag)
   {
      void * ptr = malloc(size);
      memset(ptr, 0, size);
      printf("777777 with %d new %p \n", flag, ptr);
      return ptr;   
   }
   
   static inline void kfree(void * ptr, int flags)
   {
      printf("777777 with %d free %p \n", flags, ptr);
      return free(ptr);
   }   
#else
   static inline void *kmalloc(size_t size, int flag)
   {
      void * ptr = mem_pool_malloc(flag, size);
      memset(ptr, 0, size);
      SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "memory alloc with %d new %p \n", flag, ptr);
      return ptr;   
   }
   
   static inline void kfree(void * ptr, int flag)
   {
       SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "memory release with %d free %p \n", flag, ptr);
      return mem_pool_free(flag, ptr);
   }   
#endif


typedef struct {
 int counter;
} atomic_t;


typedef struct {
 volatile long counter;
} atomic64_t;


struct ustat {
 char f_fname[6];
 char f_fpack[6];
};


struct net;

#ifndef __percpu
#define __percpu
#endif

#ifndef __rcu
#define __rcu
#endif
#define GFP_KERNEL  ((( gfp_t)0x10u) | (( gfp_t)0x40u) | (( gfp_t)0x80u))
#define GFP_ATOMIC ((( gfp_t)0x20u))


#define reciprocal_value rpl_reciprocal_value
struct reciprocal_value {
	u32 m;
	u8 sh1, sh2;
};
static inline u32 reciprocal_divide(u32 a, struct reciprocal_value R)
{
	u32 t = (u32)(((u64)a * R.m) >> 32);
	return (t + ((a - t) >> R.sh1)) >> R.sh2;
}



#define FIELD_SIZEOF(s,m) (sizeof(((s *)0)->m))

struct rcu_head {
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

typedef union {
    u32 lock;
    struct {
        u16 ticket;
        u16 serving_now;
    } h;
} arch_spinlock_t;

typedef struct raw_spinlock {
    arch_spinlock_t raw_lock;
} raw_spinlock_t;

typedef struct spinlock {
    union {
        struct raw_spinlock rlock;
    };
} spinlock_t;




typedef long ktime_t;
struct u64_stats_sync {
};


typedef atomic64_t atomic_long_t;
struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);

struct work_struct {
    atomic_long_t data;

    struct list_head entry;
    work_func_t func;

};


#define CHECKSUM_COMPLETE 2

static inline __attribute__((always_inline)) struct net *read_pnet(struct net * const *pnet)
{
 return *pnet;
}

static inline __attribute__((always_inline)) void write_pnet(struct net **pnet, struct net *net)
{
 *pnet = net;
}



//#include_next <linux/rcupdate.h>

#ifndef rcu_dereference_check
#define rcu_dereference_check(p, c) (p)
#endif

#ifndef rcu_dereference_protected
#define rcu_dereference_protected(p, c) (p)
#endif

#ifndef rcu_dereference_raw
#define rcu_dereference_raw(p) rcu_dereference_check(p, 1)
#endif

//local linux/rculish.h list.h 


#define this_cpu_ptr

#define BUILD_BUG_ON(condition) 












typedef u32 netdev_features_t;

static inline  struct sk_buff * __skb_gso_segment(struct sk_buff *skb,
      netdev_features_t features,
      bool tx_path)
{
// return rpl_skb_gso_segment(skb, features); //For TOSE
return NULL;
}

enum {
 SKB_GSO_TCPV4 = 1 << 0,
 SKB_GSO_UDP = 1 << 1,


 SKB_GSO_DODGY = 1 << 2,


 SKB_GSO_TCP_ECN = 1 << 3,

 SKB_GSO_TCPV6 = 1 << 4,

 SKB_GSO_FCOE = 1 << 5,
};

extern u32 __skb_get_hash(struct sk_buff *skb);
static inline __u32 skb_get_hash(struct sk_buff *skb)
{
#ifdef HAVE_RXHASH
	if (skb->rxhash)
#ifndef HAVE_U16_RXHASH
		return skb->rxhash;
#else
		return jhash_1word(skb->rxhash, 0);
#endif
#endif
	return __skb_get_hash(skb);
}



#define IS_ERR_VALUE(x) ((x) > (unsigned long)-1000L)

static inline void *ERR_PTR(long error)
{
 return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
 return (long) ptr;
}

static inline long IS_ERR(const void *ptr)
{
 return IS_ERR_VALUE((unsigned long)ptr);
}

//linux kernal include/linux/netdevice.h
#define IFNAMSIZ 64

struct net_device
{

	char			name[IFNAMSIZ];
//	struct hlist_node	name_hlist;
};

//socket.h
static inline  struct net *sock_net(const struct sock *sk)
{

 //return sk->__sk_common.skc_net;
 return NULL;



}
//# 21 "/home/binhhu/ovs/openvswitch-2.3.1/datapath/linux/compat/include/net/genetlink.h"

//inux/u64_stats_sync.h"
static inline  unsigned int u64_stats_fetch_begin_irq(const struct u64_stats_sync *syncp)
{


 return 0;

}

static inline  bool u64_stats_fetch_retry_irq(const struct u64_stats_sync *syncp,
      unsigned int start)
{

 return false;

}


static  void *kzalloc(size_t size, gfp_t flags)
{
 return kmalloc(size, flags);
}







//# 197 "include/net/net_namespace.h"
static inline  struct net *hold_net(struct net *net)
{
 return net;
}

//# 29 "include/net/netns/generic.h"
struct net_generic {
 unsigned int len;
 struct rcu_head rcu;

 void *ptr[0];
};


static inline  void *net_generic(struct net *net, int id)
{
 //struct net_generic *ng;
 void *ptr;
 return ptr;
}




#define rcu_assign_pointer(n,m)  (n = m)


//# 60 "include/net/checksum.h"
static inline  __wsum csum_add(__wsum csum, __wsum addend)
{
 u32 res = ( u32)csum;
 res += ( u32)addend;
 return ( __wsum)(res + (res < ( u32)addend));
}

static inline __wsum csum_sub(__wsum csum, __wsum addend)
{
 return csum_add(csum, ~addend);
}





//# 27 "include/net/ndisc.h"
enum {
 __ND_OPT_PREFIX_INFO_END = 0,
 ND_OPT_SOURCE_LL_ADDR = 1,
 ND_OPT_TARGET_LL_ADDR = 2,
 ND_OPT_PREFIX_INFO = 3,
 ND_OPT_REDIRECT_HDR = 4,
 ND_OPT_MTU = 5,
 __ND_OPT_ARRAY_MAX,
 ND_OPT_ROUTE_INFO = 24,
 ND_OPT_RDNSS = 25,
 __ND_OPT_MAX
};
#define NDISC_NEIGHBOUR_SOLICITATION 135
#define NDISC_NEIGHBOUR_ADVERTISEMENT 136


struct nd_opt_hdr {
 __u8 nd_opt_type;
 __u8 nd_opt_len;
} /*__attribute__((__packed__))*/;

struct nd_msg {
        struct icmp6hdr icmph;
        struct in6_addr target;
 __u8 opt[0];
};


//# 44 "include/linux/jhash.h"
static inline  u32 jhash(const void *key, u32 length, u32 initval)
{
 u32 a, b, c, len;
 const u8 *k = key;

 len = length;
 a = b = 0x9e3779b9;
 c = initval;

 while (len >= 12) {
  a += (k[0] +((u32)k[1]<<8) +((u32)k[2]<<16) +((u32)k[3]<<24));
  b += (k[4] +((u32)k[5]<<8) +((u32)k[6]<<16) +((u32)k[7]<<24));
  c += (k[8] +((u32)k[9]<<8) +((u32)k[10]<<16)+((u32)k[11]<<24));

  { a -= b; a -= c; a ^= (c>>13); b -= c; b -= a; b ^= (a<<8); c -= a; c -= b; c ^= (b>>13); a -= b; a -= c; a ^= (c>>12); b -= c; b -= a; b ^= (a<<16); c -= a; c -= b; c ^= (b>>5); a -= b; a -= c; a ^= (c>>3); b -= c; b -= a; b ^= (a<<10); c -= a; c -= b; c ^= (b>>15); };

  k += 12;
  len -= 12;
 }

 c += length;
 switch (len) {
 case 11: c += ((u32)k[10]<<24);
 case 10: c += ((u32)k[9]<<16);
 case 9 : c += ((u32)k[8]<<8);
 case 8 : b += ((u32)k[7]<<24);
 case 7 : b += ((u32)k[6]<<16);
 case 6 : b += ((u32)k[5]<<8);
 case 5 : b += k[4];
 case 4 : a += ((u32)k[3]<<24);
 case 3 : a += ((u32)k[2]<<16);
 case 2 : a += ((u32)k[1]<<8);
 case 1 : a += k[0];
 };

 { a -= b; a -= c; a ^= (c>>13); b -= c; b -= a; b ^= (a<<8); c -= a; c -= b; c ^= (b>>13); a -= b; a -= c; a ^= (c>>12); b -= c; b -= a; b ^= (a<<16); c -= a; c -= b; c ^= (b>>5); a -= b; a -= c; a ^= (c>>3); b -= c; b -= a; b ^= (a<<10); c -= a; c -= b; c ^= (b>>15); };

 return c;
}
//list.h
//namespace.h
static inline int net_eq(const struct net *net1, const struct net *net2)
{
 return net1 == net2;
}
//netdevice.h
struct pcpu_sw_netstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};





//# 38 "include/linux/if_vlan.h"

#if 0
static inline  void vlan_set_encap_proto(struct sk_buff *skb, struct vlan_hdr *vhdr)
{
 __be16 proto;
 unsigned char *rawp;

 proto = vhdr->h_vlan_encapsulated_proto;
 if ((( __u16)(__be16)(proto)) >= 1536) {
  skb->protocol = proto;
  return;
 }

 rawp = skb->data;
 if (*(unsigned short *) rawp == 0xFFFF)
  skb->protocol = (( __be16)(__u16)(0x0001));
 else
  skb->protocol = (( __be16)(__u16)(0x0004));
}
static inline  struct sk_buff *__vlan_hwaccel_put_tag_internal(struct sk_buff *skb,
           u16 vlan_tci)
{
 skb->vlan_tci = 0x1000 | vlan_tci;
 return skb;
}

static  struct sk_buff *__vlan_hwaccel_put_tag(struct sk_buff *skb,
           __be16 vlan_proto,
           u16 vlan_tci)
{
 return __vlan_hwaccel_put_tag_internal(skb, vlan_tci);
}

#endif



//# 51 "include/linux/if_vlan.h"
//# 1615 "include/linux/skbuff.h"

//#define vlan_tx_tag_present(__skb)	((__skb)->vlan_tci & VLAN_TAG_PRESENT)
//#define vlan_tx_tag_get(__skb)		((__skb)->vlan_tci & ~VLAN_TAG_PRESENT)
//#define vlan_tx_tag_get_id(__skb)	((__skb)->vlan_tci & VLAN_VID_MASK)

#define __vlan_put_tag(skb, proto, tag)  rpl__vlan_put_tag(skb, tag)
//# 25 "/home/binhhu/ovs/openvswitch-2.3.1/datapath/linux/compat/include/linux/if_vlan.h"
static inline  struct sk_buff *rpl__vlan_put_tag(struct sk_buff *skb, u16 vlan_tci)
{
 struct vlan_ethhdr *veth = NULL;

 if (skb_headroom(skb) < VLAN_HLEN) {
  kfree_skb(skb);
  return ((void *)0);
 }
 
 veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

 memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
// skb->mac_header -= 4;

// veth->h_vlan_proto = (( __be16)(__u16)htons(ETH_P_8021Q));

 veth->h_vlan_proto = htons(ETH_P_8021Q);

 veth->h_vlan_TCI = htons(vlan_tci);

// skb->protocol = (( __be16)(__u16)htons(ETH_P_8021Q));

 skb->protocol = htons(ETH_P_8021Q);

 return skb;
}

//# 15 "include/net/dsfield.h"
#if 0
static inline  void ipv6_change_dsfield(struct ipv6hdr *ipv6h,__u8 mask,
    __u8 value)
{
        __u16 tmp;

 tmp = (( __u16)(__be16)(*(__be16 *) ipv6h));
 tmp = (tmp & ((mask << 4) | 0xf00f)) | (value << 4);
 *(__be16 *) ipv6h = (( __be16)(__u16)(tmp));
}
enum {
	IP6_FH_F_FRAG           = (1 << 0),
	IP6_FH_F_AUTH           = (1 << 1),
	IP6_FH_F_SKIP_RH        = (1 << 2),
};
#endif

#define OVS_DEBUG( fmt, args...) printf(fmt, ##args);

static void ovs_set_tci(struct sk_buff *skb)
{

	struct ethhdr *eth = (struct ethhdr *)skb->data;
	
	if (eth->h_proto == (__be16)htons(ETH_P_8021Q)){ 
		struct vlan_hdr *vlanh = (struct vlan_hdr *)(skb->data + sizeof(struct ethhdr));
		skb->vlan_tci = (vlanh->h_vlan_TCI);		
	}
   return;
}

#include "ovs_dp_intf.h"


#endif /* OVS_DP_COMMON_H*/
