
#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"

#include <stdio.h>

#include "datapath.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vlan.h"
#include "ovs_debug.h"



struct flow_keys {
	/* (src,dst) must be grouped, in the same way than in IP header */
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	u16 thoff;
	u8 ip_proto;
};

#define __constant_htons(x) ((__force __be16)(__u16)(x))

static void iph_to_flow_copy_addrs(struct flow_keys *flow, const struct iphdr *iph)
{
	memcpy(&flow->src, &iph->saddr, sizeof(flow->src) + sizeof(flow->dst));
}


static inline int proto_ports_offset(int proto)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		return 0;
	case IPPROTO_AH:	/* SPI */
		return 4;
	default:
		return -EINVAL;
	}
}

static __be32 skb_flow_get_ports(const struct sk_buff *skb, int thoff, u8 ip_proto)
{
	int poff = proto_ports_offset(ip_proto);

	if (poff >= 0) {
		__be32 *ports, _ports;

		ports = skb_header_pointer(skb, thoff + poff,
				sizeof(_ports), &_ports);
		if (ports)
			return *ports;
	}

	return 0;
}

static bool skb_flow_dissect(const struct sk_buff *skb, struct flow_keys *flow)
{

   static int j  = 0;
   
	int nhoff = skb_network_offset(skb);
	u8 ip_proto;
	__be16 proto = skb->protocol;

	memset(flow, 0, sizeof(*flow));

again:
	switch (proto) {
#ifdef _IS_LINUX_
        case 0x0008: {
#else
        case __constant_htons(ETH_P_IP): {
#endif

            const struct iphdr *iph;
            struct iphdr _iph;
//ip:
            iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
            if (!iph)
                return false;

            ip_proto = iph->protocol;

            iph_to_flow_copy_addrs(flow, iph);

            nhoff += iph->ihl * 4;

            break;
        }

#ifdef _IS_LINUX_
            case 0x0081: {
#else
        case __constant_htons(ETH_P_8021Q): {
#endif

            const struct vlan_hdr *vlan;
            struct vlan_hdr _vlan;

            vlan = skb_header_pointer(skb, nhoff, sizeof(_vlan), &_vlan);
            if (!vlan)
                return false;

            proto = vlan->h_vlan_encapsulated_proto;
            nhoff += sizeof(*vlan);
            goto again;
        }

        default:
            return false;
    }


   switch (ip_proto) {
      case IPPROTO_GRE: {
         struct gre_hdr {
            __be16 flags;
            __be16 proto;
         } *hdr, _hdr;
   
         hdr = skb_header_pointer(skb, nhoff, sizeof(_hdr), &_hdr);
         if (!hdr)
            return false;
         /*
          * Only look inside GRE if version zero and no
          * routing
          */
         if (!(hdr->flags & (GRE_VERSION|GRE_ROUTING))) {
            proto = hdr->proto;
            nhoff += 4;
            if (hdr->flags & GRE_CSUM)
               nhoff += 4;
            if (hdr->flags & GRE_KEY)
               nhoff += 4;
            if (hdr->flags & GRE_SEQ)
               nhoff += 4;
            if (proto == htons(ETH_P_TEB)) {
               const struct ethhdr *eth;
               struct ethhdr _eth;
   
               eth = skb_header_pointer(skb, nhoff,
                         sizeof(_eth), &_eth);
               if (!eth)
                  return false;
               proto = eth->h_proto;
               nhoff += sizeof(*eth);
            }
            goto again;
         }
         break;
      }
      case IPPROTO_IPIP:
         goto again;
      default:
         break;
      }


	flow->ip_proto = ip_proto;
	flow->thoff = (u16) nhoff;
	flow->ports = skb_flow_get_ports(skb, nhoff, ip_proto);

    if (j < 1000) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n skb_flow_dissect pro:%d, ports:%d,%d, addr:%x,%x \n",
                ip_proto, flow->port16[0], flow->port16[1], flow->src, flow->dst);
        j++;
    }


	return true;
}


static void
swap(int *a, int *b)
{
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

static u32 hashrnd;
static inline void __flow_hash_secret_init(void)
{
	hashrnd = 1235;
}

static inline __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}


#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
	a += initval;
	b += initval;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}

#define JHASH_INITVAL		0xdeadbeef

inline u32 jhash_1word(u32 a, u32 initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}
static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}


static  u32 __flow_hash_3words(u32 a, u32 b, u32 c)
{
	__flow_hash_secret_init();
	return jhash_3words(a, b, c, hashrnd);
}


u32 __skb_get_hash(struct sk_buff *skb)
{

      struct flow_keys keys;
      u32 hash;

      if (!skb_flow_dissect(skb, &keys))
         return 0;
   
      /* get a consistent hash (same value on both flow directions) */
      if (((__force u32)keys.dst < (__force u32)keys.src) ||
          (((__force u32)keys.dst == (__force u32)keys.src) &&
           ((__force u16)keys.port16[1] < (__force u16)keys.port16[0]))) {
         swap((int*)&(keys.dst), (int*)&(keys.src));
         swap((int*)&(keys.port16[0]), (int*)&(keys.port16[1]));
      }
   
      hash = __flow_hash_3words((__force u32)keys.dst,
                 (__force u32)keys.src,
                 (__force u32)keys.ports);
      if (!hash)
         hash = 1;
   
      return hash;

}	


