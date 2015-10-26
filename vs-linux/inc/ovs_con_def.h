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

#ifndef _OVS_CON_DEF_H
#define _OVS_CON_DEF_H


typedef __signed__ char __s8;
typedef __signed__ short __s16;
typedef __signed__ int __s32;
typedef __signed__ long long __s64;

typedef signed char s8;
typedef unsigned char u8;

typedef signed short s16;
typedef unsigned short u16;

typedef signed int s32;
typedef unsigned int u32;

typedef signed long long s64;
typedef unsigned long long u64;

typedef unsigned long long __u64;

typedef __s8 int8_t;
typedef __s16 int16_t;
typedef __s32 int32_t;

typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;

typedef __u64 __le64;
typedef __u64 __be64;

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
typedef unsigned char unchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

/*
   following def is export from ovs
*/

#define OVS_DP_F_VPORT_PIDS 1
#define OVS_PACKET_FAMILY "ovs_packet"
#define OVS_PACKET_VERSION 0x1
#define OVS_PACKET_ATTR_MAX (__OVS_PACKET_ATTR_MAX - 1)
#define OVS_DP_ATTR_MAX __OVS_DP_ATTR_MAX
#define OVS_FLOW_ATTR_MAX __OVS_FLOW_ATTR_MAX

#define OVS_FLOW_FAMILY "ovs_flow"
#define OVS_FLOW_VERSION 0x1

#define OVS_DP_VER_FEATURES 2
#define OVS_DATAPATH_FAMILY  "ovs_datapath"
#define OVS_DATAPATH_VERSION 2
#define OVS_VPORT_ATTR_MAX __OVS_VPORT_ATTR_MAX
#define OVS_VPORT_FAMILY "ovs_vport"
#define OVS_VPORT_VERSION 0x1

struct ovs_flow_stats {
 __u64 n_packets;
 __u64 n_bytes;
};

struct ovs_vport_stats {
 __u64 rx_packets;
 __u64 tx_packets;
 __u64 rx_bytes;
 __u64 tx_bytes;
 __u64 rx_errors;
 __u64 tx_errors;
 __u64 rx_dropped;
 __u64 tx_dropped;
};

enum ovs_vport_type {
 OVS_VPORT_TYPE_UNSPEC,
 OVS_VPORT_TYPE_NETDEV,
 OVS_VPORT_TYPE_INTERNAL,
 OVS_VPORT_TYPE_GRE,
 OVS_VPORT_TYPE_VXLAN,
 OVS_VPORT_TYPE_GRE64 = 104,
 OVS_VPORT_TYPE_LISP = 105,
 __OVS_VPORT_TYPE_MAX
};

#define OVSP_LOCAL ((__u32)0)

enum ovs_frag_type {
 OVS_FRAG_TYPE_NONE,
 OVS_FRAG_TYPE_FIRST,
 OVS_FRAG_TYPE_LATER,
 __OVS_FRAG_TYPE_MAX
};


enum ovs_key_attr {
 OVS_KEY_ATTR_UNSPEC,
 OVS_KEY_ATTR_ENCAP,
 OVS_KEY_ATTR_PRIORITY,
 OVS_KEY_ATTR_IN_PORT,
 OVS_KEY_ATTR_ETHERNET,
 OVS_KEY_ATTR_VLAN,
 OVS_KEY_ATTR_ETHERTYPE,
 OVS_KEY_ATTR_IPV4,
 OVS_KEY_ATTR_IPV6,
 OVS_KEY_ATTR_TCP,
 OVS_KEY_ATTR_UDP,
 OVS_KEY_ATTR_ICMP,
 OVS_KEY_ATTR_ICMPV6,
 OVS_KEY_ATTR_ARP,
 OVS_KEY_ATTR_ND,
 OVS_KEY_ATTR_SKB_MARK,
 OVS_KEY_ATTR_TUNNEL,
 OVS_KEY_ATTR_SCTP,
 OVS_KEY_ATTR_TCP_FLAGS,
 OVS_KEY_ATTR_DP_HASH,
 OVS_KEY_ATTR_RECIRC_ID,
 OVS_KEY_ATTR_IPV4_TUNNEL,
 OVS_KEY_ATTR_MPLS = 62,
 OVS_KEY_ATTR_MAX
};

struct ovs_header {
 int dp_ifindex;
};

enum ovs_packet_attr {
 OVS_PACKET_ATTR_UNSPEC,
 OVS_PACKET_ATTR_PACKET,
 OVS_PACKET_ATTR_KEY,
 OVS_PACKET_ATTR_ACTIONS,
 OVS_PACKET_ATTR_USERDATA,
 __OVS_PACKET_ATTR_MAX
};

enum ovs_flow_cmd {
 OVS_FLOW_CMD_UNSPEC,
 OVS_FLOW_CMD_NEW,
 OVS_FLOW_CMD_DEL,
 OVS_FLOW_CMD_GET,
 OVS_FLOW_CMD_SET
};
enum ovs_vport_cmd {
 OVS_VPORT_CMD_UNSPEC,
 OVS_VPORT_CMD_NEW,
 OVS_VPORT_CMD_DEL,
 OVS_VPORT_CMD_GET,
 OVS_VPORT_CMD_SET
};

enum ovs_datapath_attr {
 OVS_DP_ATTR_UNSPEC,
 OVS_DP_ATTR_NAME,
 OVS_DP_ATTR_UPCALL_PID,
 OVS_DP_ATTR_STATS,
 OVS_DP_ATTR_MEGAFLOW_STATS,
 OVS_DP_ATTR_USER_FEATURES,
 __OVS_DP_ATTR_MAX
};

enum ovs_datapath_cmd {
 OVS_DP_CMD_UNSPEC,
 OVS_DP_CMD_NEW,
 OVS_DP_CMD_DEL,
 OVS_DP_CMD_GET,
 OVS_DP_CMD_SET
};
enum ovs_vport_attr {
 OVS_VPORT_ATTR_UNSPEC,
 OVS_VPORT_ATTR_PORT_NO,
 OVS_VPORT_ATTR_TYPE,
 OVS_VPORT_ATTR_NAME,
 OVS_VPORT_ATTR_OPTIONS,
 OVS_VPORT_ATTR_UPCALL_PID,

 OVS_VPORT_ATTR_STATS,
 __OVS_VPORT_ATTR_MAX
};

enum ovs_packet_cmd {
 OVS_PACKET_CMD_UNSPEC,
 OVS_PACKET_CMD_MISS,
 OVS_PACKET_CMD_ACTION,
 OVS_PACKET_CMD_EXECUTE
};
struct ovs_dp_megaflow_stats {
 __u64 n_mask_hit;
 __u32 n_masks;
 __u32 pad0;
 __u64 pad1;
 __u64 pad2;
};
struct ovs_dp_stats {
 __u64 n_hit;
 __u64 n_missed;
 __u64 n_lost;
 __u64 n_flows;
};

enum ovs_flow_attr {
 OVS_FLOW_ATTR_UNSPEC,
 OVS_FLOW_ATTR_KEY,
 OVS_FLOW_ATTR_ACTIONS,
 OVS_FLOW_ATTR_STATS,
 OVS_FLOW_ATTR_TCP_FLAGS,
 OVS_FLOW_ATTR_USED,
 OVS_FLOW_ATTR_CLEAR,
 OVS_FLOW_ATTR_MASK,
 __OVS_FLOW_ATTR_MAX
};

enum ovs_action_attr {
 OVS_ACTION_ATTR_UNSPEC,
 OVS_ACTION_ATTR_OUTPUT,
 OVS_ACTION_ATTR_USERSPACE,
 OVS_ACTION_ATTR_SET,
 OVS_ACTION_ATTR_PUSH_VLAN,
 OVS_ACTION_ATTR_POP_VLAN,
 OVS_ACTION_ATTR_SAMPLE,
 OVS_ACTION_ATTR_RECIRC,
 OVS_ACTION_ATTR_HASH,
 OVS_ACTION_ATTR_PUSH_MPLS,
 OVS_ACTION_ATTR_POP_MPLS,
 __OVS_ACTION_ATTR_MAX
};

enum ovs_sample_attr {
 OVS_SAMPLE_ATTR_UNSPEC,
 OVS_SAMPLE_ATTR_PROBABILITY,
 OVS_SAMPLE_ATTR_ACTIONS,
 __OVS_SAMPLE_ATTR_MAX,
};

enum ovs_userspace_attr {
 OVS_USERSPACE_ATTR_UNSPEC,
 OVS_USERSPACE_ATTR_PID,
 OVS_USERSPACE_ATTR_USERDATA,
 __OVS_USERSPACE_ATTR_MAX
};

struct ovs_key_ipv4 {
 __be32 ipv4_src;
 __be32 ipv4_dst;
 __u8 ipv4_proto;
 __u8 ipv4_tos;
 __u8 ipv4_ttl;
 __u8 ipv4_frag;
};

struct ovs_key_ipv6 {
 __be32 ipv6_src[4];
 __be32 ipv6_dst[4];
 __be32 ipv6_label;
 __u8 ipv6_proto;
 __u8 ipv6_tclass;
 __u8 ipv6_hlimit;
 __u8 ipv6_frag;
};

struct ovs_key_tcp {
 __be16 tcp_src;
 __be16 tcp_dst;
};
struct ovs_key_udp {
 __be16 udp_src;
 __be16 udp_dst;
};
struct ovs_key_sctp {
 __be16 sctp_src;
 __be16 sctp_dst;
};

struct ovs_action_push_vlan {
 __be16 vlan_tpid;
 __be16 vlan_tci;
};
struct ovs_key_ethernet {
 __u8 eth_src[6];
 __u8 eth_dst[6];
};

struct ovs_action_hash {
	uint32_t  hash_alg;	/* One of ovs_hash_alg. */
	uint32_t  hash_basis;
};

/*
   following def is export linux netinet
*/

#define VLAN_ETH_HLEN  18
#define VLAN_HLEN 4

#define IPV6_FLOWINFO_FLOWLABEL 0x000fffff
#define LLC_SAP_SNAP 0xAA

#define ARPHRD_ETHER 1
#define ETH_HLEN 14
#define ETH_ALEN 6

#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT	VLAN_CFI_MASK

#define NEXTHDR_NONE 59
#define NEXTHDR_ICMP 58
#define NEXTHDR_UDP 17
#define NEXTHDR_TCP 6
#define NEXTHDR_SCTP 132

#define ETH_P_ARP 0x0806
#define ETH_P_RARP 0x8035
#define ETH_P_IPV6 0x86DD
#define ETH_P_802_2     0x4
#define ETH_P_802_3_MIN 0x0600

#define ETH_P_8021Q 0x8100
#define ETH_P_IP 0x0800
#define ETH_P_TEB	0x6558		/* Trans Ether Bridging		*/

#define IPPROTO_AH 51
#define IPPROTO_GRE 47
#define IPPROTO_ICMP 1
#define IPPROTO_IPIP 4
#define IP_OFFSET 2
#define IP_MF 0x2000
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_SCTP 132



#define GRE_CSUM        0x8000
#define GRE_ROUTING     0x4000
#define GRE_KEY         0x2000
#define GRE_SEQ         0x1000
#define GRE_STRICT      0x0800
#define GRE_REC         0x0700
#define GRE_FLAGS       0x00F8
#define GRE_VERSION     0x0007

typedef __u16 __sum16;
typedef __u32 __wsum;

struct iphdr {
 __u8 version:4,
    ihl:4;
 __u8 tos;
 __be16 tot_len;
 __be16 id;
 __be16 frag_off;
 __u8 ttl;
 __u8 protocol;
 __sum16 check;
 __be32 saddr;
 __be32 daddr;

};

struct in6_addr {
 union {
  __u8 u6_addr8[16];
  __be16 u6_addr16[8];
  __be32 u6_addr32[4];
 } in6_u;
};

struct ethhdr {
 unsigned char h_dest[6];
 unsigned char h_source[6];
 __be16 h_proto;
} /*__attribute__((packed))*/;


struct ipv6hdr;

static inline  __u8 ipv6_get_dsfield(const struct ipv6hdr *ipv6h)
{
 return (( __u16)(__be16)(*(const __be16 *)ipv6h)) >> 4;
}

struct ipv6hdr {
 __u8 version:4,
    priority:4;
 __u8 flow_lbl[3];
 __be16 payload_len;
 __u8 nexthdr;
 __u8 hop_limit;

 struct in6_addr saddr;
 struct in6_addr daddr;
};

struct tcphdr {
 __be16 source;
 __be16 dest;
 __be32 seq;
 __be32 ack_seq;
//# 41 "include/linux/tcp.h"
 __u16 doff:4,
  res1:4,
  cwr:1,
  ece:1,
  urg:1,
  ack:1,
  psh:1,
  rst:1,
  syn:1,
  fin:1;
 __be16 window;
 __sum16 check;
 __be16 urg_ptr;
};

struct udphdr {
 __be16 source;
 __be16 dest;
 __be16 len;
 __sum16 check;
};

typedef struct sctphdr {
 __be16 source;
 __be16 dest;
 __be32 vtag;
 __le32 checksum;
} __attribute__((packed)) sctp_sctphdr_t;

struct icmphdr {
  __u8 type;
  __u8 code;
  __sum16 checksum;
  union {
 struct {
  __be16 id;
  __be16 sequence;
 } echo;
 __be32 gateway;
 struct {
  __be16 __unused;
  __be16 mtu;
 } frag;
  } un;
};

struct icmp6hdr {
 __u8 icmp6_type;
 __u8 icmp6_code;
 __sum16 icmp6_cksum;
 union {
  __be32 un_data32[1];
  __be16 un_data16[2];
  __u8 un_data8[4];

  struct icmpv6_echo {
   __be16 identifier;
   __be16 sequence;
  } u_echo;

 struct icmpv6_nd_advt {
   __u32 router:1,
     solicited:1,
     override:1,
     reserved:29;
   } u_nd_advt;

 struct icmpv6_nd_ra {
   __u8 hop_limit;
//# 51 "include/linux/icmpv6.h"
   __u8 managed:1,
     other:1,
     home_agent:1,
     router_pref:2,
     reserved:3;
     __be16 rt_lifetime;
   } u_nd_ra;
 } icmp6_dataun;
//# 79 "include/linux/icmpv6.h"
};


struct vlan_hdr {
 __be16 h_vlan_TCI;
 __be16 h_vlan_encapsulated_proto;
};

struct vlan_ethhdr {
 unsigned char h_dest[6];
 unsigned char h_source[6];
 __be16 h_vlan_proto;
 __be16 h_vlan_TCI;
 __be16 h_vlan_encapsulated_proto;
};

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}

static inline  struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
 return (struct tcphdr *)skb_transport_header(skb);
}

static inline  struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
 return (struct ipv6hdr *)skb_network_header(skb);
}

static inline  struct udphdr *udp_hdr(const struct sk_buff *skb)
{
 return (struct udphdr *)skb_transport_header(skb);
}

static inline struct sctphdr *sctp_hdr(const struct sk_buff *skb)
{
 return (struct sctphdr *)skb_transport_header(skb);
}
static inline  struct icmphdr *icmp_hdr(const struct sk_buff *skb)
{
 return (struct icmphdr *)skb_transport_header(skb);
}

static inline  struct icmp6hdr *icmp6_hdr(const struct sk_buff *skb)
{
 return (struct icmp6hdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline  void ether_addr_copy(u8 *dst, const u8 *src)
{

 u16 *a = (u16 *)dst;
 const u16 *b = (const u16 *)src;

 a[0] = b[0];
 a[1] = b[1];
 a[2] = b[2];

}

static inline int is_zero_ether_addr(const u8 *addr)
{
 return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}



#endif

