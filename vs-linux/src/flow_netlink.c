/*
 * Copyright (c) 2007-2013 Nicira, Inc.
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"
#include "ovs_debug.h"

#include "flow.h"
#include "datapath.h"
#include "flow_netlink.h"

void update_range__(struct sw_flow_match *match,
			   size_t offset, size_t size, bool is_mask)
{
	struct sw_flow_key_range *range = NULL;
	size_t start = rounddown(offset, sizeof(long));
	size_t end = rounddown(offset + size, sizeof(long))+sizeof(long);

	if (!is_mask)
		range = &match->range;
	else if (match->mask)
		range = &match->mask->range;

	if (!range)
		return;

	if (range->start == range->end) {
		range->start = start;
		range->end = end;
		return;
	}

	if (range->start > start)
		range->start = start;

	if (range->end < end)
		range->end = end;
}

#define SW_FLOW_KEY_PUT(match, field, value, is_mask) \
	do { \
		update_range__(match, offsetof(struct sw_flow_key, field),  \
				     sizeof((match)->key->field), is_mask); \
		if (is_mask) {						    \
			if ((match)->mask)				    \
				(match)->mask->key.field = value;	    \
		} else {                                                    \
			(match)->key->field = value;		            \
		}                                                           \
	} while (0)

#define SW_FLOW_KEY_MEMCPY(match, field, value_p, len, is_mask) \
	do { \
		update_range__(match, offsetof(struct sw_flow_key, field),  \
				len, is_mask);                              \
		if (is_mask) {						    \
			if ((match)->mask)				    \
				memcpy(&(match)->mask->key.field, value_p, len);\
		} else {                                                    \
			memcpy(&(match)->key->field, value_p, len);         \
		}                                                           \
	} while (0)

static u16 range_n_bytes(const struct sw_flow_key_range *range)
{
	return range->end - range->start;
}

static bool match_validate(const struct sw_flow_match *match,
			   u64 key_attrs, u64 mask_attrs)
{
	u64 key_expected = 1ULL << OVS_KEY_ATTR_ETHERNET;
	u64 mask_allowed = key_attrs;  /* At most allow all key attributes */

	/* The following mask attributes allowed only if they
	 * pass the validation tests. */
	mask_allowed &= ~((1ULL << OVS_KEY_ATTR_IPV4)
			| (1ULL << OVS_KEY_ATTR_IPV6)
			| (1ULL << OVS_KEY_ATTR_TCP)
			| (1ULL << OVS_KEY_ATTR_TCP_FLAGS)
			| (1ULL << OVS_KEY_ATTR_UDP)
			| (1ULL << OVS_KEY_ATTR_SCTP)
			| (1ULL << OVS_KEY_ATTR_ICMP)
			| (1ULL << OVS_KEY_ATTR_ICMPV6)
			| (1ULL << OVS_KEY_ATTR_ARP)
			| (1ULL << OVS_KEY_ATTR_ND));

	/* Always allowed mask fields. */
	mask_allowed |= ((1ULL << OVS_KEY_ATTR_TUNNEL)
		       | (1ULL << OVS_KEY_ATTR_IN_PORT)
		       | (1ULL << OVS_KEY_ATTR_ETHERTYPE));

	/* Check key attributes. */
	if (match->key->eth.type == htons(ETH_P_ARP)
			|| match->key->eth.type == htons(ETH_P_RARP)) {
		key_expected |= 1ULL << OVS_KEY_ATTR_ARP;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1ULL << OVS_KEY_ATTR_ARP;
	}

	if (match->key->eth.type == htons(ETH_P_IP)) {
		key_expected |= 1ULL << OVS_KEY_ATTR_IPV4;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1ULL << OVS_KEY_ATTR_IPV4;

		if (match->key->ip.frag != OVS_FRAG_TYPE_LATER) {
			if (match->key->ip.proto == IPPROTO_UDP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_UDP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_UDP;
			}

			if (match->key->ip.proto == IPPROTO_SCTP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_SCTP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_SCTP;
			}

			if (match->key->ip.proto == IPPROTO_TCP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP;
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				if (match->mask && (match->mask->key.ip.proto == 0xff)) {
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP;
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				}
			}

			if (match->key->ip.proto == IPPROTO_ICMP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_ICMP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_ICMP;
			}
		}
	}

	if (match->key->eth.type == htons(ETH_P_IPV6)) {
		key_expected |= 1ULL << OVS_KEY_ATTR_IPV6;
		if (match->mask && (match->mask->key.eth.type == htons(0xffff)))
			mask_allowed |= 1ULL << OVS_KEY_ATTR_IPV6;

		if (match->key->ip.frag != OVS_FRAG_TYPE_LATER) {
			if (match->key->ip.proto == IPPROTO_UDP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_UDP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_UDP;
			}

			if (match->key->ip.proto == IPPROTO_SCTP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_SCTP;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_SCTP;
			}

			if (match->key->ip.proto == IPPROTO_TCP) {
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP;
				key_expected |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				if (match->mask && (match->mask->key.ip.proto == 0xff)) {
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP;
					mask_allowed |= 1ULL << OVS_KEY_ATTR_TCP_FLAGS;
				}
			}
#if 0
			if (match->key->ip.proto == IPPROTO_ICMPV6) {
				key_expected |= 1ULL << OVS_KEY_ATTR_ICMPV6;
				if (match->mask && (match->mask->key.ip.proto == 0xff))
					mask_allowed |= 1ULL << OVS_KEY_ATTR_ICMPV6;

				if (match->key->tp.src ==
						htons(NDISC_NEIGHBOUR_SOLICITATION) ||
				    match->key->tp.src == htons(NDISC_NEIGHBOUR_ADVERTISEMENT)) {
					key_expected |= 1ULL << OVS_KEY_ATTR_ND;
					if (match->mask && (match->mask->key.tp.src == htons(0xff)))
						mask_allowed |= 1ULL << OVS_KEY_ATTR_ND;
				}
			}
#endif         
		}
	}

	if ((key_attrs & key_expected) != key_expected) {
		/* Key attributes check failed. */
		OVS_NLERR("Missing expected key attributes (key_attrs=%llx, expected=%llx).\n",
				(unsigned long long)key_attrs, (unsigned long long)key_expected);
		return false;
	}

	if ((mask_attrs & mask_allowed) != mask_attrs) {
		/* Mask attributes check failed. */
		OVS_NLERR("Contain more than allowed mask fields (mask_attrs=%llx, mask_allowed=%llx).\n",
				(unsigned long long)mask_attrs, (unsigned long long)mask_allowed);
		return false;
	}

	return true;
}

/* The size of the argument for each %OVS_KEY_ATTR_* Netlink attribute.  */
static const int ovs_key_lens[OVS_KEY_ATTR_MAX + 1] = {
	[OVS_KEY_ATTR_ENCAP] = -1,
	[OVS_KEY_ATTR_PRIORITY] = sizeof(u32),
	[OVS_KEY_ATTR_IN_PORT] = sizeof(u32),
	[OVS_KEY_ATTR_SKB_MARK] = sizeof(u32),
	[OVS_KEY_ATTR_ETHERNET] = sizeof(struct ovs_key_ethernet),
	[OVS_KEY_ATTR_VLAN] = sizeof(__be16),
	[OVS_KEY_ATTR_ETHERTYPE] = sizeof(__be16),
	[OVS_KEY_ATTR_IPV4] = sizeof(struct ovs_key_ipv4),
	[OVS_KEY_ATTR_IPV6] = sizeof(struct ovs_key_ipv6),
	[OVS_KEY_ATTR_TCP] = sizeof(struct ovs_key_tcp),
	[OVS_KEY_ATTR_TCP_FLAGS] = sizeof(__be16),
	[OVS_KEY_ATTR_UDP] = sizeof(struct ovs_key_udp),
	[OVS_KEY_ATTR_SCTP] = sizeof(struct ovs_key_sctp),
/*	[OVS_KEY_ATTR_ICMP] = sizeof(struct ovs_key_icmp),
	[OVS_KEY_ATTR_ICMPV6] = sizeof(struct ovs_key_icmpv6),
	[OVS_KEY_ATTR_ARP] = sizeof(struct ovs_key_arp),
	[OVS_KEY_ATTR_ND] = sizeof(struct ovs_key_nd), */
	[OVS_KEY_ATTR_DP_HASH] = sizeof(u32),
	[OVS_KEY_ATTR_RECIRC_ID] = sizeof(u32),
	[OVS_KEY_ATTR_TUNNEL] = -1,
};

static bool is_all_zero(const u8 *fp, size_t size)
{
	int i;

	if (!fp)
		return false;

	for (i = 0; i < (int)size; i++)
		if (fp[i])
			return false;

	return true;
}

static int __parse_flow_nlattrs(const struct nlattr *attr,
				const struct nlattr *a[],
				u64 *attrsp, bool nz)
{
   return 0;
}

static int parse_flow_mask_nlattrs(const struct nlattr *attr,
				   const struct nlattr *a[], u64 *attrsp)
{
	return __parse_flow_nlattrs(attr, a, attrsp, true);
}

static int parse_flow_nlattrs(const struct nlattr *attr,
			      const struct nlattr *a[], u64 *attrsp)
{
	return __parse_flow_nlattrs(attr, a, attrsp, false);
}

static int ipv4_tun_from_nlattr(const struct nlattr *attr,
				struct sw_flow_match *match, bool is_mask)
{  
   return 1;
}

static int ipv4_tun_to_nlattr(struct sk_buff *skb,
			      const struct ovs_key_ipv4_tunnel *tun_key,
			      const struct ovs_key_ipv4_tunnel *output)
{
	struct nlattr *nla;

	nla = nla_nest_start(skb, OVS_KEY_ATTR_TUNNEL);
	if (!nla)
		return -1;
#if 0
	if (output->tun_flags & TUNNEL_KEY &&
	    nla_put_be64(skb, OVS_TUNNEL_KEY_ATTR_ID, output->tun_id))
		return -EMSGSIZE;
	if (output->ipv4_src &&
		nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_SRC, output->ipv4_src))
		return -EMSGSIZE;
	if (output->ipv4_dst &&
		nla_put_be32(skb, OVS_TUNNEL_KEY_ATTR_IPV4_DST, output->ipv4_dst))
		return -EMSGSIZE;
	if (output->ipv4_tos &&
		nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TOS, output->ipv4_tos))
		return -EMSGSIZE;
	if (nla_put_u8(skb, OVS_TUNNEL_KEY_ATTR_TTL, output->ipv4_ttl))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_DONT_FRAGMENT) &&
		nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT))
		return -EMSGSIZE;
	if ((output->tun_flags & TUNNEL_CSUM) &&
		nla_put_flag(skb, OVS_TUNNEL_KEY_ATTR_CSUM))
		return -EMSGSIZE;

	nla_nest_end(skb, nla);
#endif 
	return 0;
}


static int metadata_from_nlattrs(struct sw_flow_match *match,  u64 *attrs,
				 const struct nlattr **a, bool is_mask)
{
#if 0
	if (*attrs & (1ULL << OVS_KEY_ATTR_DP_HASH)) {
		u32 hash_val = nla_get_u32(a[OVS_KEY_ATTR_DP_HASH]);

		SW_FLOW_KEY_PUT(match, ovs_flow_hash, hash_val, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_DP_HASH);
	}

	if (*attrs & (1ULL << OVS_KEY_ATTR_RECIRC_ID)) {
		u32 recirc_id = nla_get_u32(a[OVS_KEY_ATTR_RECIRC_ID]);

  		SW_FLOW_KEY_PUT(match, recirc_id, recirc_id, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_RECIRC_ID);
	}

	if (*attrs & (1ULL << OVS_KEY_ATTR_PRIORITY)) {
		SW_FLOW_KEY_PUT(match, phy.priority,
			  nla_get_u32(a[OVS_KEY_ATTR_PRIORITY]), is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_PRIORITY);
	}

	if (*attrs & (1ULL << OVS_KEY_ATTR_IN_PORT)) {
		u32 in_port = nla_get_u32(a[OVS_KEY_ATTR_IN_PORT]);

		if (is_mask)
			in_port = 0xffffffff; /* Always exact match in_port. */
		else if (in_port >= DP_MAX_PORTS)
			return -EINVAL;

		SW_FLOW_KEY_PUT(match, phy.in_port, in_port, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_IN_PORT);
	} else if (!is_mask) {
		SW_FLOW_KEY_PUT(match, phy.in_port, DP_MAX_PORTS, is_mask);
	}

	if (*attrs & (1ULL << OVS_KEY_ATTR_SKB_MARK)) {
		uint32_t mark = nla_get_u32(a[OVS_KEY_ATTR_SKB_MARK]);

		SW_FLOW_KEY_PUT(match, phy.skb_mark, mark, is_mask);
		*attrs &= ~(1ULL << OVS_KEY_ATTR_SKB_MARK);
	}
	if (*attrs & (1ULL << OVS_KEY_ATTR_TUNNEL)) {
		if (ipv4_tun_from_nlattr(a[OVS_KEY_ATTR_TUNNEL], match,
					 is_mask))
			return -EINVAL;
		*attrs &= ~(1ULL << OVS_KEY_ATTR_TUNNEL);
	}
#endif
	return 0;
}

static int ovs_key_from_nlattrs(struct sw_flow_match *match, u64 attrs,
				const struct nlattr **a, bool is_mask)
{
   return 0;
}

void sw_flow_mask_set(struct sw_flow_mask *mask,
			     struct sw_flow_key_range *range, u8 val)
{
	u8 *m = (u8 *)&mask->key + range->start;

	mask->range = *range;
	memset(m, val, range_n_bytes(range));
}

/**
 * ovs_nla_get_match - parses Netlink attributes into a flow key and
 * mask. In case the 'mask' is NULL, the flow is treated as exact match
 * flow. Otherwise, it is treated as a wildcarded flow, except the mask
 * does not include any don't care bit.
 * @match: receives the extracted flow match information.
 * @key: Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink attribute
 * sequence. The fields should of the packet that triggered the creation
 * of this flow.
 * @mask: Optional. Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink
 * attribute specifies the mask field of the wildcarded flow.
 */
int ovs_nla_get_match(struct sw_flow_match *match,
		      const struct nlattr *key,
		      const struct nlattr *mask)
{
   return 1;
}

/**
 * ovs_nla_get_flow_metadata - parses Netlink attributes into a flow key.
 * @key: Receives extracted in_port, priority, tun_key and skb_mark.
 * @attr: Netlink attribute holding nested %OVS_KEY_ATTR_* Netlink attribute
 * sequence.
 *
 * This parses a series of Netlink attributes that form a flow key, which must
 * take the same form accepted by flow_from_nlattrs(), but only enough of it to
 * get the metadata, that is, the parts of the flow key that cannot be
 * extracted from the packet itself.
 */
int ovs_nla_get_flow_metadata(const struct nlattr *attr,
			      struct sw_flow_key *key)
{
	const struct nlattr *a[OVS_KEY_ATTR_MAX + 1];
	struct sw_flow_match match;
	u64 attrs = 0;
	int err;

	err = parse_flow_nlattrs(attr, a, &attrs);
	if (err)
		return -EINVAL;

	memset(&match, 0, sizeof(match));
	match.key = key;

	key->phy.in_port = DP_MAX_PORTS;
	return metadata_from_nlattrs(&match, &attrs, a, false);
}

int ovs_nla_put_flow(const struct sw_flow_key *swkey,
		     const struct sw_flow_key *output, struct sk_buff *skb)
{  
   return 0;
}

#define MAX_ACTIONS_BUFSIZE	(32 * 1024)

struct sw_flow_actions *ovs_nla_alloc_flow_actions(int size)
{
	struct sw_flow_actions *sfa;

	if (size > MAX_ACTIONS_BUFSIZE) {
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: the size(%d) is larger than max action size(%u)\r\n",
	            __FUNCTION__, size, MAX_ACTIONS_BUFSIZE);
		return ERR_PTR(-EINVAL);
	}

	sfa = kmalloc(sizeof(*sfa) + size, ACTION_POOL_C);
	if (!sfa) {
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: alloc memory for flow action failed\r\n", __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

	sfa->actions_len = size;
	return sfa;
}

/* RCU callback used by ovs_nla_free_flow_actions. */
static void rcu_free_acts_callback(struct rcu_head *rcu)
{
//	struct sw_flow_actions *sf_acts = container_of(rcu,
//			struct sw_flow_actions, rcu);
//	kfree(sf_acts);
return;
}

/* Schedules 'sf_acts' to be freed after the next RCU grace period.
 * The caller must hold rcu_read_lock for this to be sensible. */
void ovs_nla_free_flow_actions(struct sw_flow_actions *sf_acts)
{
	//call_rcu(&sf_acts->rcu, rcu_free_acts_callback);
}

static struct nlattr *reserve_sfa_size(struct sw_flow_actions **sfa,
				       int attr_len)
{  
   return NULL;
}

static int add_action(struct sw_flow_actions **sfa, int attrtype, void *data, int len)
{
	struct nlattr *a;

	a = reserve_sfa_size(sfa, nla_attr_size(len));
	if (IS_ERR(a))
		return PTR_ERR(a);

	a->nla_type = attrtype;
	a->nla_len = nla_attr_size(len);
/*
	if (data)
		memcpy(nla_data(a), data, len);
	memset((unsigned char *) a + a->nla_len, 0, nla_padlen(len));
*/
	return 0;
}

static inline int add_nested_action_start(struct sw_flow_actions **sfa,
					  int attrtype)
{
	int used = (*sfa)->actions_len;
	int err;

	err = add_action(sfa, attrtype, NULL, 0);
	if (err)
		return err;

	return used;
}

static inline void add_nested_action_end(struct sw_flow_actions *sfa,
					 int st_offset)
{
	struct nlattr *a = (struct nlattr *) ((unsigned char *)sfa->actions +
							       st_offset);

	a->nla_len = sfa->actions_len - st_offset;
}

static int validate_and_copy_sample(const struct nlattr *attr,
				    const struct sw_flow_key *key, int depth,
				    struct sw_flow_actions **sfa)
{
#if 0
	const struct nlattr *attrs[OVS_SAMPLE_ATTR_MAX + 1];
	const struct nlattr *probability, *actions;
	const struct nlattr *a;
	int rem, start, err, st_acts;

	memset(attrs, 0, sizeof(attrs));
	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		if (!type || type > OVS_SAMPLE_ATTR_MAX || attrs[type])
			return -EINVAL;
		attrs[type] = a;
	}
	if (rem)
		return -EINVAL;

	probability = attrs[OVS_SAMPLE_ATTR_PROBABILITY];
	if (!probability || nla_len(probability) != sizeof(u32))
		return -EINVAL;

	actions = attrs[OVS_SAMPLE_ATTR_ACTIONS];
	if (!actions || (nla_len(actions) && nla_len(actions) < NLA_HDRLEN))
		return -EINVAL;

	/* validation done, copy sample action. */
	start = add_nested_action_start(sfa, OVS_ACTION_ATTR_SAMPLE);
	if (start < 0)
		return start;
	err = add_action(sfa, OVS_SAMPLE_ATTR_PROBABILITY,
			 nla_data(probability), sizeof(u32));
	if (err)
		return err;
	st_acts = add_nested_action_start(sfa, OVS_SAMPLE_ATTR_ACTIONS);
	if (st_acts < 0)
		return st_acts;

	err = ovs_nla_copy_actions(actions, key, depth + 1, sfa);
	if (err)
		return err;

	add_nested_action_end(*sfa, st_acts);
	add_nested_action_end(*sfa, start);
#endif
	return 0;
}

static int validate_tp_port(const struct sw_flow_key *flow_key)
{
	if ((flow_key->eth.type == htons(ETH_P_IP) ||
	     flow_key->eth.type == htons(ETH_P_IPV6)) &&
	    (flow_key->tp.src || flow_key->tp.dst))
		return 0;

	return -EINVAL;
}

void ovs_match_init(struct sw_flow_match *match,
		    struct sw_flow_key *key,
		    struct sw_flow_mask *mask)
{
	memset(match, 0, sizeof(*match));
	match->key = key;
	match->mask = mask;

	memset(key, 0, sizeof(*key));

	if (mask) {
		memset(&mask->key, 0, sizeof(mask->key));
		mask->range.start = mask->range.end = 0;
	}
}

static int validate_and_copy_set_tun(const struct nlattr *attr,
				     struct sw_flow_actions **sfa)
{
	struct sw_flow_match match;
	struct sw_flow_key key;
	int err, start;

	ovs_match_init(&match, &key, NULL);
	err = ipv4_tun_from_nlattr(nla_data(attr), &match, false);
	if (err)
		return err;

	start = add_nested_action_start(sfa, OVS_ACTION_ATTR_SET);
	if (start < 0)
		return start;

	err = add_action(sfa, OVS_KEY_ATTR_IPV4_TUNNEL, &match.key->tun_key,
			sizeof(match.key->tun_key));
	add_nested_action_end(*sfa, start);

	return err;
}

static int validate_set(const struct nlattr *a,
			const struct sw_flow_key *flow_key,
			struct sw_flow_actions **sfa,
			bool *set_tun)
{
	const struct nlattr *ovs_key = nla_data(a);
	int key_type = nla_type(ovs_key);

	/* There can be only one key in a action */
	if (nla_total_size(nla_len(ovs_key)) != nla_len(a))
		return -EINVAL;

	if (key_type > OVS_KEY_ATTR_MAX ||
	    (ovs_key_lens[key_type] != nla_len(ovs_key) &&
	     ovs_key_lens[key_type] != -1))
		return -EINVAL;

	switch (key_type) {
	const struct ovs_key_ipv4 *ipv4_key;
	const struct ovs_key_ipv6 *ipv6_key;
	int err;

	case OVS_KEY_ATTR_PRIORITY:
	case OVS_KEY_ATTR_SKB_MARK:
	case OVS_KEY_ATTR_ETHERNET:
		break;

	case OVS_KEY_ATTR_TUNNEL:
		*set_tun = true;
		err = validate_and_copy_set_tun(a, sfa);
		if (err)
			return err;
		break;

	case OVS_KEY_ATTR_IPV4:
		if (flow_key->eth.type != htons(ETH_P_IP))
			return -EINVAL;

		if (!flow_key->ip.proto)
			return -EINVAL;

		ipv4_key = nla_data(ovs_key);
		if (ipv4_key->ipv4_proto != flow_key->ip.proto)
			return -EINVAL;

		if (ipv4_key->ipv4_frag != flow_key->ip.frag)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_IPV6:
		if (flow_key->eth.type != htons(ETH_P_IPV6))
			return -EINVAL;

		if (!flow_key->ip.proto)
			return -EINVAL;

		ipv6_key = nla_data(ovs_key);
		if (ipv6_key->ipv6_proto != flow_key->ip.proto)
			return -EINVAL;

		if (ipv6_key->ipv6_frag != flow_key->ip.frag)
			return -EINVAL;

		if (ntohl(ipv6_key->ipv6_label) & 0xFFF00000)
			return -EINVAL;

		break;

	case OVS_KEY_ATTR_TCP:
		if (flow_key->ip.proto != IPPROTO_TCP)
			return -EINVAL;

		return validate_tp_port(flow_key);

	case OVS_KEY_ATTR_UDP:
		if (flow_key->ip.proto != IPPROTO_UDP)
			return -EINVAL;

		return validate_tp_port(flow_key);

	case OVS_KEY_ATTR_SCTP:
		if (flow_key->ip.proto != IPPROTO_SCTP)
			return -EINVAL;

		return validate_tp_port(flow_key);

	default:
		return -EINVAL;
	}

	return 0;
}

static int validate_userspace(const struct nlattr *attr)
{

	return 0;
}

static int copy_action(const struct nlattr *from,
		       struct sw_flow_actions **sfa)
{
	int totlen = NLA_ALIGN(from->nla_len);
	struct nlattr *to;

	to = reserve_sfa_size(sfa, from->nla_len);
	if (IS_ERR(to))
		return PTR_ERR(to);

	memcpy(to, from, totlen);
	return 0;
}

int ovs_nla_copy_actions(const struct nlattr *attr,
			 const struct sw_flow_key *key,
			 int depth,
			 struct sw_flow_actions **sfa)
{

	return 0;
}

static int sample_action_to_attr(const struct nlattr *attr, struct sk_buff *skb)
{

	return 1;
}

static int set_action_to_attr(const struct nlattr *a, struct sk_buff *skb)
{
	const struct nlattr *ovs_key = nla_data(a);
	int key_type = nla_type(ovs_key);
	struct nlattr *start;
	int err;

	switch (key_type) {
	case OVS_KEY_ATTR_IPV4_TUNNEL:
		start = nla_nest_start(skb, OVS_ACTION_ATTR_SET);
		if (!start)
			return -1;

		err = ipv4_tun_to_nlattr(skb, nla_data(ovs_key),
					     nla_data(ovs_key));
		if (err)
			return err;
		nla_nest_end(skb, start);
		break;
	default:
		if (nla_put(skb, OVS_ACTION_ATTR_SET, nla_len(a), ovs_key))
			return -1;
		break;
	}

	return 0;
}

int ovs_nla_put_actions(const struct nlattr *attr, int len, struct sk_buff *skb)
{

	return 0;
}
