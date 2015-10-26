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

#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"
#include "flow.h"
#include "datapath.h"
#include "ovs_debug.h"

#include "vlan.h"
#include "ovs_se_dump.h"


extern u32 jhash_1word(u32 a, u32 initval);
extern uint32_t get_random_4_bytes(void *buf, int nbytes);

//#define TBL_MIN_BUCKETS		1024
#define TBL_MIN_BUCKETS		200
#define MASK_ARRAY_SIZE_MIN	16
#define REHASH_INTERVAL		(10 * 60 * HZ)

#define MC_HASH_SHIFT		8
#define MC_HASH_ENTRIES		(1u << MC_HASH_SHIFT)
#define MC_HASH_SEGS		((sizeof(uint32_t) * 8) / MC_HASH_SHIFT)
/*
static struct kmem_cache *flow_cache;
struct kmem_cache *flow_stats_cache __read_mostly;
*/
static u16 range_n_bytes(const struct sw_flow_key_range *range)
{
	return range->end - range->start;
}

void ovs_flow_mask_key(struct sw_flow_key *dst, const struct sw_flow_key *src,
		       const struct sw_flow_mask *mask)
{
	const long *m = (const long *)((const u8 *)&mask->key +
				mask->range.start);
	const long *s = (const long *)((const u8 *)src +
				mask->range.start);
	long *d = (long *)((u8 *)dst + mask->range.start);
	int i;

	/* The memory outside of the 'mask->range' are not set since
	 * further operations on 'dst' only uses contents within
	 * 'mask->range'.
	 */
	for (i = 0; i < range_n_bytes(&mask->range); i += sizeof(long))
		*d++ = *s++ & *m++;
}

struct sw_flow *ovs_flow_alloc(void)
{
	struct sw_flow *flow = NULL;

	flow = kmalloc(sizeof(struct sw_flow), FLOW_POOL_C);
	if (!flow) {
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: alloc memory for flow failed.\r\n", __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

	flow->sf_acts = NULL;
	flow->mask = NULL;
	flow->stats_last_writer = NUMA_NO_NODE;

	return flow;
}

int ovs_flow_tbl_count(struct flow_table *table)
{
	return table->count;
}
extern struct flex_array *flex_array_alloc(int element_size, unsigned int total,
					gfp_t flags);

extern int flex_array_prealloc(struct flex_array *fa, unsigned int start,
			unsigned int nr_elements, gfp_t flags);

extern void flex_array_free(struct flex_array *fa);
extern void *flex_array_get(struct flex_array *fa, unsigned int element_nr);

extern void fake_flex_array_alloc(int element_size, unsigned int total,
					struct flex_array *ret);


struct flex_array *alloc_buckets(unsigned int n_buckets)
{
	struct flex_array *buckets = NULL;
	int i, err;

	buckets = flex_array_alloc(sizeof(struct hlist_head),
				   n_buckets, GFP_KERNEL);
	if (!buckets)
		return NULL;

	err = flex_array_prealloc(buckets, 0, n_buckets, GFP_KERNEL);
	if (err) {
		flex_array_free(buckets);
		return NULL;
	}

	for (i = 0; i < (int)n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return buckets;
}

void fake_init_buckets(unsigned int n_buckets, struct flex_array *buckets)
{
	int i;

	fake_flex_array_alloc(sizeof(struct hlist_head),
				   n_buckets, buckets);

	for (i = 0; i < (int)n_buckets; i++)
		INIT_HLIST_HEAD((struct hlist_head *)
					flex_array_get(buckets, i));

	return;
}


static void flow_free(struct sw_flow *flow)
{
	//int node;

   kfree((struct sw_flow_actions __force *)flow->sf_acts, ACTION_POOL_C);
	kfree(flow, FLOW_POOL_C);
}

static void rcu_free_flow_callback(struct rcu_head *rcu)
{
	//struct sw_flow *flow = container_of(rcu, struct sw_flow, rcu);

	//flow_free(flow);
}

static void rcu_free_sw_flow_mask_cb(struct rcu_head *rcu)
{
	//struct sw_flow_mask *mask = container_of(rcu, struct sw_flow_mask, rcu);

	//kfree(mask);
}

void ovs_flow_free(struct sw_flow *flow, bool deferred)
{
	if (!flow)
		return;

	//if (deferred)
		//call_rcu(&flow->rcu, rcu_free_flow_callback);
	//else
		flow_free(flow);
}

static void free_buckets(struct flex_array *buckets)
{
	flex_array_free(buckets);
}


static void __table_instance_destroy(struct table_instance *ti)
{
	free_buckets(ti->buckets);
   kfree(ti, MISC_POOL_C);
}

static struct table_instance *table_instance_alloc(int new_size)
{
	struct table_instance *ti = kmalloc(sizeof(*ti), MISC_POOL_C);

	if (!ti)
		return NULL;

   cvmx_rwlock_wp_init(&ti->ti_rwlock);
	ti->buckets = alloc_buckets(new_size);

	if (!ti->buckets) {
		kfree(ti,MISC_POOL_C);
		return NULL;
	}
	ti->n_buckets = new_size;
	ti->node_ver = 0;
	ti->keep_flows = false;
//  ti->hash_seed = 834423;
// get_random_bytes(&ti->hash_seed, sizeof(u32));

#ifdef _IS_LINUX_
   ti->hash_seed = 834423;
#else
   get_random_4_bytes(&ti->hash_seed, sizeof(u32));
#endif



	return ti;
}

static void mask_array_rcu_cb(struct rcu_head *rcu)
{
	//struct mask_array *ma = container_of(rcu, struct mask_array, rcu);

	//kfree(ma);
}

static struct mask_array *tbl_mask_array_alloc(int size)
{
	struct mask_array *new;

	size = max(MASK_ARRAY_SIZE_MIN, size);

	new = kzalloc(sizeof(struct mask_array) +
		      sizeof(struct sw_flow_mask *) * size, MISC_POOL_C);
	if (!new)
		return NULL;

   memset(new, 0, sizeof(struct mask_array) +
		      sizeof(struct sw_flow_mask *) * size);
	new->count = 0;
	new->max = size;

   cvmx_rwlock_wp_init(&new->rwlock);
	return new;
}

static int tbl_mask_array_realloc(struct flow_table *tbl, int size)
{
	struct mask_array *old;
	struct mask_array *new;

	new = tbl_mask_array_alloc(size);
	if (!new)
		return -ENOMEM;

	old = ovsl_dereference(tbl->mask_array);
	if (old) {
		int i, count = 0;

		for (i = 0; i < old->max; i++) {
			if (ovsl_dereference(old->masks[i]))
				new->masks[count++] = old->masks[i];
		}

		new->count = count;
	}
	rcu_assign_pointer(tbl->mask_array, new);

	//if (old)
		//call_rcu(&old->rcu, mask_array_rcu_cb);

	return 0;
}

int ovs_flow_tbl_init(struct flow_table *table)
{
	struct table_instance *ti;
	struct mask_array *ma;

	table->mask_cache = kmalloc(sizeof(struct mask_cache_entry) *
					  MC_HASH_ENTRIES,MISC_POOL_C);
	if (!table->mask_cache)
		return -ENOMEM;

	ma = tbl_mask_array_alloc(MASK_ARRAY_SIZE_MIN);
	if (!ma)
		goto free_mask_cache;

	ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!ti)
		goto free_mask_array;

	rcu_assign_pointer(table->ti, ti);
	rcu_assign_pointer(table->mask_array, ma);
	table->last_rehash = jiffies;
	table->count = 0;
	return 0;

free_mask_array:
	kfree(ma,MISC_POOL_C);
free_mask_cache:
	kfree(table->mask_cache,MISC_POOL_C);
	return -ENOMEM;
}

static void flow_tbl_destroy_rcu_cb(struct rcu_head *rcu)
{
	//struct table_instance *ti = container_of(rcu, struct table_instance, rcu);

	//__table_instance_destroy(ti);
}

static void table_instance_destroy(struct table_instance *ti, bool deferred)
{
    int i;

	if (!ti)
		return;

	if (ti->keep_flows)
		goto skip_flows;

	for (i = 0; i < (int)ti->n_buckets; i++) {
		struct sw_flow *flow = NULL;
		struct hlist_head *head = flex_array_get(ti->buckets, i);
		struct hlist_node *n = NULL;
		int ver = ti->node_ver;
/*
		hlist_for_each_entry_safe(flow, n, head, hash_node[ver]) {
			hlist_del_rcu(&flow->hash_node[ver]);
			ovs_flow_free(flow, deferred);
		}
*/    struct hlist_node *tmp = NULL;
      hlist_for_each_safe(tmp, n, head){
         flow = hlist_entry(tmp, struct sw_flow , hash_node[ver]);
         hlist_del_rcu(&flow->hash_node[ver]);
         ovs_flow_free(flow, deferred);
      }
	}

skip_flows:
	//if (deferred)
		//call_rcu(&ti->rcu, flow_tbl_destroy_rcu_cb);
	//else
		__table_instance_destroy(ti);
    return;
}

/* No need for locking this function is called from RCU callback or
 * error path. */
void ovs_flow_tbl_destroy(struct flow_table *table)
{
	struct table_instance *ti = (struct table_instance __force *)table->ti;

	SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: start to destroy flow table\n", __FUNCTION__);
	kfree(table->mask_cache, MISC_POOL_C);
	kfree((struct mask_array __force *)table->mask_array,MISC_POOL_C);
	table_instance_destroy(ti, false);
}

void display_sw_flow_actions(char *indentations,
                                 struct sw_flow_actions *sf_acts)
{
#define MAX_ACTION_STRING_LEN 1024
   char action_string[MAX_ACTION_STRING_LEN] = {0};
   int as_offset = 0;
   struct nlattr *attrs = NULL;
	int rem=0;
   struct nlattr *attr=NULL;
	int type = 0;
   struct nlattr *subattrs = NULL;
   int subrem = 0;
   struct nlattr *subattr = NULL;
   int subtype = 0;
   const struct ovs_action_push_vlan *vlan = NULL;
   struct ovs_key_udp *udp = NULL;
   struct ovs_key_ipv4 *ipv4 = NULL;
   struct ovs_key_ethernet *mac = NULL;
   const struct ovs_action_hash *act_hash = NULL;
   char ip4src[16] = {0};
   char ip4dst[16] = {0};
   char macsrc[18] = {0};
   char macdst[18] = {0};
#define dump_nla_for_each(pos, attrslist, remaining) \
      for (pos=attrslist; remaining > 0; pos = nla_next(pos, &remaining))


   as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
      "actions:");
   if (NULL == sf_acts || 0 == sf_acts->actions_len) {
      printf("empty actions.\n");
      return;
   }

   attrs=sf_acts->actions;
   rem = sf_acts->actions_len;
   dump_nla_for_each(attr, attrs, rem) {
		type = nla_type(attr);
		switch (type) {
		case OVS_ACTION_ATTR_UNSPEC:
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " attr_unspec");
			break;

		case OVS_ACTION_ATTR_USERSPACE:
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " attr_userspace:");
         subattrs = attr;
         subrem = nla_len(attr);
	      dump_nla_for_each(subattr,subattrs,subrem){
            subtype =nla_type(subattr);
            switch (subtype) {
               case OVS_USERSPACE_ATTR_PID:
                  as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
                     " pid:%d", nla_get_u32(subattr));
                  break;//= {.type = NLA_U32 },
		         case OVS_USERSPACE_ATTR_USERDATA:
                  as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
                     " userdata");
                  break;//= {.type = NLA_UNSPEC },
               default:
                  as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
                     " unknownuser");
                  break;
               }
            }
			break;

		case OVS_ACTION_ATTR_OUTPUT:
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " output:%d", nla_get_u32(attr));
			break;

		case OVS_ACTION_ATTR_HASH: {
			act_hash = nla_data(attr);
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " attr_hash:%d-%d", act_hash->hash_alg, act_hash->hash_basis);
			break;
		}

		case OVS_ACTION_ATTR_POP_VLAN:
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " pop_vlan");
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
			vlan = nla_data(attr);
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " push_vlan:%d-%d", vlan->vlan_tpid, vlan->vlan_tci);
			break;

		case OVS_ACTION_ATTR_RECIRC:
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " recirc");
			break;

		case OVS_ACTION_ATTR_SET: {
         subattr = nla_data(attr);
         subtype =nla_type(subattr);
         subrem = nla_len(attr);
         if (subrem < nla_len(subattr)) {
            as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
               " attr_set:subrem<subattrlen");
            continue;
         }
         switch (subtype) {
         case OVS_KEY_ATTR_ETHERNET:
            mac = nla_data(subattr);
            get_mac_str(macsrc, sizeof(macsrc), mac->eth_src);
            get_mac_str(macdst, sizeof(macdst), mac->eth_dst);
            as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
               " attr_set:mac:%s-%s", macsrc, macdst);
            break;
         case OVS_KEY_ATTR_IPV4:
            ipv4 = nla_data(subattr);
            get_ip4_str(ip4src, sizeof(ip4src), ipv4->ipv4_src);
            get_ip4_str(ip4dst, sizeof(ip4dst), ipv4->ipv4_dst);
            as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
               " attr_set:ipv4:%s-%s", ip4src, ip4dst);
            break;
         case OVS_KEY_ATTR_UDP:
            udp = nla_data(subattr);
            as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
               " attr_set:udp:%d-%d", udp->udp_src, udp->udp_dst);
            break;
         case OVS_KEY_ATTR_UNSPEC:
         case OVS_KEY_ATTR_ENCAP:
         case OVS_KEY_ATTR_PRIORITY:
         case OVS_KEY_ATTR_IN_PORT:
         case OVS_KEY_ATTR_VLAN:
         case OVS_KEY_ATTR_ETHERTYPE:
         case OVS_KEY_ATTR_IPV6:
         case OVS_KEY_ATTR_TCP:
         case OVS_KEY_ATTR_ICMP:
         case OVS_KEY_ATTR_ICMPV6:
         case OVS_KEY_ATTR_ARP:
         case OVS_KEY_ATTR_ND:
         case OVS_KEY_ATTR_SKB_MARK:
         case OVS_KEY_ATTR_TUNNEL:
         case OVS_KEY_ATTR_SCTP:
         case OVS_KEY_ATTR_TCP_FLAGS:
         case OVS_KEY_ATTR_DP_HASH:
         case OVS_KEY_ATTR_RECIRC_ID:
#ifdef __KERNEL__
         case OVS_KEY_ATTR_IPV4_TUNNEL:
#endif
         case OVS_KEY_ATTR_MPLS:
         default:
            as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
               " attr_set:%d ", subtype);
            break;
         }
        break;
      }
		case OVS_ACTION_ATTR_SAMPLE:
         as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
            " attr_sample");
			break;

		default:
		   printf("Error: Unknown action type. %d\n", type);
         break;
		}
	}

	if (rem > 0) {
      as_offset += snprintf(action_string+as_offset, MAX_ACTION_STRING_LEN-as_offset,
         " Un-aligned[rem=%d] ", rem);
   }
   printf("%s%s", indentations, action_string);ENDL;

	return;
}

static int dump_sw_flow(struct sw_flow *flow)
{
   if (NULL == flow) {
      printf("%s: NULL flow", __func__); ENDL;
      return 0;
   }
   ENDL;printf("----");ENDL;
   printf(NUMBER_U32_1, INDENTATION, "hash", flow->hash);ENDL;
   printf("--key");ENDL;
   display_sw_flow_key(INDENTATION, &(flow->key));

   printf("--unmasked key");ENDL;
   display_sw_flow_key(INDENTATION, &(flow->unmasked_key));

   printf("--actions");ENDL;
   display_sw_flow_actions(INDENTATION, flow->sf_acts);
//   printf("--mask");ENDL;
//   display_sw_flow_mask(INDENTATION, flow->mask);

   printf("--stat");ENDL;
   printf(NUMBER_U64_1, INDENTATION, "packets", flow->stats.packet_count);ENDL;
   printf(NUMBER_U64_1, INDENTATION, "bytes", flow->stats.byte_count);ENDL;

   return 0;
}

int  cvm_ovs_flow_cmd_dump(struct datapath *dp)
{
   unsigned int i = 0;
   int flowcount = 0;
   struct hlist_head * head = NULL;
   struct hlist_node * tmp = NULL;
   struct sw_flow *flow = NULL;

   printf("  -----start to dump SE flow tables -----\n");
    for (i = 0; i < dp->table.ti->n_buckets; i++) {
        head = flex_array_get(dp->table.ti->buckets, i);
        hlist_for_each(tmp, head) {
            /* feed watchdog */
#ifndef _IS_LINUX_   
            cvmx_write64_uint64(CVMX_CIU_PP_POKEX(cvmx_get_core_num()), 0);
#endif
            flow = hlist_entry(tmp, struct sw_flow, hash_node[dp->table.ti->node_ver]);
            dump_sw_flow(flow);
            flowcount++;
        }
    }
   printf("  ---- Totally %d flow(s) set.\n", flowcount);
   printf("  -----dump SE flow finished -----\n");
   return 0;
}


struct sw_flow *ovs_flow_tbl_dump_next(struct table_instance *ti,
				       u32 *bucket, u32 *last)
{
	struct sw_flow *flow=NULL;
	struct hlist_head *head;
	int ver;
	int i;

	ver = ti->node_ver;
	while (*bucket < ti->n_buckets) {
		i = 0;
		head = flex_array_get(ti->buckets, *bucket);

      struct hlist_node *tmp;
      hlist_for_each(tmp, head){
         flow = hlist_entry(tmp, struct sw_flow, hash_node[ver]);
			if (i < (int)*last) {
				i++;
				continue;
			}
			*last = i + 1;
			return flow;
		}
		(*bucket)++;
		*last = 0;
	}

	return NULL;
}
#if 0
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

static inline u32 jhash_1word(u32 a, u32 initval)
{
	return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif

struct hlist_head *find_bucket(struct table_instance *ti, u32 hash)
{
	hash = jhash_1word(hash, ti->hash_seed);

   SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "find_bucket element_nr is %d based on the flow hash\n",
                   (hash & (ti->n_buckets - 1)));

	return flex_array_get(ti->buckets, (hash & (ti->n_buckets - 1)));
}
extern void hlist_add_head(struct hlist_node *n, struct hlist_head *h);
void table_instance_insert(struct table_instance *ti, struct sw_flow *flow)
{
	struct hlist_head *head;

	head = find_bucket(ti, flow->hash);
	SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: bucket head for flow is %p node_ver: %d\tflow is %p\n",
	        __FUNCTION__, head, ti->node_ver, flow);
	hlist_add_head(&flow->hash_node[ti->node_ver], head);
}

static void flow_table_copy_flows(struct table_instance *old,
				  struct table_instance *new)
{
	int old_ver;
	int i;

	old_ver = old->node_ver;
	new->node_ver = !old_ver;

	/* Insert in new table. */
	for (i = 0; i < (int)old->n_buckets; i++) {
		//struct sw_flow *flow;
		struct hlist_head *head;

		head = NULL;/*flex_array_get(old->buckets, i);*/

		/*hlist_for_each_entry(flow, head, hash_node[old_ver])
			table_instance_insert(new, flow);*/
	}

	old->keep_flows = true;
}

static struct table_instance *table_instance_rehash(struct table_instance *ti,
					    int n_buckets)
{
	struct table_instance *new_ti;

	new_ti = table_instance_alloc(n_buckets);
	if (!new_ti)
		return NULL;

	flow_table_copy_flows(ti, new_ti);

	return new_ti;
}

int ovs_flow_tbl_flush(struct flow_table *flow_table)
{
	struct table_instance *old_ti;
	struct table_instance *new_ti;

	old_ti = ovsl_dereference(flow_table->ti);
	new_ti = table_instance_alloc(TBL_MIN_BUCKETS);
	if (!new_ti)
		return -ENOMEM;

	rcu_assign_pointer(flow_table->ti, new_ti);
	flow_table->last_rehash = jiffies;
	flow_table->count = 0;

	table_instance_destroy(old_ti, true);
	return 0;
}

u32 flow_hash(const struct sw_flow_key *key, int key_start,
		     int key_end)
{
	const u32 *hash_key = (const u32 *)((const u8 *)key + key_start);
	int hash_u32s = (key_end - key_start) >> 2;

	/* Make sure number of hash bytes are multiple of u32. */
	BUILD_BUG_ON(sizeof(long) % sizeof(u32));

	return jhash(hash_key, hash_u32s, 0);
}

static int flow_key_start(const struct sw_flow_key *key)
{
#ifndef _IS_LINUX_
	if (key->tun_key.ipv4_dst)
		return 0;
	else
		return rounddown(offsetof(struct sw_flow_key, phy),
					  sizeof(long));
#endif
   return 1;
}

static bool cmp_key(const struct sw_flow_key *key1,
		    const struct sw_flow_key *key2,
		    int key_start, int key_end)
{
	const long *cp1 = (const long *)((const u8 *)key1 + key_start);
	const long *cp2 = (const long *)((const u8 *)key2 + key_start);
	long diffs = 0;
	int i;

	for (i = key_start; i < key_end;  i += sizeof(long)) {
		diffs |= *cp1++ ^ *cp2++;
	}

	return diffs == 0;
}

static bool flow_cmp_masked_key(const struct sw_flow *flow,
				const struct sw_flow_key *key,
				int key_start, int key_end)
{
	return cmp_key(&flow->key, key, key_start, key_end);
}

bool ovs_flow_cmp_unmasked_key(const struct sw_flow *flow,
			       struct sw_flow_match *match)
{
	struct sw_flow_key *key = match->key;
	int key_start = flow_key_start(key);
	int key_end = match->range.end;

	return cmp_key(&flow->unmasked_key, key, key_start, key_end);
}
//extern void debug_flow_key(struct sw_flow_key *key);
static struct sw_flow *masked_flow_lookup(struct table_instance *ti,
					  const struct sw_flow_key *unmasked,
					  struct sw_flow_mask *mask,
					  u32 *n_mask_hit)
{
    struct sw_flow *flow = NULL;
    struct hlist_head *head;
    int key_start = mask->range.start;
    int key_end = mask->range.end;
    u32 hash;
    struct sw_flow_key masked_key;

    ovs_flow_mask_key(&masked_key, unmasked, mask);
    hash = flow_hash(&masked_key, key_start, key_end);
    head = find_bucket(ti, hash);
    (*n_mask_hit)++;

    if (!head) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "Can't find the head (should never happen)\n");
        return NULL;
    }

    struct hlist_node *tmp;
    bool is_equal;

    cvmx_rwlock_wp_read_lock(&ti->ti_rwlock);


    hlist_for_each(tmp, head)
    {
        flow = hlist_entry(tmp, struct sw_flow, hash_node[ti->node_ver]);
        is_equal = flow_cmp_masked_key(flow, &masked_key, key_start, key_end);
        if (flow->mask == mask && flow->hash == hash && is_equal) {

            cvmx_rwlock_wp_read_unlock(&ti->ti_rwlock);
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "lucky, we get it within masked_flow_lookup\n");
            return flow;
        }
    }
    cvmx_rwlock_wp_read_unlock(&ti->ti_rwlock);

    return NULL;
}

/* Flow lookup does full lookup on flow table. It starts with
 * mask from index passed in *index.
 */
static struct sw_flow *flow_lookup(struct flow_table *tbl,
				   struct table_instance *ti,
				   struct mask_array *ma,
				   const struct sw_flow_key *key,
				   u32 *n_mask_hit,
				   u32 *index)
{
	struct sw_flow_mask *mask;
	struct sw_flow *flow;
	int i;

    if ((int) *index < ma->max) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "begin to do flow_lookup with mask index is %d \n", *index);
        mask = rcu_dereference_ovsl(ma->masks[*index]);
        if (mask) {
            flow = masked_flow_lookup(ti, key, mask, n_mask_hit);
            if (flow)
                return flow;
        }
    }

   SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "begin full mask search in flow_lookup, ma-max: %d\n", ma->max);

	for (i = 0; i < ma->max; i++)  {

		if (i == (int)*index)
			continue;

		mask = rcu_dereference_ovsl(ma->masks[i]);
		if (!mask)
			continue;

		flow = masked_flow_lookup(ti, key, mask, n_mask_hit);
		if (flow) { /* Found */
			*index = i;
			return flow;
		}
	}

    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "end flow_lookup without hit \n");

	return NULL;
}

/*
 * mask_cache maps flow to probable mask. This cache is not tightly
 * coupled cache, It means updates to  mask list can result in inconsistent
 * cache entry in mask cache.
 * This is per cpu cache and is divided in MC_HASH_SEGS segments.
 * In case of a hash collision the entry is hashed in next segment.
 * */
struct sw_flow *ovs_flow_tbl_lookup_stats(struct flow_table *tbl,
					  const struct sw_flow_key *key,
					  u32 skb_hash,
					  u32 *n_mask_hit)
{
	struct mask_array *ma = rcu_dereference(tbl->mask_array);
	struct table_instance *ti = rcu_dereference(tbl->ti);
	struct mask_cache_entry *entries, *ce;
	struct sw_flow *flow;
	u32 hash = skb_hash;
	int seg;

	*n_mask_hit = 0;
	if (unlikely(!skb_hash)) {
		u32 mask_index = 0;
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "begin do no skb hash search in  ovs_flow_tbl_lookup_stats.\n");
		return flow_lookup(tbl, ti, ma, key, n_mask_hit, &mask_index);
	}

	ce = NULL;
	entries = this_cpu_ptr(tbl->mask_cache);

	/* Find the cache entry 'ce' to operate on. */
	for (seg = 0; seg < (int)MC_HASH_SEGS; seg++) {
		int index = hash & (MC_HASH_ENTRIES - 1);
		struct mask_cache_entry *e;

		e = &entries[index];
		if (e->skb_hash == skb_hash) {
         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "ovs_flow_tbl_lookup_stats with hit skb_hash  \n");
         flow = flow_lookup(tbl, ti, ma, key, n_mask_hit,
					   &e->mask_index);
			if (!flow)
				e->skb_hash = 0;
			return flow;
		}

		if (!ce || e->skb_hash < ce->skb_hash)
			ce = e;  /* A better replacement cache candidate. */

		hash >>= MC_HASH_SHIFT;
	}

	/* Cache miss, do full lookup. */
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "ovs_flow_tbl_lookup_stats : do full lookup \n");
	flow = flow_lookup(tbl, ti, ma, key, n_mask_hit, &ce->mask_index);

	if (flow)
		ce->skb_hash = skb_hash;

	return flow;
}

struct sw_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
				    const struct sw_flow_key *key)
{
	struct table_instance *ti = rcu_dereference_ovsl(tbl->ti);
	struct mask_array *ma = rcu_dereference_ovsl(tbl->mask_array);
	u32 __always_unused n_mask_hit;
	u32 index = 0;

	return flow_lookup(tbl, ti, ma, key, &n_mask_hit, &index);
}

struct sw_flow *ovs_flow_tbl_lookup_exact(struct flow_table *tbl,
					  struct sw_flow_match *match)
{
	struct mask_array *ma = ovsl_dereference(tbl->mask_array);
	int i;

	/* Always called under ovs-mutex. */
	for (i = 0; i < ma->max; i++) {
		struct table_instance *ti = ovsl_dereference(tbl->ti);
		u32 __always_unused n_mask_hit;
		struct sw_flow_mask *mask;
		struct sw_flow *flow;

		mask = ovsl_dereference(ma->masks[i]);
		if (!mask)
			continue;
		flow = masked_flow_lookup(ti, match->key, mask, &n_mask_hit);
		if (flow && ovs_flow_cmp_unmasked_key(flow, match))
			return flow;
	}
	return NULL;
}

int ovs_flow_tbl_num_masks(const struct flow_table *table)
{
	struct mask_array *ma;

	ma = rcu_dereference_ovsl(table->mask_array);
	return ma->count;
}

static struct table_instance *table_instance_expand(struct table_instance *ti)
{
	return table_instance_rehash(ti, ti->n_buckets * 2);
}

static void tbl_mask_array_delete_mask(struct mask_array *ma,
				       struct sw_flow_mask *mask)
{
	int i;

	/* Remove the deleted mask pointers from the array */
	for (i = 0; i < ma->max; i++) {
		if (mask == ovsl_dereference(ma->masks[i])) {
			(ma->masks[i] =  NULL);
			ma->count--;
		   kfree(mask,MISC_POOL_C);
			return;
		}
	}
	//BUG();
}

/* Remove 'mask' from the mask list, if it is not needed any more. */
static void flow_mask_remove(struct flow_table *tbl, struct sw_flow_mask *mask)
{
	if (mask) {
		/* ovs-lock is required to protect mask-refcount and
		 * mask list.
		 */
		ASSERT_OVSL();
		BUG_ON(!mask->ref_count);
		mask->ref_count--;

		if (!mask->ref_count) {
			struct mask_array *ma;

			ma = ovsl_dereference(tbl->mask_array);
			tbl_mask_array_delete_mask(ma, mask);

			/* Shrink the mask array if necessary. */
			if (ma->max >= (MASK_ARRAY_SIZE_MIN * 2) &&
			    ma->count <= (ma->max / 3))
				tbl_mask_array_realloc(tbl, ma->max / 2);

		}
	}
}

/* Must be called with OVS mutex held. */
void ovs_flow_tbl_remove(struct flow_table *table, struct sw_flow *flow)
{
	struct table_instance *ti = ovsl_dereference(table->ti);

	BUG_ON(table->count == 0);
	hlist_del_rcu(&flow->hash_node[ti->node_ver]);
	table->count--;

	/* RCU delete the mask. 'flow->mask' is not NULLed, as it should be
	 * accessible as long as the RCU read lock is held. */
	flow_mask_remove(table, flow->mask);
}

static struct sw_flow_mask *mask_alloc(void)
{
	struct sw_flow_mask *mask;

	mask = kmalloc(sizeof(*mask), MISC_POOL_C);
	if (mask)
		mask->ref_count = 1;

	return mask;
}

static bool mask_equal(const struct sw_flow_mask *a,
		       const struct sw_flow_mask *b)
{
	const u8 *a_ = (const u8 *)&a->key + a->range.start;
	const u8 *b_ = (const u8 *)&b->key + b->range.start;

	return  (a->range.end == b->range.end)
		&& (a->range.start == b->range.start)
		&& (memcmp(a_, b_, range_n_bytes(&a->range)) == 0);
}

struct sw_flow_mask *flow_mask_find(const struct flow_table *tbl,
					   const struct sw_flow_mask *mask)
{
	struct mask_array *ma;
	int i;

	ma = ovsl_dereference(tbl->mask_array);
	for (i = 0; i < ma->max; i++) {
		struct sw_flow_mask *t;

		t = ovsl_dereference(ma->masks[i]);
		if (t && mask_equal(mask, t))
			return t;
	}

	return NULL;
}

/* Add 'mask' into the mask list, if it is not already there. */
static int flow_mask_insert(struct flow_table *tbl, struct sw_flow *flow,
			    struct sw_flow_mask *new)
{
	struct sw_flow_mask *mask;

	mask = flow_mask_find(tbl, new);
	if (!mask) {
		struct mask_array *ma;
		int i;

		/* Allocate a new mask if none exsits. */
		mask = mask_alloc();
		if (!mask)
			return -ENOMEM;

		mask->key = new->key;
		mask->range = new->range;

		/* Add mask to mask-list. */
		ma = ovsl_dereference(tbl->mask_array);
		if (ma->count >= ma->max) {
			int err;

			err = tbl_mask_array_realloc(tbl, ma->max +
							  MASK_ARRAY_SIZE_MIN);
			if (err) {
				kfree(mask,MISC_POOL_C);
				return err;
			}
			ma = ovsl_dereference(tbl->mask_array);
		}

		for (i = 0; i < ma->max; i++) {
			struct sw_flow_mask *t;

			t = ovsl_dereference(ma->masks[i]);
			if (!t) {
				rcu_assign_pointer(ma->masks[i], mask);
				ma->count++;
				break;
			}
		}

	} else {
		BUG_ON(!mask->ref_count);
		mask->ref_count++;
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: flow_mask_find exist %d\n", __FUNCTION__, mask->ref_count);
	}

	flow->mask = mask;
	return 0;
}

/* Must be called with OVS mutex held. */
int ovs_flow_tbl_insert(struct flow_table *table, struct sw_flow *flow,
			struct sw_flow_mask *mask)
{
//	struct table_instance *new_ti = NULL;
    struct table_instance *ti;
    int err;

    err = flow_mask_insert(table, flow, mask);
    if (err)
        return err;

    flow->hash = flow_hash(&flow->key, flow->mask->range.start, flow->mask->range.end);
    ti = ovsl_dereference(table->ti);
    cvmx_rwlock_wp_write_lock(&ti->ti_rwlock);
    table_instance_insert(ti, flow);
    table->count++;
    cvmx_rwlock_wp_write_unlock(&ti->ti_rwlock);

	/* Expand table, if necessary, to make room. */
/*
	if (table->count > ti->n_buckets)
		new_ti = table_instance_expand(ti);
	else if (time_after(jiffies, table->last_rehash + REHASH_INTERVAL))
		new_ti = table_instance_rehash(ti, ti->n_buckets);

	if (new_ti) {
		rcu_assign_pointer(table->ti, new_ti);
		table_instance_destroy(ti, true);
		table->last_rehash = jiffies;
	}
*/
	return 0;
}

/* Initializes the flow module.
 * Returns zero if successful or a negative error code. */
int ovs_flow_init(void)
{

#if 0
reason: we will not use the cache for flow.

	flow_cache = NULL;/*kmem_cache_create("sw_flow", sizeof(struct sw_flow)
				       + (num_possible_nodes()
					  * sizeof(struct flow_stats *)),
				       0, 0, NULL);*/
	if (flow_cache == NULL)
		return -ENOMEM;

	/*flow_stats_cache
		= kmem_cache_create("sw_flow_stats", sizeof(struct flow_stats),
				    0, SLAB_HWCACHE_ALIGN, NULL);*/
	if (flow_stats_cache == NULL) {
		//kmem_cache_destroy(flow_cache);
		flow_cache = NULL;
		return -ENOMEM;
#endif

	return 0;
}

/* Uninitializes the flow module. */
void ovs_flow_exit(void)
{
	//kmem_cache_destroy(flow_stats_cache);
	//kmem_cache_destroy(flow_cache);
}
