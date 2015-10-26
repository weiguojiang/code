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

#include <stdio.h>
#include <string.h>
#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"
#include "datapath.h"
#include "vport.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "ovs_debug.h"
#include "vlan.h"

#include "ovs_se_dump.h"

/*
  the index is the ifindex of the datapath
*/
#define  DP_INDEX_MAX 100
CVMX_SHARED struct datapath * g_dp_cache_array[DP_INDEX_MAX];

CVMX_SHARED struct ovs_net g_ovs_net;


/**
 * DOC: Locking:
 *
 * All writes e.g. Writes to device state (add/remove datapath, port, set
 * operations on vports, etc.), Writes to other state (flow table
 * modifications, set miscellaneous datapath parameters, etc.) are protected
 * by ovs_lock.
 *
 * Reads are protected by RCU.
 *
 * There are a few special cases (mostly stats) that have their own
 * synchronization but they nest under all of above and don't interact with
 * each other.
 *
 * The RTNL lock nests inside ovs_mutex.
 */

//static DEFINE_MUTEX(ovs_mutex);

void ovs_lock(void)
{
	//mutex_lock(&ovs_mutex);
}

void ovs_unlock(void)
{
	//mutex_unlock(&ovs_mutex);
}

static int queue_gso_packets(struct datapath *dp, struct sk_buff *,
			     const struct dp_upcall_info *);
static int queue_userspace_packet(struct datapath *dp, struct sk_buff *,
				  const struct dp_upcall_info *);

/* Must be called with rcu_read_lock or ovs_mutex. */
struct datapath *get_dp(int dp_ifindex)
{
    if (DP_INDEX_MAX <= dp_ifindex) {
        return NULL;
    }
	return g_dp_cache_array[dp_ifindex];
}

/* Must be called with rcu_read_lock or ovs_mutex. */
const char *ovs_dp_name(const struct datapath *dp)
{
	return dp->dp_name;
}

static int get_dpifindex(struct datapath *dp)
{
	return dp->dp_ifindex;
}

static void destroy_dp_rcu(struct datapath *dp)
{
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: start to destroy dp", __FUNCTION__);

	ovs_flow_tbl_destroy(&dp->table);
	kfree(dp->ports, MISC_POOL_C);
	kfree(dp, DP_POOL_C);
}

struct hlist_head *vport_hash_bucket(const struct datapath *dp,
					    u16 port_no)
{
	return &dp->ports[port_no & (DP_VPORT_HASH_BUCKETS - 1)];
}

/* Called with ovs_mutex or RCU read lock. */

struct vport *ovs_lookup_vport(const struct datapath *dp, u16 port_no)
{
	struct vport *vport = NULL;
	struct hlist_head *head;

	head = vport_hash_bucket(dp, port_no);
   
   struct hlist_node *tmp;
   cvmx_rwlock_wp_read_lock((void *)&dp->lock);
   hlist_for_each(tmp, head) 
//   hlist_for_each_entry_rcu(vport, head, dp_hash_node)
   {  
      vport = hlist_entry(tmp, struct vport, dp_hash_node);
//      vport = (struct vport *)((char *)tmp - (char *)&((struct vport *)0)->dp_hash_node);    
		if (vport->port_no == port_no){
         cvmx_rwlock_wp_read_unlock((void *)&(dp->lock));
			return vport;
       }   
	}
   cvmx_rwlock_wp_read_unlock((void *)&(dp->lock));
	return NULL;
}

/* Called with ovs_mutex. */
static struct vport *new_vport(const struct vport_parms *parms)
{
	struct vport *vport;

	vport = ovs_vport_add(parms);
    if (!IS_ERR(vport)) {
        struct datapath *dp = parms->dp;
        struct hlist_head *head = vport_hash_bucket(dp, vport->port_no);

        cvmx_rwlock_wp_write_lock(&dp->lock);
        hlist_add_head(&vport->dp_hash_node, head);
        cvmx_rwlock_wp_write_unlock(&dp->lock);
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: success to add vport to hlist\r\n", __FUNCTION__);
    }
	return vport;
}

void ovs_dp_detach_port(struct vport *p)
{
    if (!p) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_WARN, "there is no exist vport \n");
        return;
    }
    /* First drop references to device. */
    cvmx_rwlock_wp_write_lock(&(p->dp->lock));
    hlist_del_rcu(&p->dp_hash_node);
    cvmx_rwlock_wp_write_unlock(&(p->dp->lock));

    /* Then destroy it. */
    ovs_vport_del(p);
}
void ovs_dp_process_packet_with_key(struct sk_buff *skb,
				    struct sw_flow_key *pkt_key,
				    bool recirc)
{
	const struct vport *p = OVS_CB(skb)->input_vport;
	struct datapath *dp = p->dp;
	struct sw_flow *flow;
	struct dp_stats_percpu *stats;
	u64 *stats_counter = NULL;
	u32 n_mask_hit;

	stats = &(dp->stats_percpu);

	/* Look up flow. */
	flow = ovs_flow_tbl_lookup_stats(&dp->table, pkt_key, skb_get_hash(skb),
					 &n_mask_hit);
	if ((!flow)) {      
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_WARN, "\n\nCan't find flow after ovs_dp_process_packet_with_key.\n");
#if 0            
		struct dp_upcall_info upcall;

		upcall.cmd = OVS_PACKET_CMD_MISS;
		upcall.key = pkt_key;
		upcall.userdata = NULL;
		upcall.portid = ovs_vport_find_upcall_portid(p, skb);
		ovs_dp_upcall(dp, skb, &upcall);
		consume_skb(skb);
#endif
		stats_counter = &stats->n_missed;
		goto out;
	}
    OVS_CB(skb)->pkt_key = pkt_key;
    OVS_CB(skb)->flow = flow;

    ovs_flow_stats_update(OVS_CB(skb)->flow, pkt_key->tp.flags, skb);
    ovs_execute_actions(dp, skb, recirc);

    stats_counter = &stats->n_hit;

out:
	/* Update datapath statistics. */
	#ifdef OVS_STATS 
	/*for TOSE */
	u64_stats_update_begin(&stats->sync);
#ifdef _IS_LINUX_
	(*stats_counter)++;
	stats->n_mask_hit += n_mask_hit;
#else 
      cvmx_atomic_add64((int64_t *)stats_counter, 1);
      cvmx_atomic_add64((int64_t *)&stats->n_mask_hit, n_mask_hit);
#endif
	u64_stats_update_end(&stats->sync);
	#endif
	return;
}
//extern void debug_flow_key(struct sw_flow_key *key);
/* Must be called with rcu_read_lock. */
void ovs_dp_process_received_packet(struct vport *p, struct sk_buff *skb)
{
	int error;
	struct sw_flow_key key;

	OVS_CB(skb)->input_vport = p;

	/* Extract flow from 'skb' into 'key'. */
	error = ovs_flow_key_extract(skb, &key);  
	if (unlikely(error)) {
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "\nFailed to extract flow key from skb.\n");
        OVS_CB(skb)->fp_output_res = 1/*FP_DROP*/;
        return;
    }

	ovs_dp_process_packet_with_key(skb, &key, false);
}

int ovs_dp_upcall(struct datapath *dp, struct sk_buff *skb,
		  const struct dp_upcall_info *upcall_info)
{
#ifdef OVS_STATS 
	struct dp_stats_percpu *stats;
#endif

	int err;

	if (upcall_info->portid == 0) {
		err = /*-ENOTCONN*/-134;
		goto err;
	}

	if (!skb_is_gso(skb))
		err = queue_userspace_packet(dp, skb, upcall_info);
	else
		err = queue_gso_packets(dp, skb, upcall_info);
	if (err)
		goto err;

	return 0;

err:
	
#ifdef OVS_STATS 
	stats = &(dp->stats_percpu);

	u64_stats_update_begin(&stats->sync);
	stats->n_lost++;
	u64_stats_update_end(&stats->sync);
#endif
	return err;
}

static int queue_gso_packets(struct datapath *dp, struct sk_buff *skb,
			     const struct dp_upcall_info *upcall_info)
{
   return 1;
}


static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct dp_upcall_info *upcall_info)
{
   return 0;
}

static int ovs_packet_cmd_execute(struct sk_buff *skb, struct genl_info *info)
{
	struct ovs_header *ovs_header = info->userhdr;
	struct nlattr **a = info->attrs;
	struct sw_flow_actions *acts;
	struct sk_buff *packet;
	struct sw_flow *flow;
	struct datapath *dp;
	struct ethhdr *eth;
	struct vport *input_vport;
	int len;
	int err;

	err = -EINVAL;
	if (!a[OVS_PACKET_ATTR_PACKET] || !a[OVS_PACKET_ATTR_KEY] ||
	    !a[OVS_PACKET_ATTR_ACTIONS])
		goto err;

	len = nla_len(a[OVS_PACKET_ATTR_PACKET]);
//	packet = dev_alloc_skb(NET_IP_ALIGN + len, GFP_KERNEL);
	err = -ENOMEM;
	if (!packet)
		goto err;
	skb_reserve(packet, NET_IP_ALIGN);

	//nla_memcpy(__skb_put(packet, len), a[OVS_PACKET_ATTR_PACKET], len); //TOSE

	skb_reset_mac_header(packet);
	eth = eth_hdr(packet);

	/* Normally, setting the skb 'protocol' field would be handled by a
	 * call to eth_type_trans(), but it assumes there's a sending
	 * device, which we may not have. */
	if (ntohs(eth->h_proto) >= ETH_P_802_3_MIN)
		packet->protocol = eth->h_proto;
	else
		packet->protocol = htons(ETH_P_802_2);

	/* Build an sw_flow for sending this packet. */
	flow = ovs_flow_alloc();
	err = PTR_ERR(flow);
	if (IS_ERR(flow))
		goto err_kfree_skb;

	err = ovs_flow_key_extract_userspace(a[OVS_PACKET_ATTR_KEY], packet,
					     &flow->key);
	if (err)
		goto err_flow_free;

	err = PTR_ERR(acts);
	if (IS_ERR(acts))
		goto err_flow_free;

	OVS_CB(packet)->flow = flow;
	OVS_CB(packet)->pkt_key = &flow->key;
	packet->priority = flow->key.phy.priority;
	packet->mark = flow->key.phy.skb_mark;

	//rcu_read_lock();
	dp = get_dp(ovs_header->dp_ifindex);
	err = -ENODEV;
	if (!dp)
		goto err_unlock;

	input_vport = ovs_vport_rcu(dp, flow->key.phy.in_port);
	if (!input_vport)
		input_vport = ovs_vport_rcu(dp, OVSP_LOCAL);

	if (!input_vport)
		goto err_unlock;

	OVS_CB(packet)->input_vport = input_vport;

	err = ovs_execute_actions(dp, packet, false);

	ovs_flow_free(flow, false);
	return err;

err_unlock:
	//rcu_read_unlock();
err_flow_free:
	ovs_flow_free(flow, false);
err_kfree_skb:
	kfree_skb(packet);
err:
	return err;
}



static void get_dp_stats(struct datapath *dp, struct ovs_dp_stats *stats,
			 struct ovs_dp_megaflow_stats *mega_stats)
{
   return;
}


int ovs_flow_cmd_new(struct sw_flow_key *key,
                     struct sw_flow_key *unmasked_key,
                      struct sw_flow_mask *mask,
                      struct sw_flow_actions *acts,
                      int dp_ifindex)
{
    struct sw_flow *new_flow;
    struct sw_flow * l_exist_flow;
    struct datapath *dp;
    struct sw_flow_actions * new_acts;
    int error;

    error = -EINVAL;

    new_flow = ovs_flow_alloc();
    if (!new_flow) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: alloc memory for flow failed\r\n", __FUNCTION__);
        goto error;
    }

    new_flow->key = *key;
    new_flow->unmasked_key = *unmasked_key;

    new_flow->sf_acts = NULL;
    new_flow->mask = NULL;

    new_acts = ovs_nla_alloc_flow_actions(acts->actions_len);
    if (!(new_acts)) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: alloc memory for new acts failed\r\n", __FUNCTION__);
        goto err_kfree_flow;
    }

    new_acts->rcu = acts->rcu;
    new_acts->actions_len = acts->actions_len;

   memcpy((char*)(new_acts->actions),
          (char*)(acts->actions),
          acts->actions_len);

    new_flow->sf_acts = new_acts;

    ovs_lock();
    dp = get_dp(dp_ifindex);
    if (unlikely(!dp)) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: the dp with index(%d) is not exist\r\n",
                __FUNCTION__, dp_ifindex);
        error = -ENODEV;
        goto err_unlock_ovs;
    }
    /* Check if this is a duplicate flow */
    l_exist_flow = ovs_flow_tbl_lookup(&dp->table, &new_flow->unmasked_key);
    if ((!l_exist_flow)) {
        rcu_assign_pointer(new_flow->sf_acts, new_acts);

        /* Put flow in bucket. */
        error = ovs_flow_tbl_insert(&dp->table, new_flow, mask);
        if (error) {
            acts = NULL;
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "%s: flow insert failed: %d\n", __FUNCTION__, error);
            goto err_unlock_ovs;
        }

        ovs_unlock();
    } else {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: the unmasked key exist in table\r\n", __FUNCTION__);
        error = -EEXIST;
        goto err_kfree_flow;
    }

   return 0;

err_unlock_ovs:
   ovs_unlock();
//err_kfree_acts:
   kfree(acts,DP_POOL_C);
err_kfree_flow:
   ovs_flow_free(new_flow, false);
error:
   return error;
}


static int ovs_flow_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
   return 0;
}

static int ovs_flow_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
   return 0;
}

int ovs_flow_cmd_del(struct sw_flow_key *key, int dp_ifindex)
{
    struct sw_flow *flow;
    struct datapath *dp;
    struct sw_flow_match match;
    int err;

    memset(&match, 0, sizeof(match));
    match.key = key;
    match.mask = NULL;

    ovs_lock();
    dp = get_dp(dp_ifindex);
    if (unlikely(!dp)) {
        err = -ENODEV;
        goto unlock;
    }
#if 0
      if (unlikely(!a[OVS_FLOW_ATTR_KEY])) {
         err = ovs_flow_tbl_flush(&dp->table);
         goto unlock;
      }
#endif
    flow = ovs_flow_tbl_lookup_exact(&dp->table, &match);
    if (unlikely(!flow)) {
        err = -ENOENT;
        goto unlock;
    }

    cvmx_rwlock_wp_write_lock(&dp->table.ti->ti_rwlock);
    ovs_flow_tbl_remove(&dp->table, flow);
    cvmx_rwlock_wp_write_unlock(&dp->table.ti->ti_rwlock);
    ovs_unlock();

    ovs_flow_free(flow, true);
    return 0;
unlock:
    ovs_unlock();
    return err;
   }


static void fake_ovs_flow_cmd_dump(struct datapath *dp)
{

   struct table_instance *ti;

   ti = rcu_dereference(dp->table.ti);
   for (;;) {
      struct sw_flow *flow;
      u32 bucket, obj;

      bucket = 0;
      obj = 0;
      flow = ovs_flow_tbl_dump_next(ti, &bucket, &obj);
      if (!flow)
         break;

   }
   return;
}


static size_t ovs_dp_cmd_msg_size(void)
{
	size_t msgsize = NLMSG_ALIGN(sizeof(struct ovs_header));

	return msgsize;
}

/* Called with ovs_mutex. */
static int ovs_dp_cmd_fill_info(struct datapath *dp, struct sk_buff *skb,
				u32 portid, u32 seq, u32 flags, u8 cmd)
{
   return 0;
}
/*
static struct sk_buff *ovs_dp_cmd_alloc_info(struct genl_info *info)
{
	return genlmsg_new_unicast(ovs_dp_cmd_msg_size(), info, GFP_KERNEL);
}
*/
/* Called with rcu_read_lock or ovs_mutex. */
static struct datapath *lookup_datapath(struct net *net,
					struct ovs_header *ovs_header,
					struct nlattr *a[OVS_DP_ATTR_MAX + 1])
{
	return NULL;
}

static void ovs_dp_reset_user_features(struct sk_buff *skb, struct genl_info *info)
{
	struct datapath *dp;

	dp = lookup_datapath(sock_net(skb->sk), info->userhdr, info->attrs);
	if (IS_ERR(dp))
		return;

	//WARN(dp->user_features, "Dropping previously announced user features\n");
	dp->user_features = 0;
}

static void ovs_dp_change(struct datapath *dp, struct nlattr **a)
{
	if (a[OVS_DP_ATTR_USER_FEATURES])
		dp->user_features = nla_get_u32(a[OVS_DP_ATTR_USER_FEATURES]);
}

int ovs_dp_cmd_new(int ifindex, char *dp_name)
{
//	struct vport_parms parms;
	struct datapath *dp;
//	struct vport *vport;
//	struct ovs_net *ovs_net;
	int err, i;

    err = -ENOMEM;

    dp = kzalloc(sizeof(*dp), DP_POOL_C);
    if (dp == NULL) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: alloc memory for dp failed.\r\n", __FUNCTION__);
        goto err_free_reply;
    }

   dp->dp_ifindex = ifindex;
   strncpy(dp->dp_name, dp_name, sizeof(dp->dp_name));
   cvmx_rwlock_wp_init(&dp->lock);

	err = ovs_flow_tbl_init(&dp->table);
	if (err) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: init flow table failed.\r\n", __FUNCTION__);
		goto err_free_dp;
	}

#if 0
	dp->stats_percpu = (struct dp_stats_percpu*)malloc(sizeof(struct dp_stats_percpu));
	if (!dp->stats_percpu) {
		err = -ENOMEM;
		goto err_destroy_table;
	}

	for_each_possible_cpu(i) {
		struct dp_stats_percpu *dpath_stats;
		dpath_stats = NULL;
		u64_stats_init(&dpath_stats->sync);
	}
#endif
    dp->ports = kmalloc(DP_VPORT_HASH_BUCKETS * sizeof(struct hlist_head), MISC_POOL_C);
    if (!dp->ports) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR %s: alloc memory for ports failed.\r\n", __FUNCTION__);
        err = -ENOMEM;
        goto err_destroy_percpu;
    }

    for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
        INIT_HLIST_HEAD(&dp->ports[i]);


	/* Set up our datapath device. */
#if 0
	parms.name = nla_data(a[OVS_DP_ATTR_NAME]);
	parms.type = OVS_VPORT_TYPE_INTERNAL;
	parms.options = NULL;
	parms.dp = dp;
	parms.port_no = OVSP_LOCAL;
	parms.upcall_portids = a[OVS_DP_ATTR_UPCALL_PID];

	ovs_dp_change(dp, a);

	ovs_lock();

	vport = new_vport(&parms);
	if (IS_ERR(vport)) {
		err = PTR_ERR(vport);
		if (err == -EBUSY)
			err = -EEXIST;

		if (err == -EEXIST) {
			if (info->genlhdr->version < OVS_DP_VER_FEATURES)
				ovs_dp_reset_user_features(skb, info);
		}

		goto err_destroy_ports_array;
	}
#endif

    cvmx_spinlock_lock(&g_ovs_net.lock);
	list_add_tail(&dp->list_node, &(g_ovs_net.dps));
    cvmx_spinlock_unlock(&g_ovs_net.lock);

    g_dp_cache_array[ifindex] = dp;

    return 0;

//err_destroy_ports_array:
	kfree(dp->ports,MISC_POOL_C);
err_destroy_percpu:
//	free_percpu(dp->stats_percpu);
//err_destroy_table:
	ovs_flow_tbl_destroy(&dp->table);
err_free_dp:
    kfree(dp,DP_POOL_C);
err_free_reply:
//	kfree_skb(reply);
//err:
	return err;
}

/* Called with ovs_mutex. */
static void __dp_destroy(struct datapath *dp)
{
   int i;

   for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++) {
      struct vport *vport;
      struct hlist_node *n;
      struct hlist_node *tmp;

      hlist_for_each_safe(tmp, n,  &dp->ports[i]){
         vport = hlist_entry(tmp, struct vport , dp_hash_node); 
         if (vport->port_no != OVSP_LOCAL)
            ovs_dp_detach_port(vport);
      }
   }

   list_del_rcu(&dp->list_node);

   /* OVSP_LOCAL is datapath internal port. We need to make sure that
    * all ports in datapath are destroyed first before freeing datapath.
    */
   ovs_dp_detach_port(ovs_vport_ovsl(dp, OVSP_LOCAL));

   /* RCU destroy the flow table */
   destroy_dp_rcu(dp);
}


int ovs_dp_cmd_del(int dp_ifindex)
{
   struct datapath *dp;
   int err;

   ovs_lock();
   dp = get_dp(dp_ifindex);
   if (!dp) {
       err = -ENODEV;
       SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: the specified dp with index(%d) is not exist\r\n",
               __FUNCTION__, dp_ifindex);
      goto err_unlock_free;
   }

   __dp_destroy(dp);

   ovs_unlock();
   return 0;

err_unlock_free:
   ovs_unlock();
   return err;
}

static int ovs_dp_cmd_set(struct sk_buff *skb, struct genl_info *info)
{
   return 0;
}

static int ovs_dp_cmd_get(struct sk_buff *skb, struct genl_info *info)
{
   return 0;
}

extern int  cvm_ovs_flow_cmd_dump(struct datapath *dp);

extern int ovs_vport_cmd_dump(struct datapath *dp);
static void dump_dp(struct datapath *dp)
{
   if (NULL == dp) {
      printf("%s: NULL dp", __func__); ENDL;
      return; 
   }
   printf("----------------------");ENDL;
   printf(STRING, INDENTATION, "dp_name", dp->dp_name);ENDL;
   printf(NUMBER_U32_1, INDENTATION, "dp_ifindex", dp->dp_ifindex);ENDL;
   printf(NUMBER_U64_1, INDENTATION, "stats_percpu.n_hit", dp->stats_percpu.n_hit);ENDL;
   printf(NUMBER_U64_1, INDENTATION, "stats_percpu.n_lost", dp->stats_percpu.n_lost);ENDL;
   printf(NUMBER_U64_1, INDENTATION, "stats_percpu.n_mask_hit", dp->stats_percpu.n_mask_hit);ENDL;
   printf(NUMBER_U64_1, INDENTATION, "stats_percpu.n_missed", dp->stats_percpu.n_missed);ENDL;
   ovs_vport_cmd_dump(dp);
   cvm_ovs_flow_cmd_dump(dp);
   ENDL;
   return;
}
int ovs_dp_cmd_dump(void)
{
	struct list_head *tmp;
   struct datapath *dp;
   cvmx_spinlock_lock(&g_ovs_net.lock);
   list_for_each(tmp, &g_ovs_net.dps) {
      dp = list_entry(tmp, struct datapath, list_node);
      dump_dp(dp);
   }
   cvmx_spinlock_unlock(&g_ovs_net.lock);
   return 0;
}

#if 0

/* Called with ovs_mutex or RCU read lock. */
static int ovs_vport_cmd_fill_info(struct vport *vport, struct sk_buff *skb,
				   u32 portid, u32 seq, u32 flags, u8 cmd)
{
   return 1;
}

static struct sk_buff *ovs_vport_cmd_alloc_info(void)
{
	return nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
}

/* Called with ovs_mutex, only via ovs_dp_notify_wq(). */
struct sk_buff *ovs_vport_cmd_build_info(struct vport *vport, u32 portid,
					 u32 seq, u8 cmd)
{
	struct sk_buff *skb;
	int retval;

	skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return ERR_PTR(-ENOMEM);

	retval = ovs_vport_cmd_fill_info(vport, skb, portid, seq, 0, cmd);
	BUG_ON(retval < 0);

	return skb;
}
#endif

/* Called with ovs_mutex or RCU read lock. */
static struct vport *lookup_vport(struct net *net,
				  struct ovs_header *ovs_header,
				  struct nlattr *a[OVS_VPORT_ATTR_MAX + 1])
{
   return NULL;
}

int ovs_vport_cmd_new(char * port_name_ptr, int dp_ifindex,
                      u32 port_no, unsigned port_type)
{
    struct vport_parms parms;
    struct vport *vport;
    struct datapath *dp;
    int err;

    if (port_no >= DP_MAX_PORTS) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: port NO(%u) is larger than DP_MAX_PORTS(%u)\r\n",
                __FUNCTION__, port_no, DP_MAX_PORTS);
        return -EFBIG;
    }
 
   ovs_lock();
   dp = get_dp(dp_ifindex);
   err = -ENODEV;
   if (!dp) {
       SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: the specified dp with index(%d) is not exist\r\n",
               __FUNCTION__, dp_ifindex);
      goto exit_unlock_free;
   }

    if (port_no) {
        vport = ovs_vport_ovsl(dp, port_no);
        if (vport) {
            err = -EBUSY;
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: the specified vport with index(%d) is exist\r\n",
                    __FUNCTION__, port_no);
            goto exit_unlock_free;
        }
    }

    parms.name = (const char *) port_name_ptr;
    parms.type = port_type;
    parms.dp = dp;
    parms.port_no = port_no;

    vport = new_vport(&parms);
    if (IS_ERR(vport)) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: failed to new_vport\r\n", __FUNCTION__);
        err = PTR_ERR(vport);
        goto exit_unlock_free;
    }

//    err = 0;

    ovs_unlock();

    return 0;

exit_unlock_free:
   ovs_unlock();
   return err;
}



static int ovs_vport_cmd_set(struct sk_buff *skb, struct genl_info *info)
   {
      return 1;
   }


int ovs_vport_cmd_del(char * port_name_ptr, 
                             int dp_ifindex,
                             u32 port_no)
{
    struct vport *vport = NULL;
    struct datapath *dp = NULL;
    int err;

    if (port_no >= DP_MAX_PORTS) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: port NO(%u) is larger than DP_MAX_PORTS(%u)\r\n",
                __FUNCTION__, port_no, DP_MAX_PORTS);
        return -EFBIG;
    }

   ovs_lock();
   dp = get_dp(dp_ifindex);
   err = -ENODEV;
   if (!dp) {
       SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: the specified dp with index(%d) is not exist\r\n",
               __FUNCTION__, dp_ifindex);
      goto exit_unlock_free;
   }

   if (port_no != 0) {
     vport = ovs_vport_ovsl(dp, port_no);
   }else if (port_name_ptr){
     vport =  ovs_vport_locate((const char *)(port_name_ptr));
   }    

   if (!vport) {
      err = -EBUSY;
      SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: the specified vport with index(%d) not exist\r\n",
                __FUNCTION__, port_no);
      goto exit_unlock_free;
   }

   ovs_dp_detach_port(vport);
   ovs_unlock();

   return 0;

   exit_unlock_free:
   ovs_unlock();
   return err;
   }


static int ovs_vport_cmd_get(struct sk_buff *skb, struct genl_info *info)
   {
         return 1;
      }

void dump_vport(struct vport * port)
{
#define MAX_PRINT_STRING_LEN 1024
   char pstring[MAX_PRINT_STRING_LEN] = {0};
   int ps_offset = 0;

   if (NULL == port) {
      printf("%s: NULL vport\n", __func__); 
      return; 
   }
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      "----\n");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      STRING"\n", INDENTATION, "portname", port->port_name);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U32_1"\n", INDENTATION, "portno", port->port_no);
   //err stats
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      HEAD"\n", INDENTATION, "err_stats");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "rx_dropped", port->err_stats.rx_dropped);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "rx_errors", port->err_stats.rx_errors);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "tx_dropped", port->err_stats.tx_dropped);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "tx_errors", port->err_stats.tx_errors);
   /*//offset_stats
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      HEAD"\n", INDENTATION, "offset_stats");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "rx_packets", port->offset_stats.rx_packets);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "tx_packets", port->offset_stats.tx_packets);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "rx_bytes", port->offset_stats.rx_bytes);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "tx_bytes", port->offset_stats.tx_bytes);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "rx_errors", port->offset_stats.rx_errors);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "tx_errors", port->offset_stats.tx_errors);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "rx_dropped", port->offset_stats.rx_dropped);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "tx_dropped", port->offset_stats.tx_dropped);
   */
   //packet_stats
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      HEAD"\n", INDENTATION, "percpu_stats");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "percpu_stats.rx_packets", port->percpu_stats.rx_packets);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "percpu_stats.rx_bytes", port->percpu_stats.rx_bytes);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "percpu_stats.tx_packets", port->percpu_stats.tx_packets);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", INDENTATION_2, "percpu_stats.tx_bytes", port->percpu_stats.tx_bytes);

   printf("%s", pstring);
   return;
}

int ovs_vport_cmd_dump(struct datapath *dp)
{

   unsigned int i = 0;
   unsigned int port_count = 0;
   struct hlist_node *tmp = NULL;
   struct vport *vport = NULL;

   printf("  -----start to dump SE vport -----\n");
   for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++){
      hlist_for_each(tmp, &dp->ports[i]) {
        /* feed watchdog */
#ifndef _IS_LINUX_   
         cvmx_write64_uint64(CVMX_CIU_PP_POKEX(cvmx_get_core_num()), 0);
#endif
         vport = hlist_entry(tmp, struct vport, dp_hash_node);
         dump_vport(vport);
         port_count++;
      }   
   }
   printf("  ---- Totally %d port(s) under %s.\n", port_count, dp->dp_name);
   printf("  -----dump SE port finished -----\n");

   return 0;
}




extern int ovs_dynamic_flow_test(void);

int  ovs_main(void)
{
   memset(&g_ovs_net, 0, sizeof(g_ovs_net));
   INIT_LIST_HEAD(&(g_ovs_net.dps));
#ifndef _IS_LINUX_   
      cvmx_spinlock_init(&g_ovs_net.lock);
      init_all_mem_pools();
#endif

   ovs_vport_init();

   //ovs_dynamic_flow_test();

	return 0;

}

