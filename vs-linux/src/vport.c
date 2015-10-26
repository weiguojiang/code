/*
 * Copyright (c) 2007-2012 Nicira, Inc.
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
#include "ovs_debug.h"
#include "datapath.h"
#include "vport.h"
#include "vport-internal_dev.h"


extern int sedev_send(struct vport *vport, struct sk_buff *skb);

const CVMX_SHARED struct vport_ops ovs_sedev_vport_ops = {
	.type		= OVS_VPORT_TYPE_NETDEV,
	.create		= NULL,
	.destroy	= NULL,
	.get_name	= NULL,
	.send		= sedev_send,
};
const CVMX_SHARED struct vport_ops ovs_internal_vport_ops = {
	.type		= OVS_VPORT_TYPE_INTERNAL,
	.create		= NULL,
	.destroy	= NULL,
	.get_name	= NULL,
	.send		= NULL,
};


#ifdef _IS_LINUX_
int sedev_send(struct vport *vport, struct sk_buff *skb)
{

   printf("\n 539  sedev_send %d \n", vport->port_no);

   return 1;
}
#endif

static void ovs_vport_record_error(struct vport *,
				   enum vport_err_type err_type);


/* Protected by RCU read lock for reading, ovs_mutex for writing. */

#define VPORT_HASH_BUCKETS 256
static CVMX_SHARED struct hlist_head dev_table[VPORT_HASH_BUCKETS];
CVMX_SHARED cvmx_rwlock_wp_lock_t g_vport_list_rwlock;

/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem.
 */
int ovs_vport_init(void)
{
   int i = 0;
   for (i = 0; i < VPORT_HASH_BUCKETS; i++)
       INIT_HLIST_HEAD(&dev_table[i]);
   cvmx_rwlock_wp_init(&g_vport_list_rwlock);
	return 0;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem.
 */
void ovs_vport_exit(void)
{
   return;
}

struct hlist_head * hash_bucket(const char *name)
{
	unsigned int hash = jhash(name, strlen(name), 13413546);

	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with ovs or RCU read lock.
 */
struct vport *ovs_vport_locate(const char *name)
{
	struct hlist_head *bucket = hash_bucket(name);
	struct vport *vport = NULL;

   struct hlist_node *tmp;
   
   cvmx_rwlock_wp_read_lock(&g_vport_list_rwlock);
   hlist_for_each(tmp, bucket)
   {
      vport = hlist_entry(tmp, struct vport, hash_node);
//      vport = (struct vport *)((char *)tmp - (char *)&((struct vport *)0)->hash_node);

		if (!strcmp(name, &vport->port_name[0])){
         cvmx_rwlock_wp_read_unlock(&g_vport_list_rwlock);
			return vport;
      }
   }

   cvmx_rwlock_wp_read_unlock(&g_vport_list_rwlock);
	return NULL;
}
/*
   dump the vport based on the dev_table
*/
extern void dump_vport(struct vport * port);

int ovs_vport_dump_all(void)
{

   unsigned int i = 0;
   unsigned int port_count = 0;
   struct hlist_node *tmp = NULL;
   struct vport *vport = NULL;

   printf("  -----start to dump globle vport list -----\n");

   cvmx_rwlock_wp_read_lock(&g_vport_list_rwlock);
   for (i = 0; i < VPORT_HASH_BUCKETS; i++){
      hlist_for_each(tmp, &dev_table[i]) {
        /* feed watchdog */
#ifndef _IS_LINUX_   
        cvmx_write64_uint64(CVMX_CIU_PP_POKEX(cvmx_get_core_num()), 0);
#endif
         vport = hlist_entry(tmp, struct vport, hash_node);
         dump_vport(vport);
         port_count++;

      }   
   }
   cvmx_rwlock_wp_read_unlock(&g_vport_list_rwlock);
   
   printf("  ---- Totally is  %d port(s) \n", port_count);

   return 0;
}

/**
 *	ovs_vport_alloc - allocate and initialize new vport
 *
 * @priv_size: Size of private data area to allocate.
 * @ops: vport device ops
 *
 * Allocate and initialize a new vport defined by @ops.  The vport will contain
 * a private data area of size @priv_size that can be accessed using
 * vport_priv().  vports that are no longer needed should be released with
 * ovs_vport_free().
 */
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			      const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	alloc_size = sizeof(struct vport);
	if (priv_size) {
		alloc_size += priv_size;
	}

	vport = kzalloc(alloc_size, PORT_POOL_C);
	if (!vport) {
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR %s: alloc memory for vport failed\r\n", __FUNCTION__);
		return ERR_PTR(-ENOMEM);
	}

	vport->dp = parms->dp;
	vport->port_no = parms->port_no;
	vport->ops = ops;

	INIT_HLIST_NODE(&vport->dp_hash_node);
#if 0
	vport->percpu_stats = /*alloc_percpu*/(struct pcpu_sw_netstats*)malloc(sizeof(struct pcpu_sw_netstats));
	if (!vport->percpu_stats) {
		kfree(vport);
		return ERR_PTR(-ENOMEM);
	}

	for_each_possible_cpu(i) {
		struct pcpu_sw_netstats *vport_stats;
		vport_stats = NULL/* per_cpu_ptr(vport->percpu_stats, i)*/;
		u64_stats_init(&vport_stats->syncp);
	}
#endif

	return vport;
}

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with ovs_vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
void ovs_vport_free(struct vport *vport)
{
//	kfree((struct vport_portids __force *)vport->upcall_portids);
//	free_percpu(vport->percpu_stats);
	kfree(vport, PORT_POOL_C);
}

static const struct vport_ops *get_ops_by_vport_type(enum ovs_vport_type type) {
    const struct vport_ops *ops;

    switch (type) {
        case OVS_VPORT_TYPE_INTERNAL:
            ops = &ovs_internal_vport_ops;
            break;
        case OVS_VPORT_TYPE_NETDEV:
        default :
            ops = &ovs_sedev_vport_ops;
            break;
    }
    return ops;
}
/**
 *	ovs_vport_add - add vport device (for kernel callers)
 *
 * @parms: Information about new vport.
 *
 * Creates a new vport with the specified configuration (which is dependent on
 * device type).  ovs_mutex must be held.
 */
struct vport *ovs_vport_add(const struct vport_parms *parms)
{
    struct vport *vport;
    int err = 0;
    const struct vport_ops *ops;

    struct hlist_head *bucket;

    ops = get_ops_by_vport_type(parms->type);
    vport = ovs_vport_alloc(0, ops, parms);

    if (IS_ERR(vport)) {
        err = PTR_ERR(vport);
        goto out;
    }
    strncpy(vport->port_name, parms->name, 20);
    bucket = hash_bucket(vport->port_name);
    cvmx_rwlock_wp_write_lock(&g_vport_list_rwlock);
    hlist_add_head(&vport->hash_node, bucket);
    cvmx_rwlock_wp_write_unlock(&g_vport_list_rwlock);
    return vport;

out:
    return ERR_PTR(err);
}


/**
 *	ovs_vport_set_options - modify existing vport device (for kernel callers)
 *
 * @vport: vport to modify.
 * @options: New configuration.
 *
 * Modifies an existing device with the specified configuration (which is
 * dependent on device type).  ovs_mutex must be held.
 */
int ovs_vport_set_options(struct vport *vport, struct nlattr *options)
{
	if (!vport->ops->set_options)
		return -1;
	return vport->ops->set_options(vport, options);
}

/**
 *	ovs_vport_del - delete existing vport device
 *
 * @vport: vport to delete.
 *
 * Detaches @vport from its datapath and destroys it.  It is possible to fail
 * for reasons such as lack of memory.  ovs_mutex must be held.
 */
void ovs_vport_del(struct vport *vport)
{
	ASSERT_OVSL();

   cvmx_rwlock_wp_write_lock(&g_vport_list_rwlock);
	hlist_del_rcu(&vport->hash_node);
   cvmx_rwlock_wp_write_unlock(&g_vport_list_rwlock);
//	vport->ops->destroy(vport);
   kfree(vport, PORT_POOL_C);
}

/**
 *	ovs_vport_set_stats - sets offset device stats
 *
 * @vport: vport on which to set stats
 * @stats: stats to set
 *
 * Provides a set of transmit, receive, and error stats to be added as an
 * offset to the collected data when stats are retrieved.  Some devices may not
 * support setting the stats, in which case the result will always be
 * -EOPNOTSUPP.
 *
 * Must be called with ovs_mutex.
 */
void ovs_vport_set_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	//spin_lock_bh(&vport->stats_lock);
	vport->offset_stats = *stats;
	//spin_unlock_bh(&vport->stats_lock);
}

/**
 *	ovs_vport_get_stats - retrieve device stats
 *
 * @vport: vport from which to retrieve the stats
 * @stats: location to store stats
 *
 * Retrieves transmit, receive, and error stats for the given device.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
void ovs_vport_get_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	//int i;

	/* We potentially have 3 sources of stats that need to be
	 * combined: those we have collected (split into err_stats and
	 * percpu_stats), offset_stats from set_stats(), and device
	 * error stats from netdev->get_stats() (for errors that happen
	 * downstream and therefore aren't reported through our
	 * vport_record_error() function).
	 * Stats from first two sources are merged and reported by ovs over
	 * OVS_VPORT_ATTR_STATS.
	 * netdev-stats can be directly read over netlink-ioctl.
	 */

	//spin_lock_bh(&vport->stats_lock);

	*stats = vport->offset_stats;

	stats->rx_errors	+= vport->err_stats.rx_errors;
	stats->tx_errors	+= vport->err_stats.tx_errors;
	stats->tx_dropped	+= vport->err_stats.tx_dropped;
	stats->rx_dropped	+= vport->err_stats.rx_dropped;

	//spin_unlock_bh(&vport->stats_lock);

	for_each_possible_cpu(i) {
		const struct pcpu_sw_netstats *percpu_stats;
		struct pcpu_sw_netstats local_stats;
		unsigned int start;

		percpu_stats = NULL/*per_cpu_ptr(vport->percpu_stats, i)*/;

		do {
			start = u64_stats_fetch_begin_irq(&percpu_stats->syncp);
			local_stats = *percpu_stats;
		} while (u64_stats_fetch_retry_irq(&percpu_stats->syncp, start));

		stats->rx_bytes		+= local_stats.rx_bytes;
		stats->rx_packets	+= local_stats.rx_packets;
		stats->tx_bytes		+= local_stats.tx_bytes;
		stats->tx_packets	+= local_stats.tx_packets;
	}
}

/**
 *	ovs_vport_get_options - retrieve device options
 *
 * @vport: vport from which to retrieve the options.
 * @skb: sk_buff where options should be appended.
 *
 * Retrieves the configuration of the given device, appending an
 * %OVS_VPORT_ATTR_OPTIONS attribute that in turn contains nested
 * vport-specific attributes to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room, or another
 * negative error code if a real error occurred.  If an error occurs, @skb is
 * left unmodified.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct nlattr *nla;
	int err;

	if (!vport->ops->get_options)
		return 0;

	nla = nla_nest_start(skb, OVS_VPORT_ATTR_OPTIONS);
	if (!nla)
		return -1;

	err = vport->ops->get_options(vport, skb);
	if (err) {
		nla_nest_cancel(skb, nla);
		return err;
	}

	nla_nest_end(skb, nla);
	return 0;
}

static void vport_portids_destroy_rcu_cb(struct rcu_head *rcu)
{
	//struct vport_portids *ids = container_of(rcu, struct vport_portids,
						// rcu);

	//kfree(ids);
}

/**
 *	ovs_vport_set_upcall_portids - set upcall portids of @vport.
 *
 * @vport: vport to modify.
 * @ids: new configuration, an array of port ids.
 *
 * Sets the vport's upcall_portids to @ids.
 *
 * Returns 0 if successful, -EINVAL if @ids is zero length or cannot be parsed
 * as an array of U32.
 *
 * Must be called with ovs_mutex.
 */
int ovs_vport_set_upcall_portids(struct vport *vport,  struct nlattr *ids)
{
	struct vport_portids *old, *vport_portids;

	if (!nla_len(ids) || nla_len(ids) % sizeof(u32))
		return -EINVAL;

	old = ovsl_dereference(vport->upcall_portids);

	vport_portids = kmalloc(sizeof *vport_portids + nla_len(ids),
				MISC_POOL_C);
	if (!vport_portids)
		return -ENOMEM;

	vport_portids->n_ids = nla_len(ids) / sizeof(u32);
	//vport_portids->rn_ids = reciprocal_value(vport_portids->n_ids);
	nla_memcpy(vport_portids->ids, ids, nla_len(ids));

	rcu_assign_pointer(vport->upcall_portids, vport_portids);

	//if (old)
		//call_rcu(&old->rcu, vport_portids_destroy_rcu_cb);

	return 0;
}

/**
 *	ovs_vport_get_upcall_portids - get the upcall_portids of @vport.
 *
 * @vport: vport from which to retrieve the portids.
 * @skb: sk_buff where portids should be appended.
 *
 * Retrieves the configuration of the given vport, appending the
 * %OVS_VPORT_ATTR_UPCALL_PID attribute which is the array of upcall
 * portids to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room.
 * If an error occurs, @skb is left unmodified.  Must be called with
 * ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_upcall_portids(const struct vport *vport,
				 struct sk_buff *skb)
{
	struct vport_portids *ids;

	ids = rcu_dereference_ovsl(vport->upcall_portids);

	if (vport->dp->user_features & OVS_DP_F_VPORT_PIDS)
		return nla_put(skb, OVS_VPORT_ATTR_UPCALL_PID,
			       ids->n_ids * sizeof(u32), (void *) ids->ids);
	else
		return nla_put_u32(skb, OVS_VPORT_ATTR_UPCALL_PID, ids->ids[0]);
}

/**
 *	ovs_vport_find_upcall_portid - find the upcall portid to send upcall.
 *
 * @vport: vport from which the missed packet is received.
 * @skb: skb that the missed packet was received.
 *
 * Uses the skb_get_hash() to select the upcall portid to send the
 * upcall.
 *
 * Returns the portid of the target socket.  Must be called with rcu_read_lock.
 */
u32 ovs_vport_find_upcall_portid(const struct vport *p, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 hash;

	ids = rcu_dereference(p->upcall_portids);

	if (ids->n_ids == 1 && ids->ids[0] == 0)
		return 0;

	hash = skb_get_hash(skb);
	return ids->ids[hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids)];
}

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 * @tun_key: tunnel (if any) that carried packet
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.  The caller must have already
 * called compute_ip_summed() to initialize the checksumming fields.
 */
void ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
		       struct ovs_key_ipv4_tunnel *tun_key)
{
    struct ovs_pcpu_sw_netstats *stats;

    stats = &(vport->percpu_stats);

#ifdef OVS_STATS  //just for TOSE
    u64_stats_update_begin(&stats->syncp);
#ifdef _IS_LINUX_ 
    stats->rx_packets++;
    stats->rx_bytes += skb->len;
#else   
    cvmx_atomic_add64((int64_t * )&stats->rx_packets, 1);
    cvmx_atomic_add64((int64_t * )&stats->rx_bytes, skb->len);
#endif
    u64_stats_update_end(&stats->syncp);
#endif

    OVS_CB(skb)->fp_output_res = 0/*FP_CONTINUE*/;
    OVS_CB(skb)->tun_key = tun_key;
    ovs_dp_process_received_packet(vport, skb);
}

/**
 *	ovs_vport_send - send a packet on a device
 *
 * @vport: vport on which to send the packet
 * @skb: skb to send
 *
 * Sends the given packet and returns the length of data sent.  Either ovs
 * lock or rcu_read_lock must be held.
 */
int ovs_vport_send(struct vport *vport, struct sk_buff *skb)
{
    int sent = vport->ops->send(vport, skb);

    if (likely(sent > 0)) {
        struct ovs_pcpu_sw_netstats *stats;

        stats = &(vport->percpu_stats);

        //	u64_stats_update_begin(&stats->syncp);
#ifdef _IS_LINUX_ 
        stats->tx_packets++;
        stats->tx_bytes += sent;
#else   
        cvmx_atomic_add64((int64_t * )&stats->tx_packets, 1);
        cvmx_atomic_add64((int64_t * )&stats->tx_bytes, sent);
#endif
        //	u64_stats_update_end(&stats->syncp);
    } else if (sent < 0) {
        ovs_vport_record_error(vport, VPORT_E_TX_ERROR);
//        kfree_skb(skb);
    } else {
        struct dp_stats_percpu *dp_stats;

        dp_stats = &vport->dp->stats_percpu;
#ifdef _IS_LINUX_
        dp_stats->n_lost++;
#else
        cvmx_atomic_add64((int64_t *)&dp_stats->n_lost, 1);
#endif
        ovs_vport_record_error(vport, VPORT_E_TX_DROPPED);
    }
    return sent;
}

/**
 *	ovs_vport_record_error - indicate device error to generic stats layer
 *
 * @vport: vport that encountered the error
 * @err_type: one of enum vport_err_type types to indicate the error type
 *
 * If using the vport generic stats layer indicate that an error of the given
 * type has occurred.
 */
static void ovs_vport_record_error(struct vport *vport,
				   enum vport_err_type err_type)
{
	//spin_lock(&vport->stats_lock);

	switch (err_type) {
	case VPORT_E_RX_DROPPED:
		vport->err_stats.rx_dropped++;
		break;

	case VPORT_E_RX_ERROR:
		vport->err_stats.rx_errors++;
		break;

	case VPORT_E_TX_DROPPED:
		vport->err_stats.tx_dropped++;
		break;

	case VPORT_E_TX_ERROR:
		vport->err_stats.tx_errors++;
		break;
	}

	//spin_unlock(&vport->stats_lock);
}

static void free_vport_rcu(struct rcu_head *rcu)
{
	//struct vport *vport = container_of(rcu, struct vport, rcu);

	//ovs_vport_free(vport);
}

void ovs_vport_deferred_free(struct vport *vport)
{
	if (!vport)
		return;

	//call_rcu(&vport->rcu, free_vport_rcu);
}
