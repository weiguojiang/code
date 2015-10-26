#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"

#include "datapath.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vlan.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"
#include <stdio.h>

extern int ovs_dp_cmd_del(int dp_ifindex);
extern int ovs_flow_cmd_del(struct sw_flow_key *key,
                      int dp_ifindex);

extern int dynamic_add_vports(int dp_index);

extern int ovs_dp_cmd_dump(void);
extern struct hlist_head * hash_bucket(const char *name);
extern struct hlist_head *vport_hash_bucket(const struct datapath *dp,
					    u16 port_no);

extern void sw_flow_mask_set(struct sw_flow_mask *mask,
			     struct sw_flow_key_range *range, u8 val);

extern void update_range__(struct sw_flow_match *match,
			   size_t offset, size_t size, bool is_mask);
extern unsigned int ip_str_to_num(const char *buf);

extern int  cvm_ovs_flow_cmd_dump(struct datapath *dp);

#define eipu3_dst_ip "22.22.22.14"
#define eipu2_ping_ip "22.22.22.19"
#define TEST_IP_ACTION
#define TEST_MAC_ACTION
#define TEST_UDPPORT_ACTION

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


extern const struct vport_ops ovs_sedev_vport_ops;


struct flex_array_part {
	char elements[4096];
};


struct flex_array {
	union {
		struct {
			int element_size;
			int total_nr_elements;
			int elems_per_part;
			struct reciprocal_value reciprocal_elems;
			struct flex_array_part *parts[];
		};
		/*
		 * This little trick makes sure that
		 * sizeof(flex_array) == PAGE_SIZE
		 */
		char padding[4096];
	};
};

struct internal_dev {
	struct vport *vport;
};

typedef struct fake_ovs_vport{
   struct vport  vport;
   struct pcpu_sw_netstats percpu_stats;
   struct netdev_vport netdev_vport;   
   struct net_device   net_device;
   struct internal_dev internal_dev; 
}fake_ovs_vport_t;

typedef struct fake_ovs_flow{
   struct sw_flow flow;
   struct flow_stats stats[1];
   struct sw_flow_mask mask;
   struct sw_flow_actions sf_acts;
   char  sf_action_content[96];  
}fake_ovs_flow_t;


typedef struct fake_mask_array{
	struct rcu_head rcu;
	int count, max;
	struct sw_flow_mask *masks[16];     
}fake_mask_array_t;


typedef struct fake_ovs_map_st{
   struct datapath  datapath;
   struct dp_stats_percpu stats_percpu[16];

   struct hlist_head vport_hash[DP_VPORT_HASH_BUCKETS];
   fake_ovs_vport_t  fake_port[100];

/* 
    we need 16 array for mask_cache_entry
*/
   struct mask_cache_entry mask_cache_entry[256];  
      
   struct fake_mask_array mask_array;
   struct sw_flow_mask * masks[16];

   struct table_instance table_instance;

   struct flex_array buckets;
   struct flex_array_part part[10]; 

   fake_ovs_flow_t  flow_array[100];

}fake_ovs_map_t;

struct ovs_action_set_ipv4_header {
	 struct nlattr nn1;
	struct ovs_key_ipv4 ipv4;
};

struct ovs_action_set_mac_header {
	 struct nlattr nn1;
	struct ovs_key_ethernet mac;
};

struct ovs_action_set_udp_header {
	 struct nlattr nn1;
	 struct ovs_key_udp udpkey;
};

CVMX_SHARED fake_ovs_map_t   fake_ovs_map;


int fake_create_internal_vport(fake_ovs_map_t *fake_ovs_map_ptr)
{
   struct datapath * datapath_ptr = &(fake_ovs_map_ptr->datapath);
   struct vport *vport;
   struct netdev_vport *netdev_vport;
  // struct internal_dev *internal_dev;

   fake_ovs_vport_t *fake_ovs_vport_ptr = &(fake_ovs_map_ptr->fake_port[0]);
   
   vport = &(fake_ovs_vport_ptr->vport);
   vport->dp = datapath_ptr;
   vport->port_no= OVSP_LOCAL;
//   vport->percpu_stats = &fake_ovs_vport_ptr->percpu_stats;

   INIT_HLIST_NODE(&vport->dp_hash_node);
   INIT_HLIST_NODE(&vport->hash_node);

   netdev_vport = &fake_ovs_vport_ptr->netdev_vport;
   netdev_vport->dev = &fake_ovs_vport_ptr->net_device;

   sprintf(&vport->port_name[0],"ovs%d", 0);

//   internal_dev = &fake_ovs_vport_ptr->internal_dev;
//   internal_dev->vport = vport;

/*
    create hash list between datapath and vport.
*/
   struct hlist_head *head = vport_hash_bucket(datapath_ptr, vport->port_no);
   
   hlist_add_head(&vport->dp_hash_node, head);

  /*
       create hash list between devtable and vport.
   */
   struct hlist_head *bucket = hash_bucket(&vport->port_name[0]);
   
   hlist_add_head(&vport->hash_node, bucket);

   return 0;
}


int fake_create_netdev_vport(fake_ovs_map_t *fake_ovs_map_ptr, int index)
{
   struct datapath * datapath_ptr = &(fake_ovs_map_ptr->datapath);
   struct vport *vport;
   struct netdev_vport *netdev_vport;

   fake_ovs_vport_t *fake_ovs_vport_ptr = &(fake_ovs_map_ptr->fake_port[index]);
   
   vport = &(fake_ovs_vport_ptr->vport);
   vport->dp = datapath_ptr;
   vport->port_no= index;
//   vport->percpu_stats = &fake_ovs_vport_ptr->percpu_stats;
   vport->ops = &ovs_sedev_vport_ops;
    
   INIT_HLIST_NODE(&vport->dp_hash_node);
   INIT_HLIST_NODE(&vport->hash_node);

   netdev_vport = &fake_ovs_vport_ptr->netdev_vport;
   netdev_vport->dev = &fake_ovs_vport_ptr->net_device;

/*
   init the port name based on the port-number
*/   
  sprintf(&vport->port_name[0],"sfp%d", index);

/*
    create hash list between datapath and vport.
*/
   struct hlist_head *head = vport_hash_bucket(datapath_ptr, vport->port_no);
   
   hlist_add_head(&vport->dp_hash_node, head);

  /*
       create hash list between devtable and vport.
   */

   struct hlist_head *bucket = hash_bucket(&vport->port_name[0]);
   
   hlist_add_head(&vport->hash_node, bucket);

   return 0;
}

extern struct flex_array *alloc_buckets(unsigned int n_buckets);
extern struct sw_flow_mask *flow_mask_find(const struct flow_table *tbl,
                     const struct sw_flow_mask *mask);
extern u32 flow_hash(const struct sw_flow_key *key, int key_start,
		     int key_end);


extern void fake_init_buckets(unsigned int n_buckets, struct flex_array *buckets);

extern void table_instance_insert(struct table_instance *ti, struct sw_flow *flow);
#define TBL_MIN_BUCKETS		200


int fake_ovs_flowtable_init(fake_ovs_map_t *fake_ovs_map_ptr)
{
   struct datapath * dp = &(fake_ovs_map_ptr->datapath);
	struct flow_table *table = &dp->table;

//   ovs_flow_tbl_init(table);

   table->mask_cache = &fake_ovs_map_ptr->mask_cache_entry[0];

	struct table_instance *ti;
	struct mask_array *ma;

/* 
     allocate mask_array
*/
	ma = (struct mask_array *)&fake_ovs_map_ptr->mask_array;
   ma->count = 0;
   ma->max = 16;

/*
   allocate table_instance
*/

	ti = &fake_ovs_map_ptr->table_instance;

#if 0      
   ti->buckets = alloc_buckets(200);
//   fake_ovs_map_ptr->buckets = *(ti->buckets);
#else
   ti->buckets = &(fake_ovs_map_ptr->buckets);
   fake_init_buckets(TBL_MIN_BUCKETS, &(fake_ovs_map_ptr->buckets));
#endif
 	ti->n_buckets = TBL_MIN_BUCKETS; /* not use default 1024 */
	ti->node_ver = 0;
	ti->keep_flows = false;  
   ti->hash_seed = 1999; //get_random_bytes

	rcu_assign_pointer(table->ti, ti);
	rcu_assign_pointer(table->mask_array, ma);
	table->last_rehash = jiffies;
	table->count = 0;
	return 0;
           
}

int fake_ovs_flowtable_create(fake_ovs_map_t *fake_ovs_map_ptr, int index )
{
   struct datapath * dp = &(fake_ovs_map_ptr->datapath);

	struct sw_flow *flow, *new_flow;
	struct sw_flow_mask *mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;

/*
    simulate ovs_flow_alloc to get new_flow and init it
*/
   fake_ovs_flow_t * fake_flow_ptr = &fake_ovs_map_ptr->flow_array[index];
	new_flow = &fake_flow_ptr->flow;
   
   new_flow->sf_acts = NULL;
	new_flow->mask = NULL;
//   new_flow->stats[0] = &fake_flow_ptr->stats[0];
   
   mask = &fake_flow_ptr->mask;
   ovs_match_init(&match, &new_flow->unmasked_key, mask);
   
/*
    do some key in the flow just like ovs_key_from_nlattrs
*/

   SW_FLOW_KEY_PUT(&match, phy.in_port, index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(mask, &match.range, 0xff);
	ovs_flow_mask_key(&new_flow->key, &new_flow->unmasked_key, mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 
   
   acts = & fake_flow_ptr->sf_acts;
   acts->actions_len = 8 ; /* it's the all len of the actions content.*/
   acts->actions->nla_type = OVS_ACTION_ATTR_OUTPUT;
   acts->actions->nla_len = 8;
   int l_out_index = 12;
   if(index ==  12)
      l_out_index = 13;
   *((u32 *)&(fake_flow_ptr->sf_action_content[0])) = l_out_index;

   struct vlan_attr
   {
      struct nlattr  nl;
      struct ovs_action_push_vlan tag;
   };

    struct vlan_attr vlan;
    vlan.nl.nla_len = 8;
    vlan.nl.nla_type = OVS_ACTION_ATTR_PUSH_VLAN;
    vlan.tag.vlan_tci = index;
    vlan.tag.vlan_tpid = 0;
    
    *((struct vlan_attr *)&(fake_flow_ptr->sf_action_content[4])) = vlan;
    
    new_flow->sf_acts = acts;


//   flow = ovs_flow_tbl_lookup(&dp->table, &new_flow->unmasked_key);
    flow = NULL;
   if (likely(!flow)){
#if 0      
      error = ovs_flow_tbl_insert(&dp->table, new_flow, mask);
#else
      /* simulate flow_mask_insert */
      struct flow_table *table = &dp->table;
      struct sw_flow_mask * l_mask;
      int i  = 0;
      
      l_mask = flow_mask_find(table, mask);
      if (l_mask){
         printf("\n 777 flow_mask_find exist for %d  \n", index);
         l_mask->ref_count ++;
         new_flow->mask = l_mask;   
      }else{
         printf("\n 777 flow_mask_find not  for %d  \n", index);
            
         mask->ref_count =1;
         struct mask_array  * ma = (table->mask_array);

   		for (i = 0; i < (int)ma->max; i++) {
   			struct sw_flow_mask *t;

   			t = (ma->masks[i]);
   			if (!t) {
   				ma->masks[i] = mask;
   				ma->count++;
   				break;
   			}
   		}
         
         new_flow->mask = mask;
      }
            
      new_flow->hash = flow_hash(&new_flow->key, new_flow->mask->range.start,
         new_flow->mask->range.end);

      
      table_instance_insert(table->ti, new_flow);
      table->count++;
#endif
   }

	return 0;
   
}


int fake_ovs_dp_init(fake_ovs_map_t *fake_ovs_map_ptr)
{
   struct datapath * datapath_ptr = &(fake_ovs_map_ptr->datapath);
	int i;
  
//	datapath_ptr->stats_percpu = (struct dp_stats_percpu *)&fake_ovs_map_ptr->stats_percpu;  
	datapath_ptr->ports = &fake_ovs_map_ptr->vport_hash[0];
   
	for (i = 0; i < DP_VPORT_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&datapath_ptr->ports[i]);

   return 0;
}
/*
   we want to create one datapath ovs1 with 2 port: sfp1,sfp2
   then create two flow entry in the flow table.
*/

int fake_ovs_dp_cmd_new(void)
{

   memset(&fake_ovs_map, 0, sizeof(fake_ovs_map));
   
   fake_ovs_dp_init(&fake_ovs_map);
   fake_ovs_flowtable_init(&fake_ovs_map);

   fake_create_internal_vport(&fake_ovs_map);

   int i = 1;
   while (i < 18){
      fake_create_netdev_vport(&fake_ovs_map, i);
      i ++;
   }


/* 
   create hash for datapath
*/
#if 0
	ovs_net = &ovs_net;
	list_add_tail(&dp->list_node, &ovs_net->dps);
#endif

	return 0;


}


#define ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))
#define L1_CACHE_SHIFT 5
#define L1_CACHE_BYTES (1 << L1_CACHE_SHIFT)
#define SKB_DATA_ALIGN(X)	ALIGN(X, L1_CACHE_BYTES)


struct sk_buff g_skb;
char data[4096];
struct sk_buff * _alloc_skb(unsigned int length)
{
	struct sk_buff *skb = &g_skb;

	unsigned int fragsz = SKB_DATA_ALIGN(length + 32) +
			       SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	skb->head = (unsigned char*)data;
	skb->data = (unsigned char*)data + 100;
   skb_reset_tail_pointer(skb);
	skb->end = skb->tail + fragsz;

   memset(data, 0, 1500);
//	struct skb_shared_info *shinfo;

//	shinfo = skb_shinfo(skb);
//	memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
//	shinfo->dataref.counter =  1;

	return skb;
}


int fake_vlan_ip(struct sk_buff *skb)
{

   skb_reserve(skb, 2);
 
   struct vlan_ethhdr veth ;

   veth.h_dest[0]= '3';
   veth.h_source[0]= '3';   
   veth.h_vlan_encapsulated_proto = htons(ETH_P_IP);
   
   veth.h_vlan_proto = (( __be16)(__u16)htons(ETH_P_8021Q));
   veth.h_vlan_TCI = 100;

   memcpy(skb_put(skb, sizeof(veth)),    
           &veth,              
           sizeof(veth));   

   struct iphdr  nh;

   nh.version = 4;
   nh.ihl = 5;
   nh.tos = 0;
   nh.tot_len = 84;
   nh.id = 2585;
   nh.frag_off= 0;
   nh.ttl = 12;
   nh.protocol = IPPROTO_UDP;
   nh.check = 0;
   nh.saddr = 12343;
   nh.daddr = 22222;

   memcpy(skb_put(skb, sizeof(nh)),    
           &nh,              
           sizeof(nh));

// skb->len = 98;
   skb->data_len = 0;

#if 0
   struct icmphdr icmp;
   icmp.type = 8;
   icmp.code = 0;

    memcpy(skb_put(skb, sizeof(icmp)),    
        &icmp,              
        sizeof(icmp));
#endif

   struct udphdr udp ;
   udp.source = 1000;
   udp.dest= 2000;

   memcpy(skb_put(skb, sizeof(udp)),    
       &udp,              
       sizeof(udp));

/*
   need set the protocol, since skb_flow_dissect will check the skb->protocol
   another opnion is key_extract set this protocol

*/
//   skb->protocol = htons(ETH_P_IP);		

//   skb->ip_summed = 0;

//	skb->priority = 100;
//   skb->mark = 1;

   return 0;
}

int fake_eth_ip(struct sk_buff *skb)
{

   struct ethhdr eth;
  
   eth.h_dest[0]= '3';
   eth.h_source[0]= '3';   
   eth.h_proto = htons(ETH_P_IP);

   skb_reserve(skb, 2);

   memcpy(skb_put(skb, sizeof(eth)),    
           &eth,              
           sizeof(eth));

   struct iphdr  nh;

   nh.version = 4;
   nh.ihl = 5;
   nh.tos = 0;
   nh.tot_len = 84;
   nh.id = 2585;
   nh.frag_off= 0;
   nh.ttl = 12;
   nh.protocol = IPPROTO_UDP;
   nh.check = 0;
   nh.saddr = 12343;
   nh.daddr = 22222;

   memcpy(skb_put(skb, sizeof(nh)),    
           &nh,              
           sizeof(nh));

// skb->len = 98;
   skb->data_len = 0;

#if 0
   struct icmphdr icmp;
   icmp.type = 8;
   icmp.code = 0;

    memcpy(skb_put(skb, sizeof(icmp)),    
        &icmp,              
        sizeof(icmp));
#endif

   struct udphdr udp ;
   udp.source = 1000;
   udp.dest= 2000;

   memcpy(skb_put(skb, sizeof(udp)),    
       &udp,              
       sizeof(udp));

/*
   need set the protocol, since skb_flow_dissect will check the skb->protocol
   another opnion is key_extract set this protocol

*/
//   skb->protocol = htons(ETH_P_IP);		

//   skb->ip_summed = 0;

//	skb->priority = 100;
//   skb->mark = 1;

   return 0;
}
   

int fake_poll(void)
{

   struct sk_buff *skb = _alloc_skb(1311);

   fake_eth_ip(skb);
   ovs_set_tci(skb);
   
   struct vport *vport;
   vport =  ovs_vport_locate("sfp16");
   if(vport)
	   ovs_vport_receive(vport, skb, NULL);


   skb = _alloc_skb(1311);

   fake_vlan_ip(skb);
   ovs_set_tci(skb);
   
   vport =  ovs_vport_locate("sfp15");
   if(vport)
	   ovs_vport_receive(vport, skb, NULL);

   return 1;
}


int do_poll(void)
{

   struct sk_buff *skb = _alloc_skb(1311);

   fake_eth_ip(skb);
   
   struct vport *vport;
   vport = &(fake_ovs_map.fake_port[5].vport);

	ovs_vport_receive(vport, skb, NULL);

   return 1;
}


int  ovs_static_flow_test(void)
{

   printf("enter ovs_static_flow_test \n");


   fake_ovs_dp_cmd_new();

   int i = 0;
   do{   
      fake_ovs_flowtable_create(&fake_ovs_map,i );
      i ++;
   }while(i < 20);

   
   do_poll();

   printf("exit ovs_static_flow_test \n");

	return 0;
}


extern int ovs_vport_cmd_del(char * port_name_ptr, 
                                int dp_ifindex,
                                u32 port_no);

extern  int ovs_dp_cmd_new(int ifindex, char *dp_name);


extern int ovs_vport_cmd_new(char * port_name_ptr, int dp_ifindex,
                      u32 port_no, unsigned port_type);

extern int ovs_flow_cmd_new(struct sw_flow_key *key,
                     struct sw_flow_key *unmasked_key,
                      struct sw_flow_mask *mask,
                      struct sw_flow_actions *acts,
                      int dp_ifindex);




typedef struct fake_ovs_flow_action{
   struct sw_flow_actions sf_acts;
   char  sf_action_content[96];  
}fake_ovs_flow__action_t;



int do_fake_ovs_flow_del(int index, int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_match match;

   printf("\n\n do_fake_ovs_flow_del with %d  \n", index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  

    ovs_flow_cmd_del(&new_flow.unmasked_key,dp_index);

	return 0;
   
}


int do_fake_ovs_flow_new(int index, int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
   struct fake_ovs_flow_action  fake_actoin;

   printf("\n\n do_fake_ovs_flow_new with %d  \n", index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   memset(&fake_actoin, 0, sizeof(fake_actoin));
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(&mask, &match.range, 0xff);
	ovs_flow_mask_key(&new_flow.key, &new_flow.unmasked_key, &mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 
   struct push_vlan_action
   {
      struct nlattr  n1;
      struct ovs_action_push_vlan tag;
      struct nlattr  n2;
      int port;      
   };

   struct push_vlan_action push_vlan;
   push_vlan.n1.nla_len = 8;
   push_vlan.n1.nla_type = OVS_ACTION_ATTR_PUSH_VLAN;
   push_vlan.tag.vlan_tci = 33;
   push_vlan.tag.vlan_tpid = 0;

   push_vlan.n2.nla_len = 8;
   push_vlan.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
   push_vlan.port = 15;
// action for input port = 16   

  struct pop_vlan_action
  {
     struct nlattr  n1;
     struct nlattr  n2;
     int port;      
  };
  
  struct pop_vlan_action pop_vlan;
  pop_vlan.n1.nla_len = 4;
  pop_vlan.n1.nla_type = OVS_ACTION_ATTR_POP_VLAN;
  
  pop_vlan.n2.nla_len = 8;
  pop_vlan.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
  pop_vlan.port = 16;
// action for input port = 15   


   struct output_action
   {
      struct nlattr  n2;
      int port;      
   };

   struct output_action output_12;

   output_12.n2.nla_len = 8;
   output_12.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
   output_12.port = 12;
// action for other input port    

 struct output_action output_11;
 
 output_11.n2.nla_len = 8;
 output_11.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
 output_11.port = 11;



 /*
    action end
 */

  void * tmp_action = NULL;
  int tmp_action_len = 0;

#if 0  
  if(index == 16)
  {
     tmp_action = &push_vlan;
     tmp_action_len = sizeof(push_vlan);
  }
  else if(index == 15)
  {
     tmp_action = &pop_vlan;
     tmp_action_len = sizeof(pop_vlan);
  }
  else
  {
     tmp_action = &output;
     tmp_action_len = sizeof(output);
  }
#endif
  if(index == 11)
  {
     tmp_action = &output_12;
     tmp_action_len = sizeof(output_12);
  }
  else
  {
     tmp_action = &output_11;
     tmp_action_len = sizeof(output_11);
  }

  acts = &(fake_actoin.sf_acts);
  acts->actions_len = tmp_action_len ; /* it's the all len of the actions content.*/
      
  memcpy((char*)(acts->actions),
         tmp_action,
         tmp_action_len);
    ovs_flow_cmd_new(&new_flow.key, &new_flow.unmasked_key,
                      &mask,
                      acts,
                      dp_index);

	return 0;
   
}

#ifdef TEST_IP_ACTION

int do_fake_ovs_flow_new_ip_go(int in_index, int out_index,int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
   struct fake_ovs_flow_action  fake_actoin;

   printf("\n\n do_fake_ovs_flow_new with %d  \n", in_index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   memset(&fake_actoin, 0, sizeof(fake_actoin));
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, in_index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(&mask, &match.range, 0xff);
	ovs_flow_mask_key(&new_flow.key, &new_flow.unmasked_key, &mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 

   struct set_ip_action
   {
      struct nlattr  n1;
      struct ovs_action_set_ipv4_header tag;
      struct nlattr  n2;
      int port;      
   };

   struct set_ip_action act_ipv4;
   
   memset(&act_ipv4, 0, sizeof(act_ipv4));
   
   printf("\n sizeof(set_ip_action)= %d sizeof(ovs_key_ipv4)=%d \n", (int)sizeof(act_ipv4), (int)sizeof(struct ovs_key_ipv4));
   act_ipv4.n1.nla_len = 20;
   act_ipv4.n1.nla_type = OVS_ACTION_ATTR_SET;
   act_ipv4.tag.nn1.nla_len = 16;
   act_ipv4.tag.nn1.nla_type = OVS_KEY_ATTR_IPV4;
   act_ipv4.tag.ipv4.ipv4_dst = ip_str_to_num((const char *)eipu3_dst_ip);

   act_ipv4.n2.nla_len = 8;
   act_ipv4.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
   act_ipv4.port = out_index;

   acts = &(fake_actoin.sf_acts);
   acts->actions_len = 28 ; /* it's the all len of the actions content.*/

   memcpy((char*)(acts->actions),
          (char*)&act_ipv4,
          sizeof(act_ipv4));
    ovs_flow_cmd_new(&new_flow.key, &new_flow.unmasked_key,
                      &mask,
                      acts,
                      dp_index);

	return 0;
   
}





int do_fake_ovs_flow_new_ip_back(int in_index, int out_index, int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
   struct fake_ovs_flow_action  fake_actoin;

   printf("\n\n do_fake_ovs_flow_new with in=%d out=%d  \n", in_index, out_index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   memset(&fake_actoin, 0, sizeof(fake_actoin));
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, in_index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(&mask, &match.range, 0xff);
	ovs_flow_mask_key(&new_flow.key, &new_flow.unmasked_key, &mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 
     struct set_ip_action
      {
         struct nlattr  n1;
         struct ovs_action_set_ipv4_header tag;
         struct nlattr  n2;
         int port;      
      };
    
      struct set_ip_action act_ipv4;
      
      memset(&act_ipv4, 0, sizeof(act_ipv4));
      
      printf("\n do_fake_ovs_flow_new_ip_back sizeof(set_ip_action)= %d sizeof(ovs_key_ipv4)=%d \n", (int)sizeof(act_ipv4), (int)sizeof(struct ovs_key_ipv4));
      act_ipv4.n1.nla_len = 20;
      act_ipv4.n1.nla_type = OVS_ACTION_ATTR_SET;
      act_ipv4.tag.nn1.nla_len = 16;
      act_ipv4.tag.nn1.nla_type = OVS_KEY_ATTR_IPV4;
      act_ipv4.tag.ipv4.ipv4_src = ip_str_to_num((const char *)eipu2_ping_ip);
    
      act_ipv4.n2.nla_len = 8;
      act_ipv4.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
      act_ipv4.port = out_index;
    
      acts = &(fake_actoin.sf_acts);
      acts->actions_len = 28 ; /* it's the all len of the actions content.*/
    
      memcpy((char*)(acts->actions),
             (char*)&act_ipv4,
             sizeof(act_ipv4));
       ovs_flow_cmd_new(&new_flow.key, &new_flow.unmasked_key,
                         &mask,
                         acts,
                         dp_index);
    
       return 0;
   
}
#endif

#ifdef TEST_MAC_ACTION

int do_fake_ovs_flow_new_mac_go(int in_index, int out_index,int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
   struct fake_ovs_flow_action  fake_actoin;

   printf("\n\n do_fake_ovs_flow_new_mac_go with %d  \n", in_index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   memset(&fake_actoin, 0, sizeof(fake_actoin));
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, in_index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(&mask, &match.range, 0xff);
   ovs_flow_mask_key(&new_flow.key, &new_flow.unmasked_key, &mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 

   struct set_mac_action
   {
      struct nlattr  n1;
      struct ovs_action_set_mac_header tag;
      struct nlattr  n2;
      int port;      
   };

   struct set_mac_action act_mac;
   
   memset(&act_mac, 0, sizeof(act_mac));
   
   act_mac.n1.nla_len = 20;
   act_mac.n1.nla_type = OVS_ACTION_ATTR_SET;
   act_mac.tag.nn1.nla_len = 16;
   act_mac.tag.nn1.nla_type = OVS_KEY_ATTR_ETHERNET;
   act_mac.tag.mac.eth_dst[0] = 0x0;    //HWaddr 00:D0:C9:D9:7E:2D
   act_mac.tag.mac.eth_dst[1] = 0xd0;  
   act_mac.tag.mac.eth_dst[2] = 0xc9;   
   act_mac.tag.mac.eth_dst[3] = 0xd9;   
   act_mac.tag.mac.eth_dst[4] = 0x7e;   
   act_mac.tag.mac.eth_dst[5] = 0x2d;   

   act_mac.n2.nla_len = 8;
   act_mac.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
   act_mac.port = out_index;

   acts = &(fake_actoin.sf_acts);
   acts->actions_len = 28 ; /* it's the all len of the actions content.*/

   memcpy((char*)(acts->actions),
          (char*)&act_mac,
          sizeof(act_mac));
    ovs_flow_cmd_new(&new_flow.key, &new_flow.unmasked_key,
                      &mask,
                      acts,
                      dp_index);

	return 0;
   
}


int do_fake_ovs_flow_new_mac_back(int in_index, int out_index, int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
   struct fake_ovs_flow_action  fake_actoin;

   printf("\n\n do_fake_ovs_flow_new with in=%d out=%d  \n", in_index, out_index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   memset(&fake_actoin, 0, sizeof(fake_actoin));
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, in_index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(&mask, &match.range, 0xff);
	ovs_flow_mask_key(&new_flow.key, &new_flow.unmasked_key, &mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 
     struct set_normal_action
      {
         struct nlattr  n2;
         int port;      
      };
    
      struct set_normal_action act;
      
      memset(&act, 0, sizeof(act));
      
      act.n2.nla_len = 8;
      act.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
      act.port = out_index;
    
      acts = &(fake_actoin.sf_acts);
      acts->actions_len = 8 ; /* it's the all len of the actions content.*/
    
      memcpy((char*)(acts->actions),
             (char*)&act,
             sizeof(act));
       ovs_flow_cmd_new(&new_flow.key, &new_flow.unmasked_key,
                         &mask,
                         acts,
                         dp_index);
    
       return 0;
   
}
#endif

#ifdef TEST_UDPPORT_ACTION

int do_fake_ovs_flow_new_udp_go(int in_index, int out_index,int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
   struct fake_ovs_flow_action  fake_actoin;

   printf("\n\n do_fake_ovs_flow_new_mac_go with %d  \n", in_index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   memset(&fake_actoin, 0, sizeof(fake_actoin));
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, in_index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(&mask, &match.range, 0xff);
   ovs_flow_mask_key(&new_flow.key, &new_flow.unmasked_key, &mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 

   struct set_udp_action
   {
      struct nlattr  n1;
      struct ovs_action_set_udp_header tag;
      struct nlattr  n2;
      int port;      
   };

   struct set_udp_action act_udp;
   
   memset(&act_udp, 0, sizeof(act_udp));
   
   act_udp.n1.nla_len = 12;
   act_udp.n1.nla_type = OVS_ACTION_ATTR_SET;
   act_udp.tag.nn1.nla_len = 8;
   act_udp.tag.nn1.nla_type = OVS_KEY_ATTR_UDP;
   act_udp.tag.udpkey.udp_src = 0;    
   act_udp.tag.udpkey.udp_dst = 600;  //server listen at 400 port
   
   act_udp.n2.nla_len = 8;
   act_udp.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
   act_udp.port = out_index;

   acts = &(fake_actoin.sf_acts);
   acts->actions_len = 20 ; /* it's the all len of the actions content.*/

   memcpy((char*)(acts->actions),
          (char*)&act_udp,
          sizeof(act_udp));
    ovs_flow_cmd_new(&new_flow.key, &new_flow.unmasked_key,
                      &mask,
                      acts,
                      dp_index);

	return 0;
   
}


int do_fake_ovs_flow_new_udp_back(int in_index, int out_index,int dp_index)
{

	struct sw_flow new_flow;
	struct sw_flow_mask mask;
	struct sw_flow_actions *acts;
	struct sw_flow_match match;
   struct fake_ovs_flow_action  fake_actoin;

   printf("\n\n do_fake_ovs_flow_new_mac_go with %d  \n", in_index);

   memset(&new_flow, 0, sizeof(new_flow));
   memset(&mask, 0, sizeof(mask));
   memset(&match, 0, sizeof(match));   
   memset(&fake_actoin, 0, sizeof(fake_actoin));
   
   ovs_match_init(&match, &new_flow.unmasked_key, &mask);
   

   SW_FLOW_KEY_PUT(&match, phy.in_port, in_index, false);

/*
   SW_FLOW_KEY_PUT(&match, eth.tci, htons(0xffff), true);
   SW_FLOW_KEY_PUT(&match, eth.type, htons(ETH_P_802_2), false);

   SW_FLOW_KEY_PUT(&match, tp.src, 2000, false);
   SW_FLOW_KEY_PUT(&match, tp.dst, 3000, false);
*/

 /* 
     Populate exact match flow's key mask. 
 */  
   sw_flow_mask_set(&mask, &match.range, 0xff);
   ovs_flow_mask_key(&new_flow.key, &new_flow.unmasked_key, &mask);

/*
    just like ovs_nla_copy_actions  and copy_action 
*/ 

   struct set_udp_action
   {
      struct nlattr  n1;
      struct ovs_action_set_udp_header tag;
      struct nlattr  n2;
      int port;      
   };

   struct set_udp_action act_udp;
   
   memset(&act_udp, 0, sizeof(act_udp));
   
   act_udp.n1.nla_len = 12;
   act_udp.n1.nla_type = OVS_ACTION_ATTR_SET;
   act_udp.tag.nn1.nla_len = 8;
   act_udp.tag.nn1.nla_type = OVS_KEY_ATTR_UDP;
   act_udp.tag.udpkey.udp_src = 650;    //client:nc -u 22.22.22.14 650 server:nc -ul -p 600
   act_udp.tag.udpkey.udp_dst = 0;  
   
   act_udp.n2.nla_len = 8;
   act_udp.n2.nla_type = OVS_ACTION_ATTR_OUTPUT;
   act_udp.port = out_index;

   acts = &(fake_actoin.sf_acts);
   acts->actions_len = 20 ; /* it's the all len of the actions content.*/

   memcpy((char*)(acts->actions),
          (char*)&act_udp,
          sizeof(act_udp));
    ovs_flow_cmd_new(&new_flow.key, &new_flow.unmasked_key,
                      &mask,
                      acts,
                      dp_index);

	return 0;
   
}



#endif

int dynamic_add_vports(int dp_index)
{
   int i = 8;
   char * name_array[32] = {
      "sfp0",
      "sfp1",
      "sfp2",
      "sfp3",
      "sfp4",
      "sfp5",
      "sfp6",
      "sfp7",
      "sfp8",
      "sfp9",
      "sfp10",
      "sfp11",
      "sfp12",
      "sfp13",
      "sfp14",
      "sfp15",
      "sfp16",
      "sfp17",
      "sfp18",
      "sfp19",
      "sfp20"
      };
      
   
   while (i < 20){
      ovs_vport_cmd_new(name_array[i], dp_index, i, 0);
      i ++;
   }


   return 1;

}

int  ovs_dynamic_flow_test(void)
{

   int i = 0;
   printf("enter ovs_dynamic_flow_test \n");

   ovs_dp_cmd_new(88, "ovs-br");
      
   dynamic_add_vports(88);

   i = 10;
   do{   
      do_fake_ovs_flow_new(i, 88);
      i ++;
   }while(i < 18);
 #ifdef TEST_IP_ACTION
   //do_fake_ovs_flow_new_ip_go(15, 16, 88);
   //do_fake_ovs_flow_new_ip_back(16, 15, 88);
  #endif
  #ifdef TEST_MAC_ACTION
    //do_fake_ovs_flow_new_mac_go(15, 16, 88);
    //do_fake_ovs_flow_new_mac_back(16, 15, 88);
  #endif
  #ifdef TEST_UDPPORT_ACTION
    //do_fake_ovs_flow_new_udp_go(15, 16, 88);
    //do_fake_ovs_flow_new_udp_back(16, 15, 88); 
  #endif
#ifdef _IS_LINUX_
   fake_poll();
#endif

   ovs_dp_cmd_dump();

   printf("exit ovs_dynamic_flow_test \n");
#if 0  
   i = 17;
   do{   
      do_fake_ovs_flow_del(i);
      i --;
   }while(i > 9);


   i = 8;
   do{   
      ovs_vport_cmd_del(NULL, 88, i);
      i ++;
   }while(i < 20);

   ovs_dp_cmd_del(88);

   ovs_dp_cmd_dump();
#endif

	return 0;
}


int  ovs_dynamic_mem_test(int dp_index)
{

   int i = 0;
   
   printf("enter ovs_dynamic_mem_test \n");

   ovs_dp_cmd_new(dp_index, "ovs-br1");
         
   dynamic_add_vports(dp_index);
   
   i = 10;
   do{   
      do_fake_ovs_flow_new(i, dp_index);
      i ++;
   }while(i < 18);
   
   i = 17;
   do{   
      do_fake_ovs_flow_del(i, dp_index);
      i --;
   }while(i > 9);


   i = 8;
   do{   
      ovs_vport_cmd_del(NULL, dp_index, i);
      i ++;
   }while(i < 20);

   ovs_dp_cmd_del(dp_index);

	return 0;
}
#ifdef _IS_LINUX_
int  main(void)
{

   ovs_main();
//   ovs_dynamic_mem_test(99);
   

	return 0;

}
#endif




