
#include <stdio.h>
#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"
#include "ovs_debug.h"

#include "datapath.h"
#include "flow.h"
#include "flow_table.h"
#include "flow_netlink.h"
#include "vlan.h"


const struct vport_ops ovs_netdev_vport_ops /*= {
	.type		= OVS_VPORT_TYPE_NETDEV,
	.create		= netdev_create,
	.destroy	= netdev_destroy,
	.get_name	= ovs_netdev_get_name,
	.send		= netdev_send,
}*/;
const struct vport_ops ovs_internal_vport_ops /*= {
	.type		= OVS_VPORT_TYPE_INTERNAL,
	.create		= internal_dev_create,
	.destroy	= internal_dev_destroy,
	.get_name	= ovs_netdev_get_name,
	.send		= internal_dev_recv,
}*/;
const struct vport_ops ovs_gre_vport_ops  /*={
	.type		= OVS_VPORT_TYPE_GRE,
	.create		= gre_create,
	.destroy	= gre_tnl_destroy,
	.get_name	= gre_get_name,
	.send		= gre_send,
};*/;
const struct vport_ops ovs_gre64_vport_ops /*= {
	.type		= OVS_VPORT_TYPE_GRE64,
	.create		= gre64_create,
	.destroy	= gre64_tnl_destroy,
	.get_name	= gre_get_name,
	.send		= gre64_send,
};*/;


const struct vport_ops ovs_vxlan_vport_ops /*= {
	.type		= OVS_VPORT_TYPE_VXLAN,
	.create		= vxlan_tnl_create,
	.destroy	= vxlan_tnl_destroy,
	.get_name	= vxlan_get_name,
	.get_options	= vxlan_get_options,
	.send		= vxlan_tnl_send,
};*/;


const struct vport_ops ovs_lisp_vport_ops  /*={
	.type		= OVS_VPORT_TYPE_LISP,
	.create		= lisp_tnl_create,
	.destroy	= lisp_tnl_destroy,
	.get_name	= lisp_get_name,
	.get_options	= lisp_get_options,
	.send		= lisp_send,
};*/;


struct sk_buff *__alloc_skb(unsigned int size,
       gfp_t priority, int fclone, int node)
{
	return NULL;
}
void kfree_skb(struct sk_buff *skb)
{
	return ;
}
void consume_skb(struct sk_buff *skb)
{
	return ;
}
void __kfree_skb(struct sk_buff *skb)
{
	return ;
}	
void rpl_genl_notify(struct rpl_genl_family *family, struct sk_buff *skb,
				 struct net *net, u32 portid, u32 group,
				 struct nlmsghdr *nlh, gfp_t flags)
{
	return ;
}	


int nla_put(struct sk_buff *skb, int attrtype,
    int attrlen, const void *data)
{
	return 0;
}
	
int nla_memcpy(void *dest, const struct nlattr *src, int count)
{
	return 0;

}
void skb_trim(struct sk_buff *skb, unsigned int len)
{
	return ;

}

__be16 nla_get_be16(const struct nlattr *nla)
{
	return *(__be16 *) nla_data(nla);
}

int nla_put_be16(struct sk_buff *skb, int attrtype, __be16 value)
{
	return nla_put(skb, attrtype, sizeof(__be16), &value);
}

struct nlattr *nla_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{

	return NULL;
}


struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask)
{

   return skb;
}

int ovs_dump_mac(void *data, char * info_str)
{
	struct ethhdr *eth = (struct ethhdr *)data;
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n ovs_dump_mac, info:%s. \n ",  info_str );
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n ovs_dump_mac,src mac:%02x:%02x:%02x:%02x:%02x:%02x \n", 
          eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]
          );
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n ovs_dump_mac, dst mac:%02x:%02x:%02x:%02x:%02x:%02x\n", 
          eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]
          );
    return 0;
}
int ovs_dump_data(void * data, int len)
{

   char * tmp_data = data;
	struct ethhdr *eth = (struct ethhdr *)tmp_data;
    __be16 l_proto = eth->h_proto;
   static int i = 0;

   if (i <  5000){
      SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n\n ovs_dump_data len is %d with proto is %x \n", len, eth->h_proto);

      if (l_proto == htons(ETH_P_8021Q)){ 
         struct vlan_hdr *vlanh = (struct vlan_hdr *)(tmp_data + sizeof(struct ethhdr));
         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " tci is %d and next proto is %x .\n",
            vlanh->h_vlan_TCI | htons(0x0100), vlanh->h_vlan_encapsulated_proto);

         l_proto = vlanh->h_vlan_encapsulated_proto;
         tmp_data += VLAN_HLEN;
      }

      if (l_proto == htons(ETH_P_IP)){
         struct iphdr *nh = (struct iphdr *)(tmp_data + sizeof(struct ethhdr));
         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " ip tot_len is %d and protocol is %d , header ihl is %d.\n",
            nh->tot_len, nh->protocol, nh->ihl);

         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " ip src is %x and dst is %x .\n",
            nh->saddr, nh->daddr);

         if (nh->protocol == IPPROTO_ICMP ){
            struct icmphdr *icmp = (struct icmphdr *)(tmp_data + sizeof(struct ethhdr) + nh->ihl* 4);

            /* The ICMP type and code fields use the 16-bit
				 * transport port fields, so we need to store
				 * them in 16-bit network byte order. */
	         
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " icmp type is %d and code is %d .\n",
               icmp->type, icmp->code); 
         }

         if (nh->protocol == IPPROTO_UDP ){
            struct udphdr *udp = (struct udphdr *)(tmp_data + sizeof(struct ethhdr) + nh->ihl* 4);
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "    udp src-port is %d and dst-port is %d .\n",
               udp->source, udp->dest); 
         }

         if (nh->protocol == IPPROTO_TCP ){
            struct tcphdr *tcp = (struct tcphdr *)(tmp_data + sizeof(struct ethhdr) + nh->ihl* 4);
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "    tcp src-port is %d and dst-port is %d .\n",
               tcp->source, tcp->dest); 
         }
         
      }

      if (l_proto == htons(ETH_P_ARP)){ 
         struct arp_eth_header *nh = (struct arp_eth_header *)(tmp_data + sizeof(struct ethhdr));

         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " arp hrd %d pro %d hln %d pln %d ar-op %d.\n",
            nh->ar_hrd, nh->ar_pro, nh->ar_hln, nh->ar_pln, nh->ar_op);

         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "sip is %d.%d.%d.%d ,tip is %d.%d.%d.%d\n",
            nh->ar_sip[0], nh->ar_sip[1],nh->ar_sip[2],nh->ar_sip[3],
            nh->ar_tip[0], nh->ar_tip[1],nh->ar_tip[2],nh->ar_tip[3]);
         
      }
      
      i ++;
   }  
   return 1;
}



unsigned int ip_str_to_num(const char *buf)

{

    unsigned int tmpip[4] = {0};

    unsigned int tmpip32 = 0;

    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);

    tmpip32 = (tmpip[0]<<24) | (tmpip[1]<<16) | (tmpip[2]<<8) | tmpip[3];

    return tmpip32;

}



#define IP_LEN 17

static inline void ip_num_to_str(unsigned int ip_num, char *ip_str)

{

        unsigned char * uip = (unsigned char *)&ip_num;

        snprintf(ip_str, IP_LEN , "%d.%d.%d.%d", uip[0], uip[1], uip[2], uip[3]);

}



