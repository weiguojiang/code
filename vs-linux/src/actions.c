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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"
#include "ovs_debug.h"

#include "datapath.h"
#include "vlan.h"
#include "vport.h"

int ovs_dump_data(void * data, int len);
int ovs_dump_mac(void *data, char * info_str);
struct udphdr *ovs_udp_hdr(struct sk_buff *skb);
void ovs_udp_checksum(struct sk_buff *skb );


static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			      const struct nlattr *attr, int len);

static int make_writable(struct sk_buff *skb, int write_len)
{
	//if (!skb_cloned(skb) || skb_clone_writable(skb, write_len))
		//return 0;

	//return pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
	return 0;
}

static unsigned short ovs_checksum(unsigned short *buf, int nword)
{
    unsigned long sum;
    for(sum = 0; nword > 0; nword--)
        sum += *buf++;

    sum = (sum>>16) +(sum&0xffff);
    sum += (sum>>16);
    return ~sum;
}

/* remove VLAN header from packet and update csum accordingly. */
static int ovs_pop_vlan_tci(struct sk_buff *skb, __be16 *current_tci)
{
	struct vlan_hdr *vhdr;

#if 0
	err = make_writable(skb, VLAN_ETH_HLEN);
	if (unlikely(err))
		return err;

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->csum = csum_sub(skb->csum, csum_partial(skb->data
					+ (2 * ETH_ALEN), VLAN_HLEN, 0));
#endif
	vhdr = (struct vlan_hdr *)(skb->data + ETH_HLEN);
	*current_tci = vhdr->h_vlan_TCI;

	memmove(skb->data + VLAN_HLEN, skb->data, 2 * ETH_ALEN);
	__skb_pull(skb, VLAN_HLEN);

#if 0
	vlan_set_encap_proto(skb, vhdr);
	skb->mac_header += VLAN_HLEN;
	skb_reset_mac_len(skb);
#endif
	return 0;
}

static int pop_vlan(struct sk_buff *skb)
{
    __be16 tci;

    if (skb->vlan_tci != 0) {
        ovs_pop_vlan_tci(skb, &tci);
        return 0;
    } else {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR: it's not the vlan interface when pop_vlan \n ");
        return 1;
    }
	return 0;
}

static inline  struct sk_buff *ovs_vlan_put_tag(struct sk_buff *skb, u16 vlan_tci)
{
   struct vlan_ethhdr *veth = NULL;

   if (skb_headroom(skb) < VLAN_HLEN) {
      kfree_skb(skb);
      return ((void *)0);
   }
 
   veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

   memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);

   veth->h_vlan_proto = htons(ETH_P_8021Q);

   veth->h_vlan_TCI = htons(vlan_tci);

   skb->protocol = htons(ETH_P_8021Q);
   
   return skb;
}
static int push_vlan(struct sk_buff *skb, const struct ovs_action_push_vlan *vlan)
{
      
   if (skb->vlan_tci != 0) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERROR push_vlan: it's already vlan packet \n");
        return 1;
    } else {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "push_vlan: %d %d \n", vlan->vlan_tci, vlan->vlan_tpid);

        if (!ovs_vlan_put_tag(skb, vlan->vlan_tci))
            return -ENOMEM;
        return 0;
    }

   return 0;
}

static int set_eth_addr(struct sk_buff *skb,
			const struct ovs_key_ethernet *eth_key)
{
    int i = 0;
    int src_flg = 0;
    int dst_flg = 0;
    
	struct ethhdr *eth = (struct ethhdr *)skb->data;
    for(i = 0; i < 6; i++){
        if(eth_key->eth_src[i] !=  0)
            src_flg = 1;
        if(eth_key->eth_dst[i] !=  (__u8)0)
            dst_flg = 1;
    }
    ovs_dump_mac(skb->data,"before mac modify, dump mac info.");
    if(src_flg == 1){
	    ether_addr_copy(eth->h_source, eth_key->eth_src);
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "replace src mac.\n");
	}
	
    if(dst_flg == 1){
	    ether_addr_copy(eth->h_dest, eth_key->eth_dst);
	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "replace dst mac.\n");
	}
    ovs_dump_mac(skb->data,"after mac modify, dump mac info.");

	return 0;
}

static void set_ip_addr(struct sk_buff *skb, struct iphdr *nh,
				__be32 *addr, __be32 new_addr)
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if (nh->protocol == IPPROTO_TCP) {
		/*if (likely(transport_len >= (int)sizeof(struct tcphdr)))
			inet_proto_csum_replace4(&tcp_hdr(skb)->check, skb,
						 *addr, new_addr, 1);*/
	} else if ((int)nh->protocol == IPPROTO_UDP) {
		if (likely(transport_len >= (int)sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				/*inet_proto_csum_replace4(&uh->check, skb,
							 *addr, new_addr, 1);*/
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	}

	//csum_replace4(&nh->check, *addr, new_addr);
	skb_clear_hash(skb);
	*addr = new_addr;
}

static void update_ipv6_checksum(struct sk_buff *skb, u8 l4_proto,
				 __be32 addr[4], const __be32 new_addr[4])
{
	int transport_len = skb->len - skb_transport_offset(skb);

	if ((int)l4_proto == NEXTHDR_TCP) {
		/*if (likely(transport_len >= (int)sizeof(struct tcphdr)))
			inet_proto_csum_replace16(&tcp_hdr(skb)->check, skb,
						  addr, new_addr, 1);*/
	} else if (l4_proto == NEXTHDR_UDP) {
		if (likely(transport_len >= (int)sizeof(struct udphdr))) {
			struct udphdr *uh = udp_hdr(skb);

			if (uh->check || skb->ip_summed == CHECKSUM_PARTIAL) {
				/*inet_proto_csum_replace16(&uh->check, skb,
							  addr, new_addr, 1);*/
				if (!uh->check)
					uh->check = CSUM_MANGLED_0;
			}
		}
	} else if (l4_proto == NEXTHDR_ICMP) {
		/*if (likely(transport_len >= sizeof(struct icmp6hdr)))
			inet_proto_csum_replace16(&icmp6_hdr(skb)->icmp6_cksum,
						  skb, addr, new_addr, 1);*/
	}
}

static void set_ipv6_addr(struct sk_buff *skb, u8 l4_proto,
			  __be32 addr[4], const __be32 new_addr[4],
			  bool recalculate_csum)
{
	if (recalculate_csum)
		update_ipv6_checksum(skb, l4_proto, addr, new_addr);

	skb_clear_hash(skb);
	memcpy(addr, new_addr, sizeof(__be32[4]));
}

static void set_ipv6_tc(struct ipv6hdr *nh, u8 tc)
{
	nh->priority = tc >> 4;
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0x0F) | ((tc & 0x0F) << 4);
}

static void set_ipv6_fl(struct ipv6hdr *nh, u32 fl)
{
	nh->flow_lbl[0] = (nh->flow_lbl[0] & 0xF0) | (fl & 0x000F0000) >> 16;
	nh->flow_lbl[1] = (fl & 0x0000FF00) >> 8;
	nh->flow_lbl[2] = fl & 0x000000FF;
}

static void set_ip_ttl(struct sk_buff *skb, struct iphdr *nh, u8 new_ttl)
{
	//csum_replace2(&nh->check, htons(nh->ttl << 8), htons(new_ttl << 8));
	nh->ttl = new_ttl;
}

static int set_ipv4(struct sk_buff *skb, const struct ovs_key_ipv4 *ipv4_key)
{
	struct iphdr *nh;
    struct udphdr *uh;
    
	struct ethhdr *eth = (struct ethhdr *)skb->data;
    if (eth->h_proto == htons(ETH_P_ARP)  ){ 
         struct arp_eth_header *nh = (struct arp_eth_header *)(skb->data + sizeof(struct ethhdr));

         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "it is arp, arp hrd %d pro %d hln %d pln %d ar-op %d.\n",
            nh->ar_hrd, nh->ar_pro, nh->ar_hln, nh->ar_pln, nh->ar_op);

         SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "it is arp, sip is %d.%d.%d.%d ,tip is %d.%d.%d.%d\n",
            nh->ar_sip[0], nh->ar_sip[1],nh->ar_sip[2],nh->ar_sip[3],
            nh->ar_tip[0], nh->ar_tip[1],nh->ar_tip[2],nh->ar_tip[3]);
         //replace the target ip address
         if(ipv4_key->ipv4_dst != 0)
         {
            *(__be32*)&nh->ar_tip[0] = ipv4_key->ipv4_dst;
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "after replace dst ip, arp sip is %d.%d.%d.%d ,tip is %d.%d.%d.%d\n",
            nh->ar_sip[0], nh->ar_sip[1],nh->ar_sip[2],nh->ar_sip[3],
            nh->ar_tip[0], nh->ar_tip[1],nh->ar_tip[2],nh->ar_tip[3]);
         }

         if(ipv4_key->ipv4_src != 0)
         {
            *(__be32*)&nh->ar_sip[0] = ipv4_key->ipv4_src;
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "after replace src ip, arp sip is %d.%d.%d.%d ,tip is %d.%d.%d.%d\n",
            nh->ar_sip[0], nh->ar_sip[1],nh->ar_sip[2],nh->ar_sip[3],
            nh->ar_tip[0], nh->ar_tip[1],nh->ar_tip[2],nh->ar_tip[3]);
         }
         
      }
    if (eth->h_proto == htons(ETH_P_IP) ){ 
    	nh =  (struct iphdr *)(skb->data + sizeof(struct ethhdr));
    	SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " %s: ip tot_len is %d and protocol is %d , header ihl is %d.\n",
    	       __FUNCTION__,
               nh->tot_len, 
               nh->protocol, 
               nh->ihl);
    	SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: key dst addr=%x, nh dst addr=%x\n",
            	__FUNCTION__, 
            	ipv4_key->ipv4_dst, 
            	nh->daddr );

        if(ipv4_key->ipv4_src != 0)
        {
        
    	    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: ipv4 replace src ip\n" , __FUNCTION__);
        	if (ipv4_key->ipv4_src != nh->saddr){
        	    nh->saddr = ipv4_key->ipv4_src;

        	    }
    	}
    	
        if(ipv4_key->ipv4_dst != 0)
        {
        	SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: ipv4 replace dst ip\n" , __FUNCTION__);
        	if (ipv4_key->ipv4_dst != nh->daddr){
        	    nh->daddr = ipv4_key->ipv4_dst;

        	}
    	}
        nh->check = 0;
        nh->check = ovs_checksum((unsigned short *)nh, 10);

        /*if UDP, set UPD checksum for support test case*/
        uh = ovs_udp_hdr(skb);
        if(uh != NULL){
            printf("set UPD checksum.\n");
            uh->check = 0;
            ovs_udp_checksum(skb);
        }
        
    }

	ovs_dump_data(skb->data,skb->len);

	return 0;
}

static int set_ipv6(struct sk_buff *skb, const struct ovs_key_ipv6 *ipv6_key)
{
	struct ipv6hdr *nh;
	int err;
	__be32 *saddr;
	__be32 *daddr;

	err = make_writable(skb, skb_network_offset(skb) +
			    sizeof(struct ipv6hdr));
	if (unlikely(err))
		return err;

	nh = ipv6_hdr(skb);
	saddr = (__be32 *)&nh->saddr;
	daddr = (__be32 *)&nh->daddr;

	if (memcmp(ipv6_key->ipv6_src, saddr, sizeof(ipv6_key->ipv6_src)))
		set_ipv6_addr(skb, ipv6_key->ipv6_proto, saddr,
			      ipv6_key->ipv6_src, true);

	if (memcmp(ipv6_key->ipv6_dst, daddr, sizeof(ipv6_key->ipv6_dst))) {
		//unsigned int offset = 0;
		//int flags = IP6_FH_F_SKIP_RH;
		bool recalc_csum = true;

		/*if (ipv6_ext_hdr(nh->nexthdr))
			recalc_csum = ipv6_find_hdr(skb, &offset,
						    NEXTHDR_ROUTING, NULL,
						    &flags) != NEXTHDR_ROUTING;*/

		set_ipv6_addr(skb, ipv6_key->ipv6_proto, daddr,
			      ipv6_key->ipv6_dst, recalc_csum);
	}

	set_ipv6_tc(nh, ipv6_key->ipv6_tclass);
	set_ipv6_fl(nh, ntohl(ipv6_key->ipv6_label));
	nh->hop_limit = ipv6_key->ipv6_hlimit;

	return 0;
}

/* Must follow make_writable() since that can move the skb data. */
static void set_tp_port(struct sk_buff *skb, __be16 *port,
			 __be16 new_port, __sum16 *check)
{
	//inet_proto_csum_replace2(check, skb, *port, new_port, 0);
	*port = new_port;
	skb_clear_hash(skb);
}

static void set_udp_port(struct sk_buff *skb, __be16 *port, __be16 new_port)
{
	struct udphdr *uh = udp_hdr(skb);

	if (uh->check && skb->ip_summed != CHECKSUM_PARTIAL) {
		set_tp_port(skb, port, new_port, &uh->check);

		if (!uh->check)
			uh->check = CSUM_MANGLED_0;
	} else {
		*port = new_port;
		skb_clear_hash(skb);
	}
}

struct udphdr *ovs_udp_hdr(struct sk_buff *skb)
{
    unsigned char * tmp_data = skb->data;
	struct ethhdr *eth = (struct ethhdr *)tmp_data;
    __be16 l_proto = eth->h_proto;
    if (l_proto == htons(ETH_P_IP)) {
        struct iphdr *nh = (struct iphdr *) (tmp_data + sizeof(struct ethhdr));
        if (nh->protocol == htons(IPPROTO_UDP)) {
            struct udphdr *udp = (struct udphdr *) (tmp_data + sizeof(struct ethhdr) + nh->ihl * 4);
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " get_udp_hdr   udp src-port is %d and dst-port is %d .\n",
                        udp->source, udp->dest);
            return udp;
        }
    }
    return NULL;
}

/*as it include payload,so the unit is byte rather than short*/
unsigned short ovs_checksum2(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while (size > 1)
    {
        cksum += *buffer++;
        size  -= sizeof(unsigned short);   
    }
    if (size)
    {
        cksum += *(unsigned char *)buffer;   
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum); 
}

void ovs_lay4_checksum_internal(
    void    *iphdr,
    struct udphdr *udphdr,
    char    *payload,
    int      payloadlen)
{
    struct iphdr  *v4hdr=NULL;
    unsigned long zero=0;
    char          buf[1000],
                 *ptr=NULL;
    int           chksumlen=0,
                  i;
    
    ptr = buf;
    v4hdr = (struct iphdr *)iphdr;
    
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "ovs_lay4_checksum_internal. \n");
    // Include the source and destination IP addresses
    memcpy(ptr, &v4hdr->saddr,  sizeof(v4hdr->saddr));  
    ptr += sizeof(v4hdr->saddr);
    chksumlen += sizeof(v4hdr->saddr);
    memcpy(ptr, &v4hdr->daddr, sizeof(v4hdr->daddr)); 
    ptr += sizeof(v4hdr->daddr);
    chksumlen += sizeof(v4hdr->daddr);
    
    // Include the 8 bit zero field
    memcpy(ptr, &zero, 1);
    ptr++;
    chksumlen += 1;
    // Protocol
    memcpy(ptr, &v4hdr->protocol, sizeof(v4hdr->protocol)); 
    ptr += sizeof(v4hdr->protocol);
    chksumlen += sizeof(v4hdr->protocol);
    // UDP length
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
    
    // UDP source port
    memcpy(ptr, &udphdr->source, sizeof(udphdr->source)); 
    ptr += sizeof(udphdr->source);
    chksumlen += sizeof(udphdr->source);
    // UDP destination port
    memcpy(ptr, &udphdr->dest, sizeof(udphdr->dest)); 
    ptr += sizeof(udphdr->dest);
    chksumlen += sizeof(udphdr->dest);
    // UDP length again
    memcpy(ptr, &udphdr->len, sizeof(udphdr->len)); 
    ptr += sizeof(udphdr->len);
    chksumlen += sizeof(udphdr->len);
   
    // 16-bit UDP checksum, zero 
    memcpy(ptr, &zero, sizeof(unsigned short));
    ptr += sizeof(unsigned short);
    chksumlen += sizeof(unsigned short);
    // payload
    memcpy(ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;
    // pad to next 16-bit boundary
    for(i=0 ; i < payloadlen%2 ; i++, ptr++)
    {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "pad one byte\n");
        *ptr = 0;
        ptr++;
        chksumlen++;
    }
    // Compute the checksum and put it in the UDP header
    udphdr->check = ovs_checksum2((unsigned short *)buf, chksumlen);
    return;
}

void ovs_udp_checksum(struct sk_buff *skb )
{
    struct iphdr *nh = NULL;
    struct udphdr *udp = NULL;
    char * udp_payload = NULL;
    unsigned char * tmp_data = skb->data;
	struct ethhdr *eth = (struct ethhdr *)tmp_data;
    __be16 l_proto = eth->h_proto;
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "udp_checksum \n");
    if (l_proto == htons(ETH_P_IP)){
        nh = (struct iphdr *)(tmp_data + sizeof(struct ethhdr));
        if (nh->protocol == htons(IPPROTO_UDP) ){
                    udp = (struct udphdr *)(tmp_data + sizeof(struct ethhdr) + nh->ihl* 4);
                    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "udp_checksum,src-port is %d and dst-port is %d .\n", 
                       udp->source, udp->dest); 
                 }
    }
    
    udp_payload = (char *)udp + sizeof(struct udphdr);
    ovs_lay4_checksum_internal(nh, udp, udp_payload, udp->len - sizeof(struct udphdr));
}

static int set_udp(struct sk_buff *skb, const struct ovs_key_udp *udp_port_key)
{
	struct udphdr *uh;
	int flg = 0;
	
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "enter set_udp.\n");

	uh = ovs_udp_hdr(skb);
	if(uh == NULL)
	    return -1;

	SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "before set udp, key src-port: %d and key dst-port:%d.\n",
             udp_port_key->udp_src, udp_port_key->udp_dst); 
    
    ovs_dump_data(skb->data, skb->len);
	if (udp_port_key->udp_src != 0 ){
		//set_udp_port(skb, &uh->source, udp_port_key->udp_src);
		uh->source = udp_port_key->udp_src;
		flg = 1;
	}

	if (udp_port_key->udp_dst != 0){
		//set_udp_port(skb, &uh->dest, udp_port_key->udp_dst);
		uh->dest = udp_port_key->udp_dst;
		flg = 1;
	}

	if(flg ==1){
        uh->check = 0;
  
        ovs_udp_checksum(skb);
        
	}
	
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO,"after set udp and dump data. flg=%d\n",flg);
    ovs_dump_data(skb->data, skb->len);

	return 0;
}

static int set_tcp(struct sk_buff *skb, const struct ovs_key_tcp *tcp_port_key)
{
	struct tcphdr *th;
	int err;

	err = make_writable(skb, skb_transport_offset(skb) +
				 sizeof(struct tcphdr));
	if (unlikely(err))
		return err;

	th = tcp_hdr(skb);
	if (tcp_port_key->tcp_src != th->source)
		set_tp_port(skb, &th->source, tcp_port_key->tcp_src, &th->check);

	if (tcp_port_key->tcp_dst != th->dest)
		set_tp_port(skb, &th->dest, tcp_port_key->tcp_dst, &th->check);

	return 0;
}

static int set_sctp(struct sk_buff *skb,
		     const struct ovs_key_sctp *sctp_port_key)
{
	struct sctphdr *sh;
	int err;
	unsigned int sctphoff = skb_transport_offset(skb);

	err = make_writable(skb, sctphoff + sizeof(struct sctphdr));
	if (unlikely(err))
		return err;

	sh = sctp_hdr(skb);
	if (sctp_port_key->sctp_src != sh->source ||
	    sctp_port_key->sctp_dst != sh->dest) {
		__le32 old_correct_csum = 0, new_csum = 0, old_csum;

		old_csum = sh->checksum;
		//old_correct_csum = sctp_compute_cksum(skb, sctphoff);

		sh->source = sctp_port_key->sctp_src;
		sh->dest = sctp_port_key->sctp_dst;

		//new_csum = sctp_compute_cksum(skb, sctphoff);

		/* Carry any checksum errors through. */
		sh->checksum = old_csum ^ old_correct_csum ^ new_csum;

		skb_clear_hash(skb);
	}

	return 0;
}

static int do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *vport;
	int ret = 0;

	if (unlikely(!skb))
		return -ENOMEM;

	vport = ovs_vport_rcu(dp, out_port);
	if (unlikely(!vport)) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_WARN, "%s: vport for %u in %s is NULL\n\n", __FUNCTION__, out_port, dp->dp_name);
		return -ENODEV;
	}
	if (OVS_VPORT_TYPE_INTERNAL == vport->ops->type) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_WARN, "%s: find internal port, cancel send.\n\n", __FUNCTION__);
	    return 0;
	}
	SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: vport(%s) with index %u is found.\n\n",
	        __FUNCTION__, vport->port_name, out_port);
	ret = ovs_vport_send(vport, skb);
	if (ret <= 0) {
	    return -EINVAL;
	}
	return 0;
}

static int output_userspace(struct datapath *dp, struct sk_buff *skb,
			    const struct nlattr *attr)
{
	struct dp_upcall_info upcall;
	const struct nlattr *a;
	int rem;

	BUG_ON(!OVS_CB(skb)->pkt_key);

	upcall.cmd = OVS_PACKET_CMD_ACTION;
	upcall.key = OVS_CB(skb)->pkt_key;
	upcall.userdata = NULL;
	upcall.portid = 0;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_USERSPACE_ATTR_USERDATA:
			upcall.userdata = a;
			break;

		case OVS_USERSPACE_ATTR_PID:
			upcall.portid = nla_get_u32(a);
			break;
		}
	}

	return ovs_dp_upcall(dp, skb, &upcall);
}

static bool last_action(const struct nlattr *a, int rem)
{
	return a->nla_len == rem;
}

static int sample(struct datapath *dp, struct sk_buff *skb,
		  const struct nlattr *attr)
{
	const struct nlattr *acts_list = NULL;
	const struct nlattr *a;
	struct sk_buff *sample_skb;
	int rem;

	for (a = nla_data(attr), rem = nla_len(attr); rem > 0;
		 a = nla_next(a, &rem)) {
		switch (nla_type(a)) {
		case OVS_SAMPLE_ATTR_PROBABILITY:
			break;

		case OVS_SAMPLE_ATTR_ACTIONS:
			acts_list = a;
			break;
		}
	}

	rem = nla_len(acts_list);
	a = nla_data(acts_list);

	/* Actions list is either empty or only contains a single user-space
	 * action, the latter being a special case as it is the only known
	 * usage of the sample action.
	 * In these special cases don't clone the skb as there are no
	 * side-effects in the nested actions.
	 * Otherwise, clone in case the nested actions have side effects. */
	if (likely(rem == 0 ||
		   (nla_type(a) == OVS_ACTION_ATTR_USERSPACE &&
		    last_action(a, rem)))) {
		sample_skb = skb;
		//skb_get(skb);
	} else {
		//sample_skb = skb_clone(skb, GFP_ATOMIC);
	}

	/* Note that do_execute_actions() never consumes skb.
	 * In the case where skb has been cloned above it is the clone that
	 * is consumed.  Otherwise the skb_get(skb) call prevents
	 * consumption by do_execute_actions(). Thus, it is safe to simply
	 * return the error code and let the caller (also
	 * do_execute_actions()) free skb on error. */
	return do_execute_actions(dp, sample_skb, a, rem);
}

static void execute_hash(struct sk_buff *skb, const struct nlattr *attr)
{
	struct sw_flow_key *key = OVS_CB(skb)->pkt_key;
	u32 hash = 0;

	/* OVS_HASH_ALG_L4 is the only possible hash algorithm.  */
	hash = skb_get_hash(skb);
	if (!hash)
		hash = 0x1;

	key->ovs_flow_hash = hash;
}

static int execute_set_action(struct sk_buff *skb,
				 const struct nlattr *nested_attr)
{
	int err = 0;

	switch (nla_type(nested_attr)) {
	case OVS_KEY_ATTR_PRIORITY:
		skb->priority = nla_get_u32(nested_attr);
		break;

	case OVS_KEY_ATTR_SKB_MARK:
		skb->mark = nla_get_u32(nested_attr);
		break;

	case OVS_KEY_ATTR_IPV4_TUNNEL:
		OVS_CB(skb)->tun_key = nla_data(nested_attr);
		break;

	case OVS_KEY_ATTR_ETHERNET: //mac
		err = set_eth_addr(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_IPV4: //ip
		err = set_ipv4(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_IPV6:
		err = set_ipv6(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_TCP:
		err = set_tcp(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_UDP: //udp
		err = set_udp(skb, nla_data(nested_attr));
		break;

	case OVS_KEY_ATTR_SCTP:
		err = set_sctp(skb, nla_data(nested_attr));
		break;
	}

	return err;
}

static int execute_recirc(struct datapath *dp, struct sk_buff *skb,
				 const struct nlattr *a)
{
	struct sw_flow_key recirc_key;
	int err;

	err = ovs_flow_key_extract_recirc(nla_get_u32(a), OVS_CB(skb)->pkt_key,
					  skb, &recirc_key);
	if (err) {
		kfree_skb(skb);
		return err;
	}


	ovs_dp_process_packet_with_key(skb, &recirc_key, true);

	return 0;
}

static int check_output(struct datapath *dp, struct sk_buff *skb,
                        int *port, int err_count) {
    int ret = 0;
    if (*port == -1) {
        return err_count;
    }
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n%s: prev_port is %d\n\n", __FUNCTION__, *port);
    ret = do_output(dp, skb, *port);
    if (0 > ret) {
        err_count++;
    }
    *port = -1;
    return err_count;
}

extern struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask);
/* Execute a list of actions against 'skb'. */
static int do_execute_actions(struct datapath *dp, struct sk_buff *skb,
			const struct nlattr *attr, int len)
{
	/* Every output action needs a separate clone of 'skb', but the common
	 * case is just a single output action, so that doing a clone and
	 * then freeing the original skbuff is wasteful.  So the following code
	 * is slightly obscure just to avoid that. */
	int prev_port = -1;
	const struct nlattr *a;
	int rem;
	int count = 0;
	int total = 0;
	int ret = 0;

    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " enter do_execute_actions \n");
    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: len is %d\n", __FUNCTION__, len);

	for (a = attr, rem = len; rem > 0;
	     a = nla_next(a, &rem)) {
	    total++;
		int err = 0;

		count = check_output(dp, skb, &prev_port, count);

		SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: nla_type(a) is %u\n\n", __FUNCTION__, nla_type(a));
        switch (nla_type(a)) {
            case OVS_ACTION_ATTR_OUTPUT:
                prev_port = nla_get_u32(a);
                break;

            case OVS_ACTION_ATTR_USERSPACE:
                output_userspace(dp, skb, a);
                break;

            case OVS_ACTION_ATTR_HASH:
                execute_hash(skb, a);
                break;

            case OVS_ACTION_ATTR_PUSH_VLAN:
                SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: vlan before push skb->len= %d\n", __FUNCTION__, skb->len);
                err = push_vlan(skb, nla_data(a));
                if (!err) {
                    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: vlan after push skb->len= %d\n", __FUNCTION__, skb->len);

                    m_prepend(OVS_CB(skb)->m, VLAN_HLEN);
                    if (OVS_CB(skb)->m == NULL) {
                        break;
                    }
#ifdef _USE_SKB_BUF_
                    m_copyfrombuf(OVS_CB(skb)->m, 0, skb->data, 16);
#endif
                }
                break;

            case OVS_ACTION_ATTR_POP_VLAN:

                SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: vlan before strip skb->len= %d\n",
                        __FUNCTION__, skb->len);
                err = pop_vlan(skb);
                if (!err) {
                    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: vlan after strip skb->len= %d\n",
                            __FUNCTION__, skb->len);
                    m_adj(OVS_CB(skb)->m, VLAN_HLEN);
#ifdef _USE_SKB_BUF_
                    m_copyfrombuf(OVS_CB(skb)->m, 0, skb->data, 12);
#endif
                }
                break;

            case OVS_ACTION_ATTR_RECIRC: {
                struct sk_buff *recirc_skb = NULL;

                if (last_action(a, rem))
                    return execute_recirc(dp, skb, a);

                /* Recirc action is the not the last action
                 * of the action list. */
                //recirc_skb = skb_clone(skb, GFP_ATOMIC);
                /* Skip the recirc action when out of memory, but
                 * continue on with the rest of the action list. */
                if (recirc_skb)
                    err = execute_recirc(dp, recirc_skb, a);

                break;
            }

            case OVS_ACTION_ATTR_SET:  //change header
                err = execute_set_action(skb, nla_data(a));
                if (!err) {
                    if (OVS_CB(skb)->m == NULL) {
                        break;
                    }
#ifdef _USE_SKB_BUF_
                    m_copyfrombuf(OVS_CB(skb)->m, 0, skb->data, skb->len);
#endif                    
                }
                break;

            case OVS_ACTION_ATTR_SAMPLE:
                err = sample(dp, skb, a);
                break;
        }
	}

	if (prev_port != -1) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "%s: prev_port is %d\n", __FUNCTION__, prev_port);
	    ret = do_output(dp, skb, prev_port);
	    if (0 > ret) {
	        count++;
	    }
	} else {
		consume_skb(skb);
	}
	if (count == total) {
	    OVS_CB(skb)->fp_output_res = 1/*FP_DROP*/;
	}

	return 0;
}

/* We limit the number of times that we pass into execute_actions()
 * to avoid blowing out the stack in the event that we have a loop.
 *
 * Each loop adds some (estimated) cost to the kernel stack.
 * The loop terminates when the max cost is exceeded.
 * */
#define RECIRC_STACK_COST 1
#define DEFAULT_STACK_COST 4
/* Allow up to 4 regular services, and up to 3 recirculations */
#define MAX_STACK_COST (DEFAULT_STACK_COST * 4 + RECIRC_STACK_COST * 3)

struct loop_counter {
	u8 stack_cost;		/* loop stack cost. */
	bool looping;		/* Loop detected? */
};

//static DEFINE_PER_CPU(struct loop_counter, loop_counters);

static int loop_suppress(struct datapath *dp, struct sw_flow_actions *actions)
{
	//if (net_ratelimit())
		//pr_warn("%s: flow loop detected, dropping\n",
				//ovs_dp_name(dp));
	actions->actions_len = 0;
	return -1;
}

/* Execute a list of actions against 'skb'. */
int ovs_execute_actions(struct datapath *dp, struct sk_buff *skb, bool recirc)
{
	struct sw_flow_actions *acts = rcu_dereference(OVS_CB(skb)->flow->sf_acts);
//	const u8 stack_cost = recirc ? RECIRC_STACK_COST : DEFAULT_STACK_COST;
//	struct loop_counter *loop = NULL;
	int error;

	/* Check whether we've looped too much. */
#if 0
	loop = &__get_cpu_var(loop_counters);
	loop->stack_cost += stack_cost;
	if (unlikely(loop->stack_cost > MAX_STACK_COST))
		loop->looping = true;
	if (unlikely(loop->looping)) {
		error = loop_suppress(dp, acts);
		kfree_skb(skb);
		goto out_loop;
	}
#endif
	OVS_CB(skb)->tun_key = NULL;
	error = do_execute_actions(dp, skb, acts->actions, acts->actions_len);
#if 0
	/* Check whether sub-actions looped too much. */
	if (unlikely(loop->looping))
		error = loop_suppress(dp, acts);

out_loop:
	/* Decrement loop stack cost. */
	loop->stack_cost -= stack_cost;
	if (!loop->stack_cost)
		loop->looping = false;
#endif
	return error;
}
