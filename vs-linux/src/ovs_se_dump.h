#ifndef OVS_SE_DUMP_HEADER_20150817__
#define OVS_SE_DUMP_HEADER_20150817__

//#include "ovs_se_common.h"
//#include "ovs_skb.h"
//#include "ovs_dp_common.h"
//#include "ovs_list.h"

//#include "flow.h"
//#include "vport.h"
//#include "datapath.h"

extern void *flex_array_get(struct flex_array *fa, unsigned int element_nr);


#define INDENTATION "  "
#define INDENTATION_1 INDENTATION
#define INDENTATION_2 INDENTATION INDENTATION
#define MAX_INDENTATIONS 16
#define HEAD "%s%-16s:"
#define STRING HEAD"%s"
#define NUMBER_U32_1 HEAD"%u"
#define NUMBER_U32_2 HEAD"%u-%u"
#define NUMBER_U64_1 HEAD"%lld"
#define ENDL printf("\n")


static inline void  get_ip4_str(char *str, int len, u32 ip)
{
   u8 * c = (u8 *)&ip;
   memset(str, 0, len);
   snprintf(str, len, "%d.%d.%d.%d", c[0], c[1], c[2], c[3]);
}
static inline void get_mac_str(char *str, int len, u8 *mac)
{
   memset(str, 0, len);
   snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X", 
      mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
static void display_sw_flow_key(char *indentations, struct sw_flow_key *key)
{
#define MAX_PRINT_STRING_LEN 1024
   char pstring[MAX_PRINT_STRING_LEN] = {0};
   int ps_offset = 0;
   char ip4src[16] = {0};
   char ip4dst[16] = {0};
   char macsrc[18] = {0};
   char macdst[18] = {0};

   char subindentations[MAX_INDENTATIONS] = {0};

   if (NULL == indentations) {
      printf("%s: EMPTY indentations", __func__); 
      return; 
   }
   if (NULL == key) {
      printf("%s: NULL key", __func__); 
      return; 
   }
   
   snprintf(subindentations, MAX_INDENTATIONS, "%s%s", indentations, INDENTATION);
   
   /*//printout tunnel
   get_ip4_str(ip4src, sizeof(ip4src),key->tun_key.ipv4_src);
   get_ip4_str(ip4dst, sizeof(ip4dst),key->tun_key.ipv4_dst);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      HEAD"\n", indentations, "tunnel");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U64_1"\n", subindentations, "tun_id", key->tun_key.tun_id);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      STRING"\n", subindentations, "ipv4_src", ip4src);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      STRING"\n", subindentations, "ipv4_dst", ip4dst);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U32_1"\n", subindentations, "tun_flags", key->tun_key.tun_flags);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U32_1"\n", subindentations, "ipv4_tos", key->tun_key.ipv4_tos);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U32_1"\n", subindentations, "ipv4_ttl", key->tun_key.ipv4_ttl);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U32_1"\n", indentations, "Datapath computed hash value", key->ovs_flow_hash);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      NUMBER_U32_1"\n", indentations, "Recirculation ID", key->recirc_id);
*/
   //ether mac
   get_mac_str(macsrc, sizeof(macsrc), key->eth.src);
   get_mac_str(macdst, sizeof(macdst), key->eth.dst);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset, 
      HEAD"\n", indentations, "eth");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      STRING"\n", subindentations, "eth.src", macsrc);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      STRING"\n", subindentations, "eth.dst", macdst);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "eth.tci", key->eth.tci);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "eth.type", key->eth.type);

   //IPv4 v.s IPv6:  print out ipv4 only
   get_ip4_str(ip4src, sizeof(ip4src), key->ipv4.addr.src);
   get_ip4_str(ip4dst, sizeof(ip4dst), key->ipv4.addr.dst);
   get_mac_str(macsrc, sizeof(macsrc), key->ipv4.arp.sha);
   get_mac_str(macdst, sizeof(macdst), key->ipv4.arp.tha);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      HEAD"\n", indentations, "IPv4");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      STRING"\n", subindentations, "ipv4.addr.src", ip4src);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      STRING"\n", subindentations, "ipv4.addr.dst", ip4dst);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      STRING"\n", subindentations, "ipv4.arp.sha", macsrc);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      STRING"\n", subindentations, "ipv4.arp.tha", macdst);
   //ip attr
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      HEAD"\n", indentations, "IP attributes");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "ip.proto", key->ip.proto);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "ip.tos", key->ip.tos);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "ip.ttl", key->ip.ttl);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "ip.frag", key->ip.frag);
   //L4 attr
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      HEAD"\n", indentations, "L4 ports");
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "tp.src", key->tp.src);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "tp.dst", key->tp.dst);
   ps_offset += snprintf(pstring+ps_offset, MAX_PRINT_STRING_LEN-ps_offset,
      NUMBER_U32_1"\n", subindentations, "tp.flags", key->tp.flags);

   printf("%s", pstring);

}
static void display_sw_flow_mask(char *skipspaces, struct sw_flow_mask *mask)
{
   char subindentations[MAX_INDENTATIONS] = {0};

   if (NULL == skipspaces) {
      printf("%s: EMPTY indentations", __func__); ENDL;
      return; 
   }
   if (NULL == mask) {
      printf("%s: NULL mask", __func__); ENDL;
      return; 
   }
   
   printf(NUMBER_U32_1, skipspaces, "refcount", mask->ref_count);ENDL;
   printf(NUMBER_U32_2, skipspaces, "range", mask->range.start, mask->range.end);ENDL;
   snprintf(subindentations, MAX_INDENTATIONS, "%s%s", skipspaces, INDENTATION);
   display_sw_flow_key(subindentations, &(mask->key));
}

#endif //#ifndef OVS_SE_DUMP_HEADER_20150817__
