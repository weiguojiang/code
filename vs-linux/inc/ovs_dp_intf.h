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

#ifndef OVS_DP_INTS_H
#define OVS_DP_INTS_H 1

#define NLM_F_CREATE 0x400
#define NLM_F_EXCL 0x200
#define GENL_ADMIN_PERM 0x01
#define GENL_ID_GENERATE 0

#define NLM_F_MULTI 2
#define NETLINK_CB(n) (*(struct netlink_skb_parms*)&((n)->cb))

struct nlattr{
 __u16 nla_len;
 __u16 nla_type;
} ;

#define NLMSG_DEFAULT_SIZE (((((1UL) << 12)) - (((sizeof(struct skb_shared_info)) + ((1 << 7) - 1)) & ~((1 << 7) - 1))) - ((int) ( ((sizeof(struct nlmsghdr))+4 -1) & ~(4 -1) )))

//# 34 "include/linux/netlink.h"
#define snd_portid snd_pid

struct nlmsghdr {
 __u32 nlmsg_len;
 __u16 nlmsg_type;
 __u16 nlmsg_flags;
 __u32 nlmsg_seq;
 __u32 nlmsg_pid;
};
//# 12 "include/linux/genetlink.h"
struct genlmsghdr {
 __u8 cmd;
 __u8 version;
 __u16 reserved;
};

//# 16 "include/net/genetlink.h"
#define genl_family rpl_genl_family
#define genl_notify rpl_genl_notify

struct genl_multicast_group {
 struct genl_family *family;
 struct list_head list;
 char name[16];
 u32 id;
};
//# 59 "include/net/genetlink.h"
struct genl_info {
 u32 snd_seq;
 u32 snd_pid;
 struct nlmsghdr * nlhdr;
 struct genlmsghdr * genlhdr;
 void * userhdr;
 struct nlattr ** attrs;

 struct net * _net;

};
static inline  struct net *genl_info_net(struct genl_info *info)
{
 return info->_net;
}

//# 21 "/home/binhhu/ovs/openvswitch-2.3.1/datapath/linux/compat/include/net/genetlink.h"

//# 689 "include/net/netlink.h"
static inline int nla_attr_size(int payload)
{
 return ((int) (((sizeof(struct nlattr)) + 4 - 1) & ~(4 - 1))) + payload;
}

static inline int nla_total_size(int payload)
{
 return (((nla_attr_size(payload)) + 4 - 1) & ~(4 - 1));
}


//netlink.h
#define NET_IP_ALIGN 2
extern int nla_memcpy(void *dest, const struct nlattr *src, int count);
static inline  int nla_len(const struct nlattr *nla)
{
 return nla->nla_len - ((int) (((sizeof(struct nlattr)) + 4 - 1) & ~(4 - 1)));
}

#define NLMSG_ALIGNTO       4
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLA_ALIGN NLMSG_ALIGN


enum {
 NLA_UNSPEC,
 NLA_U8,
 NLA_U16,
 NLA_U32,
 NLA_U64,
 NLA_STRING,
 NLA_FLAG,
 NLA_MSECS,
 NLA_NESTED,
 NLA_NESTED_COMPAT,
 NLA_NUL_STRING,
 NLA_BINARY,
 __NLA_TYPE_MAX,
};

//# 209 "include/net/netlink.h"
struct nla_policy {
 u16 type;
 u16 len;
};

//# 496 "include/net/netlink.h"
static inline  void *nlmsg_data(const struct nlmsghdr *nlh)
{
 return (unsigned char *) nlh + ((int) ( ((sizeof(struct nlmsghdr))+4 -1) & ~(4 -1) ));
}



//# 136 "include/net/genetlink.h"
static inline  void *genlmsg_put(struct sk_buff *skb, u32 pid, u32 seq,
    struct genl_family *family, int flags, u8 cmd)
{
 return NULL;
}
//# 1028 "include/net/netlink.h"
extern int nla_put(struct sk_buff *skb, int attrtype,
    int attrlen, const void *data);




static inline  struct nlattr *nla_nest_start(struct sk_buff *skb, int attrtype)
{
 struct nlattr *start = (struct nlattr *)skb_tail_pointer(skb);

 if (nla_put(skb, attrtype, 0, ((void *)0)) < 0)
  return ((void *)0);

 return start;
}
static inline  int nla_nest_end(struct sk_buff *skb, struct nlattr *start)
{
 start->nla_len = skb_tail_pointer(skb) - (char *)start;
 return skb->len;
}
static inline  int nla_put_u64(struct sk_buff *skb, int attrtype, u64 value)
{
 return nla_put(skb, attrtype, sizeof(u64), &value);
}

static inline  int nla_put_u8(struct sk_buff *skb, int attrtype, u8 value)
{
 return nla_put(skb, attrtype, sizeof(u8), &value);
}
//# 1062 "include/net/netlink.h"

static inline void nlmsg_trim(struct sk_buff *skb, const void *mark)
{
 if (mark)
  skb_trim(skb, (unsigned char *) mark - skb->data);
}

static inline  void nla_nest_cancel(struct sk_buff *skb, struct nlattr *start)
{
 nlmsg_trim(skb, start);
}

//# 549 "include/net/netlink.h"
static inline int nlmsg_end(struct sk_buff *skb, struct nlmsghdr *nlh)
{
 nlh->nlmsg_len = skb_tail_pointer(skb) - (char *)nlh;

 return skb->len;
}

static inline  int genlmsg_end(struct sk_buff *skb, void *hdr)
{
 return nlmsg_end(skb, hdr - ( ((sizeof(struct genlmsghdr))+4 -1) & ~(4 -1) ) - ((int) ( ((sizeof(struct nlmsghdr))+4 -1) & ~(4 -1) )));
}
static inline  void nlmsg_cancel(struct sk_buff *skb, struct nlmsghdr *nlh)
{
 nlmsg_trim(skb, nlh);
}

static inline  void genlmsg_cancel(struct sk_buff *skb, void *hdr)
{
 nlmsg_cancel(skb, hdr - ( ((sizeof(struct genlmsghdr))+4 -1) & ~(4 -1) ) - ((int) ( ((sizeof(struct nlmsghdr))+4 -1) & ~(4 -1) )));
}

static inline  int nlmsg_msg_size(int payload)
{
 return ((int) ( ((sizeof(struct nlmsghdr))+4 -1) & ~(4 -1) )) + payload;
}

static inline  int genlmsg_msg_size(int payload)
{
 return ( ((sizeof(struct genlmsghdr))+4 -1) & ~(4 -1) ) + payload;
}

static inline  int genlmsg_total_size(int payload)
{
 return ( ((genlmsg_msg_size(payload))+4 -1) & ~(4 -1) );
}

static inline  int nlmsg_total_size(int payload)
{
 return ( ((nlmsg_msg_size(payload))+4 -1) & ~(4 -1) );
}

static inline  struct sk_buff *nlmsg_new(size_t payload, gfp_t flags)
{
 return alloc_skb(nlmsg_total_size(payload), flags);
}

static inline  struct sk_buff *genlmsg_new(size_t payload, gfp_t flags)
{
 return nlmsg_new(genlmsg_total_size(payload), flags);
}

static inline  struct sk_buff *genlmsg_new_unicast(size_t payload,
        struct genl_info *info,
        gfp_t flags)
{
 return genlmsg_new(payload, flags);
}

static  int nla_put_string(struct sk_buff *skb, int attrtype,
     const char *str)
{
 return nla_put(skb, attrtype, strlen(str) + 1, str);
}
static int nla_put_u32(struct sk_buff *skb, int attrtype, u32 value)
{
 return nla_put(skb, attrtype, sizeof(u32), &value);
}

static inline int genlmsg_reply(struct sk_buff *skb, struct genl_info *info)
{
 //return genlmsg_unicast(genl_info_net(info), skb, info->snd_pid);
 return 0;
}
static inline int genl_set_err(struct genl_family *family, struct net *net,
			       u32 portid, u32 group, int code)
{
return 0;
}

static inline  void *genlmsg_data(const struct genlmsghdr *gnlh)
{
 return ((unsigned char *) gnlh + ( ((sizeof(struct genlmsghdr))+4 -1) & ~(4 -1) ));
}
static inline  void *nla_data(const struct nlattr *nla)
{
 return (char *) nla + ((int) (((sizeof(struct nlattr)) + 4 - 1) & ~(4 - 1)));
}
static inline  u32 nla_get_u32(const struct nlattr *nla)
{
 return *(u32 *) nla_data(nla);
}

//# 160 "include/linux/netlink.h" 2

struct ucred {
 __u32 pid;
 __u32 uid;
 __u32 gid;
};

/*static inline  struct nlmsghdr *v(const struct sk_buff *skb)
{
 return (struct nlmsghdr *)skb->data;
}*/

struct netlink_skb_parms {
 struct ucred creds;
 __u32 pid;
 __u32 dst_group;
 //kernel_cap_t eff_cap;
 __u32 loginuid;
 __u32 sessionid;
 __u32 sid;
};

//# 759 "include/net/netlink.h"
static inline  struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
 int totlen = (((nla->nla_len) + 4 - 1) & ~(4 - 1));

 *remaining -= totlen;
 return (struct nlattr *) ((char *) nla + totlen);
}

static inline  int nla_type(const struct nlattr *nla)
{
 return nla->nla_type & ~((1 << 15) | (1 << 14));
}


#endif /* OVS_DP_INTS_H */
