#ifndef __OVS_SKB_H__
#define __OVS_SKB_H__


//========================================================

#if 1
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned char __u8;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef unsigned char * sk_buff_data_t;
typedef unsigned gfp_t;
#endif

struct sk_buff {

 struct sk_buff *next;
 struct sk_buff *prev;

 struct sock *sk;


 char cb[96] __attribute__((aligned(8)));


 unsigned int len,
    data_len;
 __u16 mac_len,
    hdr_len;

 __u32 priority;
 
 __u8 local_df:1,
    cloned:1,
    ip_summed:2,
    nohdr:1,
    nfctinfo:3;
 __u8 pkt_type:3,
    fclone:2,
    ipvs_property:1,
    peeked:1,
    nf_trace:1;
 ;
 __be16 protocol;

 void (*destructor)(struct sk_buff *skb);

 union {
  __u32 mark;
  __u32 dropcount;
 };

 __u16 vlan_tci;


 union {
  void *vnbh;
 } nh;


 __u16 transport_header;
 __u16 network_header;
 __u16 mac_header;

 sk_buff_data_t tail;
 sk_buff_data_t end;
 unsigned char *head,
    *data;
 unsigned int truesize;
};


struct skb_shared_info {
 //atomic_t dataref;
 unsigned short nr_frags;
 unsigned short gso_size;

 unsigned short gso_segs;
 unsigned short gso_type;
 struct sk_buff *frag_list;
 void * destructor_arg;
};


struct fake_sk_buff{
    struct sk_buff sk_buf;
    char   data[4096];
};

#define skb_shinfo(SKB)    ((struct skb_shared_info *)(skb_end_pointer(SKB)))


static inline unsigned char *skb_end_pointer(const struct sk_buff *skb)
{
 return skb->end;
}

static unsigned char *skb_push(struct sk_buff *skb, unsigned int len)
{
	skb->data -= len;
	skb->len  += len;
	
	return skb->data;
}

static inline unsigned char *__skb_push(struct sk_buff *skb, unsigned int len)
{
 skb->data -= len;
 skb->len += len;
 return skb->data;
}

static inline char *skb_tail_pointer(const struct sk_buff *skb)
{
	return (char *)skb->tail;
}

static inline void skb_reset_tail_pointer(struct sk_buff *skb)
{
	skb->tail = skb->data;
}

static inline unsigned char *skb_put(struct sk_buff *skb, unsigned int len)
{
	unsigned char *tmp = (unsigned char *)skb_tail_pointer(skb);
	skb->tail += len;
	skb->len  += len;
	return tmp;
}

static inline int skb_is_gso(const struct sk_buff *skb)
{
 return ((struct skb_shared_info *)(skb_end_pointer(skb)))->gso_size;
}


static inline void skb_reset_mac_header(struct sk_buff *skb)
{
	skb->mac_header = skb->data- skb->head;
	return;
}

static inline  void skb_reset_mac_len(struct sk_buff *skb)
{
 skb->mac_len = skb->network_header - skb->mac_header;
}

static inline  void skb_reserve(struct sk_buff *skb, int len)
{
 skb->data += len;
 skb->tail += len;
}

static inline unsigned char *skb_mac_header(const struct sk_buff *skb)
{
   return skb->head + skb->mac_header;;
}

static inline  struct ethhdr *eth_hdr(const struct sk_buff *skb)
{
 return (struct ethhdr *)skb_mac_header(skb);
}


static inline  unsigned char *skb_transport_header(const struct sk_buff *skb)
{
 return skb->head + skb->transport_header;
}

static inline  void skb_reset_transport_header(struct sk_buff *skb)
{
 skb->transport_header = skb->data - skb->head;
}

static inline void skb_set_transport_header(struct sk_buff *skb,
         const int offset)
{
 skb_reset_transport_header(skb);
 skb->transport_header += offset;
}

static inline  void skb_reset_network_header(struct sk_buff *skb)
{
 skb->network_header = skb->data - skb->head;
}


static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
 return skb->head + skb->network_header;
}


static inline int skb_network_offset(const struct sk_buff *skb)
{
	return skb_network_header(skb) - skb->data;
}

static inline  int skb_cloned(const struct sk_buff *skb)
{
/*
 return skb->cloned &&
        (((&((struct skb_shared_info *)(skb_end_pointer(skb)))->dataref)->counter) & ((1 << 16) - 1)) != 1;
*/
   return 0;
}


static inline  int skb_header_cloned(const struct sk_buff *skb)
{
#if 0
 int dataref;

 if (!skb->cloned)
  return 0;

 dataref = ((&((struct skb_shared_info *)(skb_end_pointer(skb)))->dataref)->counter);
 dataref = (dataref & ((1 << 16) - 1)) - (dataref >> 16);
 return dataref != 1;
 #endif
  return 0;
}

static inline  int __skb_cow(struct sk_buff *skb, unsigned int headroom,
       int cloned)
{
#if 0
 int delta = 0;

 if (headroom < 128)
  headroom = 128;
 if (headroom > skb_headroom(skb))
  delta = headroom - skb_headroom(skb);

 if (delta || cloned)
  return pskb_expand_head(skb, ((((delta)) + ((typeof(delta)) (128) - 1)) & ~((typeof(delta)) (128) - 1)), 0,
     ((( gfp_t)0x20u)));
 #endif
 return 0;
}

static inline unsigned int skb_headroom(const struct sk_buff *skb)
{
	return skb->data - skb->head;
}

static inline  int skb_cow(struct sk_buff *skb, unsigned int headroom)
{
 return __skb_cow(skb, headroom, skb_cloned(skb));
}

static inline  int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
 return __skb_cow(skb, headroom, skb_header_cloned(skb));
}


static inline  unsigned char *__skb_pull(struct sk_buff *skb, unsigned int len)
{
 skb->len -= len;
 return skb->data += len;
}


static inline unsigned int skb_headlen(const struct sk_buff *skb)
{
	return skb->len - skb->data_len;
}

static inline void *__skb_header_pointer(const struct sk_buff *skb, int offset,
					 int len, void *data, int hlen, void *buffer)
{
	if (hlen - offset >= len)
		return data + offset;

	if (!skb)
		return (void*)0;

	return buffer;
}
static inline void *skb_header_pointer(const struct sk_buff *skb, int offset,
				       int len, void *buffer)
{
	return __skb_header_pointer(skb, offset, len, skb->data,
				    skb_headlen(skb), buffer);
}

static inline int pskb_may_pull(struct sk_buff *skb, unsigned int len)
{

	if (len <= skb_headlen(skb))
		return 1;
   
	if (len > skb->len)
		return 0;

   return 0;
}

//# 1712 "include/linux/skbuff.h"
static inline  void skb_postpull_rcsum(struct sk_buff *skb,
          const void *start, unsigned int len)
{
// if (skb->ip_summed == 2)
  //skb->csum = csum_sub(skb->csum, csum_partial(start, len, 0));
}



static inline void skb_clear_hash(struct sk_buff *skb)
{

}

static inline  int skb_transport_offset(const struct sk_buff *skb)
{
 return skb_transport_header(skb) - skb->data;
}


extern void kfree_skb(struct sk_buff *skb);
extern void consume_skb(struct sk_buff *skb);
extern void __kfree_skb(struct sk_buff *skb);
extern struct sk_buff *alloc_skb(unsigned int size, gfp_t priority);
extern struct sk_buff *__dev_alloc_skb(unsigned int length, gfp_t gfp_mask);
extern void skb_trim(struct sk_buff *skb, unsigned int len);
extern struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask);


//========================================================


#endif


