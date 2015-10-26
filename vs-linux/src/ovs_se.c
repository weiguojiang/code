#include "ovs_se_common.h"
#include "ovs_skb.h"
#include "ovs_dp_common.h"
#include "ovs_debug.h"

#include "datapath.h"
#include "flow.h"
#include "flow_netlink.h"

#include "vlan.h"

#include "fp-log.h"
#include "fp-main-process.h"

#include "fp-ether.h"
#include "fp-cksum.h"
#include "fp-ip.h"
#include "fp-if.h"

#include "cvmx-rng.h"

uint32_t get_random_4_bytes(void *buf, int nbytes)
{
   return cvmx_rng_get_random32();
}


#if 0

#if defined(BCN_MIPS)
#define CVMX_FPA_PKTBUF_POOL                 (7)             
#else
#define CVMX_FPA_PKTBUF_POOL                 (6)         
#endif

#define CVMX_FPA_PKTBUF_POOL_SIZE            (16 * CVMX_CACHE_LINE_SIZE)

struct fake_sk_buff  fake_sk_buf;

#define ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))
#define L1_CACHE_SHIFT 5
#define L1_CACHE_BYTES (1 << L1_CACHE_SHIFT)
#define SKB_DATA_ALIGN(X)	ALIGN(X, L1_CACHE_BYTES)

struct sk_buff * se_alloc_skb(unsigned int length)
{
	struct sk_buff *skb = &fake_sk_buf.sk_buf;
	unsigned int fragsz = SKB_DATA_ALIGN(length + 32) +
			       SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	skb->head = (unsigned char*)&(fake_sk_buf.data[0]);
	skb->data = (unsigned char*)&(fake_sk_buf.data[0]);
   skb_reset_tail_pointer(skb);
	skb->end = skb->tail + fragsz;

	return skb;
}

static struct sk_buff * cvmx_wqe_to_skbuf(cvmx_wqe_t *wqe)
{
	struct sk_buff *skb;

	cvmx_buf_ptr_t segment_ptr = wqe->packet_ptr;
	uint16_t pki_100_adjust = 8;
   
	uint16_t len = w_len(wqe);
	uint8_t segs = wqe->word2.s.bufs;

   uint16_t segment_len = 0;

	if ( ((segment_ptr.s.pool == 0)||(segment_ptr.s.pool == CVMX_FPA_PKTBUF_POOL)) && (((uint64_t)segment_ptr.s.size +
					((uint64_t)segment_ptr.s.back << 7) + ((uint64_t)segment_ptr.s.addr & 0x7F))
				!= (CVMX_FPA_PACKET_POOL_SIZE+8))) {
		pki_100_adjust = 0;
	}

   skb = se_alloc_skb(len);
   
   if(segs == 0){
      memcpy(skb_put(skb, len), wqe->packet_data, len);
   }else{
	   for (;;) {
		   if (--segs == 0) {
            memcpy(skb_put(skb,len),           
                cvmx_phys_to_ptr(segment_ptr.s.addr),            
                len);
            break;         
		   } else {
            segment_len = segment_ptr.s.size - pki_100_adjust;
            memcpy(skb_put(skb, segment_len),           
                   cvmx_phys_to_ptr(segment_ptr.s.addr),            
                   segment_len);
			
			   len -= segment_len;

			   segment_ptr = *(cvmx_buf_ptr_t*)cvmx_phys_to_ptr(segment_ptr.s.addr - 8);		
		   }
	   }
   }
   skb->ip_summed = 0;
   return skb;
}

int ovs_se_handle_frame(cvmx_wqe_t * wqe)
{
	struct sk_buff *skb;

   printf("\n***** 555 *****.\n");

   skb = cvmx_wqe_to_skbuf(wqe);

   printf("\n***** 666 *****.\n");

   return 1;
}

#endif

extern struct vport *ovs_vport_locate(const char *name);
extern int ovs_dump_data(void * data, int len);
extern int fp_if_output(struct mbuf *m, fp_ifnet_t *ifp);

/*
  the index is the ifindex of the interface
*/
#define  IF_INDEX_MAX 100
CVMX_SHARED struct vport * g_vport_cache_array[IF_INDEX_MAX];

/*
    the index is the port index of the vport. we only support one datapath
*/
#define  PORT_NO_MAX 100   
CVMX_SHARED fp_ifnet_t *g_ifp_cache_array[PORT_NO_MAX];


/*
   use for save header for the packet
*/
struct sk_buff g_sk_buf;
char   g_frame_data[4096];

int ovs_se_check_vport(fp_ifnet_t *ifp)
{

   static CVMX_SHARED int j = 0;
   if(g_vport_cache_array[ifp->if_index] != NULL){
      return 1;
   }
     
   struct vport * l_vport = NULL;
   l_vport =  ovs_vport_locate((const char *)&(ifp->if_name[0]));

    if (l_vport) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n****  get port %s *****.\n",
                (const char * )&(ifp->if_name[0]));
        j++;
        g_vport_cache_array[ifp->if_index] = l_vport;
        g_ifp_cache_array[l_vport->port_no] = ifp;

        return 1;
    }

    if (j < 10) {
        SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n**** not get port %s *****.\n",
                (const char * )&(ifp->if_name[0]));
        j++;
    }
   return 0;
}

fp_ifnet_t* ovs_se_get_ifnet(struct vport  *vportp)
 {

    if (g_ifp_cache_array[vportp->port_no] != NULL) {
        return g_ifp_cache_array[vportp->port_no];
    }

    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " ovs_se_get_ifnet  not find the ifnet \n");

    fp_ifnet_t* l_ifp = NULL;
    l_ifp = fp_getifnetbyname((const char *) &(vportp->port_name[0]));

    SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, " ovs_se_get_ifnet after fp get \n");

    if (l_ifp) {
        g_ifp_cache_array[vportp->port_no] = l_ifp;

        return l_ifp;
    }

    return NULL;
}


/* Not support jumpo frame */
#define MAX_FRAME_SIZE   2000

struct sk_buff * ovs_alloc_skb(struct mbuf *m)
 {

    struct sk_buff *skb = &g_sk_buf;
    memset(skb, 0, sizeof(struct sk_buff));

#ifdef _USE_SKB_BUF_
    uint16_t len = w_len(&(m->wqe));
    
    //here we only copy the header, 96 maybe enough for GTPU header
    if (len > 196){
       len = 196;
    }

    skb->head = (unsigned char*) &(g_frame_data[0]); //reserve header
    skb->data = (unsigned char*) &(g_frame_data[32]);
    skb_reset_tail_pointer(skb);
    skb->end = skb->tail + MAX_FRAME_SIZE;

    skb->tail += len;
    skb->data_len = 0;
    skb->len = len;

    m_copytobuf(skb->data, m, 0, len);
#else

/* 
   #define CVMX_HELPER_FIRST_MBUFF_SKIP 208
   CVMX_HELPER_FIRST_MBUFF_SKIP is the number of bytes to reserve 
   before the beginning of the packet.  

   here i only use 18.
*/

 	uint64_t buf = ((uint64_t)((long)((m)->wqe.packet_ptr.s.addr)));
	uint64_t start = buf - 8 - 10;
	uint64_t tail = buf + m_len(m);   

   skb->head = (unsigned char *)cvmx_phys_to_ptr(start);
   skb->data = (unsigned char *)cvmx_phys_to_ptr(buf); 
   skb->tail = (unsigned char *)cvmx_phys_to_ptr(tail); ;
   skb->end = skb->tail;
   
   skb->data_len = 0;
   skb->len = m_len(m);
   
#endif

    return skb;
}


int ovs_input_novnb(struct mbuf *m, fp_ifnet_t *ifp)
 {
    int l_res = 0;
    struct sk_buff *skb = NULL;
    struct vport * vport = NULL;

    if (0 == strncmp((const char *) &(ifp->if_name[0]), "sfp", 3)) {

        l_res = ovs_se_check_vport(ifp);
        if (l_res == 1) {

            skb = ovs_alloc_skb(m);

//            ovs_dump_data((char*) skb->data, skb->len);

            OVS_CB(skb)->m = m;

            vport = g_vport_cache_array[ifp->if_index];
            if (vport) {
                ovs_vport_receive(vport, skb, NULL);
                return OVS_CB(skb)->fp_output_res;
            }
        }
    }

    return FP_NONE;
}
#if 0
int ovs_se_handle_ether(struct mbuf *m, fp_ifnet_t *ifp, char * data, int len)
{

	struct sk_buff *skb = &g_sk_buf;
   memset(skb, 0, sizeof(struct sk_buff));

	skb->head = (unsigned char*)&(g_frame_data[0]);
	skb->data = (unsigned char*)&(g_frame_data[0]);
   skb_reset_tail_pointer(skb);
	skb->end = skb->tail + 4000;

   skb->tail += len;
   skb->data_len = 0;
   skb->len = len;

   ovs_dump_data(data, len);

	OVS_CB(skb)->m = m;

   ovs_vport_receive(g_vport_cache_array[ifp->if_index], skb, NULL);
   
   return OVS_CB(skb)->fp_output_res;
}
#endif



int sedev_send(struct vport *vport, struct sk_buff *skb) {

    int l_res = -1;
    int send_len = w_len(&(OVS_CB(skb)->m->wqe));
    int ret;

    fp_ifnet_t* l_ifp = ovs_se_get_ifnet(vport);
    if (l_ifp) {
        if (OVS_CB(skb)->m) {
            ret = fp_if_output(OVS_CB(skb)->m, l_ifp);
            OVS_CB(skb)->fp_output_res = ret;
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_INFO, "\n>>>%s: l_res is %d\n\n", __FUNCTION__, ret);
            if (FP_DONE == ret) {
                l_res = send_len;
            }
        } else {
            OVS_CB(skb)->fp_output_res = FP_DROP;
            SE_DEBUG_PRINT(SE_DEBUG_LEVEL_ERROR, "ERR: There's no valid mbuf to send.\n");
            l_res = 0;
        }
    }

    return l_res;
}



