/*
     * if_vlan.c - pseudo-device driver for IEEE 802.1Q virtual LANs.  Might be
     * extended some day to also handle IEEE 802.1P priority tagging.  This is
     * sort of sneaky in the implementation, since we need to pretend to be
     * enough of an Ethernet implementation to make ARP work.  The way we do
     * this is by telling everyone that we are an Ethernet interface, and then
     * catch the packets that ether_output() left on our output queue when it
     * calls if_start(), rewrite them for use by the real outgoing interface,
     * and ask it to send them.
     *
     * TODO:
     *
     *      - Need some way to notify vlan interfaces when the parent
     *        interface changes MTU.
     */
    
#include "queue.h"
#include "mbuf.h"
#include "protosw.h"
#include "socket.h"
#include "sockio.h"
#include "if.h"
#include "route.h"
#include "in.h"
#include "if_ether.h"
#include "in_var.h"
#include "if_vlanvar.h"

/* the follwing definition be added for debug */


#define  ETHER_MIN_LEN 100
#define  sockaddr_storage sockaddr
#define ethercom arpcom

int if_cloners_count  = 0;

#define VLANNAME	"vl"
#define VLAN_MAXUNIT	0x7fff

#define ASSERT(e)

extern int ifqmaxlen;
extern struct ifaddr **ifnet_addrs;
/*
 LIST_HEAD(, ifvlan) ifv_list= {NULL};
*/
struct {							
	struct ifvlan *lh_first;	
	
}ifv_list = {NULL};



static	int vlan_clone_create(struct if_clone *, int *);
static	void vlan_clone_destroy(struct ifnet *);
static	void vlan_start(struct ifnet *ifp);
static	void vlan_ifinit(void *foo);
static	int vlan_ioctl(struct ifnet *ifp, u_long cmd, caddr_t addr);
static	int vlan_unconfig(struct ifnet *ifp);
static	int vlan_config(struct ifvlan *ifv, struct ifnet *p);
              int  vlan_input(struct ether_header *eh, struct mbuf *m);

extern void if_detach(struct ifnet *ifp);
extern void rt_vlanmsg(ifp);

struct if_clone vlan_cloner =
    IF_CLONE_INITIALIZER("vl", vlan_clone_create, vlan_clone_destroy);


#define ETHERTYPE_VLAN		0x8100	/* IEEE 802.1Q VLAN tagging (XXX conflicts) */


static int
vlan_ether_addmulti(struct ifvlan *ifv, struct ifreq *ifr)
{
	struct vlan_mc_entry *mc;
	u_int8_t addrlo[ETHER_ADDR_LEN], addrhi[ETHER_ADDR_LEN];
	int error;

	if (ifr->ifr_addr.sa_len > sizeof(struct sockaddr_storage))
		return (EINVAL);

	error = ether_addmulti(ifr, &ifv->ifv_ac);
	if (error != ENETRESET)
		return (error);

	/*
	 * This is new multicast address.  We have to tell parent
	 * about it.  Also, remember this multicast address so that
	 * we can delete them on unconfigure.
	 */
	MALLOC(mc, struct vlan_mc_entry *, sizeof(struct vlan_mc_entry),
	    M_DEVBUF, M_NOWAIT);
	if (mc == NULL) {
		error = ENOMEM;
		goto alloc_failed;
	}

	/*
	 * As ether_addmulti() returns ENETRESET, following two
	 * statement shouldn't fail.
	 */
	(void)ether_multiaddr(&ifr->ifr_addr, addrlo, addrhi);
	ETHER_LOOKUP_MULTI(addrlo, addrhi, &ifv->ifv_ac, mc->mc_enm);
	memcpy(&mc->mc_addr, &ifr->ifr_addr, ifr->ifr_addr.sa_len);
	LIST_INSERT_HEAD(&ifv->vlan_mc_listhead, mc, mc_entries);

	error = (*ifv->ifv_p->if_ioctl)(ifv->ifv_p, SIOCADDMULTI,
	    (caddr_t)ifr);
	if (error != 0)
		goto ioctl_failed;
	return (error);

 ioctl_failed:
	LIST_REMOVE(mc, mc_entries);
	FREE(mc, M_DEVBUF);
 alloc_failed:
	(void)ether_delmulti(ifr, &ifv->ifv_ac);
	return (error);
}

static int
vlan_ether_delmulti(struct ifvlan *ifv, struct ifreq *ifr)
{
	struct ether_multi *enm;
	struct vlan_mc_entry *mc;
	u_int8_t addrlo[ETHER_ADDR_LEN], addrhi[ETHER_ADDR_LEN];
	int error;

	/*
	 * Find a key to lookup vlan_mc_entry.  We have to do this
	 * before calling ether_delmulti for obvious reason.
	 */
	if ((error = ether_multiaddr(&ifr->ifr_addr, addrlo, addrhi)) != 0)
		return (error);
	ETHER_LOOKUP_MULTI(addrlo, addrhi, &ifv->ifv_ac, enm);

	error = ether_delmulti(ifr, &ifv->ifv_ac);
	if (error != ENETRESET)
		return (error);

	/* We no longer use this multicast address.  Tell parent so. */
	error = (*ifv->ifv_p->if_ioctl)(ifv->ifv_p, SIOCDELMULTI,
	    (caddr_t)ifr);
	if (error == 0) {
		/* And forget about this address. */
		for (mc = LIST_FIRST(&ifv->vlan_mc_listhead); mc != NULL;
		    mc = LIST_NEXT(mc, mc_entries)) {
			if (mc->mc_enm == enm) {
				LIST_REMOVE(mc, mc_entries);
				FREE(mc, M_DEVBUF);
				break;
			}
		}
		ASSERT(mc != NULL);
	} else
		(void)ether_addmulti(ifr, &ifv->ifv_ac);
	return (error);
}

/*
 * Delete any multicast address we have asked to add form parent
 * interface.  Called when the vlan is being unconfigured.
 */
static void
vlan_ether_purgemulti(struct ifvlan *ifv)
{
	struct ifnet *ifp = ifv->ifv_p;		/* Parent. */
	struct vlan_mc_entry *mc;
	union {
		struct ifreq ifreq;
		struct {
			char ifr_name[IFNAMSIZ];
			struct sockaddr_storage ifr_ss;
		} ifreq_storage;
	} ifreq;
	struct ifreq *ifr = &ifreq.ifreq;

	memcpy(ifr->ifr_name, ifp->if_name, IFNAMSIZ);
	while ((mc = LIST_FIRST(&ifv->vlan_mc_listhead)) != NULL) {
		memcpy(&ifr->ifr_addr, &mc->mc_addr, sizeof(struct ether_addr ));
		(void)(*ifp->if_ioctl)(ifp, SIOCDELMULTI, (caddr_t)ifr);
		LIST_REMOVE(mc, mc_entries);
		FREE(mc, M_DEVBUF);
	}
}


void
vlaninit(int n)
{/*
	LIST_INIT(&ifv_list);*/
	if_clone_attach(&vlan_cloner);
}

static int
vlan_clone_create(struct if_clone *ifc, int *unit)
{

	struct ifvlan *ifv;
	struct ifnet *ifp;
	int s;

	if (*unit > VLAN_MAXUNIT)
	      return (ENXIO);

	if (*unit < 0) {
	      return (ENOSPC);
	}

	ifv = malloc(sizeof(struct ifvlan));
	memset(ifv, 0, sizeof(struct ifvlan));
	ifp = &ifv->ifv_if;
	LIST_INIT(&ifv->vlan_mc_listhead);

	s = splnet();
        LIST_INSERT_HEAD(&ifv_list, ifv, ifv_list);
	splx(s);

       ifp->if_softc = ifv;

	ifp->if_name = "vl";
	ifp->if_unit = *unit;

	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST | IFF_LOGICAL;
	
	/* NB: flags are not set here */
#if 0	
	ifp->if_linkmib = &ifv->ifv_mib;
	ifp->if_linkmiblen = sizeof ifv->ifv_mib;
#endif
	/* NB: mtu is not set here */

	ifp->if_init = vlan_ifinit;
	ifp->if_start = vlan_start;
	ifp->if_ioctl = vlan_ioctl;
	ifp->if_output = ether_output;
	ifp->if_snd.ifq_maxlen = ifqmaxlen;	

	ether_ifattach(ifp);
	if_attach(ifp);

/*
	if(ifp)
   	  rt_ifmsg(ifp);

       rt_ifannouncemsg(ifp, IFAN_ARRIVAL);
*/
/*	
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
*/
	/* Now undo some of the damage... 
	   ifp->if_data.ifi_type = IFT_L2VLAN; */
	ifp->if_data.ifi_hdrlen = EVL_ENCAPLEN;

	return (0);


}


static void
vlan_clone_destroy(struct ifnet *ifp)
{
	struct ifvlan *ifv = ifp->if_softc;
	int s;
	int err;

       ifp->if_flags |= IFF_LINK1;

	s = splnet();
	LIST_REMOVE(ifv, ifv_list);
	vlan_unconfig(ifp);
	splx(s);
	 
       if_detach(ifp);
	free(ifv, M_DEVBUF);

}

static void
vlan_ifinit(void *foo)
{
	return;
}

static void
vlan_start(struct ifnet *ifp)
{
	struct ifvlan *ifv;
	struct ifnet *p;
	struct ether_vlan_header *evl;
	struct mbuf *m;

	ifv = ifp->if_softc;
	p = ifv->ifv_p;

	ifp->if_flags |= IFF_OACTIVE;
	for (;;) {
		IF_DEQUEUE(&ifp->if_snd, m);
		if (m == 0)
			break;

#if NBPFILTER > 0		
		if (ifp->if_bpf)
			bpf_mtap(ifp, m);
#endif /* NBPFILTER > 0 */

		/*
		 * Do not run parent's if_start() if the parent is not up,
		 * or parent's driver will cause a system crash.
		 */
		if ((p->if_flags & (IFF_UP | IFF_RUNNING)) !=
					(IFF_UP | IFF_RUNNING)) {
			m_freem(m);
			ifp->if_data.ifi_collisions++;
			continue;
		}

		/*
		 * If the LINK0 flag is set, it means the underlying interface
		 * can do VLAN tag insertion itself and doesn't require us to
	 	 * create a special header for it. In this case, we just pass
		 * the packet along. However, we need some way to tell the
		 * interface where the packet came from so that it knows how
		 * to find the VLAN tag to use, so we set the rcvif in the
		 * mbuf header to our ifnet.
		 *
		 * Note: we also set the M_PROTO1 flag in the mbuf to let
		 * the parent driver know that the rcvif pointer is really
		 * valid. We need to do this because sometimes mbufs will
		 * be allocated by other parts of the system that contain
		 * garbage in the rcvif pointer. Using the M_PROTO1 flag
		 * lets the driver perform a proper sanity check and avoid
		 * following potentially bogus rcvif pointers off into
		 * never-never land.
		 */
		if (ifp->if_flags & IFF_LINK0) {
			m->m_pkthdr.rcvif = ifp;
			m->m_flags |= M_PROTO1;
		} else {
			M_PREPEND(m, EVL_ENCAPLEN, M_DONTWAIT);
			if (m == NULL) {
				printf("vlan%d: M_PREPEND failed", ifp->if_unit);
				ifp->if_ierrors++;
				continue;
			}
			/* M_PREPEND takes care of m_len, m_pkthdr.len for us */

			m = m_pullup(m, ETHER_HDR_LEN + EVL_ENCAPLEN);
			if (m == NULL) {
				printf("vlan%d: m_pullup failed", ifp->if_unit);
				ifp->if_ierrors++;
				continue;
			}

			/*
			 * Transform the Ethernet header into an Ethernet header
			 * with 802.1Q encapsulation.
			 */
			bcopy(mtod(m, char *) + EVL_ENCAPLEN, mtod(m, char *),
			      sizeof(struct ether_header));
			evl = mtod(m, struct ether_vlan_header *);
			evl->evl_proto = evl->evl_encap_proto;
			evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
			evl->evl_tag = htons(ifv->ifv_tag);

#define ARP_VLAN_RPIORITY 0xE000
#define VLAN_PRIORITY_MASK 0x1FFF
			/* If the sent packet is arp, hardcode its vlan priority with 7 
			   if(ETHERTYPE_ARP == evl->evl_proto)
                             
                        */
			
                         evl->evl_tag = evl->evl_tag & VLAN_PRIORITY_MASK | ARP_VLAN_RPIORITY;
			

#ifdef DEBUG
			printf("vlan_start: %*D\n", sizeof *evl,
			    (char *)evl, ":");
#endif
		}

		/*
		 * Send it, precisely as ether_output() would have.
		 * We are already running at splimp.
		 */
		if (IF_QFULL(&p->if_snd)) {
			IF_DROP(&p->if_snd);
				/* XXX stats */
			ifp->if_oerrors++;
			m_freem(m);
			continue;
		}
		IF_ENQUEUE(&p->if_snd, m);
		ifp->if_opackets++;
		p->if_obytes += m->m_pkthdr.len;
		if (m->m_flags & M_MCAST)
			p->if_omcasts++;
		if ((p->if_flags & IFF_OACTIVE) == 0)
			p->if_start(p);
	}
	ifp->if_flags &= ~IFF_OACTIVE;

	return;
}

 int
vlan_input_tag(struct ether_header *eh, struct mbuf *m, u_int16_t t)
{
	struct ifvlan *ifv;

	/*
	 * Fake up a header and send the packet to the physical interface's
	 * bpf tap if active.
	 */
	if (m->m_pkthdr.rcvif->if_bpf != NULL) {
		struct m_hdr mh;
		struct ether_vlan_header evh;

		bcopy(eh, &evh, 2*ETHER_ADDR_LEN);
		evh.evl_encap_proto = htons(ETHERTYPE_VLAN);
		evh.evl_tag = htons(t);
		evh.evl_proto = eh->ether_type;

		/* This kludge is OK; BPF treats the "mbuf" as read-only */
		mh.mh_next = m;
		mh.mh_data = (char *)&evh;
		mh.mh_len = ETHER_HDR_LEN + EVL_ENCAPLEN;
/*		bpf_mtap(m->m_pkthdr.rcvif, (struct mbuf *)&mh); */
	}

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	    ifv = LIST_NEXT(ifv, ifv_list)) {
		if (m->m_pkthdr.rcvif == ifv->ifv_p
		    && ifv->ifv_tag == EVL_VLANOFTAG(t))
			break;
	}  

	if (ifv == NULL || (ifv->ifv_if.if_flags & IFF_UP) == 0) {
		m_freem(m);
		return -1;	/* So the parent can take note */
	}

	/*
	 * Having found a valid vlan interface corresponding to
	 * the given source interface and vlan tag, run the
	 * the real packet through ether_input().
	 */
	m->m_pkthdr.rcvif = &ifv->ifv_if;

	ifv->ifv_if.if_ipackets++;
	ether_input(&ifv->ifv_if, eh, m);
	return 0;
}

 int
vlan_input(struct ether_header *eh, struct mbuf *m)
{
	struct ifvlan *ifv;

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	    ifv = LIST_NEXT(ifv, ifv_list)) {
		if (m->m_pkthdr.rcvif == ifv->ifv_p
		    && (EVL_VLANOFTAG(ntohs(*mtod(m, u_int16_t *)))
			== ifv->ifv_tag))
			break;
	}

	if (ifv == NULL || (ifv->ifv_if.if_flags & IFF_UP) == 0) {
		m->m_pkthdr.rcvif->if_noproto++;
		m_freem(m);
		return -1;	/* so ether_input can take note */
	}



	/*
	 * Having found a valid vlan interface corresponding to
	 * the given source interface and vlan tag, remove the
	 * encapsulation, and run the real packet through
	 * ether_input() a second time (it had better be
	 * reentrant!).
	 */
	m->m_pkthdr.rcvif = &ifv->ifv_if;
	eh->ether_type = mtod(m, u_int16_t *)[1];
	m->m_data += EVL_ENCAPLEN;
	m->m_len -= EVL_ENCAPLEN;
	m->m_pkthdr.len -= EVL_ENCAPLEN;

#if NBPFILTER > 0
	if (ifv->ifv_if.if_bpf) {
		/*
		 * Do the usual BPF fakery.  Note that we don't support
		 * promiscuous mode here, since it would require the
		 * drivers to know about VLANs and we're not ready for
		 * that yet.
		 */
		struct mbuf m0;
		m0.m_next = m;
		m0.m_len = sizeof(struct ether_header);
		m0.m_data = (char *)eh;
		bpf_mtap(&ifv->ifv_if, &m0);
	}
#endif

	ifv->ifv_if.if_ipackets++;
	ether_input(&ifv->ifv_if, eh, m);
	return 0;
}

static int
vlan_config(struct ifvlan *ifv, struct ifnet *p)
{
	struct ifaddr *ifa1, *ifa2;
	struct sockaddr_dl *sdl1, *sdl2;

	if (p->if_data.ifi_type != IFT_ETHER)
		return EPROTONOSUPPORT;
	if (ifv->ifv_p)
		return EBUSY;
	
	ifv->ifv_p = p;
	if (p->if_data.ifi_hdrlen == sizeof(struct ether_vlan_header))
		ifv->ifv_if.if_mtu = p->if_mtu;
	else
		ifv->ifv_if.if_mtu = p->if_data.ifi_mtu - EVL_ENCAPLEN;

	/*
	 * Copy only a selected subset of flags from the parent.
	 * Other flags are none of our business.
	 */
	ifv->ifv_if.if_flags |= (p->if_flags &
	    (IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX ));

	ifv->ifv_if.if_flags |= IFF_LOGICAL;

	ifv->ifv_if.if_type = p->if_type;

	/*
	 * Set up our ``Ethernet address'' to reflect the underlying
	 * physical interface's.
	 */
#ifndef KAME6
  	ifa1 = ifnet_addrs[ifv->ifv_if.if_index - 1];
#else
	ifa1 = ifnet_addrs[ifv->ifv_if.if_index];
#endif /* KAME6 */		


#ifndef KAME6
	ifa2 = ifnet_addrs[p->if_index - 1];
#else
	ifa2 = ifnet_addrs[p->if_index];
#endif /* KAME6 */


	sdl1 = (struct sockaddr_dl *)ifa1->ifa_addr;
	sdl2 = (struct sockaddr_dl *)ifa2->ifa_addr;
	sdl1->sdl_type = IFT_ETHER;
	sdl1->sdl_alen = ETHER_ADDR_LEN;

	
	bcopy(LLADDR(sdl2), LLADDR(sdl1), ETHER_ADDR_LEN);
	bcopy(LLADDR(sdl2), ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);

	/*
	 * Configure multicast addresses that may already be
	 * joined on the vlan device.
	 */

	/* 
           vlan_ether_addmulti
	 */
	return 0;
}

static int
vlan_unconfig(struct ifnet *ifp)
{
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;
	struct vlan_mc_entry *mc;
	struct ifvlan *ifv;
	int error;

       ifv = ifp->if_softc;

/*
	vlan_ether_purgemulti(ifv); 
*/

#ifndef KAME6
	ifa = ifnet_addrs[ifv->ifv_if.if_index - 1];
#else
	ifa = ifnet_addrs[ifv->ifv_if.if_index ];
#endif /* KAME6 */		

	if (ifa == NULL) {
          return 0;
	}
	
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	sdl->sdl_type = IFT_ETHER;
	sdl->sdl_alen = ETHER_ADDR_LEN;
	bzero(LLADDR(sdl), ETHER_ADDR_LEN);
	bzero(ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);

	/* Disconnect from parent. */
	ifv->ifv_p = NULL;
	ifv->ifv_if.if_mtu = ETHERMTU;
       ifv->ifv_if.if_flags = 0;
	
	ifp->if_flags &= ~(IFF_UP|IFF_RUNNING);
	return 0;
}
void
vlan_change_running_status(struct ifnet *ifp, int running)
{
	struct ifvlan *ifv;
	int s;

	s = splimp();

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	     ifv = LIST_NEXT(ifv, ifv_list)) {
		if (ifv->ifv_p == ifp) {
			if (running) {
				/* Parent must be UP and RUNNING, before VLAN
				 * can be RUNNING!
				 */
				if ((ifv->ifv_p->if_flags & (IFF_UP|IFF_RUNNING)) == (IFF_UP|IFF_RUNNING))
					ifv->ifv_if.if_flags |= IFF_RUNNING;
			} else
				ifv->ifv_if.if_flags &= ~IFF_RUNNING;

			rt_ifmsg(&ifv->ifv_if);

		}
	}

	splx(s);
}



void vlan_change_mac(struct ifnet *ifp)
{
	struct ifvlan *ifv;
	int s;
	struct ifaddr *ifa1, *ifa2;
	struct sockaddr_dl *sdl1, *sdl2;	

	s = splimp();

	for (ifv = LIST_FIRST(&ifv_list); ifv != NULL;
	     ifv = LIST_NEXT(ifv, ifv_list)) {
		if (ifv->ifv_p == ifp) {
						#ifndef KAME6
							ifa1 = ifnet_addrs[ifp->if_index - 1];
						#else
							ifa1 = ifnet_addrs[ifp->if_index];
						#endif /* KAME6 */


						#ifndef KAME6
							ifa2 = ifnet_addrs[ifv->ifv_if.if_index - 1];
						#else
							ifa2 = ifnet_addrs[ifv->ifv_if.if_index];
						#endif /* KAME6 */


						sdl1 = (struct sockaddr_dl *)ifa1->ifa_addr;
						sdl2 = (struct sockaddr_dl *)ifa2->ifa_addr;
						

						bcopy(LLADDR(sdl1), LLADDR(sdl2), ETHER_ADDR_LEN);
						bcopy(LLADDR(sdl1), ifv->ifv_ac.ac_enaddr, ETHER_ADDR_LEN);


						rt_ifmsg(&ifv->ifv_if);

		}
	}

	splx(s);
}
static int
vlan_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ifaddr *ifa;
	struct ifnet *p;
	struct ifreq *ifr;
	struct ifvlan *ifv;
	struct vlanreq vlr;
	int error = 0;

	ifr = (struct ifreq *)data;
	ifa = (struct ifaddr *)data;
	ifv = ifp->if_softc;

	switch (cmd) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			arp_ifinit(&ifv->ifv_if, ifa);
			break;
#endif
		default:
			break;
		}
		break;

	case SIOCGIFADDR:
		{
			struct sockaddr *sa;

			sa = (struct sockaddr *) &ifr->ifr_data;
			bcopy(((struct arpcom *)ifp->if_softc)->ac_enaddr,
			      (caddr_t) sa->sa_data, ETHER_ADDR_LEN);
		}
		break;

	case SIOCGIFMEDIA:
		if (ifv->ifv_p != NULL) {
			error = (ifv->ifv_p->if_ioctl)(ifv->ifv_p, SIOCGIFMEDIA, data);
			/* Limit the result to the parent's current config. */
			if (error == 0) {
				struct ifmediareq *ifmr;

				ifmr = (struct ifmediareq *) data;
				if (ifmr->ifm_count >= 1 && ifmr->ifm_ulist) {
					ifmr->ifm_count = 1;
					error = copyout(&ifmr->ifm_current,
						ifmr->ifm_ulist, 
						sizeof(int));
				}
			}
		} else
			error = EINVAL;
		break;

	case SIOCSIFMEDIA:
		error = EINVAL;
		break;

	case SIOCSIFMTU:
		/*
		 * Set the interface MTU.
		 * This is bogus. The underlying interface might support
	 	 * jumbo frames.
		 */
		
              if (ifv->ifv_p == NULL)
                 break;

              if (ifr->ifr_mtu > ifv->ifv_p->if_mtu) {
			error = EINVAL;
		} else {
			ifp->if_mtu = ifr->ifr_mtu;
		}
		break;

	case SIOCSETVLAN:
		error = copyin(ifr->ifr_data, &vlr, sizeof vlr);
		if (error)
			break;
		if (vlr.vlr_tag & ~EVL_VLID_MASK) {
			error = EINVAL;
			break;
		}
		if (vlr.vlr_parent[0] == '\0') {
			vlan_unconfig(ifp);
			if (ifp->if_flags & IFF_UP) {
				int s = splimp();
				if_down(ifp);
				splx(s);
			}		
			ifp->if_flags &= ~IFF_RUNNING;
			break;
		}
		p = ifunit(vlr.vlr_parent);
        	if (p == 0){
#ifdef DYNAMIC_INTERFACE
                  p = ifmake(vlr.vlr_parent);
                  if (p == 0){
                     return (ENXIO);
	   	    }          
#else
                  return (ENXIO);
#endif
	       }	
			
		error = vlan_config(ifv, p);
		if (error)
			break;
		ifv->ifv_tag = vlr.vlr_tag;

		if ((p->if_flags & (IFF_RUNNING|IFF_UP)) != (IFF_RUNNING|IFF_UP))
			ifp->if_flags &= ~IFF_RUNNING;
		else
			ifp->if_flags |= IFF_RUNNING;
		
		rt_vlanmsg(ifp);
		break;
		
	case SIOCGETVLAN:
		
		bzero(&vlr, sizeof vlr);
		if (ifv->ifv_p) {
			sprintf(vlr.vlr_parent, sizeof(vlr.vlr_parent),
			    "%s%d", ifv->ifv_p->if_name, ifv->ifv_p->if_unit);
			vlr.vlr_tag = ifv->ifv_tag;
		}
		error = copyout(&vlr, ifr->ifr_data, sizeof vlr);
		break;
		
	case SIOCSIFFLAGS:		
		/*
		 * We don't support promiscuous mode
		 * right now because it would require help from the
		 * underlying drivers, which hasn't been implemented.
		 */
		if (ifr->ifr_flags & (IFF_PROMISC)) {
			ifp->if_flags &= ~(IFF_PROMISC);
			error = EINVAL;
		}
		break;
	case SIOCADDMULTI:
		error = (ifv->ifv_p != NULL) ?
		    vlan_ether_addmulti(ifv, ifr) : EINVAL;
		break;
		
	case SIOCDELMULTI:
		error = (ifv->ifv_p != NULL) ?
		    vlan_ether_delmulti(ifv, ifr) : EINVAL;
		break;
	default:
		error = 0; /*EINVAL; */
	}
	return error;
}	

void create_vlan_r()
{

  struct if_clone ifc;
  int unit = 0;

 int		cmd;
 struct socket		so;
 
 struct ifreq		ifreq_rec;
 struct in_aliasreq		alias_rec;

 struct ifnet *      ifnet_eth_ptr;
 struct ifnet *      ifnet_vlan_ptr;
 

 memset (ifreq_rec.ifr_name,0,IFNAMSIZ);
 memcpy(ifreq_rec.ifr_name,"eth1",5);
 
 ifnet_eth_ptr = ifunit(ifreq_rec.ifr_name);
 if(ifnet_eth_ptr == NULL)
 	return;  

 
   
    vlan_clone_create(&ifc, &unit);


memset (ifreq_rec.ifr_name,0,IFNAMSIZ);
 memcpy(ifreq_rec.ifr_name,"vl0",4);
 
 ifnet_vlan_ptr = ifunit(ifreq_rec.ifr_name);
 if(ifnet_vlan_ptr == NULL)
 	return;  
	

   vlan_config(ifnet_vlan_ptr, ifnet_eth_ptr);
   

}





