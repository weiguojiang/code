
#include "queue.h"
#include "if.h"
#include "if_ether.h"
#include "if_vlanvar.h"
#include "bpf.h"


int	ifqmaxlen = IFQ_MAXLEN;
void	if_slowtimo __P((void *arg));

struct ifnet *ifnet;
extern struct	ifqueue ipintrq;


#ifndef NULL
#define NULL (void *)0
#endif
/*
LIST_HEAD(, if_clone) if_cloners = {NULL};
*/
struct {							
	struct if_clone *lh_first;	
	
}if_cloners = {NULL};


int if_cloners_count;


/*
 * Look up a network interface cloner.
 */
struct if_clone *
if_clone_lookup(name, unitp)
	const char *name;
	int *unitp;
{
	struct if_clone *ifc;
	const char *cp;
	int i;

	for (ifc = LIST_FIRST(&if_cloners); ifc != NULL;) {
		for (cp = name, i = 0; i < ifc->ifc_namelen; i++, cp++) {
			if (ifc->ifc_name[i] != *cp)
				goto next_ifc;
		}
		goto found_name;
 next_ifc:
		ifc = LIST_NEXT(ifc, ifc_list);
	}

	/* No match. */
	return (NULL);

 found_name:
	for (i = 0; *cp != '\0'; cp++) {
		if (*cp < '0' || *cp > '9') {
			/* Bogus unit number. */
			return (NULL);
		}
		i = (i * 10) + (*cp - '0');
	}

	if (unitp != NULL)
		*unitp = i;

	return (ifc);
}

/*
 * Register a network interface cloner.
 */
void
if_clone_attach(ifc)
	struct if_clone *ifc;
{
	LIST_INSERT_HEAD(&if_cloners, ifc, ifc_list);
	if_cloners_count++;
}

/*
 * Unregister a network interface cloner.
 */
void
if_clone_detach(ifc)
	struct if_clone *ifc;
{
	LIST_REMOVE(ifc, ifc_list);
	if_cloners_count--;
}

int
if_clone_create(name)
	const char *name;
{
	struct if_clone *ifc;
	int unit;

	ifc = if_clone_lookup(name, &unit);
	if (ifc == NULL)
		return (EINVAL);

	if (ifunit(name) != NULL)
		return (EEXIST);

	return ((*ifc->ifc_create)(ifc, unit));
}

/*
 * Destroy a clone network interface.
 */
int
if_clone_destroy(name)
	const char *name;
{
	struct if_clone *ifc;
	struct ifnet *ifp;

	ifc = if_clone_lookup(name, NULL);
	if (ifc == NULL)
		return (EINVAL);

	ifp = ifunit(name);
	if (ifp == NULL)
		return (ENXIO);

	if (ifc->ifc_destroy == NULL)
		return (EOPNOTSUPP);

	(*ifc->ifc_destroy)(ifp);
	return (0);
}

/*
 * Provide list of interface cloners to userspace.
 */
int
if_clone_list(ifcr)
	struct if_clonereq *ifcr;
{
	char outbuf[IFNAMSIZ], *dst;
	struct if_clone *ifc;
	int count, error = 0;

	ifcr->ifcr_total = if_cloners_count;
	if ((dst = ifcr->ifcr_buffer) == NULL) {
		/* Just asking how many there are. */
		return (0);
	}

	if (ifcr->ifcr_count < 0)
		return (EINVAL);

	count = (if_cloners_count < ifcr->ifcr_count) ?
	    if_cloners_count : ifcr->ifcr_count;

	for (ifc = LIST_FIRST(&if_cloners); ifc != NULL && count != 0;
	     ifc = LIST_NEXT(ifc, ifc_list), count--, dst += IFNAMSIZ) {
		strncpy(outbuf, ifc->ifc_name, IFNAMSIZ);
		outbuf[IFNAMSIZ - 1] = '\0';	/* sanity */
		error = copyout(outbuf, dst, IFNAMSIZ);
		if (error)
			break;
	}

	return (error);
}




/*
 * Network interface utility routines.
 *
 * Routines with ifa_ifwith* names take sockaddr *'s as
 * parameters.
 */
void
ifinit()
{
	register struct ifnet *ifp;

	for (ifp = ifnet; ifp; ifp = ifp->if_next)
		if (ifp->if_snd.ifq_maxlen == 0)
			ifp->if_snd.ifq_maxlen = ifqmaxlen;
	if_slowtimo(0);
}


int if_index = 0;
struct ifaddr **ifnet_addrs;
static char *sprint_d __P((u_int, char *, int));

/*
 * Attach an interface to the
 * list of "active" interfaces.
 */
void
if_attach(ifp)
	struct ifnet *ifp;
{
	unsigned socksize, ifasize;
	int namelen, unitlen, masklen, ether_output();
	char workbuf[12], *unitname;
	register struct ifnet **p = &ifnet;
	register struct sockaddr_dl *sdl;
	register struct ifaddr *ifa;
	static int if_indexlim = 8;
	extern void link_rtrequest();

	while (*p)
		p = &((*p)->if_next);
	*p = ifp;
	ifp->if_index = ++if_index;
	if (ifnet_addrs == 0 || if_index >= if_indexlim) {
		unsigned n = (if_indexlim <<= 1) * sizeof(ifa);
		struct ifaddr **q = (struct ifaddr **)
					malloc(n);
		if (ifnet_addrs) {
			memcpy((caddr_t)q, (caddr_t)ifnet_addrs,  n/2);
			free((caddr_t)ifnet_addrs );
		}
		ifnet_addrs = q;
	}
	/*
	 * create a Link Level name for this device
	 */
	unitname = sprint_d((u_int)ifp->if_unit, workbuf, sizeof(workbuf));
	namelen = strlen(ifp->if_name);
	unitlen = strlen(unitname);
#define _offsetof(t, m) ((int)((caddr_t)&((t *)0)->m))
	masklen = _offsetof(struct sockaddr_dl, sdl_data[0]) +
			       unitlen + namelen;
	socksize = masklen + ifp->if_addrlen;
#define ROUNDUP(a) (1 + (((a) - 1) | (sizeof(long) - 1)))
	socksize = ROUNDUP(socksize);
	
	if (socksize < sizeof(*sdl))
		socksize = sizeof(*sdl);
/*
   if (socksize < sizeof(struct sockaddr_dl))
		socksize = sizeof(struct sockaddr_dl);
*/		
	ifasize = sizeof(*ifa) + 2 * socksize;
	if (ifa = (struct ifaddr *)malloc(ifasize)) {
		bzero((caddr_t)ifa, ifasize);
		sdl = (struct sockaddr_dl *)(ifa + 1);
		sdl->sdl_len = socksize;
		sdl->sdl_family = AF_LINK;
		memcpy(sdl->sdl_data, ifp->if_name, namelen);
		memcpy(namelen + (caddr_t)sdl->sdl_data, unitname, unitlen);
		sdl->sdl_nlen = (namelen += unitlen);
		sdl->sdl_index = ifp->if_index;
		sdl->sdl_type = ifp->if_type;
		ifnet_addrs[if_index - 1] = ifa;
		ifa->ifa_ifp = ifp;
		ifa->ifa_next = ifp->if_addrlist;
		ifa->ifa_rtrequest = link_rtrequest;
		ifp->if_addrlist = ifa;
		ifa->ifa_addr = (struct sockaddr *)sdl;
		sdl = (struct sockaddr_dl *)(socksize + (caddr_t)sdl);
		ifa->ifa_netmask = (struct sockaddr *)sdl;
		sdl->sdl_len = masklen;
		while (namelen != 0)
			sdl->sdl_data[--namelen] = 0xff;
	}
	/* XXX -- Temporary fix before changing 10 ethernet drivers */
	
	if (ifp->if_output == ether_output) 
		ether_ifattach(ifp);  
#if 1
	rt_ifannouncemsg(ifp, IFAN_ARRIVAL);
#endif
}


/*
 * Delete Routes for a Network Interface
 * 
 * Called for each routing entry via the rnh->rnh_walktree() call above
 * to delete all route entries referencing a detaching network interface.
 *
 * Arguments:
 *	rn	pointer to node in the routing table
 *	arg	argument passed to rnh->rnh_walktree() - detaching interface
 *
 * Returns:
 *	0	successful
 *	errno	failed - reason indicated
 *
 */
static int
if_rtdel(rn, arg)
	struct radix_node	*rn;
	void			*arg;
{
	struct rtentry	*rt = (struct rtentry *)rn;
	struct ifnet	*ifp = (struct ifnet	*)arg;
	int		err;

	if (rt->rt_ifp == ifp) {

		/*
		 * Protect (sorta) against walktree recursion problems
		 * with cloned routes
		 */
		if ((rt->rt_flags & RTF_UP) == 0)
			return (0);

		err = rtrequest(RTM_DELETE, rt_key(rt), rt->rt_gateway,
				rt_mask(rt), rt->rt_flags,
				(struct rtentry **) NULL);
		if (err) {
			log(LOG_WARNING, "if_rtdel: error %d\n", err);
		}
	}

	return (0);
}



/*
 * Detach an interface, removing it from the
 * list of "active" interfaces.
 */
void
if_detach(ifp)
	struct ifnet *ifp;
{
	struct ifaddr *ifa, *next;
	struct radix_node_head	*rnh;
	int s;
	int i;
	struct ifnet *iter;
	struct ifnet **p = &ifnet;
	int found;

	/*
	 * Remove routes and flush queues.
	 */
	s = splnet();

	if_down(ifp);

	/*
	 * Remove address from ifnet_addrs[] and maybe decrement if_index.
	 * Clean up all addresses.
	 */

#ifndef KAME6
	ifnet_addrs[ifp->if_index - 1] = 0;
#else
	ifnet_addrs[ifp->if_index] = 0;
#endif /* KAME6 */

	for (ifa = ifp->if_addrlist;  ifa; ifa = ifp->if_addrlist->ifa_next) {

		if (ifa->ifa_addr->sa_family == AF_LINK)
			continue;
#ifdef INET
		/* XXX: Ugly!! ad hoc just for INET */
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
			/* fake socket to keep in_control happy */
			struct socket so[1];
			struct ifaliasreq ifr;

			so->so_state = SS_PRIV;
			bzero(&ifr, sizeof(ifr));
			ifr.ifra_addr = *ifa->ifa_addr;
			if (ifa->ifa_dstaddr)
				ifr.ifra_broadaddr = *ifa->ifa_dstaddr;
			if (in_control(so, SIOCDIFADDR, (caddr_t)&ifr, ifp,
			    NULL) == 0)
				continue;
		}
#endif /* INET */
#ifdef INET6
		if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
			in6_purgeaddr(ifa, ifp);
			/* ifp_addrhead is already updated */
			continue;
		}
#endif /* INET6 */

	}

#ifdef INET6
	/*
	 * Remove all IPv6 kernel structs related to ifp.  This should be done
	 * before removing routing entries below, since IPv6 interface direct
	 * routes are expected to be removed by the IPv6-specific kernel API.
	 * Otherwise, the kernel will detect some inconsistency and bark it.
	 */
	in6_ifdetach(ifp);
#endif

       if(ifp->if_addrlist)
	      IFAFREE(ifp->if_addrlist);

	/*
	 * Delete all remaining routes using this interface
	 * Unfortuneatly the only way to do this is to slog through
	 * the entire routing table looking for routes which point
	 * to this interface...oh well...
	 */
	for (i = 1; i <= AF_MAX; i++) {
		if ((rnh = rt_tables[i]) == NULL)
			continue;
		(void) rnh->rnh_walktree(rnh, if_rtdel, ifp);
	}

   /* Announce that the interface is gone.  */
   rt_ifannouncemsg(ifp, IFAN_DEPARTURE); 

 /*  ifindex2ifnet[ifp->if_index] = NULL;  */

  while (*p) {
  	if ((*p) == ifp){    
           *p = (ifp->if_next);
	    break;                       		   
       }
       p = &((*p)->if_next);	   
  }
	
   splx(s);
}


/*
 * Locate an interface based on a complete address.
 */
/*ARGSUSED*/

struct ifaddr *
ifa_ifwithaddr(addr)
	register struct sockaddr *addr;
{
	register struct ifnet *ifp;
	register struct ifaddr *ifa;

#define	equal(a1, a2) \
  (bcmp((caddr_t)(a1), (caddr_t)(a2), ((struct sockaddr *)(a1))->sa_len) == 0)
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
	    for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != addr->sa_family)
			continue;
		if (equal(addr, ifa->ifa_addr))
			return (ifa);
		if ((ifp->if_flags & IFF_BROADCAST) && ifa->ifa_broadaddr &&
		    equal(ifa->ifa_broadaddr, addr))
			return (ifa);
	}
 
	return ((struct ifaddr *)0);
}

/*
 * Locate the point to point interface with a given destination address.
 */
/*ARGSUSED*/

struct ifaddr *
ifa_ifwithdstaddr(addr)
	register struct sockaddr *addr;
{
	register struct ifnet *ifp;
	register struct ifaddr *ifa;

	for (ifp = ifnet; ifp; ifp = ifp->if_next) 
	    if (ifp->if_flags & IFF_POINTOPOINT)
		for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr->sa_family != addr->sa_family)
				continue;
			if (equal(addr, ifa->ifa_dstaddr))
				return (ifa);
	}
 	return ((struct ifaddr *)0);
}

/*
 * Find an interface on a specific network.  If many, choice
 * is most specific found.
 */
 
struct ifaddr *
ifa_ifwithnet(addr)
	struct sockaddr *addr;
{
	register struct ifnet *ifp;
	register struct ifaddr *ifa;
	struct ifaddr *ifa_maybe = (struct ifaddr *) 0;
	u_int af = addr->sa_family;
	char *addr_data = addr->sa_data, *cplim;

	if (af == AF_LINK) {
	    register struct sockaddr_dl *sdl = (struct sockaddr_dl *)addr;
	    if (sdl->sdl_index && sdl->sdl_index <= if_index)
		return (ifnet_addrs[sdl->sdl_index - 1]);
	}
	for (ifp = ifnet; ifp; ifp = ifp->if_next)
	    for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) {
			char *cp, *cp2, *cp3;
			if (ifa->ifa_addr->sa_family != af)
next:                continue;			
 
                     if (ifp->if_flags & IFF_POINTOPOINT) {
				if (ifa->ifa_dstaddr != 0
				    && equal(addr, ifa->ifa_dstaddr))
 					return (ifa);
			} else {

				
                          /*
				 * Scan all the bits in the ifa's address.
				 * If a bit dissagrees with what we are
				 * looking for, mask it with the netmask
				 * to see if it really matters.
				 * (A byte at a time)
				 */
			   if (ifa->ifa_netmask == 0)
			      continue;

			cp = addr_data;
			cp2 = ifa->ifa_addr->sa_data;
			cp3 = ifa->ifa_netmask->sa_data;
			cplim = (char *)ifa->ifa_netmask +
			    ifa->ifa_netmask->sa_len;
			while (cp3 < cplim) {
				if ((*cp++ ^ *cp2++) & *cp3++) {
					/* want to continue for() loop */
					goto next;
				}
			}
			if (ifa_maybe == 0 ||
			    rn_refines((caddr_t)ifa->ifa_netmask,
			    (caddr_t)ifa_maybe->ifa_netmask))
				ifa_maybe = ifa;
			}
		}
	return (ifa_maybe);
}

/*
 * Find an interface using a specific address family
 */
 
struct ifaddr *
ifa_ifwithaf(af)
	register int af;
{
	register struct ifnet *ifp;
	register struct ifaddr *ifa;

	for (ifp = ifnet; ifp; ifp = ifp->if_next)
	    for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == af)
			return (ifa);
	return ((struct ifaddr *)0);
}

/*
 * Find an interface address specific to an interface best matching
 * a given address.
 */
 
struct ifaddr *
ifaof_ifpforaddr(addr, ifp)
	struct sockaddr *addr;
	register struct ifnet *ifp;
{
	register struct ifaddr *ifa;
	register char *cp, *cp2, *cp3;
	register char *cplim;
	struct ifaddr *ifa_maybe = 0;
	u_int af = addr->sa_family;
  
	if (af >= AF_MAX)
		return (0);
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family != af)
			continue;
		ifa_maybe = ifa;
		if (ifa->ifa_netmask == 0) {
			if (equal(addr, ifa->ifa_addr) ||
			    (ifa->ifa_dstaddr && equal(addr, ifa->ifa_dstaddr)))
				return (ifa);
			continue;
		}
		cp = addr->sa_data;
		cp2 = ifa->ifa_addr->sa_data;
		cp3 = ifa->ifa_netmask->sa_data;
		cplim = ifa->ifa_netmask->sa_len + (char *)ifa->ifa_netmask;
		for (; cp3 < cplim; cp3++)
			if ((*cp++ ^ *cp2++) & *cp3)
				break;
		if (cp3 == cplim)
			return (ifa);
	}
	
	return (ifa_maybe);
}

/*
 * Default action when installing a route with a Link Level gateway.
 * Lookup an appropriate real ifa to point to.
 * This should be moved to /sys/net/link.c eventually.
 */
void
link_rtrequest(cmd, rt, sa)
	int cmd;
	register struct rtentry *rt;
	struct sockaddr *sa;
{
	register struct ifaddr *ifa;
	struct sockaddr *dst;
	struct ifnet *ifp;

	if (cmd != RTM_ADD || ((ifa = rt->rt_ifa) == 0) ||
	    ((ifp = ifa->ifa_ifp) == 0) || ((dst = rt_key(rt)) == 0))
		return;
		
	if (ifa = ifaof_ifpforaddr(dst, ifp)) {
		IFAFREE(rt->rt_ifa);
		rt->rt_ifa = ifa;
		ifa->ifa_refcnt++;
		if (ifa->ifa_rtrequest && ifa->ifa_rtrequest != link_rtrequest)
			ifa->ifa_rtrequest(cmd, rt, sa);
	} 
}

/*
 * Mark an interface down and notify protocols of
 * the transition.
 * NOTE: must be called at splnet or eqivalent.
 */
void
if_down(ifp)
	register struct ifnet *ifp;
{
	register struct ifaddr *ifa;

	ifp->if_flags &= ~IFF_UP;
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
	 /*pfctlinput(PRC_IFDOWN, ifa->ifa_addr) */;
	if_qflush(&ifp->if_snd);
       rt_ifmsg(ifp); 
}

/*
 * Mark an interface up and notify protocols of
 * the transition.
 * NOTE: must be called at splnet or eqivalent.
 */
void
if_up(ifp)
	register struct ifnet *ifp;
{
	register struct ifaddr *ifa;

	ifp->if_flags |= IFF_UP;
#ifdef notyet
	/* this has no effect on IP, and will kill all iso connections XXX */
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
		pfctlinput(PRC_IFUP, ifa->ifa_addr);
#endif
  	rt_ifmsg(ifp);
}

/*
 * Flush an interface queue.
 */
void
if_qflush(ifq)
	register struct ifqueue *ifq;
{
	register struct mbuf *m, *n;

	n = ifq->ifq_head;
	while (m = n) {
		n = m->m_act;
	/*	m_free(m); */
	}
	ifq->ifq_head = 0;
	ifq->ifq_tail = 0;
	ifq->ifq_len = 0;
}

/*
 * Handle interface watchdog timer routines.  Called
 * from softclock, we decrement timers (if set) and
 * call the appropriate interface routine on expiration.
 */
void
if_slowtimo(arg)
	void *arg;
{
	register struct ifnet *ifp;
	int s = splimp();

	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if (ifp->if_timer == 0 || --ifp->if_timer)
			continue;
		if (ifp->if_watchdog)
			(*ifp->if_watchdog)(ifp->if_unit);
	}
	splx(s);
	timeout(if_slowtimo, (void *)0, hz / IFNET_SLOWHZ); 
}

/*
 * Map interface name to
 * interface structure pointer.
 */
struct ifnet *
ifunit(name)
	register char *name;
{
	register char *cp;
	register struct ifnet *ifp;
	int unit;
	unsigned len;
	char *ep, c;

	for (cp = name; cp < name + IFNAMSIZ && *cp; cp++)
		if (*cp >= '0' && *cp <= '9')
			break;
	if (*cp == '\0' || cp == name + IFNAMSIZ)
		return ((struct ifnet *)0);
	/*
	 * Save first char of unit, and pointer to it,
	 * so we can put a null there to avoid matching
	 * initial substrings of interface names.
	 */
	len = cp - name + 1;
	c = *cp;
	ep = cp;
	for (unit = 0; *cp >= '0' && *cp <= '9'; )
		unit = unit * 10 + *cp++ - '0';
	*ep = 0;
	for (ifp = ifnet; ifp; ifp = ifp->if_next) {
		if (bcmp(ifp->if_name, name, len))
			continue;
		if (unit == ifp->if_unit)
			break;
	}
	*ep = c;
	return (ifp);
}

/*
 * Interface ioctls.
 */
int
ifioctl(so, cmd, data, p)
	struct socket *so;
	int cmd;
	caddr_t data;
	struct proc *p;
{
	register struct ifnet *ifp;
	register struct ifreq *ifr;
	int error;

	switch (cmd) {

	case SIOCGIFCONF:
	case OSIOCGIFCONF:
		return (ifconf(cmd, data));
	}
	ifr = (struct ifreq *)data;
	ifp = ifunit(ifr->ifr_name);
	if (ifp == 0)
		return (-1);
	switch (cmd) {

	case SIOCGIFFLAGS:
		ifr->ifr_flags = ifp->if_flags;
		break;

	case SIOCGIFMETRIC:
		ifr->ifr_metric = ifp->if_metric;
		break;

	case SIOCSIFFLAGS:
   /*	if (error = suser(p->p_ucred, &p->p_acflag))
			return (error);  */
		if (ifp->if_flags & IFF_UP && (ifr->ifr_flags & IFF_UP) == 0) {
			int s = splimp();
			if_down(ifp);
			splx(s);
		}
		if (ifr->ifr_flags & IFF_UP && (ifp->if_flags & IFF_UP) == 0) {
			int s = splimp();
			if_up(ifp);
			splx(s);
		}
		ifp->if_flags = (ifp->if_flags & IFF_CANTCHANGE) |
			(ifr->ifr_flags &~ IFF_CANTCHANGE);
		if (ifp->if_ioctl)
			(void) (*ifp->if_ioctl)(ifp, cmd, data);
		break;

	case SIOCSIFMETRIC:
	/*	if (error = suser(p->p_ucred, &p->p_acflag))
			return (error);
   */		ifp->if_metric = ifr->ifr_metric;
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
	/*	if (error = suser(p->p_ucred, &p->p_acflag))
			return (error);
      */		
		if (ifp->if_ioctl == NULL)
			return (EOPNOTSUPP);
		return ((*ifp->if_ioctl)(ifp, cmd, data));

	default:
	/*	if (so->so_proto == 0)
			return (EOPNOTSUPP);
#ifndef COMPAT_43
		return ((*so->so_proto->pr_usrreq)(so, PRU_CONTROL,
			cmd, data, ifp));
#else
	    {
		int ocmd = cmd;
   */
		switch (cmd) {

		case SIOCSIFDSTADDR:
		case SIOCSIFADDR:
		case SIOCSIFBRDADDR:
	
#if BYTE_ORDER != BIG_ENDIAN
			if (ifr->ifr_addr.sa_family == 0 &&
			    ifr->ifr_addr.sa_len < 16) {
				ifr->ifr_addr.sa_family = ifr->ifr_addr.sa_len;
				ifr->ifr_addr.sa_len = 16;
			}
#else
			if (ifr->ifr_addr.sa_len == 0)
				ifr->ifr_addr.sa_len = 16;
#endif
			break;

		case OSIOCGIFADDR:
			cmd = SIOCGIFADDR;
			break;

		case OSIOCGIFDSTADDR:
			cmd = SIOCGIFDSTADDR;
			break;

		case OSIOCGIFBRDADDR:
			cmd = SIOCGIFBRDADDR;
			break;

		case OSIOCGIFNETMASK:
			cmd = SIOCGIFNETMASK;
		}
		error = -1;
		switch (cmd) {

		case OSIOCGIFADDR:
		case OSIOCGIFDSTADDR:
		case OSIOCGIFBRDADDR:
		case OSIOCGIFNETMASK:
			*(u_short *)&ifr->ifr_addr = ifr->ifr_addr.sa_family;
		}
		return (error);

	    }
	
	return (0);
}

/*
 * Return interface configuration
 * of system.  List may be used
 * in later ioctl's (above) to get
 * other information.
 */
/*ARGSUSED*/
int
ifconf(cmd, data)
	int cmd;
	caddr_t data;
{
	register struct ifconf *ifc = (struct ifconf *)data;
	register struct ifnet *ifp = ifnet;
	register struct ifaddr *ifa;
	register char *cp, *ep;
	struct ifreq ifr, *ifrp;
	int space = ifc->ifc_len, error = 0;

	ifrp = ifc->ifc_req;
	ep = ifr.ifr_name + sizeof (ifr.ifr_name) - 2;
	for (; space > sizeof (ifr) && ifp; ifp = ifp->if_next) {
		strncpy(ifr.ifr_name, ifp->if_name, sizeof (ifr.ifr_name) - 2);
		for (cp = ifr.ifr_name; cp < ep && *cp; cp++)
			continue;
		*cp++ = '0' + ifp->if_unit; *cp = '\0';
		if ((ifa = ifp->if_addrlist) == 0) {
			bzero((caddr_t)&ifr.ifr_addr, sizeof(ifr.ifr_addr));
			error = copyout((caddr_t)&ifr, (caddr_t)ifrp,
			    sizeof (ifr));
			if (error)
				break;
			space -= sizeof (ifr), ifrp++;
		} else 
		    for ( ; space > sizeof (ifr) && ifa; ifa = ifa->ifa_next) {
			register struct sockaddr *sa = ifa->ifa_addr;
#ifdef COMPAT_43
			if (cmd == OSIOCGIFCONF) {
				struct osockaddr *osa =
					 (struct osockaddr *)&ifr.ifr_addr;
				ifr.ifr_addr = *sa;
				osa->sa_family = sa->sa_family;
				error = memcpy((caddr_t)&ifr, (caddr_t)ifrp,
						sizeof (ifr));
				ifrp++;
			} else
#endif
			if (sa->sa_len <= sizeof(*sa)) {
				ifr.ifr_addr = *sa;
				error = copyout((caddr_t)&ifr, (caddr_t)ifrp,
						sizeof (ifr));
				ifrp++;
			} else {
				space -= sa->sa_len - sizeof(*sa);
				if (space < sizeof (ifr))
					break;
				error = copyout((caddr_t)&ifr, (caddr_t)ifrp,
						sizeof (ifr.ifr_name));
				if (error == 0)
				    error = copyout((caddr_t)sa,
				      (caddr_t)&ifrp->ifr_addr, sa->sa_len);
				ifrp = (struct ifreq *)
					(sa->sa_len + (caddr_t)&ifrp->ifr_addr);
			}
			if (error)
				break;
			space -= sizeof (ifr);
		}
	}
	ifc->ifc_len -= space;
	return (error);
}

static char *
sprint_d(n, buf, buflen)
	u_int n;
	char *buf;
	int buflen;
{
	register char *cp = buf + buflen - 1;

	*cp = 0;
	do {
		cp--;
		*cp = "0123456789"[n % 10];
		n /= 10;
	} while (n != 0);
	return (cp);
}
	
/*
   just two p2p interface.
   

struct sl_softc sl_softc[2];

void
slattach()
{
	register struct sl_softc *sc;
	register int i = 0;

	for (sc = sl_softc; i < 2; sc++) {
		sc->sc_if.if_name = "sl";
		sc->sc_if.if_next = NULL;
		sc->sc_if.if_unit = i++;
		sc->sc_if.if_mtu = 296;
		sc->sc_if.if_flags =
		    IFF_POINTOPOINT | SC_AUTOCOMP | IFF_MULTICAST;
		sc->sc_if.if_type = IFT_SLIP;
		sc->sc_if.if_ioctl = slioctl;
		sc->sc_if.if_output = sloutput;
		sc->sc_if.if_snd.ifq_maxlen = 50;
		sc->sc_fastq.ifq_maxlen = 32;
		if_attach(&sc->sc_if);
	}
}

*/

/*
   just one loop interface.
   
*/
#define	LOMTU	(1024+512)

struct	ifnet loif;

void
loopattach()
{
	register struct ifnet *ifp = &loif;

	ifp->if_name = "lo";
	ifp->if_mtu = LOMTU;
	ifp->if_flags = IFF_LOOPBACK | IFF_MULTICAST;
	ifp->if_ioctl = loioctl;
	ifp->if_output = looutput ;
	ifp->if_type = IFT_LOOP;
	ifp->if_hdrlen = 0;
	ifp->if_addrlen = 0;
	if_attach(ifp);
#if NBPFILTER > 0
	bpfattach(&ifp->if_bpf, ifp, DLT_NULL, sizeof(u_int));
#endif
}

int
looutput(ifp, m, dst, rt)
	struct ifnet *ifp;
	register struct mbuf *m;
	struct sockaddr *dst;
	register struct rtentry *rt;
{
	int s, isr;
	register struct ifqueue *ifq = 0;

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("looutput no HDR");
	
	//ifp->if_lastchange = time;
#if 0
	if (loif.if_bpf) {
		/*
		 * We need to prepend the address family as
		 * a four byte field.  Cons up a dummy header
		 * to pacify bpf.  This is safe because bpf
		 * will only read from the mbuf (i.e., it won't
		 * try to free it or keep a pointer a to it).
		 */
		struct mbuf m0;
		u_int af = dst->sa_family;

		m0.m_next = m;
		m0.m_len = 4;
		m0.m_data = (char *)&af;
		
		bpf_mtap(loif.if_bpf, &m0);
	}
#endif
	m->m_pkthdr.rcvif = ifp;

	if (rt && rt->rt_flags & (RTF_REJECT|RTF_BLACKHOLE)) {
		m_freem(m);
		return (rt->rt_flags & RTF_BLACKHOLE ? 0 :
		        rt->rt_flags & RTF_HOST ? EHOSTUNREACH : ENETUNREACH);
	}
	ifp->if_opackets++;
	ifp->if_obytes += m->m_pkthdr.len;
	switch (dst->sa_family) {

#ifdef INET
	case AF_INET:
		ifq = &ipintrq;
		isr = NETISR_IP;
		break;
#endif
#ifdef NS
	case AF_NS:
		ifq = &nsintrq;
		isr = NETISR_NS;
		break;
#endif
#ifdef ISO
	case AF_ISO:
		ifq = &clnlintrq;
		isr = NETISR_ISO;
		break;
#endif
	default:
		printf("lo%d: can't handle af%d\n", ifp->if_unit,
			dst->sa_family);
		m_freem(m);
		return (EAFNOSUPPORT);
	}
	s = splimp();
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		m_freem(m);
		splx(s);
		return (ENOBUFS);
	}
	IF_ENQUEUE(ifq, m);
	schednetisr(isr);
	ifp->if_ipackets++;
	ifp->if_ibytes += m->m_pkthdr.len;
	splx(s);
	return (0);
}

/* ARGSUSED */
void
lortrequest(cmd, rt, sa)
	int cmd;
	struct rtentry *rt;
	struct sockaddr *sa;
{

	if (rt)
		rt->rt_rmx.rmx_mtu = LOMTU;
}

/*
 * Process an ioctl request.
 */
/* ARGSUSED */
int
loioctl(ifp, cmd, data)
	register struct ifnet *ifp;
	int cmd;
	caddr_t data;
{
	register struct ifaddr *ifa;
	register struct ifreq *ifr;
	register int error = 0;

	switch (cmd) {

	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		ifa = (struct ifaddr *)data;
		if (ifa != 0 && ifa->ifa_addr->sa_family == AF_ISO)
			ifa->ifa_rtrequest = lortrequest;
		/*
		 * Everything else is done at a higher level.
		 */
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		ifr = (struct ifreq *)data;
		if (ifr == 0) {
			error = EAFNOSUPPORT;		/* XXX */
			break;
		}
		switch (ifr->ifr_addr.sa_family) {

#ifdef INET
		case AF_INET:
			break;
#endif

		default:
			error = EAFNOSUPPORT;
			break;
		}
		break;

	default:
		error = EINVAL;
	}
	return (error);
}


void main_loop()
{ 
	slattach();	

	loopattach();	
 		
	return ;
}
