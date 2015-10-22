

#include "if.h"
#include "route.h"
#include "socket.h"
#include "radix.h"
#include "in_var.h"
#include "if_ether.h"

#if 0
void
igmp_leavegroup(inm)
	struct in_multi *inm;
{
	/*
	 * No action required on leaving a group.
	 */
}

void
igmp_joingroup(inm)
	struct in_multi *inm;
{
	register int s = splnet();

	splx(s);
}
#endif

extern struct	ifnet loif;

#ifdef INET
/*
 * Return the network number from an internet address.
 */
u_long
in_netof(in)
	struct in_addr in;
{
	register u_long i = ntohl(in.s_addr);
	register u_long net;
	register struct in_ifaddr *ia;
    	
	if (IN_CLASSA(i))
		net = i & IN_CLASSA_NET;
	else if (IN_CLASSB(i))
		net = i & IN_CLASSB_NET;
	else if (IN_CLASSC(i))
		net = i & IN_CLASSC_NET;
	else if (IN_CLASSD(i))
		net = i & IN_CLASSD_NET;
	else
		return (0);

	/*
	 * Check whether network is a subnet;
	 * if so, return subnet number.
	 */
	for (ia = in_ifaddr; ia; ia = ia->ia_next)
		if (net == ia->ia_net)
			return (i & ia->ia_subnetmask);
	return (net);
}

#ifndef SUBNETSARELOCAL
#define	SUBNETSARELOCAL	1
#endif
int subnetsarelocal = SUBNETSARELOCAL;
/*
 * Return 1 if an internet address is for a ``local'' host
 * (one to which we have a connection).  If subnetsarelocal
 * is true, this includes other subnets of the local net.
 * Otherwise, it includes only the directly-connected (sub)nets.
 */
in_localaddr(in)
	struct in_addr in;
{
	register u_long i = ntohl(in.s_addr);
	register struct in_ifaddr *ia;

	if (subnetsarelocal) {
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
			if ((i & ia->ia_netmask) == ia->ia_net)
				return (1);
	} else {
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
			if ((i & ia->ia_subnetmask) == ia->ia_subnet)
				return (1);
	}
	return (0);
}

/*
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 */
in_canforward(in)
	struct in_addr in;
{
	register u_long i = ntohl(in.s_addr);
	register u_long net;

	if (IN_EXPERIMENTAL(i) || IN_MULTICAST(i))
		return (0);
	if (IN_CLASSA(i)) {
		net = i & IN_CLASSA_NET;
		if (net == 0 || net == (IN_LOOPBACKNET << IN_CLASSA_NSHIFT))
			return (0);
	}
	return (1);
}

/*
 * Trim a mask in a sockaddr
 */
void
in_socktrim(ap)
struct sockaddr_in *ap;
{
    register char *cplim = (char *) &ap->sin_addr;
    register char *cp = (char *) (&ap->sin_addr + 1);

    ap->sin_len = 0;
    while (--cp > cplim)
        if (*cp) {
	    (ap)->sin_len = cp - (char *) (ap) + 1;
	    break;
	}
}

int	in_interfaces;		/* number of external internet interfaces */
extern	struct ifnet loif;

/*
 * Generic internet control operations (ioctl's).
 * Ifp is 0 if not an interface-specific ioctl.
 */
/* ARGSUSED */
in_control(so, cmd, data, ifp)
	struct socket *so;
	int cmd;
	caddr_t data;
	register struct ifnet *ifp;
{
	register struct ifreq *ifr = (struct ifreq *)data;
	register struct in_ifaddr *ia = 0;
	register struct ifaddr *ifa;
	struct in_ifaddr *oia;
	struct in_aliasreq *ifra = (struct in_aliasreq *)data;
	struct sockaddr_in oldaddr;
	int error, hostIsNew, maskIsNew;
	u_long i;

	/*
	 * Find address for this interface, if it exists.
	 */
	if (ifp)
		for (ia = in_ifaddr; ia; ia = ia->ia_next)
			if (ia->ia_ifp == ifp)
				break;

	switch (cmd) {

	case SIOCAIFADDR:
	case SIOCDIFADDR:
		if (ifra->ifra_addr.sin_family == AF_INET)
		    for (oia = ia; ia; ia = ia->ia_next) {
			if (ia->ia_ifp == ifp  &&
			    ia->ia_addr.sin_addr.s_addr ==
				ifra->ifra_addr.sin_addr.s_addr)
			    break;
		}
		if (cmd == SIOCDIFADDR && ia == 0)
			return (EADDRNOTAVAIL);
		/* FALLTHROUGH */
	case SIOCSIFADDR:
	case SIOCSIFNETMASK:
	case SIOCSIFDSTADDR:
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);

		if (ifp == 0)
			panic("in_control");
		if (ia == (struct in_ifaddr *)0) {
			oia = (struct in_ifaddr *)
				malloc(sizeof *oia);
			/*  M_IFADDR, M_WAITOK); */
			if (oia == (struct in_ifaddr *)NULL)
				return (ENOBUFS);
			bzero((caddr_t)oia, sizeof *oia);
			if (ia = in_ifaddr) {
				for ( ; ia->ia_next; ia = ia->ia_next)
					continue;
				ia->ia_next = oia;
			} else
				in_ifaddr = oia;
			ia = oia;
			if (ifa = ifp->if_addrlist) {
				for ( ; ifa->ifa_next; ifa = ifa->ifa_next)
					continue;
				ifa->ifa_next = (struct ifaddr *) ia;
			} else
				ifp->if_addrlist = (struct ifaddr *) ia;
			ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
			ia->ia_ifa.ifa_dstaddr
					= (struct sockaddr *)&ia->ia_dstaddr;
			ia->ia_ifa.ifa_netmask
					= (struct sockaddr *)&ia->ia_sockmask;
			ia->ia_sockmask.sin_len = 8;
			if (ifp->if_flags & IFF_BROADCAST) {
				ia->ia_broadaddr.sin_len = sizeof(ia->ia_addr);
				ia->ia_broadaddr.sin_family = AF_INET;
			}
			ia->ia_ifp = ifp;
			if (ifp != &loif)
				in_interfaces++;
		}
		break;
	case SIOCSIFBRDADDR:
		if ((so->so_state & SS_PRIV) == 0)
			return (EPERM);
	case SIOCGIFADDR:
	case SIOCGIFNETMASK:
	case SIOCGIFDSTADDR:
	case SIOCGIFBRDADDR:
		if (ia == (struct in_ifaddr *)0)
			return (EADDRNOTAVAIL);
		break;
	}
	switch (cmd) {

	case SIOCGIFADDR:
		*((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_addr;
		break;

	case SIOCGIFBRDADDR:
		if ((ifp->if_flags & IFF_BROADCAST) == 0)
			return (EINVAL);
		*((struct sockaddr_in *)&ifr->ifr_dstaddr) = ia->ia_broadaddr;
		break;

	case SIOCGIFDSTADDR:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return (EINVAL);
		*((struct sockaddr_in *)&ifr->ifr_dstaddr) = ia->ia_dstaddr;
		break;

	case SIOCGIFNETMASK:
		*((struct sockaddr_in *)&ifr->ifr_addr) = ia->ia_sockmask;
		break;

	case SIOCSIFDSTADDR:
		if ((ifp->if_flags & IFF_POINTOPOINT) == 0)
			return (EINVAL);
		oldaddr = ia->ia_dstaddr;
		ia->ia_dstaddr = *(struct sockaddr_in *)&ifr->ifr_dstaddr;
		if (ifp->if_ioctl && (error = (*ifp->if_ioctl)
					(ifp, SIOCSIFDSTADDR, (caddr_t)ia))) {
			ia->ia_dstaddr = oldaddr;
			return (error);
		}
		if (ia->ia_flags & IFA_ROUTE) {
			ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&oldaddr;
			rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
			ia->ia_ifa.ifa_dstaddr =
					(struct sockaddr *)&ia->ia_dstaddr;
			rtinit(&(ia->ia_ifa), (int)RTM_ADD, RTF_HOST|RTF_UP);
		}
		break;

	case SIOCSIFBRDADDR:
		if ((ifp->if_flags & IFF_BROADCAST) == 0)
			return (EINVAL);
		ia->ia_broadaddr = *(struct sockaddr_in *)&ifr->ifr_broadaddr;
		break;

	case SIOCSIFADDR:
		return (in_ifinit(ifp, ia,
		    (struct sockaddr_in *) &ifr->ifr_addr, 1));

	case SIOCSIFNETMASK:
		i = ifra->ifra_addr.sin_addr.s_addr;
		ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr = i);
		break;

	case SIOCAIFADDR:
		maskIsNew = 0;
		hostIsNew = 1;
		error = 0;
		if (ia->ia_addr.sin_family == AF_INET) {
			if (ifra->ifra_addr.sin_len == 0) {
				ifra->ifra_addr = ia->ia_addr;
				hostIsNew = 0;
			} else if (ifra->ifra_addr.sin_addr.s_addr ==
					       ia->ia_addr.sin_addr.s_addr)
				hostIsNew = 0;
		}
		if (ifra->ifra_mask.sin_len) {
			in_ifscrub(ifp, ia);
			ia->ia_sockmask = ifra->ifra_mask;
			ia->ia_subnetmask =
			     ntohl(ia->ia_sockmask.sin_addr.s_addr);
			maskIsNew = 1;
		}
		if ((ifp->if_flags & IFF_POINTOPOINT) &&
		    (ifra->ifra_dstaddr.sin_family == AF_INET)) {
			in_ifscrub(ifp, ia);
			ia->ia_dstaddr = ifra->ifra_dstaddr;
			maskIsNew  = 1; /* We lie; but the effect's the same */
		}
		if (ifra->ifra_addr.sin_family == AF_INET &&
		    (hostIsNew || maskIsNew))
			error = in_ifinit(ifp, ia, &ifra->ifra_addr, 0);
		if ((ifp->if_flags & IFF_BROADCAST) &&
		    (ifra->ifra_broadaddr.sin_family == AF_INET))
			ia->ia_broadaddr = ifra->ifra_broadaddr;
		return (error);

	case SIOCDIFADDR:
		in_ifscrub(ifp, ia);
		if ((ifa = ifp->if_addrlist) == (struct ifaddr *)ia)
			ifp->if_addrlist = ifa->ifa_next;
		else {
			while (ifa->ifa_next &&
			       (ifa->ifa_next != (struct ifaddr *)ia))
				    ifa = ifa->ifa_next;
			if (ifa->ifa_next)
				ifa->ifa_next = ((struct ifaddr *)ia)->ifa_next;
			else
				printf("Couldn't unlink inifaddr from ifp\n");
		}
		oia = ia;
		if (oia == (ia = in_ifaddr))
			in_ifaddr = ia->ia_next;
		else {
			while (ia->ia_next && (ia->ia_next != oia))
				ia = ia->ia_next;
			if (ia->ia_next)
				ia->ia_next = oia->ia_next;
			else
				printf("Didn't unlink inifadr from list\n");
		}
		IFAFREE((&oia->ia_ifa));
		break;

	default:
		if (ifp == 0 || ifp->if_ioctl == 0)
			return (EOPNOTSUPP);
		return ((*ifp->if_ioctl)(ifp, cmd, data));
	}
	return (0);
}

/*
 * Delete any existing route for an interface.
 */
void
in_ifscrub(ifp, ia)
	register struct ifnet *ifp;
	register struct in_ifaddr *ia;
{
#if 0   
    if ((ia->ia_flags & IFA_ROUTE) == 0) {
        if(ifp->if_flags & IFF_POINTOPOINT) {
            rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
        }
        return;
    }
    if (ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT)) {
        rtinit(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
    } else {
        rtinit(&(ia->ia_ifa), (int)RTM_DELETE, 0);
    }
    ia->ia_flags &= ~IFA_ROUTE;
    
#else
    in_scrubprefix(ia);
#endif       
}

#define rtinitflags(x) \
	((((x)->ia_ifp->if_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) != 0) \
	    ? RTF_HOST : 0)
/*
 * remove a route to prefix ("connected route" in cisco terminology).
 * re-installs the route by using another interface address, if there's one
 * with the same prefix (otherwise we lose the route mistakenly).
 */
static int
in_scrubprefix(target)
	struct in_ifaddr *target;
{
	struct in_ifaddr *ia;
	struct in_addr prefix, mask, p;
	int error;
	
	if ((target->ia_flags & IFA_ROUTE) == 0) {
		return 0;
	}

	if (rtinitflags(target))
		prefix = target->ia_dstaddr.sin_addr;
	else
		prefix = target->ia_addr.sin_addr;
	mask = target->ia_sockmask.sin_addr;
	prefix.s_addr &= mask.s_addr;

	for (ia = in_ifaddr; ia; ia = ia->ia_next) {
		/* easy one first */
		if (mask.s_addr != ia->ia_sockmask.sin_addr.s_addr)
			continue;

		if (rtinitflags(ia))
			p = ia->ia_dstaddr.sin_addr;
		else
			p = ia->ia_addr.sin_addr;
		p.s_addr &= ia->ia_sockmask.sin_addr.s_addr;
		if (prefix.s_addr != p.s_addr)
			continue;

		/*
		 * if we got a matching prefix route, move IFA_ROUTE to him
		 */
		if ((ia->ia_flags & IFA_ROUTE) == 0) {
			rtinit(&(target->ia_ifa), (int)RTM_DELETE,
			    rtinitflags(target));
			target->ia_flags &= ~IFA_ROUTE;

			error = rtinit(&ia->ia_ifa, (int)RTM_ADD,
			    rtinitflags(ia) | RTF_UP);
			if (error == 0)
				ia->ia_flags |= IFA_ROUTE;
			return error;
		}
	}

	/*
	 * noone seem to have prefix route.  remove it.
	 */
	rtinit(&(target->ia_ifa), (int)RTM_DELETE, rtinitflags(target));
	target->ia_flags &= ~IFA_ROUTE;	
	return 0;
}


/*
 * Initialize an interface's internet address
 * and routing table entry.
 */
in_ifinit(ifp, ia, sin, scrub)
	register struct ifnet *ifp;
	register struct in_ifaddr *ia;
	struct sockaddr_in *sin;
	int scrub;
{
	register u_long i = ntohl(sin->sin_addr.s_addr);
	struct sockaddr_in oldaddr;
	int s = splimp(), flags = RTF_UP, error, ether_output();

	oldaddr = ia->ia_addr;
	ia->ia_addr = *sin;
	/*
	 * Give the interface a chance to initialize
	 * if this is its first address,
	 * and to validate the address if necessary.
	 */
	if (ifp->if_ioctl &&
	    (error = (*ifp->if_ioctl)(ifp, SIOCSIFADDR, (caddr_t)ia))) {
		splx(s);
		ia->ia_addr = oldaddr;
		return (error);
	}
	if (ifp->if_output == ether_output) { /* XXX: Another Kludge */
		ia->ia_ifa.ifa_rtrequest = arp_rtrequest;
		ia->ia_ifa.ifa_flags |= RTF_CLONING;
	}
	splx(s);
	if (scrub) {
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&oldaddr;
		in_ifscrub(ifp, ia);
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	}
	if (IN_CLASSA(i))
		ia->ia_netmask = IN_CLASSA_NET;
	else if (IN_CLASSB(i))
		ia->ia_netmask = IN_CLASSB_NET;
	else
		ia->ia_netmask = IN_CLASSC_NET;
	/*
	 * The subnet mask usually includes at least the standard network part,
	 * but may may be smaller in the case of supernetting.
	 * If it is set, we believe it.
	 */
	if (ia->ia_subnetmask == 0) {
		ia->ia_subnetmask = ia->ia_netmask;
		ia->ia_sockmask.sin_addr.s_addr = htonl(ia->ia_subnetmask);
	} else
		ia->ia_netmask &= ia->ia_subnetmask;
	ia->ia_net = i & ia->ia_netmask;
	ia->ia_subnet = i & ia->ia_subnetmask;
	in_socktrim(&ia->ia_sockmask);
	/*
	 * Add route for the network.
	 */
	ia->ia_ifa.ifa_metric = ifp->if_metric;
	if (ifp->if_flags & IFF_BROADCAST) {
		ia->ia_broadaddr.sin_addr.s_addr =
			htonl(ia->ia_subnet | ~ia->ia_subnetmask);
		ia->ia_netbroadcast.s_addr =
			htonl(ia->ia_net | ~ ia->ia_netmask);
	} else if (ifp->if_flags & IFF_LOOPBACK) {
		ia->ia_ifa.ifa_dstaddr = ia->ia_ifa.ifa_addr;
		flags |= RTF_HOST;
	} else if (ifp->if_flags & IFF_POINTOPOINT) {
		if (ia->ia_dstaddr.sin_family != AF_INET)
			return (0);
		flags |= RTF_HOST;
	}
	if ((error = rtinit(&(ia->ia_ifa), (int)RTM_ADD, flags)) == 0)
		ia->ia_flags |= IFA_ROUTE;
	/*
	 * If the interface supports multicast, join the "all hosts"
	 * multicast group on that interface.
	 */
	if (ifp->if_flags & IFF_MULTICAST) {
		struct in_addr addr;

		addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
		in_addmulti(&addr, ifp);
	}
	return (error);
}


/*
 * Return 1 if the address might be a local broadcast address.
 */
in_broadcast(in, ifp)
	struct in_addr in;
        struct ifnet *ifp;
{
	register struct ifaddr *ifa;
	u_long t;

	if (in.s_addr == INADDR_BROADCAST ||
	    in.s_addr == INADDR_ANY)
		return 1;
	if ((ifp->if_flags & IFF_BROADCAST) == 0)
		return 0;
	t = ntohl(in.s_addr);
	/*
	 * Look through the list of addresses for a match
	 * with a broadcast address.
	 */
#define ia ((struct in_ifaddr *)ifa)
	for (ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next)
		if (ifa->ifa_addr->sa_family == AF_INET &&
		    (in.s_addr == ia->ia_broadaddr.sin_addr.s_addr ||
		     in.s_addr == ia->ia_netbroadcast.s_addr ||
		     /*
		      * Check for old-style (host 0) broadcast.
		      */
		     t == ia->ia_subnet || t == ia->ia_net))
			    return 1;
	return (0);
#undef ia
}
/*
 * Add an address to the list of IP multicast addresses for a given interface.
 */
struct in_multi *
in_addmulti(ap, ifp)
	register struct in_addr *ap;
	register struct ifnet *ifp;
{
	register struct in_multi *inm;
	struct ifreq ifr;
	struct in_ifaddr *ia;
	int s = splnet();

	/*
	 * See if address already in list.
	 */
	IN_LOOKUP_MULTI(*ap, ifp, inm);
	if (inm != NULL) {
		/*
		 * Found it; just increment the reference count.
		 */
		++inm->inm_refcount;
	}
	else {
		/*
		 * New address; allocate a new multicast record
		 * and link it into the interface's multicast list.
		 */
	  inm = (struct in_multi *)malloc(sizeof(*inm));
	         /*   M_IPMADDR, M_NOWAIT); */
		if (inm == NULL) {
			splx(s);
			return (NULL);
		}
		inm->inm_addr = *ap;
		inm->inm_ifp = ifp;
		inm->inm_refcount = 1;
		IFP_TO_IA(ifp, ia);
		if (ia == NULL) {
			free(inm, M_IPMADDR);
			splx(s);
			return (NULL);
		}
		inm->inm_ia = ia;
		inm->inm_next = ia->ia_multiaddrs;
		ia->ia_multiaddrs = inm;
		/*
		 * Ask the network driver to update its multicast reception
		 * filter appropriately for the new address.
		 */
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_len = sizeof(struct sockaddr_in);
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr = *ap;
		if ((ifp->if_ioctl == NULL) ||
		    (*ifp->if_ioctl)(ifp, SIOCADDMULTI,(caddr_t)&ifr) != 0) {
			ia->ia_multiaddrs = inm->inm_next;
			free(inm, M_IPMADDR);
			splx(s);
			return (NULL);
		}
		/*
		 * Let IGMP know that we have joined a new IP multicast group.
		 */
		igmp_joingroup(inm);
	}
	splx(s);
	return (inm);
}

/*
 * Delete a multicast address record.
 */
int
in_delmulti(inm)
	register struct in_multi *inm;
{
	register struct in_multi **p;
	struct ifreq ifr;
	int s = splnet();

	if (--inm->inm_refcount == 0) {
		/*
		 * No remaining claims to this record; let IGMP know that
		 * we are leaving the multicast group.
		 */
		igmp_leavegroup(inm);
		/*
		 * Unlink from list.
		 */
		for (p = &inm->inm_ia->ia_multiaddrs;
		     *p != inm;
		     p = &(*p)->inm_next)
			 continue;
		*p = (*p)->inm_next;
		/*
		 * Notify the network driver to update its multicast reception
		 * filter.
		 */
		((struct sockaddr_in *)&(ifr.ifr_addr))->sin_family = AF_INET;
		((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr =
								inm->inm_addr;
		(*inm->inm_ifp->if_ioctl)(inm->inm_ifp, SIOCDELMULTI,
							     (caddr_t)&ifr);
		free(inm, M_IPMADDR);
	}
	splx(s);
}
#endif


extern struct ifnet *ifnet;

void cfg_eth0_ip()
{

	int		cmd;
	struct socket		so;
	struct ifreq		ifreq_rec;
	struct in_aliasreq		alias_rec;
	
	
	struct ifnet * ifnet_eth0_ptr;
	
	memset (alias_rec.ifra_name,0,IFNAMSIZ);
	memcpy(alias_rec.ifra_name,"eth0",5);
	
	ifnet_eth0_ptr = ifunit(alias_rec.ifra_name);
	if(ifnet_eth0_ptr == NULL)
		return;
	
	if_up(ifnet_eth0_ptr);

   ifreq_rec.ifr_addr.sa_len = 16;
   ifreq_rec.ifr_addr.sa_family = AF_INET;

   
  /*
     IP address is 224.0.0.1
   */

   ifreq_rec.ifr_addr.sa_data[2] = 224;
   ifreq_rec.ifr_addr.sa_data[3] = 0;
   ifreq_rec.ifr_addr.sa_data[4] = 0;
   ifreq_rec.ifr_addr.sa_data[5] = 1;
   
  cmd = SIOCSIFADDR;

 so.so_state = SS_PRIV;	
 in_control(&so,cmd,(char *)&ifreq_rec,ifnet_eth0_ptr);

/* 
   alias another ip address
   IP address is 8c.fc.0e.21  = 140.252.14.33
*/
	
	alias_rec.ifra_addr.sin_len = 16;
	alias_rec.ifra_addr.sin_family = AF_INET;
	
	alias_rec.ifra_addr.sin_addr.s_addr = 0x210efc8c;
	
	 cmd = SIOCAIFADDR;
	so.so_state = SS_PRIV;	
	
	in_control(&so,cmd,(char *)&alias_rec,ifnet_eth0_ptr); 
  
}

void  cfg_eth1_ip()
{

 int		cmd;
 struct socket		so;
 
 struct ifreq		ifreq_rec;
 struct in_aliasreq		alias_rec;

 struct ifnet *      ifnet_eth_ptr;
 

 memset (ifreq_rec.ifr_name,0,IFNAMSIZ);
 memcpy(ifreq_rec.ifr_name,"eth1",5);
 
 ifnet_eth_ptr = ifunit(ifreq_rec.ifr_name);
 if(ifnet_eth_ptr == NULL)
 	return;


    if_up(ifnet_eth_ptr);

   ifreq_rec.ifr_addr.sa_len = 16;
   ifreq_rec.ifr_addr.sa_family = AF_INET;
   
  /*
     IP address is 140.252.13.33
   */

   ifreq_rec.ifr_addr.sa_data[2] = 140;
   ifreq_rec.ifr_addr.sa_data[3] = 252;
   ifreq_rec.ifr_addr.sa_data[4] = 13;
   ifreq_rec.ifr_addr.sa_data[5] = 33;
   
  cmd = SIOCSIFADDR;

 so.so_state = SS_PRIV;	
 in_control(&so,cmd,(char *)&ifreq_rec,ifnet_eth_ptr);   

 /* 
    to set subnetmask for this interface 
    IP address is 140.252.13.32	
 */
 
   ifreq_rec.ifr_addr.sa_data[2] = 140;
   ifreq_rec.ifr_addr.sa_data[3] = 252;
   ifreq_rec.ifr_addr.sa_data[4] = 13;
   ifreq_rec.ifr_addr.sa_data[5] = 32;
   
   cmd =  SIOCSIFNETMASK;

   so.so_state = SS_PRIV;	
   in_control(&so,cmd,(char *)&ifreq_rec,ifnet_eth_ptr); 


   
/* 
   alias another ip address
   IP address is 8c.fc.0e.21  = 141.252.14.33
*/
	
	alias_rec.ifra_addr.sin_len = 16;
	alias_rec.ifra_addr.sin_family = AF_INET;
	
	alias_rec.ifra_addr.sin_addr.s_addr = 0x210efc8d;
	
	 cmd = SIOCAIFADDR;
	so.so_state = SS_PRIV;	
	
	in_control(&so,cmd,(char *)&alias_rec,ifnet_eth_ptr); 

   return;		
   
}


void  create_vlan_ip__r()
{

 int		cmd;
 struct socket		so;

struct ifreq		ifreq_rec; 
 struct in_aliasreq		alias_rec;

 struct ifnet *      ifnet_eth_ptr;

 int i = 0;
 

 memset (ifreq_rec.ifr_name,0,IFNAMSIZ);
 memcpy(ifreq_rec.ifr_name,"vl0",5);
 
 ifnet_eth_ptr = ifunit(ifreq_rec.ifr_name);
 if(ifnet_eth_ptr == NULL)
 	return;

/* 
   alias ip address
   IP address is 8c.fc.0e.21  = 141.252.14.33
*/
	
	alias_rec.ifra_addr.sin_len = 16;
	alias_rec.ifra_addr.sin_family = AF_INET;

 for (i=1; i<200; i++){	
	alias_rec.ifra_addr.sin_addr.s_addr = 0x210efc01 + i;
	
	 cmd = SIOCAIFADDR;
	so.so_state = SS_PRIV;	
	
	in_control(&so,cmd,(char *)&alias_rec,ifnet_eth_ptr); 
}
   return;		
   
}

void  cfg_p2p_ip()
{

	int		cmd;
	struct socket		so;
 
	struct ifreq		ifreq_rec;

	struct ifnet *      ifnet_eth_ptr;
 

/*
   1. set IP address for a p2p interface.
   2. set destnation 
*/

 memset(ifreq_rec.ifr_name,0,IFNAMSIZ);
 memset(&ifreq_rec.ifr_addr,0,sizeof(struct sockaddr));
  
 memcpy(ifreq_rec.ifr_name,"sl1",4);

 ifnet_eth_ptr = ifunit(ifreq_rec.ifr_name);
 if(ifnet_eth_ptr == NULL)
 	return;

	if_up(ifnet_eth_ptr);
 
   ifreq_rec.ifr_addr.sa_len = 16;
   ifreq_rec.ifr_addr.sa_family = AF_INET;

  /*  IP address is 140.252.1.183	
 */
   ifreq_rec.ifr_addr.sa_data[2] = 140;
   ifreq_rec.ifr_addr.sa_data[3] = 252;
   ifreq_rec.ifr_addr.sa_data[4] = 1;
   ifreq_rec.ifr_addr.sa_data[5] = 183;
   
   cmd = SIOCSIFADDR;

   so.so_state = SS_PRIV;	
   in_control(&so,cmd,(char *)&ifreq_rec,ifnet_eth_ptr); 
   
 /*
 
  to set destination for this interface 
  IP address is 140.252.1.35	

 */
	ifreq_rec.ifr_addr.sa_data[2] = 140;
	ifreq_rec.ifr_addr.sa_data[3] = 252;
	ifreq_rec.ifr_addr.sa_data[4] = 1;
	ifreq_rec.ifr_addr.sa_data[5] = 35;
   
	cmd =SIOCSIFDSTADDR;

	so.so_state = SS_PRIV;	
	in_control(&so,cmd,(char *)&ifreq_rec,ifnet_eth_ptr);

	return;

}
	
void  cfg_loop_ip()
{

	int		cmd;
	struct socket		so;
 
	struct ifreq		ifreq_rec;

	struct ifnet *      ifnet_loop_ptr;
 
	ifreq_rec.ifr_addr.sa_len = 16;
	ifreq_rec.ifr_addr.sa_family = AF_INET;

	memset (ifreq_rec.ifr_name,0,IFNAMSIZ);
	memcpy(ifreq_rec.ifr_name,"lo0",4);
 
	ifnet_loop_ptr = ifunit(ifreq_rec.ifr_name);
	if(ifnet_loop_ptr == NULL)
 		return;

	if_up(ifnet_loop_ptr);
 
	ifreq_rec.ifr_addr.sa_data[2] = 127;
	ifreq_rec.ifr_addr.sa_data[3] = 0;
	ifreq_rec.ifr_addr.sa_data[4] = 0;
	ifreq_rec.ifr_addr.sa_data[5] = 1;
   
	cmd =SIOCSIFADDR;

	so.so_state = SS_PRIV;	
	in_control(&so,cmd,(char *)&ifreq_rec,ifnet_loop_ptr);
  		
	return ;
  
}

void create_ip_addr_r()
{

   cfg_eth1_ip();

}

void main_inc()
{ 

	cfg_eth0_ip();	
	cfg_eth1_ip();

	cfg_p2p_ip();
	cfg_loop_ip();

}