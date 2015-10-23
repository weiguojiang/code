/*
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef _if_h
#define _if_h

#include "generic.h"

#include "mbuf.h"
/* #include "if_ether.h" */
#include "socket.h"
#include "route.h"


#define	IFT_OTHER	0x1		/* none of the following */
#define	IFT_1822	0x2		/* old-style arpanet imp */
#define	IFT_HDH1822	0x3		/* HDH arpanet imp */
#define	IFT_X25DDN	0x4		/* x25 to imp */
#define	IFT_X25		0x5		/* PDN X25 interface (RFC877) */
#define	IFT_ETHER	0x6		/* Ethernet CSMACD */
#define	IFT_ISO88023	0x7		/* CMSA CD */
#define	IFT_ISO88024	0x8		/* Token Bus */
#define	IFT_ISO88025	0x9		/* Token Ring */
#define	IFT_ISO88026	0xa		/* MAN */
#define	IFT_STARLAN	0xb
#define	IFT_P10		0xc		/* Proteon 10MBit ring */
#define	IFT_P80		0xd		/* Proteon 10MBit ring */
#define	IFT_HY		0xe		/* Hyperchannel */
#define	IFT_FDDI	0xf
#define	IFT_LAPB	0x10
#define	IFT_SDLC	0x11
#define	IFT_T1		0x12
#define	IFT_CEPT	0x13		/* E1 - european T1 */
#define	IFT_ISDNBASIC	0x14
#define	IFT_ISDNPRIMARY	0x15
#define	IFT_PTPSERIAL	0x16		/* Proprietary PTP serial */
#define	IFT_PPP		0x17		/* RFC 1331 */
#define	IFT_LOOP	0x18		/* loopback */
#define	IFT_EON		0x19		/* ISO over IP */
#define	IFT_XETHER	0x1a		/* obsolete 3MB experimental ethernet */
#define	IFT_NSIP	0x1b		/* XNS over IP */
#define	IFT_SLIP	0x1c		/* IP over generic TTY */
#define	IFT_ULTRA	0x1d		/* Ultra Technologies */
#define	IFT_DS3		0x1e		/* Generic T3 */
#define	IFT_SIP		0x1f		/* SMDS */
#define	IFT_FRELAY	0x20		/* Frame Relay DTE only */
#define	IFT_RS232	0x21
#define	IFT_PARA	0x22		/* parallel-port */
#define	IFT_ARCNET	0x23
#define	IFT_ARCNETPLUS	0x24
#define	IFT_ATM		0x25		/* ATM cells */
#define	IFT_MIOX25	0x26
#define	IFT_SONET	0x27		/* SONET or SDH */
#define	IFT_X25PLE	0x28
#define	IFT_ISO88022LLC	0x29
#define	IFT_LOCALTALK	0x2a
#define	IFT_SMDSDXI	0x2b
#define	IFT_FRELAYDCE	0x2c		/* Frame Relay DCE */
#define	IFT_V35		0x2d
#define	IFT_HSSI	0x2e
#define	IFT_HIPPI	0x2f
#define	IFT_MODEM	0x30		/* Generic Modem */
#define	IFT_AAL5	0x31		/* AAL5 over ATM */
#define	IFT_SONETPATH	0x32
#define	IFT_SONETVT	0x33
#define	IFT_SMDSICIP	0x34		/* SMDS InterCarrier Interface */
#define	IFT_PROPVIRTUAL	0x35		/* Proprietary Virtual/internal */
#define	IFT_PROPMUX	0x36		/* Proprietary Multiplexing */


#define	SIOCSHIWAT	  0
#define	SIOCGHIWAT	  1
#define	SIOCSLOWAT	  2
#define	SIOCGLOWAT	  3
#define	SIOCATMARK	  7
#define	SIOCSPGRP	  8
#define	SIOCGPGRP	  9

#define	SIOCADDRT	10
#define	SIOCDELRT	11

#define	SIOCSIFADDR	  12
#define	OSIOCGIFADDR   13	
#define	SIOCGIFADDR	   14
#define	SIOCSIFDSTADDR	  15
#define	OSIOCGIFDSTADDR	16
#define	SIOCGIFDSTADDR	   17
#define	SIOCSIFFLAGS	  18
#define	SIOCGIFFLAGS	 19
#define	OSIOCGIFBRDADDR	20
#define	SIOCGIFBRDADDR	   21
#define	SIOCSIFBRDADDR	  88
#define	OSIOCGIFCONF	  89
#define	SIOCGIFCONF	 36
#define	OSIOCGIFNETMASK  44	
#define	SIOCGIFNETMASK	  37
#define	SIOCSIFNETMASK	  22
#define	SIOCGIFMETRIC	  23
#define	SIOCSIFMETRIC	  24
#define	SIOCDIFADDR	  25
#define	SIOCAIFADDR	  26

#define	SIOCADDMULTI	  49
#define	SIOCDELMULTI	  50


struct	ether_header_if {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
};

#define	ETHERTYPE_PUP		0x0200	/* PUP protocol */
#define	ETHERTYPE_IP		0x0800	/* IP protocol */
#define ETHERTYPE_ARP		0x0806	/* Addr. resolution protocol */
#define ETHERTYPE_REVARP	0x8035	/* reverse Addr. resolution protocol */

#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#define	ETHERTYPE_NTRAILER	16

#define	ETHERMTU	1500
#define	ETHERMIN	(60-14)

/*
 * Forward structure declarations for function prototypes [sic].

struct	mbuf;
struct	proc;
struct	rtentry;	
struct	socket;
struct	ether_header;
 */
 
/*
 * Structure describing information about an interface
 * which may be of interest to management entities.
 */
/*
 * Structure defining a queue for a network interface.
 *
 * (Would like to call this struct ``if'', but C isn't PL/1.)
 */


/*  #define IFNAMSIZ        IF_NAMESIZE */
    
    /*
     * Structure describing a `cloning' interface.
     */
    struct if_clone {
            LIST_ENTRY(if_clone) ifc_list;  /* on list of cloners */
            const char *ifc_name;           /* name of device, e.g. `gif' */
            size_t ifc_namelen;             /* length of name */
    
            int     (*ifc_create)(struct if_clone *, int);
            int     (*ifc_destroy)(struct ifnet *);
    };
    
    #define IF_CLONE_INITIALIZER(name, create, destroy)                     \
            { { NULL, NULL }, name, sizeof(name) - 1, create, destroy }
    
    /*
     * Structure used to query names of interface cloners.
     */
    struct if_clonereq {
            int     ifcr_total;             /* total cloners (out) */
            int     ifcr_count;             /* room for this many in user buffer */
            char    *ifcr_buffer;           /* buffer for cloner names */
    };
	

struct ifnet {
	void	*if_softc;		/* pointer to driver state */	
	char	*if_name;		/* name, e.g. ``en'' or ``lo'' */
	struct	ifnet *if_next;		/* all struct ifnets are chained */
	struct	ifaddr *if_addrlist;	/* linked list of addresses per if */
   int	   if_pcount;		/* number of promiscuous listeners */
	caddr_t	if_bpf;			/* packet filter structure */
	u_short	if_index;		/* numeric abbreviation for this if  */
	short	if_unit;		/* sub-unit for lower level driver */
	short	if_timer;		/* time 'til if_watchdog called */
	short	if_flags;		/* up/down, broadcast, etc. */
	struct	if_data {
/* generic interface information */
		u_char	ifi_type;	/* ethernet, tokenring, etc */
		u_char	ifi_addrlen;	/* media address length */
		u_char	ifi_hdrlen;	/* media header length */
		u_long	ifi_mtu;	/* maximum transmission unit */
		u_long	ifi_metric;	/* routing metric (external only) */
		u_long	ifi_baudrate;	/* linespeed */
/* volatile statistics */
		u_long	ifi_ipackets;	/* packets received on interface */
		u_long	ifi_ierrors;	/* input errors on interface */
		u_long	ifi_opackets;	/* packets sent on interface */
		u_long	ifi_oerrors;	/* output errors on interface */
		u_long	ifi_collisions;	/* collisions on csma interfaces */
		u_long	ifi_ibytes;	/* total number of octets received */
		u_long	ifi_obytes;	/* total number of octets sent */
		u_long	ifi_imcasts;	/* packets received via multicast */
		u_long	ifi_omcasts;	/* packets sent via multicast */
		u_long	ifi_iqdrops;	/* dropped on input, this interface */
		u_long	ifi_noproto;	/* destined for unsupported protocol */
	/*	struct	timeval ifi_lastchange; last updated */
	}	if_data;
/* procedure handles */
	int	(*if_init)		/* init routine */
		__P((int));
	int	(*if_output)		/* output routine (enqueue) */
		__P((struct ifnet *, struct mbuf *, struct sockaddr *,
		     struct rtentry *));
	int	(*if_start)		/* initiate output routine */
		__P((struct ifnet *));
	int	(*if_done)		/* output complete routine */
		__P((struct ifnet *));	/* (XXX not used; fake prototype) */
	int	(*if_ioctl)		/* ioctl routine */
		__P((struct ifnet *, int, caddr_t));
	int	(*if_reset)	
		__P((int));		/* new autoconfig will permit removal */
	int	(*if_watchdog)		/* timer routine */
		__P((int));
	struct	ifqueue {
		struct	mbuf *ifq_head;
		struct	mbuf *ifq_tail;
		int	ifq_len;
		int	ifq_maxlen;
		int	ifq_drops;
	} if_snd;			/* output queue */
};
#define	if_mtu		if_data.ifi_mtu
#define	if_type		if_data.ifi_type
#define	if_addrlen	if_data.ifi_addrlen
#define	if_hdrlen	if_data.ifi_hdrlen
#define	if_metric	if_data.ifi_metric
#define	if_baudrate	if_data.ifi_baudrate
#define	if_ipackets	if_data.ifi_ipackets
#define	if_ierrors	if_data.ifi_ierrors
#define	if_opackets	if_data.ifi_opackets
#define	if_oerrors	if_data.ifi_oerrors
#define	if_collisions	if_data.ifi_collisions
#define	if_ibytes	if_data.ifi_ibytes
#define	if_obytes	if_data.ifi_obytes
#define	if_imcasts	if_data.ifi_imcasts
#define	if_omcasts	if_data.ifi_omcasts
#define	if_iqdrops	if_data.ifi_iqdrops
#define	if_noproto	if_data.ifi_noproto
#define	if_lastchange	if_data.ifi_lastchange

#define	IFF_UP		0x1		/* interface is up */
#define	IFF_BROADCAST	0x2		/* broadcast address valid */
#define	IFF_DEBUG	0x4		/* turn on debugging */
#define	IFF_LOOPBACK	0x8		/* is a loopback net */
#define	IFF_POINTOPOINT	0x10		/* interface is point-to-point link */
#define	IFF_NOTRAILERS	0x20		/* avoid use of trailers */
#define	IFF_RUNNING	0x40		/* resources allocated */
#define	IFF_NOARP	0x80		/* no address resolution protocol */
#define	IFF_PROMISC	0x100		/* receive all packets */
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets */
#define	IFF_OACTIVE	0x400		/* transmission in progress */
#define	IFF_SIMPLEX	0x800		/* can't hear own transmissions */
#define	IFF_LINK0	0x1000		/* per link layer defined bit */
#define	IFF_LINK1	0x2000		/* per link layer defined bit */
#define	IFF_LINK2	0x4000		/* per link layer defined bit */
#define	IFF_MULTICAST	0x8000		/* supports multicast */

#define	IFF_LOGICAL IFF_LINK2

/* flags set internally only: */
#define	IFF_CANTCHANGE \
	(IFF_BROADCAST|IFF_POINTOPOINT|IFF_RUNNING|IFF_OACTIVE|\
	    IFF_SIMPLEX|IFF_MULTICAST|IFF_ALLMULTI)

/*
 * Output queues (ifp->if_snd) and internetwork datagram level (pup level 1)
 * input routines have queues of messages stored on ifqueue structures
 * (defined above).  Entries are added to and deleted from these structures
 * by these macros, which should be called with ipl raised to splimp().
 */
#define	IF_QFULL(ifq)		((ifq)->ifq_len >= (ifq)->ifq_maxlen)
#define	IF_DROP(ifq)		((ifq)->ifq_drops++)
#define	IF_ENQUEUE(ifq, m) { \
	(m)->m_nextpkt = 0; \
	if ((ifq)->ifq_tail == 0) \
		(ifq)->ifq_head = m; \
	else \
		(ifq)->ifq_tail->m_nextpkt = m; \
	(ifq)->ifq_tail = m; \
	(ifq)->ifq_len++; \
}
#define	IF_PREPEND(ifq, m) { \
	(m)->m_nextpkt = (ifq)->ifq_head; \
	if ((ifq)->ifq_tail == 0) \
		(ifq)->ifq_tail = (m); \
	(ifq)->ifq_head = (m); \
	(ifq)->ifq_len++; \
}
#define	IF_DEQUEUE(ifq, m) { \
	(m) = (ifq)->ifq_head; \
	if (m) { \
		if (((ifq)->ifq_head = (m)->m_nextpkt) == 0) \
			(ifq)->ifq_tail = 0; \
		(m)->m_nextpkt = 0; \
		(ifq)->ifq_len--; \
	} \
}

#define	IFQ_MAXLEN	50
#define	IFNET_SLOWHZ	1		/* granularity is 1 second */

/*
 * The ifaddr structure contains information about one address
 * of an interface.  They are maintained by the different address families,
 * are allocated and attached when an address is set, and are linked
 * together so all addresses for an interface can be located.
 */
struct ifaddr {
	struct	sockaddr *ifa_addr;	/* address of interface */
	struct	sockaddr *ifa_dstaddr;	/* other end of p-to-p link */
#define	ifa_broadaddr	ifa_dstaddr	/* broadcast address interface */
	struct	sockaddr *ifa_netmask;	/* used to determine subnet */
	struct	ifnet *ifa_ifp;		/* back-pointer to interface */
	struct	ifaddr *ifa_next;	/* next address for interface */
	void	(*ifa_rtrequest)();	/* check or clean routes (+ or -)'d */
	u_short	ifa_flags;		/* mostly rt_flags for cloning */
	short	ifa_refcnt;		/* extra to malloc for link info */
	int	ifa_metric;		/* cost of going out this interface */
#ifdef notdef
	struct	rtentry *ifa_rt;	/* XXXX for ROUTETOIF ????? */
#endif
};
#define	IFA_ROUTE	RTF_UP		/* route installed */

/*
struct arpcom_if{
    struct ifnet ac_if;
	u_char ac_enaddr[6];
};
*/
/*
 * Message format for use in obtaining information about interfaces
 * from getkerninfo and the routing socket
 */
struct if_msghdr {
	u_short	ifm_msglen;	/* to skip over non-understood messages */
	u_char	ifm_version;	/* future binary compatability */
	u_char	ifm_type;	/* message type */
	int	ifm_addrs;	/* like rtm_addrs */
	int	ifm_flags;	/* value of if_flags */
	u_short	ifm_index;	/* index for associated ifp */
   
	struct	if_data ifm_data;
  
};

/*
 * Message format for use in obtaining information about interface addresses
 * from getkerninfo and the routing socket
 */
struct ifa_msghdr {
	u_short	ifam_msglen;	/* to skip over non-understood messages */
	u_char	ifam_version;	/* future binary compatability */
	u_char	ifam_type;	/* message type */
	int	ifam_addrs;	/* like rtm_addrs */
	int	ifam_flags;	/* value of ifa_flags */
	u_short	ifam_index;	/* index for associated ifp */
	int	ifam_metric;	/* value of ifa_metric */
};

/*
 * Interface request structure used for socket
 * ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 */
struct	ifreq {
#define	IFNAMSIZ	16
	char	ifr_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	union {
		struct	sockaddr ifru_addr;
		struct	sockaddr ifru_dstaddr;
		struct	sockaddr ifru_broadaddr;
		short	ifru_flags;
		int	ifru_metric;
		int	ifru_mtu;
		caddr_t	ifru_data;
	} ifr_ifru;
#define	ifr_addr	ifr_ifru.ifru_addr	/* address */
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-to-p link */
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address */
#define	ifr_flags	ifr_ifru.ifru_flags	/* flags */
#define	ifr_metric	ifr_ifru.ifru_metric	/* metric */
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface */
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu */
};

struct ifaliasreq {
	char	ifra_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	struct	sockaddr ifra_addr;
	struct	sockaddr ifra_broadaddr;
	struct	sockaddr ifra_mask;
};


struct ifmediareq {
	char	ifm_name[IFNAMSIZ];	/* if name, e.g. "en0" */
	int	ifm_current;		/* current media options */
	int	ifm_mask;		/* don't care mask */
	int	ifm_status;		/* media status */
	int	ifm_active;		/* active options */
	int	ifm_count;		/* # entries in ifm_ulist array */
	int	*ifm_ulist;		/* media words */
};

/*
 * Structure used in SIOCGIFCONF request.
 * Used to retrieve interface configuration
 * for machine (useful for programs which
 * must know all networks accessible).
 */
struct	ifconf {
	int	ifc_len;		/* size of associated buffer */
	union {
		caddr_t	ifcu_buf;
		struct	ifreq *ifcu_req;
	} ifc_ifcu;
#define	ifc_buf	ifc_ifcu.ifcu_buf	/* buffer address */
#define	ifc_req	ifc_ifcu.ifcu_req	/* array of structures returned */
};


#define	IFAFREE(ifa) \
	if ((ifa)->ifa_refcnt <= 0) \
		ifafree(ifa); \
	else \
		(ifa)->ifa_refcnt--;

void	ether_ifattach __P((struct ifnet *));
/* void	ether_input __P((struct ifnet *, struct ether_header *, struct mbuf *)); */
int	ether_output __P((struct ifnet *,
	   struct mbuf *, struct sockaddr *, struct rtentry *));
char	*ether_sprintf __P((u_char *));

void	if_attach __P((struct ifnet *));
void	if_down __P((struct ifnet *));
void	if_qflush __P((struct ifqueue *));
void	if_slowtimo __P((void *));
void	if_up __P((struct ifnet *));

int	ifconf __P((int, caddr_t));
void	ifinit __P((void));
/*
int	ifpromisc __P((struct ifnet *, int));
*/
struct	ifnet *ifunit __P((char *));

struct	ifaddr *ifa_ifwithaddr __P((struct sockaddr *));
struct	ifaddr *ifa_ifwithaf __P((int));
struct	ifaddr *ifa_ifwithdstaddr __P((struct sockaddr *));
struct	ifaddr *ifa_ifwithnet __P((struct sockaddr *));
struct	ifaddr *ifa_ifwithroute __P((int, struct sockaddr *,
					struct sockaddr *));
struct	ifaddr *ifaof_ifpforaddr __P((struct sockaddr *, struct ifnet *));
void	ifafree __P((struct ifaddr *));
void	link_rtrequest __P((int, struct rtentry *, struct sockaddr *));

int	loioctl __P((struct ifnet *, int, caddr_t));
void	loopattach __P(());
int	looutput __P((struct ifnet *,
	   struct mbuf *, struct sockaddr *, struct rtentry *));
void	lortrequest __P((int, struct rtentry *, struct sockaddr *));


/*----------------------------------------*/

struct slcompress {
	u_char last_recv;	/* last rcvd conn. id */
	u_char last_xmit;	/* last sent conn. id */
	u_short flags;
};

struct sl_softc {
	struct	ifnet sc_if;		/* network-visible interface */
       struct	ifqueue sc_fastq;	/* interactive output queue */
	struct	tty *sc_ttyp;		/* pointer */
	u_char	*sc_mp;			/* pointer to next available buf char */
	u_char	*sc_ep;			/* pointer to last available buf char */
	u_char	*sc_buf;		/* input buffer */
	u_int	sc_flags;		/* see below */
	u_int	sc_escape;	/* =1 if last char input was FRAME_ESCAPE */
	long	sc_lasttime;		/* last time a char arrived */
	long	sc_abortcount;		/* number of abort esacpe chars */
	long	sc_starttime;		/* time of first abort in window */
      struct	slcompress sc_comp;	
	caddr_t	sc_bpf;			/* BPF data */
};

/* internal flags */
#define	SC_ERROR	0x0001		/* had an input error */

/* visible flags */
#define	SC_COMPRESS	IFF_LINK0	/* compress TCP traffic */
#define	SC_NOICMP	IFF_LINK1	/* supress ICMP traffic */
#define	SC_AUTOCOMP	IFF_LINK2	/* auto-enable TCP compression */


void	slattach __P((void));
void	slclose __P((struct tty *));
void	slinput __P((int, struct tty *));
int	slioctl __P((struct ifnet *, int, caddr_t));
int	slopen __P((dev_t, struct tty *));
int	sloutput __P((struct ifnet *,
	    struct mbuf *, struct sockaddr *, struct rtentry *));
void	slstart __P((struct tty *));
int	sltioctl __P((struct tty *, int, caddr_t, int));



/*
 * Message format announcing the arrival or departure of a network interface.
 */
struct if_announcemsghdr {
	u_short	ifan_msglen;	/* to skip over non-understood messages */
	u_char	ifan_version;	/* future binary compatibility */
	u_char	ifan_type;	/* message type */
	u_short	ifan_index;	/* index for associated ifp */
	char	ifan_name[IFNAMSIZ]; /* if name, e.g. "en0" */
	u_short	ifan_what;	/* what type of announcement */
};

#define	IFAN_ARRIVAL	0	/* interface arrival */
#define	IFAN_DEPARTURE	1	/* interface departure */

#endif
