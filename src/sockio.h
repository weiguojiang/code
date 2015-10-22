#ifndef	_SYS_SOCKIO_H_
#define	_SYS_SOCKIO_H_

#define PAGE_SHIFT	13		/* LOG2(PAGE_SIZE) */
#define PAGE_SIZE	(1<<PAGE_SHIFT)	/* bytes/page */

/*
 * Ioctl's have the command encoded in the lower word, and the size of
 * any in or out parameters in the upper word.  The high 3 bits of the
 * upper word are used to encode the in/out status of the parameter.
 */
#define	IOCPARM_MASK	0x1fff		/* parameter length, at most 13 bits */
#define	IOCPARM_LEN(x)	(((x) >> 16) & IOCPARM_MASK)
#define	IOCBASECMD(x)	((x) & ~(IOCPARM_MASK << 16))
#define	IOCGROUP(x)	(((x) >> 8) & 0xff)

#define	IOCPARM_MAX	PAGE_SIZE		/* max size of ioctl, mult. of PAGE_SIZE */
#define	IOC_VOID	0x20000000	/* no parameters */
#define	IOC_OUT		0x40000000	/* copy out parameters */
#define	IOC_IN		0x80000000	/* copy in parameters */
#define	IOC_INOUT	(IOC_IN|IOC_OUT)
#define	IOC_DIRMASK	0xe0000000	/* mask for IN/OUT/VOID */

#ifdef win
#define	_IOC(inout,group,num,len) \
	(inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))
#else
#define	_IOC(inout,group,num,len)  num

#endif


#define	_IO(g,n)	_IOC(IOC_VOID,	(g), (n), 0)
#define	_IOR(g,n,t)	_IOC(IOC_OUT,	(g), (n), sizeof(t))
#define	_IOW(g,n,t)	_IOC(IOC_IN,	(g), (n), sizeof(t))
/* this should be _IORW, but stdio got there first */
#define	_IOWR(g,n,t)	_IOC(IOC_INOUT,	(g), (n), sizeof(t))
/* Socket ioctl's. */



#if 0

#define	SIOCSHIWAT	 _IOW('s',  0, int)		/* set high watermark */
#define	SIOCGHIWAT	 _IOR('s',  1, int)		/* get high watermark */
#define	SIOCSLOWAT	 _IOW('s',  2, int)		/* set low watermark */
#define	SIOCGLOWAT	 _IOR('s',  3, int)		/* get low watermark */
#define	SIOCATMARK	 _IOR('s',  7, int)		/* at oob mark? */
#define	SIOCSPGRP	 _IOW('s',  8, int)		/* set process group */
#define	SIOCGPGRP	 _IOR('s',  9, int)		/* get process group */


#define	SIOCADDRT	 _IOW('r', 10, struct ortentry)	/* add route */
#define	SIOCDELRT	 _IOW('r', 11, struct ortentry)	/* delete route */
#define	SIOCGETVIFCNT	_IOWR('r', 15, struct ortentry)/* get vif pkt cnt */
#define	SIOCGETSGCNT	_IOWR('r', 16, struct ortentry) /* get s,g pkt cnt */

#define	SIOCSIFADDR	 _IOW('i', 12, struct ifreq)	/* set ifnet address */
#define	OSIOCGIFADDR	_IOWR('i', 13, struct ifreq)	/* get ifnet address */
#define	SIOCGIFADDR	_IOWR('i', 33, struct ifreq)	/* get ifnet address */
#define	SIOCSIFDSTADDR	 _IOW('i', 14, struct ifreq)	/* set p-p address */
#define	OSIOCGIFDSTADDR	_IOWR('i', 15, struct ifreq)	/* get p-p address */
#define	SIOCGIFDSTADDR	_IOWR('i', 34, struct ifreq)	/* get p-p address */
#define	SIOCSIFFLAGS	 _IOW('i', 16, struct ifreq)	/* set ifnet flags */
#define	SIOCGIFFLAGS	_IOWR('i', 17, struct ifreq)	/* get ifnet flags */
#define	OSIOCGIFBRDADDR	_IOWR('i', 18, struct ifreq)	/* get broadcast addr */
#define	SIOCGIFBRDADDR	_IOWR('i', 35, struct ifreq)	/* get broadcast addr */
#define	SIOCSIFBRDADDR	 _IOW('i', 19, struct ifreq)	/* set broadcast addr */
#define	OSIOCGIFCONF	_IOWR('i', 20, struct ifconf)	/* get ifnet list */
#define	SIOCGIFCONF	_IOWR('i', 36, struct ifconf)	/* get ifnet list */
#define	OSIOCGIFNETMASK	_IOWR('i', 21, struct ifreq)	/* get net addr mask */
#define	SIOCGIFNETMASK	_IOWR('i', 37, struct ifreq)	/* get net addr mask */
#define	SIOCSIFNETMASK	 _IOW('i', 22, struct ifreq)	/* set net addr mask */
#define	SIOCGIFMETRIC	_IOWR('i', 23, struct ifreq)	/* get IF metric */
#define	SIOCSIFMETRIC	 _IOW('i', 24, struct ifreq)	/* set IF metric */
#define	SIOCDIFADDR	 _IOW('i', 25, struct ifreq)	/* delete IF addr */
#define	SIOCAIFADDR	 _IOW('i', 26, struct ifaliasreq)/* add/chg IF alias */



#define SIOCALIFADDR     _IOW('i', 27, struct if_laddrreq) /* add IF addr */
#define SIOCGLIFADDR    _IOWR('i', 28, struct if_laddrreq) /* get IF addr */
#define SIOCDLIFADDR     _IOW('i', 29, struct if_laddrreq) /* delete IF addr */
#endif /* KAME6 */

#define	SIOCADDMULTI	 _IOW('i', 49, struct ifreq)	/* add m'cast addr */
#define	SIOCDELMULTI	 _IOW('i', 50, struct ifreq)	/* del m'cast addr */
#define	SIOCGIFMTU	_IOWR('i', 51, struct ifreq)	/* get IF mtu */
#define	SIOCSIFMTU	 _IOW('i', 52, struct ifreq)	/* set IF mtu */
#define	SIOCGIFPHYS	_IOWR('i', 53, struct ifreq)	/* get IF wire */
#define	SIOCSIFPHYS	 _IOW('i', 54, struct ifreq)	/* set IF wire */
#define	SIOCSIFMEDIA	_IOWR('i', 55, struct ifreq)	/* set net media */
#define	SIOCGIFMEDIA	_IOWR('i', 56, struct ifreq) /* get net media */
#define SIOCSIFENTER     _IOW('i', 157, struct ifreq)	/* generic */

#ifdef KAME6
#define SIOCSIFPHYADDR   _IOW('i', 70, struct ifaliasreq) /* set gif addres */
#define SIOCGIFPSRCADDR _IOWR('i', 71, struct ifreq)    /* get gif psrc addr */
#define SIOCGIFPDSTADDR _IOWR('i', 72, struct ifreq)    /* get gif pdst addr */
#define SIOCDIFPHYADDR   _IOW('i', 73, struct ifreq)    /* delete gif addrs */
#endif /* KAME6 */

#ifndef BSD_SOURCE_BASE
/*
 * undocumented ioctl entry for internal ether stressed test.
 */

#define SIOCHOTSWAP	    _IO('i', 57)   /* hot swap simulation */
#define SIOCSETOSICOOKIE    _IO('i', 58)   /* set osi cookie */
#define SIOCSETIPCCOOKIE    _IO('i', 59)   /* set ipc cookie */

#endif /* BSD_SOURCE_BASE */

#define	SIOCSIFGENERIC	_IOW('i', 57, struct ifreq)	/* generic IF set op */
#define	SIOCGIFGENERIC	_IOWR('i', 58, struct ifreq)	/* generic IF get op */


#define	SIOCIFCREATE	 _IOW('i', 122, struct ifreq)	/* create clone if */
#define	SIOCIFDESTROY	 _IOW('i', 121, struct ifreq)	/* destroy clone if */
#define	SIOCIFGCLONERS _IOWR('i', 120, struct if_clonereq) /* get cloners */

#endif /* !_SYS_SOCKIO_H_ */

