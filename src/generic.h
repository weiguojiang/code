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

#ifndef _generic_h_
#define _generic_h_

#define NBPFILTER 10

#define _is_cgywin

#define bcopy(a,b,c) memcpy (b,a,c)
#define bzero(a,b) memset (a,0,b)
#define bcmp(a,b,c) memcmp (a,b,c) 

#define	ntohl(x)	(x)
#define	ntohs(x)	(x)
#define	htonl(x)	(x)
#define	htons(x)	(x)



#ifdef _is_cgywin

   #include "types.h" 

   #define	LITTLE_ENDIAN	1234	/* LSB first: i386, vax */
   #define	BIG_ENDIAN	4321	/* MSB first: 68000, ibm, net */
   #define	PDP_ENDIAN	3412	/* LSB first in word, MSW first in long */
   #define	BYTE_ORDER	LITTLE_ENDIAN
   
   #define	__CONCAT(x,y)	x##y
   #define __P(a)  a 
   
   struct timeval{
     int tv_sec;
     int tv_usec;
   };
   
#else  

  #include <sys/types.h> 
    
#endif

typedef	long		       __intptr_t;
typedef	unsigned long	      __uintptr_t;

#ifndef	intptr_t
typedef	__intptr_t	intptr_t;
#define	intptr_t	__intptr_t
#endif

typedef unsigned int	u_32_t;

/*
  it used to control the compile enviornment.
*/

#define  in_cksum(m, len) 0

#define  sorwakeup(last) 0

/*
 * Per-process open flags.
 */
#define	UF_EXCLOSE 	0x01		/* auto-close on exec */
#define	UF_MAPPED 	0x02		/* mapped from device */


/*
 * Resource limits
 */
#define	RLIMIT_CPU	0		/* cpu time in milliseconds */
#define	RLIMIT_FSIZE	1		/* maximum file size */
#define	RLIMIT_DATA	2		/* data size */
#define	RLIMIT_STACK	3		/* stack size */
#define	RLIMIT_CORE	4		/* core file size */
#define	RLIMIT_RSS	5		/* resident set size */
#define	RLIMIT_MEMLOCK	6		/* locked-in-memory address space */
#define	RLIMIT_NPROC	7		/* number of processes */
#define	RLIMIT_NOFILE	8		/* number of open files */

#define	RLIM_NLIMITS	9		/* number of resource limits */



#define  sowwakeup(last) 0

#define  wakeup(last) 0


#include "queue.h" 

/* it's for the undefined fucntion */

/*
struct qelem {
  struct qelem *q_forw;
  struct qelem *q_back;
};


void
insque (struct qelem *elem, struct qelem *pred);


void
remque (struct qelem *elem);
*/



 

  

#include "errno.h"


#ifndef NULL
#define NULL (void *)0
#endif


#define imin(a, b) ((a < b ? a : b))

/*
 * Definitions for byte order, according to byte significance from low
 * address to high.
 */

#define MULTICAST
#define GATEWAY

#define	FREAD		0x0001
#define	FWRITE		0x0002

typedef u_short n_short;		/* short as received from the net */
typedef u_long	n_long;			/* long as received from the net */

typedef	u_long	n_time;			/* ms since 00:00 GMT, byte rev */

/*
 * Macros for network/external number representation conversion.
 */
#if BYTE_ORDER == BIG_ENDIAN 
#define	ntohl(x)	(x)
#define	ntohs(x)	(x)
#define	htonl(x)	(x)
#define	htons(x)	(x)
#define	NTOHL(x)	(x)
#define	NTOHS(x)	(x)
#define	HTONL(x)	(x)
#define	HTONS(x)	(x)

#else

#define	NTOHL(x)	(x) = ntohl((u_long)x)
#define	NTOHS(x)	(x) = ntohs((u_short)x)
#define	HTONL(x)	(x) = htonl((u_long)x)
#define	HTONS(x)	(x) = htons((u_short)x)
#endif

#define NLE 10 

#define KERNEL

#define lint

#define INET


#define min(a, b)       ((a) < (b) ? (a) : (b))
#define max(a, b)       ((a) > (b) ? (a) : (b))

#define splx(s) 
#define splimp()  0
#define splnet()  0

#define  panic(a) printf(a)
// #define  traverse(p)  0


#define timeout(a,b, C) 0 

#define FREE(addr, type) free((caddr_t)(addr))



#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

#define	LOG_PRIMASK	0x07	/* mask to extract priority part (internal) */
				/* extract priority */
#define	LOG_PRI(p)	((p) & LOG_PRIMASK)
#define	LOG_MAKEPRI(fac, pri)	(((fac) << 3) | (pri))

/*
 * Socket state bits.
 */
#define	SS_NOFDREF		0x001	/* no file table ref any more */
#define	SS_ISCONNECTED		0x002	/* socket connected to a peer */
#define	SS_ISCONNECTING		0x004	/* in process of connecting to peer */
#define	SS_ISDISCONNECTING	0x008	/* in process of disconnecting */
#define	SS_CANTSENDMORE		0x010	/* can't send more data to peer */
#define	SS_CANTRCVMORE		0x020	/* can't receive more data from peer */
#define	SS_RCVATMARK		0x040	/* at mark on input */

#define	SS_PRIV			0x080	/* privileged for broadcast, raw... */
#define	SS_NBIO			0x100	/* non-blocking ops */
#define	SS_ASYNC		0x200	/* async i/o notify */
#define	SS_ISCONFIRMING		0x400	/* deciding to accept connection req */
/*
#define arp_rtrequest 0 */


#define	NETISR_RAW	0		/* same as AF_UNSPEC */
#define	NETISR_IP	2		/* same as AF_INET */
#define	NETISR_IMP	3		/* same as AF_IMPLINK */
#define	NETISR_NS	6		/* same as AF_NS */
#define	NETISR_ISO	7		/* same as AF_ISO */
#define	NETISR_CCITT	10		/* same as AF_CCITT */
#define	NETISR_ARP	18		/* same as AF_LINK */


int	softem;	
int	netisr;				/* scheduling bits for network */

#define	schednetisr(anisr)	{\
	if(netisr == 0) { \
		softem++; \
	} \
	netisr |= 1<<(anisr); \
}




/*
 *	@(#)if_lereg.h	8.1 (Berkeley) 6/10/93
 */

#define	LEID		21

#define	LEMTU		1518
#define	LEMINSIZE	60	/* should be 64 if mode DTCR is set */
#define	LERBUF		8
#define	LERBUFLOG2	3
#define	LE_RLEN		(LERBUFLOG2 << 13)
#define	LETBUF		2
#define	LETBUFLOG2	1
#define	LE_TLEN		(LETBUFLOG2 << 13)

/*
 * LANCE registers.
 */
 
 #define vu_char u_char
 
struct lereg0 {
	u_char	ler0_pad0;
	vu_char	ler0_id;	/* ID */
	u_char	ler0_pad1;
	vu_char	ler0_status;	/* interrupt enable/status */
};

struct lereg1 {
	u_short	ler1_rdp;	/* data port */
	u_short	ler1_rap;	/* register select port */
};

/*
 * Overlayed on 16K dual-port RAM.
 * Current size is 15,284 bytes with 8 x 1518 receive buffers and
 * 2 x 1518 transmit buffers.
 */
struct lereg2 {
	/* init block */
	u_short	ler2_mode;		/* +0x0000 */
	u_char	ler2_padr[6];		/* +0x0002 */
	u_long	ler2_ladrf[2];		/* +0x0008 */
	u_short	ler2_rdra;		/* +0x0010 */
	u_short	ler2_rlen;		/* +0x0012 */
	u_short	ler2_tdra;		/* +0x0014 */
	u_short	ler2_tlen;		/* +0x0016 */
	/* receive message descriptors */
	struct	lermd {			/* +0x0018 */
		u_short	rmd0;
		u_short	rmd1;
		short	rmd2;
		u_short	rmd3;
	} ler2_rmd[LERBUF];
	/* transmit message descriptors */
	struct	letmd {			/* +0x0058 */
		u_short	tmd0;
		u_short	tmd1;
		short	tmd2;
		u_short	tmd3;
	} ler2_tmd[LETBUF];
	char	ler2_rbuf[LERBUF][LEMTU]; /* +0x0068 */
	char	ler2_tbuf[LETBUF][LEMTU]; /* +0x2FD8 */
};

/*
 * Control and status bits -- lereg0
 */
#define	LE_IE		0x80		/* interrupt enable */
#define	LE_IR		0x40		/* interrupt requested */
#define	LE_LOCK		0x08		/* lock status register */
#define	LE_ACK		0x04		/* ack of lock */
#define	LE_JAB		0x02		/* loss of tx clock (???) */
#define LE_IPL(x)	((((x) >> 4) & 0x3) + 3)

/*
 * Control and status bits -- lereg1
 */
#define	LE_CSR0		0
#define	LE_CSR1		1
#define	LE_CSR2		2
#define	LE_CSR3		3

#define	LE_SERR		0x8000
#define	LE_BABL		0x4000
#define	LE_CERR		0x2000
#define	LE_MISS		0x1000
#define	LE_MERR		0x0800
#define	LE_RINT		0x0400
#define	LE_TINT		0x0200
#define	LE_IDON		0x0100
#define	LE_INTR		0x0080
#define	LE_INEA		0x0040
#define	LE_RXON		0x0020
#define	LE_TXON		0x0010
#define	LE_TDMD		0x0008
#define	LE_STOP		0x0004
#define	LE_STRT		0x0002
#define	LE_INIT		0x0001

#define	LE_BSWP		0x4
#define	LE_MODE		0x0

/*
 * Control and status bits -- lereg2
 */
#define	LE_OWN		0x8000
#define	LE_ERR		0x4000
#define	LE_STP		0x0200
#define	LE_ENP		0x0100

#define	LE_FRAM		0x2000
#define	LE_OFLO		0x1000
#define	LE_CRC		0x0800
#define	LE_RBUFF	0x0400
#define	LE_MORE		0x1000
#define	LE_ONE		0x0800
#define	LE_DEF		0x0400
#define	LE_TBUFF	0x8000
#define	LE_UFLO		0x4000
#define	LE_LCOL		0x1000
#define	LE_LCAR		0x0800
#define	LE_RTRY		0x0400


/* 
   filedesc.h
*/

#define NDFILE		20
#define NDEXTENT	50		/* 250 bytes in 256-byte alloc. */ 

struct filedesc {
	struct	file **fd_ofiles;	/* file structures for open files */
	char	*fd_ofileflags;		/* per-process open file flags */
	int	fd_nfiles;		/* number of open files allocated */
	u_short	fd_lastfile;		/* high-water mark of fd_ofiles */
	u_short	fd_freefile;		/* approx. next free file */
	u_short	fd_cmask;		/* mask for file creation */
	u_short	fd_refcnt;		/* reference count */
};

/* 
   uio.h
*/

struct iovec {
	char	*      iov_base;	/* Base address. */
	size_t	 iov_len;	/* Length. */
};

enum	uio_rw { UIO_READ, UIO_WRITE };

/* Segment flag values. */
enum uio_seg {
	UIO_USERSPACE,		/* from user data space */
	UIO_SYSSPACE,		/* from system space */
	UIO_USERISPACE		/* from user I space */
};


struct uio {
	struct	iovec *uio_iov;
	int	uio_iovcnt;
	off_t	uio_offset;
	int	uio_resid;
	enum	uio_seg uio_segflg;
	enum	uio_rw uio_rw;
	struct	proc *uio_procp;
};

#define UIO_MAXIOV	1024		/* max 1K of iov's */
#define UIO_SMALLIOV	8		/* 8 on stack, else malloc */

/* 
   syslimits.h
*/

#define	ARG_MAX			20480	/* max bytes for an exec function */
#define	CHILD_MAX		   40	/* max simultaneous processes */
#define	LINK_MAX		32767	/* max file link count */
#define	MAX_CANON		  255	/* max bytes in term canon input line */
#define	MAX_INPUT		  255	/* max bytes in terminal input */
#define	NAME_MAX		  255	/* max bytes in a file name */
#define	NGROUPS_MAX		   16	/* max supplemental group id's */
#define	OPEN_MAX		   64	/* max open files per process */
#define	PATH_MAX		 1024	/* max bytes in pathname */
#define	PIPE_BUF		  512	/* max bytes for atomic pipe writes */

#define	BC_BASE_MAX		   99	/* max ibase/obase values in bc(1) */
#define	BC_DIM_MAX		 2048	/* max array elements in bc(1) */
#define	BC_SCALE_MAX		   99	/* max scale value in bc(1) */
#define	BC_STRING_MAX		 1000	/* max const string length in bc(1) */
#define	COLL_WEIGHTS_MAX	    0	/* max weights for order keyword */
#define	EXPR_NEST_MAX		   32	/* max expressions nested in expr(1) */
#define	LINE_MAX		 2048	/* max bytes in an input line */
#define	RE_DUP_MAX		  255	/* max RE's in interval notation */

/* 
    param.h
    
*/
#define	MAXCOMLEN	16		/* max command name remembered */
#define	MAXINTERP	32		/* max interpreter file name length */
#define	MAXLOGNAME	12		/* max login name length */
#define	MAXUPRC		CHILD_MAX	/* max simultaneous processes */
#define	NCARGS		ARG_MAX		/* max bytes for an exec function */
#define	NGROUPS		NGROUPS_MAX	/* max number groups */
#define	NOFILE		OPEN_MAX	/* max open files per process */
#define	NOGROUP		65535		/* marker for empty group set member */
#define MAXHOSTNAMELEN	256		/* max hostname size */

struct ucred {
	u_short	cr_ref;			/* reference count */
	uid_t	cr_uid;			/* effective user id */
	short	cr_ngroups;		/* number of groups */
	gid_t	cr_groups[NGROUPS];	/* groups */
};

/*
  file.h
*/
  
struct file {
	struct	file *f_filef;	/* list of active files */
	struct	file **f_fileb;	/* list of active files */
	short	f_flag;		/* see fcntl.h */
#define	DTYPE_VNODE	1	/* file */
#define	DTYPE_SOCKET	2	/* communications endpoint */
	short	f_type;		/* descriptor type */
	short	f_count;	/* reference count */
	short	f_msgcount;	/* references from message queue */
	struct	ucred *f_cred;	/* credentials associated with descriptor */
	struct	fileops {
		int	(*fo_read)	__P((struct file *fp, struct uio *uio,
					    struct ucred *cred));
		int	(*fo_write)	__P((struct file *fp, struct uio *uio,
					    struct ucred *cred));
		int	(*fo_ioctl)	__P((struct file *fp, int com,
					    caddr_t data, struct proc *p));
		int	(*fo_select)	__P((struct file *fp, int which,
					    struct proc *p));
		int	(*fo_close)	__P((struct file *fp, struct proc *p));
	} *f_ops;
	off_t	f_offset;
	caddr_t	f_data;		/* vnode or socket */
};

/*
 * Storage required per open file descriptor.
 */
#define OFILESIZE (sizeof(struct file *) + sizeof(char))

/*
 * Kernel global variables and routines.
 */
int	fdalloc __P((struct proc *p, int want, int *result));
int	fdavail __P((struct proc *p, int n));
int	falloc __P((struct proc *p, struct file **resultfp, int *resultfd));
struct	filedesc *fdcopy __P((struct proc *p));
void	fdfree __P((struct proc *p));

void log(int level, const char *fmt, ...);


#endif 
