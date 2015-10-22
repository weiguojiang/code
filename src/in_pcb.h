#ifndef _in_pcb_h
#define _in_pcb_h

#include "generic.h"
#include "mbuf.h"
#include "in.h"
#include "ip.h"
#include "ip_var.h"
#include "socket.h"



/*
 * Common structure pcb for internet protocol implementation.
 * Here are stored pointers to local and foreign host table
 * entries, local and foreign socket numbers, and pointers
 * up (to a socket structure) and down (to a protocol-specific)
 * control block.
 */
struct inpcb {
	struct	inpcb *inp_next,*inp_prev;
					/* pointers to other pcb's */
	struct	inpcb *inp_head;	/* pointer back to chain of inpcb's
					   for this protocol */
	struct	in_addr inp_faddr;	/* foreign host table entry */
	u_short	inp_fport;		/* foreign port */
	struct	in_addr inp_laddr;	/* local host table entry */
	u_short	inp_lport;		/* local port */
	struct	socket *inp_socket;	/* back pointer to socket */
	caddr_t	inp_ppcb;		/* pointer to per-protocol pcb */
	struct	route inp_route;	/* placeholder for routing entry */
	int	inp_flags;		/* generic IP/datagram flags */
	struct	ip inp_ip;		/* header prototype; should have more */
	struct	mbuf *inp_options;	/* IP options */
	struct	ip_moptions *inp_moptions; /* IP multicast options */
};

/* flags in inp_flags: */
#define	INP_RECVOPTS		0x01	/* receive incoming IP options */
#define	INP_RECVRETOPTS		0x02	/* receive IP options for reply */
#define	INP_RECVDSTADDR		0x04	/* receive IP dst address */
#define	INP_CONTROLOPTS		(INP_RECVOPTS|INP_RECVRETOPTS|INP_RECVDSTADDR)
#define	INP_HDRINCL		0x08	/* user supplies entire IP header */

#define	INPLOOKUP_WILDCARD	1
#define	INPLOOKUP_SETLOCAL	2

#define	sotoinpcb(so)	((struct inpcb *)(so)->so_pcb)


int	 in_losing __P((struct inpcb *));
int	 in_pcballoc __P((struct socket *, struct inpcb *));
int	 in_pcbbind __P((struct inpcb *, struct mbuf *));
int	 in_pcbconnect __P((struct inpcb *, struct mbuf *));
int	 in_pcbdetach __P((struct inpcb *));
int	 in_pcbdisconnect __P((struct inpcb *));
struct inpcb *
	 in_pcblookup __P((struct inpcb *,
	    struct in_addr, u_int, struct in_addr, u_int, int));
int	 in_pcbnotify __P((struct inpcb *, struct sockaddr *,
	    u_int, struct in_addr, u_int, int, void (*)(struct inpcb *, int)));
void	 in_rtchange __P((struct inpcb *, int));
int	 in_setpeeraddr __P((struct inpcb *, struct mbuf *));
int	 in_setsockaddr __P((struct inpcb *, struct mbuf *));



/*
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressible except for those marked "(PROC ONLY)" below,
 * which might be addressible only on a processor on which the process
 * is running.
 */
struct rlimit {
	quad_t	rlim_cur;		/* current (soft) limit */
	quad_t	rlim_max;		/* maximum value for rlim_cur */
};

struct plimit {
	struct	rlimit pl_rlimit[RLIM_NLIMITS];
#define	PL_SHAREMOD	0x01		/* modifications are shared */
	int	p_lflags;
	int	p_refcnt;		/* number of references */
};

struct	pcred {
	struct	ucred *pc_ucred;	/* Current credentials. */
	uid_t	p_ruid;			/* Real user id. */
	uid_t	p_svuid;		/* Saved effective user id. */
	gid_t	p_rgid;			/* Real group id. */
	gid_t	p_svgid;		/* Saved effective group id. */
	int	p_refcnt;		/* Number of references. */
};

struct	proc {
	struct	proc *p_forw;		/* Doubly-linked run/sleep queue. */
	struct	proc *p_back;
	struct	proc *p_next;		/* Linked list of active procs */
	struct	proc **p_prev;		/*    and zombies. */

	/* substructures: */
	struct pcred *p_cred;		/* Process owner's identity. */
	struct filedesc *p_fd;		/* Ptr to open files structure. */
	int *p_stats;	/* Accounting/statistics (PROC ONLY). */
	struct plimit *p_limit;	/* Process limits. */
	int *p_vmspace;	/* Address space. */
	int *p_sigacts;	/* Signal actions, state (PROC ONLY). */

#define	p_ucred		p_cred->pc_ucred
#define	p_rlimit	p_limit->pl_rlimit

	int	p_flag;			/* P_* flags. */
	char	p_stat;			/* S* process status. */
	char	p_pad1[3];

	int  	p_pid;			/* Process identifier. */
	struct	proc *p_hash;	 /* Hashed based on p_pid for kill+exit+... */
	struct	proc *p_pgrpnxt; /* Pointer to next process in process group. */
	struct	proc *p_pptr;	 /* Pointer to process structure of parent. */
	struct	proc *p_osptr;	 /* Pointer to older sibling processes. */

/* The following fields are all zeroed upon creation in fork. */
#define	p_startzero	p_ysptr
	struct	proc *p_ysptr;	 /* Pointer to younger siblings. */
	struct	proc *p_cptr;	 /* Pointer to youngest living child. */
	int	p_oppid;	 /* Save parent pid during ptrace. XXX */
	int	p_dupfd;	 /* Sideways return value from fdopen. XXX */

	/* scheduling */
	u_int	p_estcpu;	 /* Time averaged value of p_cpticks. */
	int	p_cpticks;	 /* Ticks of cpu time. */
	int	p_pctcpu;	 /* %cpu for this process during p_swtime */
	void	*p_wchan;	 /* Sleep address. */
	char	*p_wmesg;	 /* Reason for sleep. */
	u_int	p_swtime;	 /* Time swapped in or out. */
	u_int	p_slptime;	 /* Time since last blocked. */

	struct	timeval p_rtime;	/* Real time. */
	int p_uticks;		/* Statclock hits in user mode. */
	int p_sticks;		/* Statclock hits in system mode. */
	int p_iticks;		/* Statclock hits processing intr. */

	int	p_traceflag;		/* Kernel trace points. */
		int *p_tracep;	/* Trace to vnode. */

	int	p_siglist;		/* Signals arrived but not delivered. */

		int *p_textvp;	/* Vnode of executable. */

	long	p_spare[5];		/* pad to 256, avoid shifting eproc. */

/* End area that is zeroed on creation. */
#define	p_endzero	p_startcopy

/* The following fields are all copied upon creation in fork. */
#define	p_startcopy	p_sigmask

	int p_sigmask;	/* Current signal mask. */
	int p_sigignore;	/* Signals being ignored. */
	int p_sigcatch;	/* Signals being caught by user. */

	u_char	p_priority;	/* Process priority. */
	u_char	p_usrpri;	/* User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value. */
	char	p_comm[16+1];


/* End area that is copied on creation. */
#define	p_endcopy	p_thread
	int	p_thread;	/* Id for this "thread"; Mach glue. XXX */
		int *p_addr;	/* Kernel virtual addr of u-area (PROC ONLY). */
	int p_md;	/* Any machine-dependent fields. */

	u_short	p_xstat;	/* Exit status for wait; also stop signal. */
	u_short	p_acflag;	/* Accounting flags. */
		int *p_ru;	/* Exit information. XXX */

};
#endif

