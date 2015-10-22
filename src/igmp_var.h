
/* Internet Group Management Protocol (IGMP) definitions. */

/*
 * IGMP packet format.
 */
struct igmp {
	u_char		igmp_type;	/* version & type of IGMP message  */
	u_char		igmp_code;	/* unused, should be zero          */
	u_short		igmp_cksum;	/* IP-style checksum               */
	struct in_addr	igmp_group;	/* group address being reported    */
};					/*  (zero for queries)             */

#define IGMP_MINLEN		     8

#define IGMP_HOST_MEMBERSHIP_QUERY   0x11  /* message types, incl. version */
#define IGMP_HOST_MEMBERSHIP_REPORT  0x12
#define IGMP_DVMRP		     0x13  /* for experimental multicast   */
					   /*  routing protocol            */

#define IGMP_MAX_HOST_REPORT_DELAY   10    /* max delay for response to    */



/*
 * Internet Group Management Protocol (IGMP),
 * implementation-specific definitions.
 *
 * Written by Steve Deering, Stanford, May 1988.
 *
 * MULTICAST 1.1
 */

struct igmpstat {
	u_long	igps_rcv_total;		/* total IGMP messages received */
	u_long	igps_rcv_tooshort;	/* received with too few bytes */
	u_long	igps_rcv_badsum;	/* received with bad checksum */
	u_long	igps_rcv_queries;	/* received membership queries */
	u_long	igps_rcv_badqueries;	/* received invalid queries */
	u_long	igps_rcv_reports;	/* received membership reports */
	u_long	igps_rcv_badreports;	/* received invalid reports */
	u_long	igps_rcv_ourreports;	/* received reports for our groups */
	u_long	igps_snd_reports;	/* sent membership reports */
};

#ifdef KERNEL
struct igmpstat igmpstat;

/*
 * Macro to compute a random timer value between 1 and (IGMP_MAX_REPORTING_
 * DELAY * countdown frequency).  We generate a "random" number by adding
 * the total number of IP packets received, our primary IP address, and the
 * multicast address being timed-out.  The 4.3 random() routine really
 * ought to be available in the kernel!
 */
#define IGMP_RANDOM_DELAY(multiaddr) \
	/* struct in_addr multiaddr; */ \
	( (ipstat.ips_total + \
	   ntohl(IA_SIN(in_ifaddr)->sin_addr.s_addr) + \
	   ntohl((multiaddr).s_addr) \
	  ) \
	  % (IGMP_MAX_HOST_REPORT_DELAY * PR_FASTHZ) + 1 \
	)

void	igmp_init __P(());
void	igmp_input __P((struct mbuf *, int));
void	igmp_joingroup __P((struct in_multi *));
void	igmp_leavegroup __P((struct in_multi *));
void	igmp_fasttimo __P(());
#endif

