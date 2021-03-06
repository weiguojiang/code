/*	$NetBSD: ip_scan.c,v 1.1.1.1 2004/03/28 08:56:49 martti Exp $	*/

/*
 * Copyright (C) 1995-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 */
#if 0 
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#include <sys/param.h>
#if defined(__hpux) && (HPUXREV >= 1111) && !defined(_KERNEL)
# include <sys/kern_svcs.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/errno.h>
#if !defined(_KERNEL)
# include <stdlib.h>
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#else
# include <sys/systm.h>
# if !defined(__svr4__) && !defined(__SVR4)
#  include <sys/mbuf.h>
# endif
#endif
#include <sys/socket.h>
#if !defined(__hpux) && !defined(__osf__) && !defined(linux)
# include <sys/ioccom.h>
#endif
#ifdef __FreeBSD__
# include <sys/filio.h>
# include <sys/malloc.h>
#else
# include <sys/ioctl.h>
#endif

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <net/if.h>


#include "netinet/ip_compat.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_state.h"
#include "netinet/ip_scan.h"
/* END OF INCLUDES */
#else
#include "ip.h"
#include "ip_var.h"
#include "ip_icmp.h"
#include "ip_nat.h"
#include "tcp.h"
#include "socket.h"
#include "protosw.h"
#include "domain.h"
#include "mbuf.h"
#include "udp_var.h"
#include "if.h"
#include "radix.h"
#include "route.h"
#include "in.h"
#include "in_var.h"
#include "in_pcb.h"
#include "ipl.h"
#include "ip_compat.h"
#include "ip_fil.h"
#include "ip_pool.h"
#include "ip_state.h"
#include "ip_frag.h"
#include "ip_scan.h"
#endif


#if !defined(lint)
static const char sccsid[] = "@(#)ip_state.c	1.8 6/5/96 (C) 1993-2000 Darren Reed";
static const char rcsid[] = "@(#)Id: ip_scan.c,v 2.40 2004/01/27 00:24:56 darrenr Exp";
#endif

#ifdef	IPFILTER_SCAN	/* endif at bottom of file */


ipscan_t	*ipsc_list = NULL,
		*ipsc_tail = NULL;
ipscanstat_t	ipsc_stat;
# ifdef USE_MUTEXES
ipfrwlock_t	ipsc_rwlock;
# endif

# ifndef isalpha
#  define	isalpha(x)	(((x) >= 'A' && 'Z' >= (x)) || \
				 ((x) >= 'a' && 'z' >= (x)))
# endif


int ipsc_add __P((caddr_t));
int ipsc_delete __P((caddr_t));
struct ipscan *ipsc_lookup __P((char *));
int ipsc_matchstr __P((sinfo_t *, char *, int));
int ipsc_matchisc __P((ipscan_t *, ipstate_t *, int, int, int *));
int ipsc_match __P((ipstate_t *));



int ipsc_init()
{
	RWLOCK_INIT(&ipsc_rwlock, "ip scan rwlock");
	return 0;
}


void fr_scanunload()
{
	RW_DESTROY(&ipsc_rwlock);
}


int ipsc_add(data)
caddr_t data;
{
	ipscan_t *i, *isc;
	int err;

	KMALLOC(isc, ipscan_t *);
	if (!isc)
		return ENOMEM;

	err = copyinptr(data, isc, sizeof(*isc));
	if (err)
		return err;

	WRITE_ENTER(&ipsc_rwlock);

	i = ipsc_lookup(isc->ipsc_tag);
	if (i) {
		RWLOCK_EXIT(&ipsc_rwlock);
		KFREE(isc);
		return EEXIST;
	}

	if (ipsc_tail) {
		ipsc_tail->ipsc_next = isc;
		isc->ipsc_pnext = &ipsc_tail->ipsc_next;
		ipsc_tail = isc;
	} else {
		ipsc_list = isc;
		ipsc_tail = isc;
		isc->ipsc_pnext = &ipsc_list;
	}
	isc->ipsc_next = NULL;

	isc->ipsc_hits = 0;
	isc->ipsc_fref = 0;
	isc->ipsc_sref = 0;
	isc->ipsc_active = 0;

	ipsc_stat.iscs_entries++;
	RWLOCK_EXIT(&ipsc_rwlock);
	return 0;
}


int ipsc_delete(data)
caddr_t data;
{
	ipscan_t isc, *i;
	int err;

	err = copyinptr(data, &isc, sizeof(isc));
	if (err)
		return err;

	WRITE_ENTER(&ipsc_rwlock);

	i = ipsc_lookup(isc.ipsc_tag);
	if (i == NULL)
		err = ENOENT;
	else {
		if (i->ipsc_fref) {
			RWLOCK_EXIT(&ipsc_rwlock);
			return EBUSY;
		}

		*i->ipsc_pnext = i->ipsc_next;
		if (i->ipsc_next)
			i->ipsc_next->ipsc_pnext = i->ipsc_pnext;
		else {
			if (i->ipsc_pnext == &ipsc_list)
				ipsc_tail = NULL;
			else
				ipsc_tail = *(*i->ipsc_pnext)->ipsc_pnext;
		}

		ipsc_stat.iscs_entries--;
		KFREE(i);
	}
	RWLOCK_EXIT(&ipsc_rwlock);
	return err;
}


struct ipscan *ipsc_lookup(tag)
char *tag;
{
	ipscan_t *i;

	for (i = ipsc_list; i; i = i->ipsc_next)
		if (!strcmp(i->ipsc_tag, tag))
			return i;
	return NULL;
}


int ipsc_attachfr(fr)
struct frentry *fr;
{
	ipscan_t *i;

	if (fr->fr_isctag[0]) {
		READ_ENTER(&ipsc_rwlock);
		i = ipsc_lookup(fr->fr_isctag);
		if (i != NULL) {
			ATOMIC_INC32(i->ipsc_fref);
		}
		RWLOCK_EXIT(&ipsc_rwlock);
		if (i == NULL)
			return ENOENT;
		fr->fr_isc = i;
	}
	return 0;
}


int ipsc_attachis(is)
struct ipstate *is;
{
	frentry_t *fr;
	ipscan_t *i;

	READ_ENTER(&ipsc_rwlock);
	fr = is->is_rule;
	if (fr) {
		i = fr->fr_isc;
		if (!i || (i != (ipscan_t *)-1)) {
			is->is_isc = i;
			if (i) {
				ATOMIC_INC32(i->ipsc_sref);
				if (i->ipsc_clen)
					is->is_flags |= IS_SC_CLIENT;
				else
					is->is_flags |= IS_SC_MATCHC;
				if (i->ipsc_slen)
					is->is_flags |= IS_SC_SERVER;
				else
					is->is_flags |= IS_SC_MATCHS;
			} else
				is->is_flags |= (IS_SC_CLIENT|IS_SC_SERVER);
		}
	}
	RWLOCK_EXIT(&ipsc_rwlock);
	return 0;
}


int ipsc_detachfr(fr)
struct frentry *fr;
{
	ipscan_t *i;

	i = fr->fr_isc;
	if (i != NULL) {
		ATOMIC_DEC32(i->ipsc_fref);
	}
	return 0;
}


int ipsc_detachis(is)
struct ipstate *is;
{
	ipscan_t *i;

	READ_ENTER(&ipsc_rwlock);
	if ((i = is->is_isc) && (i != (ipscan_t *)-1)) {
		ATOMIC_DEC32(i->ipsc_sref);
		is->is_isc = NULL;
		is->is_flags &= ~(IS_SC_CLIENT|IS_SC_SERVER);
	}
	RWLOCK_EXIT(&ipsc_rwlock);
	return 0;
}


/*
 * 'string' compare for scanning
 */
int ipsc_matchstr(sp, str, n)
sinfo_t *sp;
char *str;
int n;
{
	char *s, *t, *up;
	int i = n;

	if (i > sp->s_len)
		i = sp->s_len;
	up = str;

	for (s = sp->s_txt, t = sp->s_msk; i; i--, s++, t++, up++)
		switch ((int)*t)
		{
		case '.' :
			if (*s != *up)
				return 1;
			break;
		case '?' :
			if (!isalpha(*up) || ((*s & 0x5f) != (*up & 0x5f)))
				return 1;
			break;
		case '*' :
			break;
		}
	return 0;
}


/*
 * Returns 3 if both server and client match, 2 if just server,
 * 1 if just client
 */
int ipsc_matchisc(isc, is, cl, sl, maxm)
ipscan_t *isc;
ipstate_t *is;
int cl, sl, maxm[2];
{
	int i, j, k, n, ret = 0, flags;

	flags = is->is_flags;

	/*
	 * If we've already matched more than what is on offer, then
	 * assume we have a better match already and forget this one.
	 */
	if (maxm != NULL) {
		if (isc->ipsc_clen < maxm[0])
			return 0;
		if (isc->ipsc_slen < maxm[1])
			return 0;
		j = maxm[0];
		k = maxm[1];
	} else {
		j = 0;
		k = 0;
	}

	if (!isc->ipsc_clen)
		ret = 1;
	else if (((flags & (IS_SC_MATCHC|IS_SC_CLIENT)) == IS_SC_CLIENT) &&
		 cl && isc->ipsc_clen) {
		i = 0;
		n = MIN(cl, isc->ipsc_clen);
		if ((n > 0) && (!maxm || (n >= maxm[1]))) {
			if (!ipsc_matchstr(&isc->ipsc_cl, is->is_sbuf[0], n)) {
				i++;
				ret |= 1;
				if (n > j)
					j = n;
			}
		}
	}

	if (!isc->ipsc_slen)
		ret |= 2;
	else if (((flags & (IS_SC_MATCHS|IS_SC_SERVER)) == IS_SC_SERVER) &&
		 sl && isc->ipsc_slen) {
		i = 0;
		n = MIN(cl, isc->ipsc_slen);
		if ((n > 0) && (!maxm || (n >= maxm[1]))) {
			if (!ipsc_matchstr(&isc->ipsc_sl, is->is_sbuf[1], n)) {
				i++;
				ret |= 2;
				if (n > k)
					k = n;
			}
		}
	}

	if (maxm && (ret == 3)) {
		maxm[0] = j;
		maxm[1] = k;
	}
	return ret;
}


int ipsc_match(is)
ipstate_t *is;
{
	int i, j, k, n, cl, sl, maxm[2];
	ipscan_t *isc, *lm;
	tcpdata_t *t;

	for (cl = 0, n = is->is_smsk[0]; n & 1; n >>= 1)
		cl++;
	for (sl = 0, n = is->is_smsk[1]; n & 1; n >>= 1)
		sl++;

	j = 0;
	isc = is->is_isc;
	if (isc != NULL) {
		/*
		 * Known object to scan for.
		 */
		i = ipsc_matchisc(isc, is, cl, sl, NULL);
		if (i & 1) {
			is->is_flags |= IS_SC_MATCHC;
			is->is_flags &= ~IS_SC_CLIENT;
		} else if (cl >= isc->ipsc_clen)
			is->is_flags &= ~IS_SC_CLIENT;
		if (i & 2) {
			is->is_flags |= IS_SC_MATCHS;
			is->is_flags &= ~IS_SC_SERVER;
		} else if (sl >= isc->ipsc_slen)
			is->is_flags &= ~IS_SC_SERVER;
	} else {
		i = 0;
		lm = NULL;
		maxm[0] = 0;
		maxm[1] = 0;
		for (k = 0, isc = ipsc_list; isc; isc = isc->ipsc_next) {
			i = ipsc_matchisc(isc, is, cl, sl, maxm);
			if (i) {
				/*
				 * We only want to remember the best match
				 * and the number of times we get a best
				 * match.
				 */
				if ((j == 3) && (i < 3))
					continue;
				if ((i == 3) && (j != 3))
					k = 1;
				else
					k++;
				j = i;
				lm = isc;
			}
		}
		if (k == 1)
			isc = lm;

		/*
		 * No matches or partial matches, so reset the respective
		 * search flag.
		 */
		if (!(j & 1))
			is->is_flags &= ~IS_SC_CLIENT;

		if (!(j & 2))
			is->is_flags &= ~IS_SC_SERVER;

		/*
		 * If we found the best match, then set flags appropriately.
		 */
		if ((j == 3) && (k == 1)) {
			is->is_flags &= ~(IS_SC_SERVER|IS_SC_CLIENT);
			is->is_flags |= (IS_SC_MATCHS|IS_SC_MATCHC);
		}
	}

	/*
	 * If the acknowledged side of a connection has moved past the data in
	 * which we are interested, then reset respective flag.
	 */
	t = &is->is_tcp.ts_data[0];
	if (t->td_end > is->is_s0[0] + 15)
		is->is_flags &= ~IS_SC_CLIENT;

	t = &is->is_tcp.ts_data[1];
	if (t->td_end > is->is_s0[1] + 15)
		is->is_flags &= ~IS_SC_SERVER;

	/*
	 * Matching complete ?
	 */
	j = ISC_A_NONE;
	if ((is->is_flags & IS_SC_MATCHALL) == IS_SC_MATCHALL) {
		j = isc->ipsc_action;
		ipsc_stat.iscs_acted++;
	} else if ((is->is_isc != NULL) &&
		   ((is->is_flags & IS_SC_MATCHALL) != IS_SC_MATCHALL) &&
		   !(is->is_flags & (IS_SC_CLIENT|IS_SC_SERVER))) {
		/*
		 * Matching failed...
		 */
		j = isc->ipsc_else;
		ipsc_stat.iscs_else++;
	}

	switch (j)
	{
	case  ISC_A_CLOSE :
		/*
		 * If as a result of a successful match we are to
		 * close a connection, change the "keep state" info.
		 * to block packets and generate TCP RST's.
		 */
		is->is_pass &= ~FR_RETICMP;
		is->is_pass |= FR_RETRST;
		break;
	default :
		break;
	}

	return i;
}


/*
 * check if a packet matches what we're scanning for
 */
int ipsc_packet(fin, is)
fr_info_t *fin;
ipstate_t *is;
{
	int i, j, rv, dlen, off, thoff;
	u_32_t seq, s0;
	tcphdr_t *tcp;

	rv = !IP6_EQ(&fin->fin_fi.fi_src, &is->is_src);
	tcp = fin->fin_dp;
	seq = ntohl(tcp->th_seq);

	if (!is->is_s0[rv])
		return 1;

	/*
	 * check if this packet has more data that falls within the first
	 * 16 bytes sent in either direction.
	 */
	s0 = is->is_s0[rv];
	off = seq - s0;
	if ((seq > s0 + 15) || (off < 0))
		return 1;
	thoff = TCP_OFF(tcp) << 2;
	dlen = fin->fin_dlen - thoff;
	if (dlen <= 0)
		return 1;
	seq += dlen;
	if (seq > s0 + 15)
		dlen -= (seq - (s0 + 15));

	j = 0xffff >> (16 - dlen);
	i = (0xffff & j) << off;
#ifdef _KERNEL
	COPYDATA(*(mb_t **)fin->fin_mp, fin->fin_hlen + thoff, dlen,
		 (caddr_t)is->is_sbuf[rv] + off);
#endif
	is->is_smsk[rv] |= i;
	for (j = 0, i = is->is_smsk[rv]; i & 1; i >>= 1)
		j++;
	if (j == 0)
		return 1;

	(void) ipsc_match(is);
#if 0
	/*
	 * There is the potential here for plain text passwords to get
	 * buffered and stored for some time...
	 */
	if (!(is->is_flags & IS_SC_CLIENT))
		bzero(is->is_sbuf[0], sizeof(is->is_sbuf[0]));
	if (!(is->is_flags & IS_SC_SERVER))
		bzero(is->is_sbuf[1], sizeof(is->is_sbuf[1]));
#endif
	return 0;
}


int fr_scan_ioctl(data, cmd, mode)
caddr_t data;
ioctlcmd_t cmd;
int mode;
{
	ipscanstat_t ipscs;
	int err = 0;

	switch (cmd)
	{
	case SIOCADSCA :
		err = ipsc_add(data);
		break;
	case SIOCRMSCA :
		err = ipsc_delete(data);
		break;
	case SIOCGSCST :
		bcopy((char *)&ipsc_stat, (char *)&ipscs, sizeof(ipscs));
		ipscs.iscs_list = ipsc_list;
		BCOPYOUT(&ipscs, data, sizeof(ipscs));
		break;
	default :
		err = EINVAL;
		break;
	}

	return err;
}
#endif	/* IPFILTER_SCAN */
