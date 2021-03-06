/*	$NetBSD: ipl.h,v 1.15.2.1 2004/08/13 16:46:52 jmc Exp $	*/

/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * @(#)ipl.h	1.21 6/5/96
 * Id: ipl.h,v 2.52.2.4 2004/07/18 04:13:45 darrenr Exp
 */

#ifndef	__IPL_H__
#define	__IPL_H__


#define IPFILTER_LOG

#define	IPL_VERSION	"IP Filter: v4.1.3"

#define	IPFILTER_VERSION	4010300


/*
 * Flags indicating what fields to do matching upon (ac_mflag).
 */
#define	IPMAC_DIRECTION	0x0001
#define	IPMAC_DSTIP	0x0002
#define	IPMAC_DSTPORT	0x0004
#define	IPMAC_EVERY	0x0008
#define	IPMAC_GROUP	0x0010
#define	IPMAC_INTERFACE	0x0020
#define	IPMAC_LOGTAG	0x0040
#define	IPMAC_NATTAG	0x0080
#define	IPMAC_PROTOCOL	0x0100
#define	IPMAC_RESULT	0x0200
#define	IPMAC_RULE	0x0400
#define	IPMAC_SRCIP	0x0800
#define	IPMAC_SRCPORT	0x1000
#define	IPMAC_TYPE	0x2000
#define	IPMAC_WITH	0x4000

#define	IPMR_BLOCK	1
#define	IPMR_PASS	2
#define	IPMR_NOMATCH	3
#define	IPMR_LOG	4

#define	IPMDO_SAVERAW	0x0001

#define	OPT_SYSLOG	0x001
#define	OPT_RESOLVE	0x002
#define	OPT_HEXBODY	0x004
#define	OPT_VERBOSE	0x008
#define	OPT_HEXHDR	0x010
#define	OPT_TAIL	0x020
#define	OPT_NAT		0x080
#define	OPT_STATE	0x100
#define	OPT_FILTER	0x200
#define	OPT_PORTNUM	0x400
#define	OPT_LOGALL	(OPT_NAT|OPT_STATE|OPT_FILTER)

#define	OPT_REMOVE	0x000001
#define	OPT_DEBUG	0x000002
#define	OPT_AUTHSTATS	0x000004
#define	OPT_RAW		0x000008
#define	OPT_LOG		0x000010
#define	OPT_SHOWLIST	0x000020
#define	OPT_VERBOSE	0x000040
#define	OPT_DONOTHING	0x000080
#define	OPT_HITS	0x000100
#define	OPT_BRIEF	0x000200
#define	OPT_ACCNT	0x000400
#define	OPT_FRSTATES	0x000800
#define	OPT_SHOWLINENO	0x001000
#define	OPT_PRINTFR	0x002000
#define	OPT_OUTQUE	FR_OUTQUE	/* 0x4000 */
#define	OPT_INQUE	FR_INQUE	/* 0x8000 */
#define	OPT_ZERORULEST	0x010000
#define	OPT_SAVEOUT	0x020000
#define	OPT_IPSTATES	0x040000
#define	OPT_INACTIVE	0x080000
#define	OPT_NAT		0x100000
#define	OPT_GROUPS	0x200000
#define	OPT_STATETOP	0x400000
#define	OPT_FLUSH	0x800000
#define	OPT_CLEAR	0x1000000
#define	OPT_HEX		0x2000000
#define	OPT_ASCII	0x4000000
#define	OPT_NORESOLVE	0x8000000

#define	OPT_STAT	OPT_FRSTATES
#define	OPT_LIST	OPT_SHOWLIST
#endif
