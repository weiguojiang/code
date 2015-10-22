/*
  *
 *	@(#)if_sl.c	8.6 (Berkeley) 2/1/94
 */


#include "mbuf.h"
#include "protosw.h"
#include "socket.h"
#include "if.h"
#include "route.h"
#include "in.h"
#include "if_ether.h"
#include "in_var.h"

#include "slip.h"
#include "bpf.h"


#define	MCLOFSET	(MCLBYTES - 1)
#define	CBLOCK	64		/* Clist block size, must be a power of 2. */
#define CBQSIZE	(CBLOCK/NBBY)	/* Quote bytes/cblock - can do better. */
				/* Data chars/clist. */
#define	CBSIZE	(CBLOCK  - CBQSIZE)
#define   SLIOCGUNIT  22

struct tty {	
	long	t_rawcc;		/* Raw input queue statistics. */
	 /* some fields are deleted */
	void	*t_sc;			/* XXX: net/if_sl.c:sl_softc. */
	short	t_column;		/* Tty output column. */
	short	t_rocount, t_rocol;	/* Tty. */
	short	t_hiwat;		/* High water mark. */
	short	t_lowat;		/* Low water mark. */
	short	t_gen;			/* Generation number. */
};


#if NBPFILTER > 0
#define	BUFOFFSET	(128+sizeof(struct ifnet **)+SLIP_HDRLEN)
#else
#define	BUFOFFSET	(128+sizeof(struct ifnet **))
#endif
#define	SLMAX		(MCLBYTES - BUFOFFSET)
#define	SLBUFSIZE	(SLMAX + BUFOFFSET)
#define	SLMTU		296
#define	SLIP_HIWAT	roundup(50,CBSIZE)
#define	CLISTRESERVE	1024	/* Can't let clists get too low */

#define NSL  2

/*
 * SLIP ABORT ESCAPE MECHANISM:
 *	(inspired by HAYES modem escape arrangement)
 *	1sec escape 1sec escape 1sec escape { 1sec escape 1sec escape }
 *	within window time signals a "soft" exit from slip mode by remote end
 *	if the IFF_DEBUG flag is on.
 */
#define	ABT_ESC		'\033'	/* can't be t_intr - distant host must know it*/
#define	ABT_IDLE	1	/* in seconds - idle before an escape */
#define	ABT_COUNT	3	/* count of escapes for abort */
#define	ABT_WINDOW	(ABT_COUNT*2+2)	/* in seconds - time to count */

struct sl_softc sl_softc[3];

#define FRAME_END	 	0xc0		/* Frame End */
#define FRAME_ESCAPE		0xdb		/* Frame Esc */
#define TRANS_FRAME_END	 	0xdc		/* transposed frame end */
#define TRANS_FRAME_ESCAPE 	0xdd		/* transposed frame esc */

extern struct timeval time;

static int slinit __P((struct sl_softc *));
static struct mbuf *sl_btom __P((struct sl_softc *, int));

/*
 * Called from boot code to establish sl interfaces.
 */
void
slattach()
{
	register struct sl_softc *sc;
	register int i = 0;

	for (sc = sl_softc; i < NSL; sc++) {
		sc->sc_if.if_name = "sl";
		sc->sc_if.if_next = NULL;
		sc->sc_if.if_unit = i++;
		sc->sc_if.if_mtu = SLMTU;
		sc->sc_if.if_flags =
		    IFF_POINTOPOINT | SC_AUTOCOMP | IFF_MULTICAST;
		sc->sc_if.if_type = IFT_SLIP;
		sc->sc_if.if_ioctl = slioctl;
		sc->sc_if.if_output = NULL /* sloutput */;
		sc->sc_if.if_snd.ifq_maxlen = 50;
		sc->sc_fastq.ifq_maxlen = 32;
		if_attach(&sc->sc_if);
#if NBPFILTER > 0
		bpfattach(&sc->sc_bpf, &sc->sc_if, DLT_SLIP, SLIP_HDRLEN);
#endif		

	}
}

static int
slinit(sc)
	register struct sl_softc *sc;
{
	register caddr_t p;

	if (sc->sc_ep == NULL ) {
		MCLALLOC(p, M_WAIT);
		if (p)
			sc->sc_ep = (u_char *)p + SLBUFSIZE;
		else {
			sc->sc_if.if_flags &= ~IFF_UP;
			return (0);
		}
	}
	sc->sc_buf = sc->sc_ep - SLMAX;
	sc->sc_mp = sc->sc_buf;
	
//	sl_compress_init(&sc->sc_comp);
	
	return (1);
}

/*
 * Line specific open routine.
 * Attach the given tty to the first available sl unit.
 */
/* ARGSUSED */
int
slopen(dev, tp)
	dev_t dev;
	register struct tty *tp;
{

	register struct sl_softc *sc;
	register int nsl;
	int error;
/*
	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);

	if (tp->t_line == SLIPDISC)
		return (0);
*/
	for (nsl = NSL, sc = sl_softc; --nsl >= 0; sc++)
		if (sc->sc_ttyp == NULL) {
			if (slinit(sc) == 0)
				return (ENOBUFS);
			tp->t_sc = (caddr_t)sc;


			return (0);
		}
	return (ENXIO);
}

/*
 * Line specific close routine.
 * Detach the tty from the sl unit.
 */
void
slclose(tp)
	struct tty *tp;
{
	register struct sl_softc *sc;
	int s;

	s = splimp();		/* actually, max(spltty, splnet) */

	sc = (struct sl_softc *)tp->t_sc;
	if (sc != NULL) {
		if_down(&sc->sc_if);
		sc->sc_ttyp = NULL;
		tp->t_sc = NULL;
		MCLFREE((caddr_t)(sc->sc_ep - SLBUFSIZE));
		sc->sc_ep = 0;
		sc->sc_mp = 0;
		sc->sc_buf = 0;
	}
	splx(s);
}

/*
 * Line specific (tty) ioctl routine.
 * Provide a way to get the sl unit number.
 */
/* ARGSUSED */
int
sltioctl(tp, cmd, data, flag)
	struct tty *tp;
	int cmd;
	caddr_t data;
	int flag;
{
	struct sl_softc *sc = (struct sl_softc *)tp->t_sc;

	switch (cmd) {
	case SLIOCGUNIT:
		*(int *)data = sc->sc_if.if_unit;
		break;

	default:
		return (-1);
	}
	return (0);
}

/*
 * Queue a packet.  Start transmission if not active.
 * Compression happens in slstart; if we do it here, IP TOS
 * will cause us to not compress "background" packets, because
 * ordering gets trashed.  It can be done for all packets in slstart.
 */
int
sloutput(ifp, m, dst, rtp)
	struct ifnet *ifp;
	register struct mbuf *m;
	struct sockaddr *dst;
	struct rtentry *rtp;
{
	register struct sl_softc *sc = &sl_softc[ifp->if_unit];
	register struct ip *ip;
	register struct ifqueue *ifq;
	int s;

	/*
	 * `Cannot happen' (see slioctl).  Someday we will extend
	 * the line protocol to support other address families.
	 */
	if (dst->sa_family != AF_INET) {
		printf("sl%d: af%d not supported\n", sc->sc_if.if_unit,
			dst->sa_family);
		m_freem(m);
		sc->sc_if.if_noproto++;
		return (EAFNOSUPPORT);
	}

	if (sc->sc_ttyp == NULL) {
		m_freem(m);
		return (ENETDOWN);	/* sort of */
	} /*
	if ((sc->sc_ttyp->t_state & TS_CARR_ON) == 0 &&
	    (sc->sc_ttyp->t_cflag & CLOCAL) == 0) {
		m_freem(m);
		return (EHOSTUNREACH);
	}*/
	ifq = &sc->sc_if.if_snd;
	ip = mtod(m, struct ip *);  /*
	if (sc->sc_if.if_flags & SC_NOICMP && ip->ip_p == IPPROTO_ICMP) {
		m_freem(m);
		return (ENETRESET);	
	}*/

		ifq = &sc->sc_fastq;
	s = splimp();
	if (IF_QFULL(ifq)) {
		IF_DROP(ifq);
		m_freem(m);
		splx(s);
		sc->sc_if.if_oerrors++;
		return (ENOBUFS);
	}
	IF_ENQUEUE(ifq, m);
	
	splx(s);
	return (0);
}

/*
 * Start output on interface.  Get another datagram
 * to send from the interface queue and map it to
 * the interface before starting output.
 */
void
slstart(tp)
	register struct tty *tp;
{
	register struct sl_softc *sc = (struct sl_softc *)tp->t_sc;
	register struct mbuf *m;
	register u_char *cp;
	register struct ip *ip;
	int s;
	struct mbuf *m2;
#if NBPFILTER > 0
	u_char bpfbuf[SLMTU + SLIP_HDRLEN];
	register int len;
#endif
	extern int cfreecount;

	return ;
	
}

/*
 * Copy data buffer to mbuf chain; add ifnet pointer.
 */
static struct mbuf *
sl_btom(sc, len)
	register struct sl_softc *sc;
	register int len;
{
	register struct mbuf *m;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return (NULL);

	/*
	 * If we have more than MHLEN bytes, it's cheaper to
	 * queue the cluster we just filled & allocate a new one
	 * for the input buffer.  Otherwise, fill the mbuf we
	 * allocated above.  Note that code in the input routine
	 * guarantees that packet will fit in a cluster.
	 */
	if (len >= MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			/*
			 * we couldn't get a cluster - if memory's this
			 * low, it's time to start dropping packets.
			 */
			(void) m_free(m);
			return (NULL);
		}
		sc->sc_ep = mtod(m, u_char *) + SLBUFSIZE;
		m->m_data = (caddr_t)sc->sc_buf;
		m->m_ext.ext_buf = (caddr_t)((int)sc->sc_buf &~ MCLOFSET);
	} else
		bcopy((caddr_t)sc->sc_buf, mtod(m, caddr_t), len);

	m->m_len = len;
	m->m_pkthdr.len = len;
	m->m_pkthdr.rcvif = &sc->sc_if;
	return (m);
}

/*
 * tty interface receiver interrupt.
 */
void
slinput(c, tp)
	register int c;
	register struct tty *tp;
{
	register struct sl_softc *sc;
	register struct mbuf *m;
	register int len;
	int s;
	


	++sc->sc_if.if_ibytes;

	if (sc->sc_if.if_flags & IFF_DEBUG) {
		if (c == ABT_ESC) {
			/*
			 * If we have a previous abort, see whether
			 * this one is within the time limit.
			 */
			if (sc->sc_abortcount &&
			    time.tv_sec >= sc->sc_starttime + ABT_WINDOW)
				sc->sc_abortcount = 0;
			/*
			 * If we see an abort after "idle" time, count it;
			 * record when the first abort escape arrived.
			 */
			if (time.tv_sec >= sc->sc_lasttime + ABT_IDLE) {
				if (++sc->sc_abortcount == 1)
					sc->sc_starttime = time.tv_sec;
				if (sc->sc_abortcount >= ABT_COUNT) {
					slclose(tp);
					return;
				}
			}
		} else
			sc->sc_abortcount = 0;
		sc->sc_lasttime = time.tv_sec;
	}

	switch (c) {

	case TRANS_FRAME_ESCAPE:
		if (sc->sc_escape)
			c = FRAME_ESCAPE;
		break;

	case TRANS_FRAME_END:
		if (sc->sc_escape)
			c = FRAME_END;
		break;

	case FRAME_ESCAPE:
		sc->sc_escape = 1;
		return;

	case FRAME_END:
		if(sc->sc_flags & SC_ERROR) {
			sc->sc_flags &= ~SC_ERROR;
			goto newpack;
		}
		len = sc->sc_mp - sc->sc_buf;
		if (len < 3)
			/* less than min length packet - ignore */
			goto newpack;

		m = sl_btom(sc, len);
		if (m == NULL)
			goto error;

		sc->sc_if.if_ipackets++;
	
		s = splimp();
		if (IF_QFULL(&ipintrq)) {
			IF_DROP(&ipintrq);
			sc->sc_if.if_ierrors++;
			sc->sc_if.if_iqdrops++;
			m_freem(m);
		} else {
			IF_ENQUEUE(&ipintrq, m);
			schednetisr(NETISR_IP);
		}
		splx(s);
		goto newpack;
	}
	if (sc->sc_mp < sc->sc_ep) {
		*sc->sc_mp++ = c;
		sc->sc_escape = 0;
		return;
	}

	/* can't put lower; would miss an extra frame */
	sc->sc_flags |= SC_ERROR;

error:
	sc->sc_if.if_ierrors++;
newpack:
	sc->sc_mp = sc->sc_buf = sc->sc_ep - SLMAX;
	sc->sc_escape = 0;
}

/*
 * Process an ioctl request.
 */
int
slioctl(ifp, cmd, data)
	register struct ifnet *ifp;
	int cmd;
	caddr_t data;
{
	register struct ifaddr *ifa = (struct ifaddr *)data;
	register struct ifreq *ifr;
	register int s = splimp(), error = 0;

	switch (cmd) {

	case SIOCSIFADDR:
		if (ifa->ifa_addr->sa_family == AF_INET)
			ifp->if_flags |= IFF_UP;
		else
			error = EAFNOSUPPORT;
		break;

	case SIOCSIFDSTADDR:
		if (ifa->ifa_addr->sa_family != AF_INET)
			error = EAFNOSUPPORT;
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
	splx(s);
	return (error);
}

