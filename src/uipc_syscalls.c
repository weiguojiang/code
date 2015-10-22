#include "if.h"
#include "mbuf.h"
#include "protosw.h"
#include "socket.h"
#include "in.h"
#include "in_pcb.h"
#include "route.h"
#include "ip_icmp.h"

int  copyin( void *dest, const void *src, size_t count )
{
   memcpy(src , dest, count );
   return 0;

};

int  copyout( void *dest, const void *src, size_t count )
{
   memcpy(dest, src , count );
   return 0;

};

struct	stat {
        /* First some PRIMOS standard entries */
	off_t	st_size;
	time_t	st_mtime;
	short	st_type;        /* Primos file type */
	short	st_rwlock;      /* Primos read/write lock */

	/* Begin Unix compatibility - don't believe these entries! */
	dev_t	st_dev;       
	ino_t	st_ino;
	mode_t	st_mode;
	short	st_nlink;
	uid_t	st_uid;
	gid_t	st_gid;
	dev_t	st_rdev;
	time_t	st_atime;
	time_t	st_ctime;
	long	st_blksize;
	long	st_blocks;
};

struct file g_file;


/* ARGSUSED */
soo_read(fp, uio, cred)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
{

	return (soreceive((struct socket *)fp->f_data, (struct mbuf **)0,
		uio, (struct mbuf **)0, (struct mbuf **)0, (int *)0));
}

/* ARGSUSED */
soo_write(fp, uio, cred)
	struct file *fp;
	struct uio *uio;
	struct ucred *cred;
{

	return (sosend((struct socket *)fp->f_data, (struct mbuf *)0,
		uio, (struct mbuf *)0, (struct mbuf *)0, 0));
}

soo_ioctl(fp, cmd, data, p)
	struct file *fp;
	int cmd;
	register caddr_t data;
	struct proc *p;
{
	register struct socket *so = (struct socket *)fp->f_data;

	switch (cmd) {



	case SIOCSPGRP:
		so->so_pgid = *(int *)data;
		return (0);

	case SIOCGPGRP:
		*(int *)data = so->so_pgid;
		return (0);

	case SIOCATMARK:
		*(int *)data = (so->so_state&SS_RCVATMARK) != 0;
		return (0);
	}
	/*
	 * Interface/routing/protocol specific ioctls:
	 * interface and routing ioctls should have a
	 * different entry since a socket's unnecessary
	 */
	return ((*so->so_proto->pr_usrreq)(so, PRU_CONTROL, 
	    (struct mbuf *)cmd, (struct mbuf *)data, (struct mbuf *)0));
}

soo_select(fp, which, p)
	struct file *fp;
	int which;
	struct proc *p;
{
	register struct socket *so = (struct socket *)fp->f_data;
	register int s = splnet();

	return (0);
}

soo_stat(so, ub)
	register struct socket *so;
	register struct stat *ub;
{

	bzero((caddr_t)ub, sizeof (*ub));
	return ((*so->so_proto->pr_usrreq)(so, PRU_SENSE,
	    (struct mbuf *)ub, (struct mbuf *)0, 
	    (struct mbuf *)0));
}

/* ARGSUSED */
soo_close(fp, p)
	struct file *fp;
	struct proc *p;
{
	int error = 0;

	if (fp->f_data)
		error = soclose((struct socket *)fp->f_data);
	fp->f_data = 0;
	return (error);
}


/* sys_socket.c */
struct socket_args {
	int	domain;
	int	type;
	int	protocol;
};

struct	fileops socketops =
    { soo_read, soo_write, soo_ioctl, soo_select, soo_close };

/*
char *
copyin(src, space)
	register char *src;
	char **space;
{
	register char *cp;
	char *top;

	top = cp = *space;
	while (*cp++ = *src++)
		;
	*space = cp;
	return (top);
}; 
*/
socket(p, uap, retval)
	struct proc *p;
	register struct socket_args *uap;
	int *retval;
{
	struct filedesc *fdp = p->p_fd;
	struct socket *so;
	struct file *fp;
	int fd , error;

      fd = 0;
        /*
       fp = &g_file;
		*/   

	if (error = falloc(p, &fp, &fd))
		return (error);

	fp->f_flag = FREAD|FWRITE;
	fp->f_type = 2;
	fp->f_ops = &socketops;
	if (error = socreate(uap->domain, &so, uap->type, uap->protocol)) {
		fdp->fd_ofiles[fd] = 0;
		/*
		ffree(fp);
		*/
	} else {
		fp->f_data = (caddr_t)so;
		*retval = fd;
	}
	return (error);
}

struct bind_args {
	int	s;
	caddr_t	name;
	int	namelen;
};
/* ARGSUSED */
bind(p, uap, retval)
	struct proc *p;
	register struct bind_args *uap;
	int *retval;
{
	struct file *fp;
	struct mbuf *nam;
	int error;

	if (error = getsock(p->p_fd, uap->s, &fp))
		return (error);
	if (error = sockargs(&nam, uap->name, uap->namelen, MT_SONAME))
		return (error);
	error = sobind((struct socket *)fp->f_data, nam);
	m_freem(nam);
	return (error);
}

struct listen_args {
	int	s;
	int	backlog;
};
/* ARGSUSED */
listen(p, uap, retval)
	struct proc *p;
	register struct listen_args *uap;
	int *retval;
{
	struct file *fp;
	int error;

	if (error = getsock(p->p_fd, uap->s, &fp))
		return (error);
	return (solisten((struct socket *)fp->f_data, uap->backlog));
}

struct accept_args {
	int	s;
	caddr_t	name;
	int	*anamelen;
#ifdef COMPAT_OLDSOCK
	int	compat_43;	/* pseudo */
#endif
};

#ifdef COMPAT_OLDSOCK
accept(p, uap, retval)
	struct proc *p;
	struct accept_args *uap;
	int *retval;
{

	uap->compat_43 = 0;
	return (accept1(p, uap, retval));
}

oaccept(p, uap, retval)
	struct proc *p;
	struct accept_args *uap;
	int *retval;
{

	uap->compat_43 = 1;
	return (accept1(p, uap, retval));
}
#else /* COMPAT_OLDSOCK */

#define	accept1	accept
#endif

accept1(p, uap, retval)
	struct proc *p;
	register struct accept_args *uap;
	int *retval;
{
	struct file *fp;
	struct mbuf *nam;
	int namelen, error, s;
	register struct socket *so;

	if (uap->name && (error = copyin((caddr_t)uap->anamelen,
	    (caddr_t)&namelen, sizeof (namelen))))
		return (error);
	if (error = getsock(p->p_fd, uap->s, &fp))
		return (error);
	s = splnet();
	so = (struct socket *)fp->f_data;
	if ((so->so_options & SO_ACCEPTCONN) == 0) {
		splx(s);
		return (EINVAL);
	}
	if ((so->so_state & SS_NBIO) && so->so_qlen == 0) {
		splx(s);
		return (EWOULDBLOCK);
	}
	while (so->so_qlen == 0 && so->so_error == 0) {
		if (so->so_state & SS_CANTRCVMORE) {
			so->so_error = ECONNABORTED;
			break;
		}
		/*
		if (error = tsleep((caddr_t)&so->so_timeo, PSOCK | PCATCH,
		    netcon, 0)) {
			splx(s);
			return (error);
		}
		*/
	}
	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		splx(s);
		return (error);
	}
	/*
	if (error = falloc(p, &fp, retval)) {
		splx(s);
		return (error);
	}
	*/
	{ struct socket *aso = so->so_q;
	  if (soqremque(aso, 1) == 0)
		panic("accept");
	  so = aso;
	}
	fp->f_type = DTYPE_SOCKET;
	fp->f_flag = FREAD|FWRITE;
	fp->f_ops = &socketops;
	fp->f_data = (caddr_t)so;
	nam = m_get(M_WAIT, MT_SONAME);
	(void) soaccept(so, nam);
	if (uap->name) {
#ifdef COMPAT_OLDSOCK
		if (uap->compat_43)
			mtod(nam, struct osockaddr *)->sa_family =
			    mtod(nam, struct sockaddr *)->sa_family;
#endif
		if (namelen > nam->m_len)
			namelen = nam->m_len;
		/* SHOULD COPY OUT A CHAIN HERE */
		if ((error = copyout(mtod(nam, caddr_t), (caddr_t)uap->name,
		    (u_int)namelen)) == 0)
			error = copyout((caddr_t)&namelen,
			    (caddr_t)uap->anamelen, sizeof (*uap->anamelen));
	}
	m_freem(nam);
	splx(s);
	return (error);
}

struct connect_args {
	int	s;
	caddr_t	name;
	int	namelen;
};
/* ARGSUSED */
connect(p, uap, retval)
	struct proc *p;
	register struct connect_args *uap;
	int *retval;
{
	struct file *fp;
	register struct socket *so;
	struct mbuf *nam;
	int error, s;

	if (error = getsock(p->p_fd, uap->s, &fp))
		return (error);
	so = (struct socket *)fp->f_data;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING))
		return (EALREADY);
	if (error = sockargs(&nam, uap->name, uap->namelen, MT_SONAME))
		return (error);
	error = soconnect(so, nam);
	if (error)
		goto bad;
	if ((so->so_state & SS_NBIO) && (so->so_state & SS_ISCONNECTING)) {
		m_freem(nam);
		return (EINPROGRESS);
	}
	s = splnet();
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0)
		/*if (error = tsleep((caddr_t)&so->so_timeo, PSOCK | PCATCH,
		    netcon, 0)) */
			break;
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	splx(s);
bad:
	so->so_state &= ~SS_ISCONNECTING;
	m_freem(nam);
	if (error == ERESTART)
		error = EINTR;
	return (error);
}

struct socketpair_args {
	int	domain;
	int	type;
	int	protocol;
	int	*rsv;
};
socketpair(p, uap, retval)
	struct proc *p;
	register struct socketpair_args *uap;
	int retval[];
{
	register struct filedesc *fdp = p->p_fd;
	struct file *fp1, *fp2;
	struct socket *so1, *so2;
	int fd, error, sv[2];

	if (error = socreate(uap->domain, &so1, uap->type, uap->protocol))
		return (error);
	if (error = socreate(uap->domain, &so2, uap->type, uap->protocol))
		goto free1;
	
	#if 0
	if (error = falloc(p, &fp1, &fd))
		goto free2;
	#endif


	fp1 = &g_file;
	
	sv[0] = fd;
	fp1->f_flag = FREAD|FWRITE;
	fp1->f_type = DTYPE_SOCKET;
	fp1->f_ops = &socketops;
	fp1->f_data = (caddr_t)so1;


	#if 0
	
	if (error = falloc(p, &fp2, &fd))
		goto free3;

       #endif

	fp2->f_flag = FREAD|FWRITE;
	fp2->f_type = DTYPE_SOCKET;
	fp2->f_ops = &socketops;
	fp2->f_data = (caddr_t)so2;
	sv[1] = fd;
	if (error = soconnect2(so1, so2))
		goto free4;
	if (uap->type == SOCK_DGRAM) {
		/*
		 * Datagram socket connection is asymmetric.
		 */
		 if (error = soconnect2(so2, so1))
			goto free4;
	}
	error = copyout((caddr_t)sv, (caddr_t)uap->rsv, 2 * sizeof (int));
	retval[0] = sv[0];		/* XXX ??? */
	retval[1] = sv[1];		/* XXX ??? */
	return (error);
free4:
	
	fdp->fd_ofiles[sv[1]] = 0;
free3:
	
	fdp->fd_ofiles[sv[0]] = 0;
free2:
	(void)soclose(so2);
free1:
	(void)soclose(so1);
	return (error);
}

struct sendto_args {
	int	s;
	caddr_t	buf;
	size_t	len;
	int	flags;
	caddr_t	to;
	int	tolen;
};
sendto(p, uap, retval)
	struct proc *p;
	register struct sendto_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov;

	msg.msg_name = uap->to;
	msg.msg_namelen = uap->tolen;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	msg.msg_control = 0;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = 0;
#endif
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	return (sendit(p, uap->s, &msg, uap->flags, retval));
}

#ifdef COMPAT_OLDSOCK
struct osend_args {
	int	s;
	caddr_t	buf;
	int	len;
	int	flags;
};
osend(p, uap, retval)
	struct proc *p;
	register struct osend_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = 0;
	return (sendit(p, uap->s, &msg, uap->flags, retval));
}

#define MSG_COMPAT	0x8000
struct osendmsg_args {
	int	s;
	caddr_t	msg;
	int	flags;
};
osendmsg(p, uap, retval)
	struct proc *p;
	register struct osendmsg_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	if (error = copyin(uap->msg, (caddr_t)&msg, sizeof (struct omsghdr)))
		return (error);
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV)
			return (EMSGSIZE);
		MALLOC(iov, struct iovec *,
		      sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV, 
		      M_WAITOK);
	} else
		iov = aiov;
	if (error = copyin((caddr_t)msg.msg_iov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec))))
		goto done;
	msg.msg_flags = MSG_COMPAT;
	msg.msg_iov = iov;
	error = sendit(p, uap->s, &msg, uap->flags, retval);
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	return (error);
}
#endif

struct sendmsg_args {
	int	s;
	caddr_t	msg;
	int	flags;
};
sendmsg(p, uap, retval)
	struct proc *p;
	register struct sendmsg_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	if (error = copyin(uap->msg, (caddr_t)&msg, sizeof (msg)))
		return (error);
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV)
			return (EMSGSIZE);
		MALLOC(iov, struct iovec *,
		       sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		       M_WAITOK);
	} else
		iov = aiov;
	if (msg.msg_iovlen &&
	    (error = copyin((caddr_t)msg.msg_iov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec)))))
		goto done;
	msg.msg_iov = iov;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = 0;
#endif
	error = sendit(p, uap->s, &msg, uap->flags, retval);
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	return (error);
}

sendit(p, s, mp, flags, retsize)
	register struct proc *p;
	int s;
	register struct msghdr *mp;
	int flags, *retsize;
{
	struct file *fp;
	struct uio auio;
	register struct iovec *iov;
	register int i;
	struct mbuf *to, *control;
	int len, error;
#ifdef KTRACE
	struct iovec *ktriov = NULL;
#endif
	
	if (error = getsock(p->p_fd, s, &fp))
		return (error);
	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_procp = p;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
		if (iov->iov_len < 0)
			return (EINVAL);
		if ((auio.uio_resid += iov->iov_len) < 0)
			return (EINVAL);
	}
	if (mp->msg_name) {
		if (error = sockargs(&to, mp->msg_name, mp->msg_namelen,
		    MT_SONAME))
			return (error);
	} else
		to = 0;
	if (mp->msg_control) {
		if (mp->msg_controllen < sizeof(struct cmsghdr)
#ifdef COMPAT_OLDSOCK
		    && mp->msg_flags != MSG_COMPAT
#endif
		) {
			error = EINVAL;
			goto bad;
		}
		if (error = sockargs(&control, mp->msg_control,
		    mp->msg_controllen, MT_CONTROL))
			goto bad;
#ifdef COMPAT_OLDSOCK
		if (mp->msg_flags == MSG_COMPAT) {
			register struct cmsghdr *cm;

			M_PREPEND(control, sizeof(*cm), M_WAIT);
			if (control == 0) {
				error = ENOBUFS;
				goto bad;
			} else {
				cm = mtod(control, struct cmsghdr *);
				cm->cmsg_len = control->m_len;
				cm->cmsg_level = SOL_SOCKET;
				cm->cmsg_type = SCM_RIGHTS;
			}
		}
#endif
	} else
		control = 0;
#ifdef KTRACE
	if (KTRPOINT(p, KTR_GENIO)) {
		int iovlen = auio.uio_iovcnt * sizeof (struct iovec);

		MALLOC(ktriov, struct iovec *, iovlen, M_TEMP, M_WAITOK);
		bcopy((caddr_t)auio.uio_iov, (caddr_t)ktriov, iovlen);
	}
#endif
	len = auio.uio_resid;
	if (error = sosend((struct socket *)fp->f_data, to, &auio,
	    (struct mbuf *)0, control, flags)) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/*
		if (error == EPIPE)
			psignal(p, SIGPIPE);  */
	}
	if (error == 0)
		*retsize = len - auio.uio_resid;
#ifdef KTRACE
	if (ktriov != NULL) {
		if (error == 0)
			ktrgenio(p->p_tracep, s, UIO_WRITE,
				ktriov, *retsize, error);
		FREE(ktriov, M_TEMP);
	}
#endif
bad:
	if (to)
		m_freem(to);
	return (error);
}

struct recvfrom_args {
	int	s;
	caddr_t	buf;
	size_t	len;
	int	flags;
	caddr_t	from;
	int	*fromlenaddr;
};

#ifdef COMPAT_OLDSOCK
orecvfrom(p, uap, retval)
	struct proc *p;
	struct recvfrom_args *uap;
	int *retval;
{

	uap->flags |= MSG_COMPAT;
	return (recvfrom(p, uap, retval));
}
#endif

recvfrom(p, uap, retval)
	struct proc *p;
	register struct recvfrom_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov;
	int error;

	if (uap->fromlenaddr) {
		if (error = copyin((caddr_t)uap->fromlenaddr,
		    (caddr_t)&msg.msg_namelen, sizeof (msg.msg_namelen)))
			return (error);
	} else
		msg.msg_namelen = 0;
	msg.msg_name = uap->from;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = uap->flags;
	return (recvit(p, uap->s, &msg, (caddr_t)uap->fromlenaddr, retval));
}

#ifdef COMPAT_OLDSOCK
struct orecv_args {
	int	s;
	caddr_t	buf;
	int	len;
	int	flags;
};
orecv(p, uap, retval)
	struct proc *p;
	register struct orecv_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = &aiov;
	msg.msg_iovlen = 1;
	aiov.iov_base = uap->buf;
	aiov.iov_len = uap->len;
	msg.msg_control = 0;
	msg.msg_flags = uap->flags;
	return (recvit(p, uap->s, &msg, (caddr_t)0, retval));
}

/*
 * Old recvmsg.  This code takes advantage of the fact that the old msghdr
 * overlays the new one, missing only the flags, and with the (old) access
 * rights where the control fields are now.
 */
struct orecvmsg_args {
	int	s;
	struct	omsghdr *msg;
	int	flags;
};
orecvmsg(p, uap, retval)
	struct proc *p;
	register struct orecvmsg_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *iov;
	int error;

	if (error = copyin((caddr_t)uap->msg, (caddr_t)&msg,
	    sizeof (struct omsghdr)))
		return (error);
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV)
			return (EMSGSIZE);
		MALLOC(iov, struct iovec *,
		      sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		      M_WAITOK);
	} else
		iov = aiov;
	msg.msg_flags = uap->flags | MSG_COMPAT;
	if (error = copyin((caddr_t)msg.msg_iov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec))))
		goto done;
	msg.msg_iov = iov;
	error = recvit(p, uap->s, &msg, (caddr_t)&uap->msg->msg_namelen, retval);

	if (msg.msg_controllen && error == 0)
		error = copyout((caddr_t)&msg.msg_controllen,
		    (caddr_t)&uap->msg->msg_accrightslen, sizeof (int));
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	return (error);
}
#endif

struct recvmsg_args {
	int	s;
	struct	msghdr *msg;
	int	flags;
};
recvmsg(p, uap, retval)
	struct proc *p;
	register struct recvmsg_args *uap;
	int *retval;
{
	struct msghdr msg;
	struct iovec aiov[UIO_SMALLIOV], *uiov, *iov;
	register int error;

	if (error = copyin((caddr_t)uap->msg, (caddr_t)&msg, sizeof (msg)))
		return (error);
	if ((u_int)msg.msg_iovlen >= UIO_SMALLIOV) {
		if ((u_int)msg.msg_iovlen >= UIO_MAXIOV)
			return (EMSGSIZE);
		MALLOC(iov, struct iovec *,
		       sizeof(struct iovec) * (u_int)msg.msg_iovlen, M_IOV,
		       M_WAITOK);
	} else
		iov = aiov;
#ifdef COMPAT_OLDSOCK
	msg.msg_flags = uap->flags &~ MSG_COMPAT;
#else
	msg.msg_flags = uap->flags;
#endif
	uiov = msg.msg_iov;
	msg.msg_iov = iov;
	if (error = copyin((caddr_t)uiov, (caddr_t)iov,
	    (unsigned)(msg.msg_iovlen * sizeof (struct iovec))))
		goto done;
	if ((error = recvit(p, uap->s, &msg, (caddr_t)0, retval)) == 0) {
		msg.msg_iov = uiov;
		error = copyout((caddr_t)&msg, (caddr_t)uap->msg, sizeof(msg));
	}
done:
	if (iov != aiov)
		FREE(iov, M_IOV);
	return (error);
}

recvit(p, s, mp, namelenp, retsize)
	register struct proc *p;
	int s;
	register struct msghdr *mp;
	caddr_t namelenp;
	int *retsize;
{
	struct file *fp;
	struct uio auio;
	register struct iovec *iov;
	register int i;
	int len, error;
	struct mbuf *from = 0, *control = 0;
#ifdef KTRACE
	struct iovec *ktriov = NULL;
#endif
	
	if (error = getsock(p->p_fd, s, &fp))
		return (error);
	auio.uio_iov = mp->msg_iov;
	auio.uio_iovcnt = mp->msg_iovlen;
	auio.uio_segflg = UIO_USERSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_procp = p;
	auio.uio_offset = 0;			/* XXX */
	auio.uio_resid = 0;
	iov = mp->msg_iov;
	for (i = 0; i < mp->msg_iovlen; i++, iov++) {
		if (iov->iov_len < 0)
			return (EINVAL);
		if ((auio.uio_resid += iov->iov_len) < 0)
			return (EINVAL);
	}
#ifdef KTRACE
	if (KTRPOINT(p, KTR_GENIO)) {
		int iovlen = auio.uio_iovcnt * sizeof (struct iovec);

		MALLOC(ktriov, struct iovec *, iovlen, M_TEMP, M_WAITOK);
		bcopy((caddr_t)auio.uio_iov, (caddr_t)ktriov, iovlen);
	}
#endif
	len = auio.uio_resid;
	if (error = soreceive((struct socket *)fp->f_data, &from, &auio,
	    (struct mbuf **)0, mp->msg_control ? &control : (struct mbuf **)0,
	    &mp->msg_flags)) {
		if (auio.uio_resid != len && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
#ifdef KTRACE
	if (ktriov != NULL) {
		if (error == 0)
			ktrgenio(p->p_tracep, s, UIO_READ,
				ktriov, len - auio.uio_resid, error);
		FREE(ktriov, M_TEMP);
	}
#endif
	if (error)
		goto out;
	*retsize = len - auio.uio_resid;
	if (mp->msg_name) {
		len = mp->msg_namelen;
		if (len <= 0 || from == 0)
			len = 0;
		else {
#ifdef COMPAT_OLDSOCK
			if (mp->msg_flags & MSG_COMPAT)
				mtod(from, struct osockaddr *)->sa_family =
				    mtod(from, struct sockaddr *)->sa_family;
#endif
			if (len > from->m_len)
				len = from->m_len;
			/* else if len < from->m_len ??? */
			if (error = copyout(mtod(from, caddr_t),
			    (caddr_t)mp->msg_name, (unsigned)len))
				goto out;
		}
		mp->msg_namelen = len;
		if (namelenp &&
		    (error = copyout((caddr_t)&len, namelenp, sizeof (int)))) {
#ifdef COMPAT_OLDSOCK
			if (mp->msg_flags & MSG_COMPAT)
				error = 0;	/* old recvfrom didn't check */
			else
#endif
			goto out;
		}
	}
	if (mp->msg_control) {
#ifdef COMPAT_OLDSOCK
		/*
		 * We assume that old recvmsg calls won't receive access
		 * rights and other control info, esp. as control info
		 * is always optional and those options didn't exist in 4.3.
		 * If we receive rights, trim the cmsghdr; anything else
		 * is tossed.
		 */
		if (control && mp->msg_flags & MSG_COMPAT) {
			if (mtod(control, struct cmsghdr *)->cmsg_level !=
			    SOL_SOCKET ||
			    mtod(control, struct cmsghdr *)->cmsg_type !=
			    SCM_RIGHTS) {
				mp->msg_controllen = 0;
				goto out;
			}
			control->m_len -= sizeof (struct cmsghdr);
			control->m_data += sizeof (struct cmsghdr);
		}
#endif
		len = mp->msg_controllen;
		if (len <= 0 || control == 0)
			len = 0;
		else {
			if (len >= control->m_len)
				len = control->m_len;
			else
				mp->msg_flags |= MSG_CTRUNC;
			error = copyout((caddr_t)mtod(control, caddr_t),
			    (caddr_t)mp->msg_control, (unsigned)len);
		}
		mp->msg_controllen = len;
	}
out:
	if (from)
		m_freem(from);
	if (control)
		m_freem(control);
	return (error);
}

struct shutdown_args {
	int	s;
	int	how;
};
/* ARGSUSED */
shutdown(p, uap, retval)
	struct proc *p;
	register struct shutdown_args *uap;
	int *retval;
{
	struct file *fp;
	int error;

	if (error = getsock(p->p_fd, uap->s, &fp))
		return (error);
	return (soshutdown((struct socket *)fp->f_data, uap->how));
}

struct setsockopt_args {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	valsize;
};
/* ARGSUSED */
setsockopt(p, uap, retval)
	struct proc *p;
	register struct setsockopt_args *uap;
	int *retval;
{
	struct file *fp;
	struct mbuf *m = NULL;
	int error;

	if (error = getsock(p->p_fd, uap->s, &fp))
		return (error);
	if (uap->valsize > MLEN)
		return (EINVAL);
	if (uap->val) {
		m = m_get(M_WAIT, MT_SOOPTS);
		if (m == NULL)
			return (ENOBUFS);
		if (error = copyin(uap->val, mtod(m, caddr_t),
		    (u_int)uap->valsize)) {
			(void) m_free(m);
			return (error);
		}
		m->m_len = uap->valsize;
	}
	return (sosetopt((struct socket *)fp->f_data, uap->level,
	    uap->name, m));
}

struct getsockopt_args {
	int	s;
	int	level;
	int	name;
	caddr_t	val;
	int	*avalsize;
};
/* ARGSUSED */
getsockopt(p, uap, retval)
	struct proc *p;
	register struct getsockopt_args *uap;
	int *retval;
{
	struct file *fp;
	struct mbuf *m = NULL;
	int valsize, error;

	if (error = getsock(p->p_fd, uap->s, &fp))
		return (error);
	if (uap->val) {
		if (error = copyin((caddr_t)uap->avalsize, (caddr_t)&valsize,
		    sizeof (valsize)))
			return (error);
	} else
		valsize = 0;
	if ((error = sogetopt((struct socket *)fp->f_data, uap->level,
	    uap->name, &m)) == 0 && uap->val && valsize && m != NULL) {
		if (valsize > m->m_len)
			valsize = m->m_len;
		error = copyout(mtod(m, caddr_t), uap->val, (u_int)valsize);
		if (error == 0)
			error = copyout((caddr_t)&valsize,
			    (caddr_t)uap->avalsize, sizeof (valsize));
	}
	if (m != NULL)
		(void) m_free(m);
	return (error);
}

#if 0

struct pipe_args {
	int	dummy;
};
/* ARGSUSED */
pipe(p, uap, retval)
	struct proc *p;
	struct pipe_args *uap;
	int retval[];
{
	register struct filedesc *fdp = p->p_fd;
	struct file *rf, *wf;
	struct socket *rso, *wso;
	int fd, error;

	if (error = socreate(AF_UNIX, &rso, SOCK_STREAM, 0))
		return (error);
	if (error = socreate(AF_UNIX, &wso, SOCK_STREAM, 0))
		goto free1;
	if (error = falloc(p, &rf, &fd))
		goto free2;
	retval[0] = fd;
	rf->f_flag = FREAD;
	rf->f_type = DTYPE_SOCKET;
	rf->f_ops = &socketops;
	rf->f_data = (caddr_t)rso;
	if (error = falloc(p, &wf, &fd))
		goto free3;
	wf->f_flag = FWRITE;
	wf->f_type = DTYPE_SOCKET;
	wf->f_ops = &socketops;
	wf->f_data = (caddr_t)wso;
	retval[1] = fd;
	if (error = unp_connect2(wso, rso))
		goto free4;
	return (0);
free4:
	ffree(wf);
	fdp->fd_ofiles[retval[1]] = 0;
free3:
	ffree(rf);
	fdp->fd_ofiles[retval[0]] = 0;
free2:
	(void)soclose(wso);
free1:
	(void)soclose(rso);
	return (error);
}
#endif

/*
 * Get socket name.
 */
struct getsockname_args {
	int	fdes;
	caddr_t	asa;
	int	*alen;
#ifdef COMPAT_OLDSOCK
	int	compat_43;	/* pseudo */
#endif
};
#ifdef COMPAT_OLDSOCK
getsockname(p, uap, retval)
	struct proc *p;
	struct getsockname_args *uap;
	int *retval;
{

	uap->compat_43 = 0;
	return (getsockname1(p, uap, retval));
}

ogetsockname(p, uap, retval)
	struct proc *p;
	struct getsockname_args *uap;
	int *retval;
{

	uap->compat_43 = 1;
	return (getsockname1(p, uap, retval));
}
#else /* COMPAT_OLDSOCK */

#define	getsockname1	getsockname
#endif

/* ARGSUSED */
getsockname1(p, uap, retval)
	struct proc *p;
	register struct getsockname_args *uap;
	int *retval;
{
	struct file *fp;
	register struct socket *so;
	struct mbuf *m;
	int len, error;

	if (error = getsock(p->p_fd, uap->fdes, &fp))
		return (error);
	if (error = copyin((caddr_t)uap->alen, (caddr_t)&len, sizeof (len)))
		return (error);
	so = (struct socket *)fp->f_data;
	m = m_getclr(M_WAIT, MT_SONAME);
	if (m == NULL)
		return (ENOBUFS);
	if (error = (*so->so_proto->pr_usrreq)(so, PRU_SOCKADDR, 0, m, 0))
		goto bad;
	if (len > m->m_len)
		len = m->m_len;
#ifdef COMPAT_OLDSOCK
	if (uap->compat_43)
		mtod(m, struct osockaddr *)->sa_family =
		    mtod(m, struct sockaddr *)->sa_family;
#endif
	error = copyout(mtod(m, caddr_t), (caddr_t)uap->asa, (u_int)len);
	if (error == 0)
		error = copyout((caddr_t)&len, (caddr_t)uap->alen,
		    sizeof (len));
bad:
	m_freem(m);
	return (error);
}

/*
 * Get name of peer for connected socket.
 */
struct getpeername_args {
	int	fdes;
	caddr_t	asa;
	int	*alen;
#ifdef COMPAT_OLDSOCK
	int	compat_43;	/* pseudo */
#endif
};

#ifdef COMPAT_OLDSOCK
getpeername(p, uap, retval)
	struct proc *p;
	struct getpeername_args *uap;
	int *retval;
{

	uap->compat_43 = 0;
	return (getpeername1(p, uap, retval));
}

ogetpeername(p, uap, retval)
	struct proc *p;
	struct getpeername_args *uap;
	int *retval;
{

	uap->compat_43 = 1;
	return (getpeername1(p, uap, retval));
}
#else /* COMPAT_OLDSOCK */

#define	getpeername1	getpeername
#endif

/* ARGSUSED */
getpeername1(p, uap, retval)
	struct proc *p;
	register struct getpeername_args *uap;
	int *retval;
{
	struct file *fp;
	register struct socket *so;
	struct mbuf *m;
	int len, error;

	if (error = getsock(p->p_fd, uap->fdes, &fp))
		return (error);
	so = (struct socket *)fp->f_data;
	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONFIRMING)) == 0)
		return (ENOTCONN);
	if (error = copyin((caddr_t)uap->alen, (caddr_t)&len, sizeof (len)))
		return (error);
	m = m_getclr(M_WAIT, MT_SONAME);
	if (m == NULL)
		return (ENOBUFS);
	if (error = (*so->so_proto->pr_usrreq)(so, PRU_PEERADDR, 0, m, 0))
		goto bad;
	if (len > m->m_len)
		len = m->m_len;
#ifdef COMPAT_OLDSOCK
	if (uap->compat_43)
		mtod(m, struct osockaddr *)->sa_family =
		    mtod(m, struct sockaddr *)->sa_family;
#endif
	if (error = copyout(mtod(m, caddr_t), (caddr_t)uap->asa, (u_int)len))
		goto bad;
	error = copyout((caddr_t)&len, (caddr_t)uap->alen, sizeof (len));
bad:
	m_freem(m);
	return (error);
}

sockargs(mp, buf, buflen, type)
	struct mbuf **mp;
	caddr_t buf;
	int buflen, type;
{
	register struct sockaddr *sa;
	register struct mbuf *m;
	int error;

	if ((u_int)buflen > MLEN) {
#ifdef COMPAT_OLDSOCK
		if (type == MT_SONAME && (u_int)buflen <= 112)
			buflen = MLEN;		/* unix domain compat. hack */
		else
#endif
		return (EINVAL);
	}
	m = m_get(M_WAIT, type);
	if (m == NULL)
		return (ENOBUFS);
	m->m_len = buflen;
	error = copyin(buf, mtod(m, caddr_t), (u_int)buflen);
	if (error)
		(void) m_free(m);
	else {
		*mp = m;
		if (type == MT_SONAME) {
			sa = mtod(m, struct sockaddr *);

#if defined(COMPAT_OLDSOCK) && BYTE_ORDER != BIG_ENDIAN
			if (sa->sa_family == 0 && sa->sa_len < AF_MAX)
				sa->sa_family = sa->sa_len;
#endif
			sa->sa_len = buflen;
		}
	}
	return (error);
}

getsock(fdp, fdes, fpp)
	struct filedesc *fdp;
	int fdes;
	struct file **fpp;
{
	register struct file *fp;

	if ((unsigned)fdes >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[fdes]) == NULL)
		return (EBADF);
	if (fp->f_type != DTYPE_SOCKET)
		return (ENOTSOCK);
	*fpp = fp;
	return (0);
}


unsigned long
inet_addr(cp)
register char   *cp;
{
	unsigned long val, base, n;
	register char c;
	unsigned long octet[4], *octetptr = octet;
#ifndef htonl
	extern  unsigned long   htonl();
#endif  /* htonl */
again:
	/*
	 * Collect number up to ``.''.
	 * Values are specified as for C:
	 * 0x=hex, 0=octal, other=decimal.
	 */
	val = 0; base = 10;
	if (*cp == '0')
		base = 8, cp++;
	if (*cp == 'x' || *cp == 'X')
		base = 16, cp++;
	while (c = *cp) {
		if (isdigit(c)) {
			val = (val * base) + (c - '0');
			cp++;
			continue;
		}
		if (base == 16 && isxdigit(c)) {
			val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
			cp++;
			continue;
		}
		break;
	}
	if (*cp == '.') {
		/*
		 * Internet format:
		 *      a.b.c.d
		 *      a.b.c   (with c treated as 16-bits)
		 *      a.b     (with b treated as 24 bits)
		 */
		if (octetptr >= octet + 4)
			return (-1);
		*octetptr++ = val, cp++;
		goto again;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && !isspace(*cp))
		return (-1);
	*octetptr++ = val;
	/*
	 * Concoct the address according to
	 * the number of octet specified.
	 */
	n = octetptr - octet;
	switch (n) {

	case 1:                         /* a -- 32 bits */
		val = octet[0];
		break;

	case 2:                         /* a.b -- 8.24 bits */
		val = (octet[0] << 24) | (octet[1] & 0xffffff);
		break;

	case 3:                         /* a.b.c -- 8.8.16 bits */
		val = (octet[0] << 24) | ((octet[1] & 0xff) << 16) |
			(octet[2] & 0xffff);
		break;

	case 4:                         /* a.b.c.d -- 8.8.8.8 bits */
		val = (octet[0] << 24) | ((octet[1] & 0xff) << 16) |
		      ((octet[2] & 0xff) << 8) | (octet[3] & 0xff);
		break;

	default:
		return (-1);
	}
	val = htonl(val);
	return (val);
}


 struct proc   my_proc; 


void test_raw_sock()
{

   struct icmp *icp=NULL;
    int          ch=0;
  int                   result=0;
  u_char                packet[1024];
  struct timeval        sent;
 

   int      retval;
   struct   socket_args		l_data;
  
   struct   bind_args		l_bind_data;
   struct   sendto_args		l_send_data;

   struct   sockaddr_in		my_addr, to_addr;

   struct   plimit			my_limit;
   struct   filedesc			my_fdp;

   struct    rt_msghdr          rt_msg;

/* pre-condition */  
  my_limit.pl_rlimit[RLIMIT_NOFILE].rlim_cur = 100; 
  my_proc.p_limit  = &my_limit;

  memset(&my_fdp, 0, sizeof(struct filedesc));
  my_proc.p_fd  = &my_fdp; 

/* create socket */  

  memset(&my_addr, 0, sizeof(struct sockaddr_in));
  memset(&to_addr, 0, sizeof(struct sockaddr_in));
  
  memset(&l_data, 0, sizeof(struct socket_args));
  memset(&l_bind_data, 0, sizeof(struct bind_args));
  memset(&l_send_data, 0, sizeof(struct sendto_args));
  
  l_data.domain   = AF_INET;
  l_data.protocol  = IPPROTO_ICMP;
  l_data.type       =  SOCK_RAW; 

  socket(&my_proc,  &l_data,  &retval);

  /* create and send a single ping */
  icp = (struct icmp *)packet;
  icp->icmp_type = (u_char)ICMP_ECHO;
  icp->icmp_code = (u_char)0;
  icp->icmp_cksum = 0;
  icp->icmp_seq = 0;
  icp->icmp_id = (n_short) 0;

  /* compute ICMP checksum */
  ch = 64;
  icp->icmp_cksum = in_cksum((u_short *)icp, ch);
 //(void) gettimeofday(&sent, NULL);

/* sendto data */  

  to_addr.sin_family  =  AF_INET;
  to_addr.sin_port    =  htons(4000);
  to_addr.sin_addr.s_addr = inet_addr("140.252.13.33");
 	
  l_send_data.s      =   retval;
  l_send_data.buf    =   &rt_msg	;
  l_send_data.len    =   sizeof(struct rt_msghdr);
  l_send_data.to     =   &to_addr	;
  l_send_data.tolen  =   sizeof(struct sockaddr_in);
   
  sendto(&my_proc,  &l_send_data,  &retval);


}


struct rtSocketMsg_t{
   struct    rt_msghdr          rt_msg;
   char       appendBuf [512];      
} ;

struct rtSocketMsg_t rtSocketMsg;


struct sockaddr_in test_mask = { sizeof (struct sockaddr_in), AF_INET };
struct sockaddr_in test_dst = { sizeof (struct sockaddr_in), AF_INET };
struct sockaddr_in test_gw = { sizeof (struct sockaddr_in), AF_INET };


void fake_route_record()
{
  
   test_dst.sin_addr.s_addr =   0x04030201;
   test_gw.sin_addr.s_addr =   0x220dfc8c;
   test_mask.sin_addr.s_addr = 0x200dfc8c;   

   return;
}


void fake_rt_socketMsg()
{

/*35969260*/
  rtSocketMsg.rt_msg.rtm_version = RTM_VERSION;
  rtSocketMsg.rt_msg.rtm_type = RTM_ADD;
  rtSocketMsg.rt_msg.rtm_flags = RTF_DONE | RTF_GATEWAY | RTF_HOST;
  rtSocketMsg.rt_msg.rtm_errno = 0;
  rtSocketMsg.rt_msg.rtm_addrs = 7;
  rtSocketMsg.rt_msg.rtm_msglen = sizeof(struct rt_msghdr) + 3*sizeof(struct sockaddr_in);

  memcpy(rtSocketMsg.appendBuf, &test_dst, sizeof(struct sockaddr_in));
  memcpy(rtSocketMsg.appendBuf+sizeof(struct sockaddr_in), &test_gw, sizeof(struct sockaddr_in));
  memcpy(rtSocketMsg.appendBuf+2*sizeof(struct sockaddr_in), &test_mask, sizeof(struct sockaddr_in));  

/**/
}




void test_add_route_r()
{

   struct mbuf *m;
   
   	
   int      retval;
   struct   socket_args		l_data;
  
   struct   bind_args		l_bind_data;
   struct   sendto_args		l_send_data;

   struct   sockaddr_in		my_addr, to_addr;

   struct   plimit			my_limit;
   struct   filedesc			my_fdp;

           

/* pre-condition */  
  my_limit.pl_rlimit[RLIMIT_NOFILE].rlim_cur = 100; 
  my_proc.p_limit  = &my_limit;

  memset(&my_fdp, 0, sizeof(struct filedesc));
  my_proc.p_fd  = &my_fdp; 

/* create socket */  

  memset(&my_addr, 0, sizeof(struct sockaddr_in));
  memset(&to_addr, 0, sizeof(struct sockaddr_in));
  
  memset(&l_data, 0, sizeof(struct socket_args));
  memset(&l_bind_data, 0, sizeof(struct bind_args));
  memset(&l_send_data, 0, sizeof(struct sendto_args));
  
  l_data.domain   = PF_ROUTE;
  l_data.protocol  = 0;
  l_data.type       =  SOCK_RAW; 

  socket(&my_proc,  &l_data,  &retval);

/* sendto data */  
  fake_route_record();
  fake_rt_socketMsg();
 	
  l_send_data.s      =   retval;
  
  l_send_data.buf    =  &rtSocketMsg ;
  l_send_data.len    =   rtSocketMsg.rt_msg.rtm_msglen ;
   
  l_send_data.to     =  NULL; 
  l_send_data.tolen  =   sizeof(struct sockaddr_in);
   
  sendto(&my_proc,  &l_send_data,  &retval);


}

 
void  send_data_via_sock_r()
{ 
	
  /*  struct proc   my_proc; 
  */
  int      retval;
  struct   socket_args		l_data;
  
  struct   bind_args			l_bind_data;
  struct   sendto_args		l_send_data;

  struct   sockaddr_in		my_addr, to_addr;

  struct   plimit					my_limit;
  struct   filedesc				my_fdp;

/* pre-condition */  
  my_limit.pl_rlimit[RLIMIT_NOFILE].rlim_cur = 100; 
  my_proc.p_limit  = &my_limit;

  memset(&my_fdp, 0, sizeof(struct filedesc));
  my_proc.p_fd  = &my_fdp; 

/* create socket */  

  memset(&my_addr, 0, sizeof(struct sockaddr_in));
  memset(&to_addr, 0, sizeof(struct sockaddr_in));
  
  memset(&l_data, 0, sizeof(struct socket_args));
  memset(&l_bind_data, 0, sizeof(struct bind_args));
  memset(&l_send_data, 0, sizeof(struct sendto_args));
  
  l_data.domain   = AF_INET;
  l_data.protocol  = 0;
  l_data.type       =  SOCK_DGRAM; 

  socket(&my_proc,  &l_data,  &retval);

/* bind socket */  

  my_addr.sin_family  =  AF_INET;
  my_addr.sin_port    =  htons(5000);
  my_addr.sin_addr.s_addr = inet_addr("140.252.1.29");
//  my_addr.sin_addr.s_addr = inet_addr("140.252.13.33");

  l_bind_data.s       =   retval;
  l_bind_data.name    =   &my_addr	;
  l_bind_data.namelen =   sizeof(struct sockaddr_in);
	
  bind(&my_proc,  &l_bind_data,  &retval);

/* sendto data */  

  to_addr.sin_family  =  AF_INET;
  to_addr.sin_port    =  htons(4000);
   to_addr.sin_addr.s_addr = inet_addr("1.2.3.4");
 // to_addr.sin_addr.s_addr = inet_addr("140.252.13.33");
  	
  l_send_data.s      =   retval;
  l_send_data.buf    =   &l_send_data	;
  l_send_data.len    =   sizeof(struct sendto_args);
  l_send_data.to     =   &to_addr	;
  l_send_data.tolen  =   sizeof(struct sockaddr_in);
   
  sendto(&my_proc,  &l_send_data,  &retval);
   
	return ;
};