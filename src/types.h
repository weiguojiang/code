
#ifndef _SYS_TYPES_H_
#define	_SYS_TYPES_H_

/* Machine type dependent parameters. */




typedef	unsigned char	u_char;
typedef	unsigned short	u_short;
typedef	unsigned int	u_int;
typedef	unsigned long	u_long;
typedef	unsigned short	ushort;		/* Sys V compatibility */
typedef	unsigned int	uint;		/* Sys V compatibility */

typedef	unsigned char	u_int8_t;
typedef	unsigned short	u_int16_t;
typedef	unsigned int 	u_int32_t;
typedef	unsigned  /* long */ long u_quad_t;	/* quads */
typedef /* long */ long	quad_t;
typedef	quad_t *	qaddr_t;

typedef	char *		caddr_t;	/* core address */
typedef	long		daddr_t;	/* disk address */
typedef	unsigned long	dev_t;		/* device number */
typedef unsigned long	fixpt_t;	/* fixed point number */
typedef	unsigned long	gid_t;		/* group id */
typedef	unsigned long	ino_t;		/* inode number */
typedef	unsigned short	mode_t;		/* permissions */
typedef	unsigned short	nlink_t;	/* link count */
typedef	quad_t		off_t;		/* file offset */
typedef	long		pid_t;		/* process id */
typedef	long		segsz_t;	/* segment size */
typedef	long		swblk_t;	/* swap offset */
typedef	unsigned long	uid_t;		/* user id */

#define	major(x)	((int)(((u_int)(x) >> 8)&0xff))	/* major number */
#define	minor(x)	((int)((x)&0xff))		/* minor number */
#define	makedev(x,y)	((dev_t)(((x)<<8) | (y)))	/* create dev_t */

typedef	int	clock_t;
typedef	int	size_t;
typedef	int	ssize_t;
typedef	int	time_t;

#define	NBBY	8		/* number of bits in a byte */

#define	FD_SETSIZE	256

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	howmany(x, y)	(((x)+((y)-1))/(y))

typedef	struct fd_set {
	fd_mask	fds_bits[howmany(FD_SETSIZE, NFDBITS)];
} fd_set;

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define	FD_COPY(f, t)	bcopy(f, t, sizeof(*(f)))
#define	FD_ZERO(p)	bzero(p, sizeof(*(p)))

#define NULL 0

#endif /* !_SYS_TYPES_H_ */
