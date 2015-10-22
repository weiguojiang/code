
#include "generic.h"
#include "in_pcb.h"

/*
 * Allocate a file descriptor for the process.
 */
int fdexpand;

int maxfiles =  100; 

int nfiles = 0;             /* actual number of open files */

struct file *filehead;	/* head of list of open files */
 	

fdalloc(p, want, result)
	struct proc *p;
	int want;
	int *result;
{
	register struct filedesc *fdp = p->p_fd;
	register int i;
	int lim, last, nfiles;
	struct file **newofile;
	char *newofileflags;

	/*
	 * Search for a free descriptor starting at the higher
	 * of want or fd_freefile.  If that fails, consider
	 * expanding the ofile array.
	 */
	lim = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	for (;;) {
		last = min(fdp->fd_nfiles, lim);
		if ((i = want) < fdp->fd_freefile)
			i = fdp->fd_freefile;
		for (; i < last; i++) {
			if (fdp->fd_ofiles[i] == NULL) {
				fdp->fd_ofileflags[i] = 0;
				if (i > fdp->fd_lastfile)
					fdp->fd_lastfile = i;
				if (want <= fdp->fd_freefile)
					fdp->fd_freefile = i;
				*result = i;
				return (0);
			}
		}

		/*
		 * No space in current array.  Expand?
		 */
		if (fdp->fd_nfiles >= lim)
			return (EMFILE);
		if (fdp->fd_nfiles < NDEXTENT)
			nfiles = NDEXTENT;
		else
			nfiles = 2 * fdp->fd_nfiles;
		MALLOC(newofile, struct file **, nfiles * OFILESIZE,
		    M_FILEDESC, M_WAITOK);
		newofileflags = (char *) &newofile[nfiles];
		/*
		 * Copy the existing ofile and ofileflags arrays
		 * and zero the new portion of each array.
		 */
		bcopy(fdp->fd_ofiles, newofile,
			(i = sizeof(struct file *) * fdp->fd_nfiles));
		bzero((char *)newofile + i, nfiles * sizeof(struct file *) - i);
		bcopy(fdp->fd_ofileflags, newofileflags,
			(i = sizeof(char) * fdp->fd_nfiles));
		bzero(newofileflags + i, nfiles * sizeof(char) - i);
		if (fdp->fd_nfiles > NDFILE)
			FREE(fdp->fd_ofiles, M_FILEDESC);
		fdp->fd_ofiles = newofile;
		fdp->fd_ofileflags = newofileflags;
		fdp->fd_nfiles = nfiles;
		fdexpand++;
	}
}

/*
 * Check to see whether n user file descriptors
 * are available to the process p.
 */
fdavail(p, n)
	struct proc *p;
	register int n;
{
	register struct filedesc *fdp = p->p_fd;
	register struct file **fpp;
	register int i, lim;

	lim = min((int)p->p_rlimit[RLIMIT_NOFILE].rlim_cur, maxfiles);
	if ((i = lim - fdp->fd_nfiles) > 0 && (n -= i) <= 0)
		return (1);
	fpp = &fdp->fd_ofiles[fdp->fd_freefile];
	for (i = fdp->fd_nfiles - fdp->fd_freefile; --i >= 0; fpp++)
		if (*fpp == NULL && --n <= 0)
			return (1);
	return (0);
}

/*
 * Create a new open file structure and allocate
 * a file decriptor for the process that refers to it.
 */
falloc(p, resultfp, resultfd)
	register struct proc *p;
	struct file **resultfp;
	int *resultfd;
{
	register struct file *fp, *fq, **fpp;
	int error, i;

	if (error = fdalloc(p, 0, &i))
		return (error);
	if (nfiles >= maxfiles) {
		return (ENFILE);
	}
	/*
	 * Allocate a new file descriptor.
	 * If the process has file descriptor zero open, add to the list
	 * of open files at that point, otherwise put it at the front of
	 * the list of open files.
	 */
	nfiles++;
	MALLOC(fp, struct file *, sizeof(struct file), M_FILE, M_WAITOK);
	bzero(fp, sizeof(struct file));
	if (fq = p->p_fd->fd_ofiles[0])
		fpp = &fq->f_filef;
	else
		fpp = &filehead;
	p->p_fd->fd_ofiles[i] = fp;
	if (fq = *fpp)
		fq->f_fileb = &fp->f_filef;
	fp->f_filef = fq;
	fp->f_fileb = fpp;
	*fpp = fp;
	fp->f_count = 1;
	/*
	fp->f_cred = p->p_ucred;
      */
	if (resultfp)
		*resultfp = fp;
	if (resultfd)
		*resultfd = i;
	return (0);
}

/*
 * Free a file descriptor.
 */
 crfree(cr)
	struct ucred *cr;
{
	int s;

	if (--cr->cr_ref == 0)
		FREE((caddr_t)cr, M_CRED);

}

ffree(fp)
	register struct file *fp;
{
	register struct file *fq;

	if (fq = fp->f_filef)
		fq->f_fileb = fp->f_fileb;
	*fp->f_fileb = fq;
	crfree(fp->f_cred);
#ifdef DIAGNOSTIC
	fp->f_filef = NULL;
	fp->f_fileb = NULL;
	fp->f_count = 0;
#endif
	nfiles--;
	FREE(fp, M_FILE);
}

/*
 * Copy a filedesc structure.
 */
struct filedesc *
fdcopy(p)
	struct proc *p;
{
	register struct filedesc *newfdp, *fdp = p->p_fd;
	register struct file **fpp;
	register int i;

#if 0
	MALLOC(newfdp, struct filedesc *, sizeof(struct filedesc0),
	    M_FILEDESC, M_WAITOK);
	bcopy(fdp, newfdp, sizeof(struct filedesc));
	VREF(newfdp->fd_cdir);
	if (newfdp->fd_rdir)
		VREF(newfdp->fd_rdir);
	newfdp->fd_refcnt = 1;

	/*
	 * If the number of open files fits in the internal arrays
	 * of the open file structure, use them, otherwise allocate
	 * additional memory for the number of descriptors currently
	 * in use.
	 */
	if (newfdp->fd_lastfile < NDFILE) {
		newfdp->fd_ofiles = ((struct filedesc0 *) newfdp)->fd_dfiles;
		newfdp->fd_ofileflags =
		    ((struct filedesc0 *) newfdp)->fd_dfileflags;
		i = NDFILE;
	} else {
		/*
		 * Compute the smallest multiple of NDEXTENT needed
		 * for the file descriptors currently in use,
		 * allowing the table to shrink.
		 */
		i = newfdp->fd_nfiles;
		while (i > 2 * NDEXTENT && i > newfdp->fd_lastfile * 2)
			i /= 2;
		MALLOC(newfdp->fd_ofiles, struct file **, i * OFILESIZE,
		    M_FILEDESC, M_WAITOK);
		newfdp->fd_ofileflags = (char *) &newfdp->fd_ofiles[i];
	}
	newfdp->fd_nfiles = i;
	bcopy(fdp->fd_ofiles, newfdp->fd_ofiles, i * sizeof(struct file **));
	bcopy(fdp->fd_ofileflags, newfdp->fd_ofileflags, i * sizeof(char));
	fpp = newfdp->fd_ofiles;
	for (i = newfdp->fd_lastfile; i-- >= 0; fpp++)
		if (*fpp != NULL)
			(*fpp)->f_count++;
#endif		
	return (newfdp);
}

/*
 * Release a filedesc structure.
 */
void
fdfree(p)
	struct proc *p;
{
	register struct filedesc *fdp = p->p_fd;
	struct file **fpp;
	register int i;

	if (--fdp->fd_refcnt > 0)
		return;
#if 0	
	fpp = fdp->fd_ofiles;
	for (i = fdp->fd_lastfile; i-- >= 0; fpp++)
		if (*fpp)
			(void) closef(*fpp, p);
	if (fdp->fd_nfiles > NDFILE)
		FREE(fdp->fd_ofiles, M_FILEDESC);
	vrele(fdp->fd_cdir);
	if (fdp->fd_rdir)
		vrele(fdp->fd_rdir);
	FREE(fdp, M_FILEDESC);
#endif
}
