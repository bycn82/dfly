/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * @(#)wsetup.c	8.1 (Berkeley) 6/4/93
 * $FreeBSD: src/lib/libc/stdio/wsetup.c,v 1.11 2009/01/08 06:38:06 das Exp $
 * $DragonFly: src/lib/libc/stdio/wsetup.c,v 1.5 2005/07/23 20:23:06 joerg Exp $
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "local.h"
#include "priv_stdio.h"

/*
 * Various output routines call wsetup to be sure it is safe to write,
 * because either _flags does not include __SWR, or _buf is NULL.
 * _wsetup returns 0 if OK to write; otherwise, it returns EOF and sets errno.
 */
int
__swsetup(FILE *fp)
{
	/* make sure stdio is set up */
	if (!__sdidinit)
		__sinit();

	/*
	 * If we are not writing, we had better be reading and writing.
	 */
	if ((fp->pub._flags & __SWR) == 0) {
		if ((fp->pub._flags & __SRW) == 0) {
			errno = EBADF;
			fp->pub._flags |= __SERR;
			return (EOF);
		}
		if (fp->pub._flags & __SRD) {
			/* clobber any ungetc data */
			if (HASUB(fp))
				FREEUB(fp);
			fp->pub._flags &= ~(__SRD|__SEOF);
			fp->pub._r = 0;
			fp->pub._p = fp->_bf._base;
		}
		fp->pub._flags |= __SWR;
	}

	/*
	 * Make a buffer if necessary, then set _w.
	 */
	if (fp->_bf._base == NULL)
		__smakebuf(fp);
	if (fp->pub._flags & __SLBF) {
		/*
		 * It is line buffered, so make _lbfsize be -_bufsize
		 * for the putc() macro.  We will change _lbfsize back
		 * to 0 whenever we turn off __SWR.
		 */
		fp->pub._w = 0;
		fp->pub._lbfsize = -fp->_bf._size;
	} else
		fp->pub._w = fp->pub._flags & __SNBF ? 0 : fp->_bf._size;
	return (0);
}
