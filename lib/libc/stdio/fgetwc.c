/* $NetBSD: fgetwc.c,v 1.8 2007/04/01 18:35:53 tnozaki Exp $ */
/* $DragonFly: src/lib/libc/stdio/fgetwc.c,v 1.1 2005/07/25 00:37:41 joerg Exp $ */

/*-
 * Copyright (c)2001 Citrus Project,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Citrus$
 */

#include "namespace.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <wchar.h>
#include "un-namespace.h"

#include "libc_private.h"
#include "local.h"
#include "priv_stdio.h"

wint_t
__fgetwc_unlock(FILE *fp)
{
	struct wchar_io_data *wcio;
	wchar_t wc;
	size_t nr;

	_DIAGASSERT(fp != NULL);

	_SET_ORIENTATION(fp, 1);
	wcio = WCIO_GET(fp);
	_DIAGASSERT(wcio != NULL);

	/* if there're ungetwc'ed wchars, use them */
	if (wcio->wcio_ungetwc_inbuf)
		return(wcio->wcio_ungetwc_buf[--wcio->wcio_ungetwc_inbuf]);

	if (fp->pub._r <= 0) {
restart:
		if (__srefill(fp) != 0)
			return WEOF;
	}
	nr = mbrtowc(&wc, (const char *)fp->pub._p,
	    (size_t)fp->pub._r, &wcio->wcio_mbstate_in);
	if (nr == (size_t)-1) {
		fp->pub._flags |= __SERR;
		return WEOF;
	} else if (nr == (size_t)-2) {
		fp->pub._p += fp->pub._r;
		fp->pub._r = 0;
		goto restart;
	}
	if (wc == L'\0') {
		while (*fp->pub._p != '\0') {
			++fp->pub._p;
			--fp->pub._r;
		}
		nr = 1;
	}
	fp->pub._p += nr;
	fp->pub._r -= nr;

	return wc;
}

wint_t
fgetwc(FILE *fp)
{
	wint_t r;

	_DIAGASSERT(fp != NULL);

	FLOCKFILE(fp);
	r = __fgetwc_unlock(fp);
	FUNLOCKFILE(fp);

	return (r);
}

