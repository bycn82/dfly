# $FreeBSD: src/usr.bin/fetch/Makefile,v 1.3.6.4 2003/01/09 11:54:58 des Exp $

PROG=		fetch
DPADD=		${LIBFETCH}
LDADD=		-lfetch

DPADD+=		${LIBSSL} ${LIBCRYPTO}
LDADD+=		-lprivate_ssl -lprivate_crypto
LDFLAGS+=	${PRIVATELIB_LDFLAGS}
CFLAGS+=	-I${.CURDIR}/../../crypto/libressl/include

.include <bsd.prog.mk>
