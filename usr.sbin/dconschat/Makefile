# $FreeBSD: src/usr.sbin/dconschat/Makefile,v 1.1 2003/10/24 15:44:10 simokawa Exp $

PROG=	dconschat
MAN=	dconschat.8
NO_STRICT_ALIASING=

CFLAGS+= -I${.CURDIR}/../../sys

DPADD=  ${LIBKVM}
LDADD=  -lkvm

.include <bsd.prog.mk>
