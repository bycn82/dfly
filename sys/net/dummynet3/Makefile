# $FreeBSD: src/sys/modules/dummynet/Makefile,v 1.1.2.2 2003/04/08 10:18:00 maxim Exp $
# $DragonFly: src/sys/net/dummynet/Makefile,v 1.7 2008/09/16 12:30:57 sephe Exp $

KMOD=	dummynet3
SRCS=	fw3_opt.h
SRCS+=	ip_dummynet3.c

.ifndef BUILDING_WITH_KERNEL
fw3_opt.h:
	echo '#define INET 1' > ${.OBJDIR}/${.TARGET}
	echo '#define IPFIREWALL3 1' >> ${.OBJDIR}/${.TARGET}
	# Debug prints
	#echo '#define IPFIREWALL3_DEBUG 1' >> ${.OBJDIR}/${.TARGET}
	#
	#
	# If you want it to pass all packets by default
	#echo '#define IPFIREWALL_DEFAULT_TO_ACCEPT 1' >> ${.OBJDIR}/${.TARGET}
.endif

.include <bsd.kmod.mk>
