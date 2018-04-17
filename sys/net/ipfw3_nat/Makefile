KMOD=	ipfw3_nat
SRCS=	fw3_opt.h
SRCS+=	ip_fw3_nat.c

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
