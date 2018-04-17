KMOD=	ipfw3_basic
SRCS=	fw3_opt.h
SRCS+=	ip_fw3_basic.c ip_fw3_basic.h
SRCS+=	ip_fw3_log.c ip_fw3_log.h
SRCS+=  ip_fw3_state.c ip_fw3_state.h
SRCS+=  ip_fw3_table.c ip_fw3_table.h
SRCS+=  ip_fw3_sync.c ip_fw3_sync.h

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
