PROG=	bsdtar
SRCS=	bsdtar.c cmdline.c creation_set.c read.c subst.c util.c write.c
SRCS+=	err.c line_reader.c passphrase.c
DPADD=	${LIBARCHIVE} ${LIBBZ2} ${LIBLZMA} ${LIBMD} ${LIBCRYPTO} ${LIBZ}
LDADD=	-larchive -lbz2 -llzma -lmd -lprivate_crypto -lz
LDFLAGS+=	${PRIVATELIB_LDFLAGS}

CONTRIBDIR=	${.CURDIR}/../../contrib/libarchive/tar
.PATH: ${CONTRIBDIR} ${CONTRIBDIR}/../libarchive_fe
LIBARCHIVE_VERSION!=	cat ${CONTRIBDIR}/../build/version
VERSION!=	echo $$((${LIBARCHIVE_VERSION} / 1000000)).$$((${LIBARCHIVE_VERSION} / 1000 % 1000)).$$((${LIBARCHIVE_VERSION} % 1000))
CFLAGS+=	-I${.CURDIR}/../../lib/libarchive -I${CONTRIBDIR} -I${CONTRIBDIR}/../libarchive_fe
CFLAGS+=	-DPLATFORM_CONFIG_H=\"config.h\"
CFLAGS+=	-DBSDTAR_VERSION_STRING=\"${VERSION}\"

SYMLINKS=	bsdtar ${BINDIR}/tar
MLINKS=	bsdtar.1 tar.1

.include <bsd.prog.mk>
