.PATH:	${SRCTOP}/sys/fs/erofs
.PATH:	${SRCTOP}/sys/contrib/xz-embedded/linux/lib/xz

KMOD=	erofs
SRCS=	opt_ufs.h \
	opt_zstdio.h \
	vnode_if.h \
	data.c \
	decompressor.c \
	decompressor_deflate.c \
	decompressor_lz4.c \
	decompressor_lzma.c \
	decompressor_zstd.c \
	dir.c \
	erofs_vnops.c \
	erofs_zutil.c \
	fileio.c \
	inode.c \
	namei.c \
	super.c \
	sysfs.c \
	trace.c \
	xattr.c \
	zdata.c \
	zmap.c

# Pass UFS_ACL (POSIX ACLs) and ZSTDIO (ZSTD images) to a module built outside
# a kernel build, where there is no opt_*.h to say so.
.if !defined(KERNBUILDDIR)
CFLAGS+=	-DUFS_ACL -DZSTDIO
.endif

CFLAGS.decompressor_zstd.c+=	-I${SRCTOP}/sys/contrib/zstd/lib/freebsd
CFLAGS.decompressor_lzma.c+=	-DXZ_USE_CRC64 \
	-I${SRCTOP}/sys/contrib/xz-embedded/freebsd \
	-I${SRCTOP}/sys/contrib/xz-embedded/linux/lib/xz \
	-I${SRCTOP}/sys/contrib/xz-embedded/linux/include/linux

.include <bsd.kmod.mk>
