/* SPDX-License-Identifier: MIT */

#include "opt_ufs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/extattr.h>
#include <sys/filio.h>
#include <sys/fnv_hash.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sf_buf.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>

#ifdef UFS_ACL
#include <sys/acl.h>
#endif

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vnode_pager.h>

#include <fs/erofs/internal.h>
#include <fs/erofs/xattr.h>

static vop_inactive_t erofs_inactive;
static vop_reclaim_t erofs_reclaim;

static vop_readdir_t erofs_readdir;
static vop_readlink_t erofs_readlink;

static vop_open_t erofs_open;
static vop_read_t erofs_read;
static vop_getpages_t erofs_getpages;
static vop_bmap_t erofs_bmap;
static vop_strategy_t erofs_strategy;
static vop_ioctl_t erofs_ioctl;

static vop_getattr_t erofs_getattr;
static vop_setattr_t erofs_setattr;
static vop_access_t erofs_access;
static vop_pathconf_t erofs_pathconf;

static vop_getextattr_t erofs_getextattr;
static vop_listextattr_t erofs_listextattr;
static vop_deleteextattr_t erofs_deleteextattr;
static vop_setextattr_t erofs_setextattr;
#ifdef UFS_ACL
static vop_getacl_t erofs_vop_getacl;
static vop_aclcheck_t erofs_aclcheck;
static vop_setacl_t erofs_setacl;
#endif

/* vop_fhtovp removed in FreeBSD 15.0 */
static vop_vptofh_t erofs_vptofh;

/*
 * Access check: data nodes are read-only, but device/FIFO nodes are not
 * denied writes.
 */
static int
erofs_access(struct vop_access_args *ap)
{
	struct vnode *vp;
	struct erofs_inode *vi;
#ifdef UFS_ACL
	struct acl *acl;
#endif
	accmode_t accmode;
	int error;

	vp = ap->a_vp;
	vi = VTOE(vp);
	accmode = ap->a_accmode;
	if ((accmode & VMODIFY_PERMS) != 0) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			return (EROFS);
		default:
			break;
		}
	}
	error = vfs_unixify_accmode(&accmode);
	if (error != 0)
		return (error);
#ifdef UFS_ACL
	if ((vp->v_mount->mnt_flag & MNT_ACLS) == 0)
		return (vaccess(vp->v_type, vi->mode & ALLPERMS, vi->uid,
		    vi->gid, accmode, ap->a_cred));

	acl = acl_alloc(M_WAITOK);
	error = erofs_get_acl(vp, ACL_TYPE_ACCESS, acl);
	if (error == 0)
		error = vaccess_acl_posix1e(vp->v_type, vi->uid, vi->gid, acl,
		    accmode, ap->a_cred);
	acl_free(acl);
	return (error);
#else
	return (vaccess(vp->v_type, vi->mode & ALLPERMS, vi->uid, vi->gid,
	    accmode, ap->a_cred));
#endif
}

static int
erofs_bmap(struct vop_bmap_args *bmap_args)
{
	struct erofs_vmio_extent extent;
	size_t bufsize, max_io_bytes, run_blocks;
	int error;

	if (bmap_args->a_bop != NULL)
		*bmap_args->a_bop = NULL;
	if (bmap_args->a_bnp != NULL)
		*bmap_args->a_bnp = -1;
	if (bmap_args->a_runp != NULL)
		*bmap_args->a_runp = 0;
	if (bmap_args->a_runb != NULL)
		*bmap_args->a_runb = 0;
	error = erofs_vmio_map(bmap_args->a_vp, bmap_args->a_bn, &extent);
	if (error != 0)
		return (error);
	if (bmap_args->a_bop != NULL)
		*bmap_args->a_bop = extent.device_bufobj;
	if (bmap_args->a_bnp != NULL)
		*bmap_args->a_bnp = extent.device_blkno;
	if (bmap_args->a_runp != NULL) {
		bufsize = erofs_vmio_bufsize(bmap_args->a_vp);
		max_io_bytes = bmap_args->a_vp->v_mount->mnt_iosize_max;
		run_blocks = MIN(extent.mapped_bytes, max_io_bytes) / bufsize;

		/* The forward run excludes the current block. */
		*bmap_args->a_runp = run_blocks - 1;
	}
	return (0);
}

/* VMIO uses the residual count when setting valid bits, even on error. */
static void
erofs_buf_error(struct buf *io_buf, int error)
{
	struct buf *child_buf;

	io_buf->b_ioflags |= BIO_ERROR;
	io_buf->b_error = error;
	io_buf->b_resid = io_buf->b_bcount;

	if ((io_buf->b_flags & B_CLUSTER) == 0)
		return;

	/* cluster_callback propagates the errno but not the residual. */
	TAILQ_FOREACH(child_buf, &io_buf->b_cluster.cluster_head,
	    b_cluster.cluster_entry)
		child_buf->b_resid = child_buf->b_bcount;
}

/* A short GEOM read must fail before VMIO or the cluster validates pages. */
static void
erofs_read_done(struct buf *io_buf)
{
	int error;

	error = 0;
	if ((io_buf->b_ioflags & BIO_ERROR) != 0) {
		error = io_buf->b_error;
		if (error == 0)
			error = EIO;
	} else if (io_buf->b_resid != 0) {
		error = EIO;
	}

	if (error != 0)
		erofs_buf_error(io_buf, error);

	io_buf->b_iodone = io_buf->b_fsprivate1;
	io_buf->b_fsprivate1 = NULL;
	bufdone(io_buf);
}

static int
erofs_strategy(struct vop_strategy_args *strategy_args)
{
	struct erofs_vmio_extent extent;
	struct buf *io_buf;
	size_t bufmask;
	int error;

	io_buf = strategy_args->a_bp;
	if (io_buf->b_iocmd != BIO_READ)
		error = EROFS;
	else
		error = erofs_vmio_map(strategy_args->a_vp, io_buf->b_lblkno,
		    &extent);
	if (error == 0) {
		bufmask = erofs_vmio_bufsize(strategy_args->a_vp) - 1;
		if (io_buf->b_bcount <= 0 ||
		    (io_buf->b_bcount & bufmask) != 0 ||
		    (size_t)io_buf->b_bcount > extent.mapped_bytes)
			error = EIO;
	}
	if (error != 0) {
		erofs_buf_error(io_buf, error);
		bufdone(io_buf);
		return (0);
	}
	/* b_lblkno identifies the file block even for a premapped cluster. */
	io_buf->b_blkno = extent.device_blkno;
	io_buf->b_iooffset = dbtob(extent.device_blkno);
	io_buf->b_fsprivate1 = io_buf->b_iodone;
	io_buf->b_iodone = erofs_read_done;
	BO_STRATEGY(extent.device_bufobj, io_buf);
	return (0);
}

/* No dirty writeback on last ref release, so inactive is a no-op. */
static int
erofs_inactive(struct vop_inactive_args *ap __unused)
{
	return (0);
}

static int
erofs_open(struct vop_open_args *ap)
{
	struct vnode *vp;
	struct erofs_inode *vi;
	int error;

	vp = ap->a_vp;
	vi = VTOE(vp);
	if (VN_ISDEV(vp))
		return (EOPNOTSUPP);
	if (vp->v_type == VREG) {
		error = vnode_create_vobject(vp, vi->size, ap->a_td);
		return (error);
	}
	return (0);
}

static int
erofs_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp;
	struct erofs_inode *vi;
	struct erofs_sb_info *sbi;
	struct vattr *vap;

	vp = ap->a_vp;
	vi = VTOE(vp);
	sbi = MTOE(vp->v_mount);
	vap = ap->a_vap;
	VATTR_NULL(vap);
	/* The image has no creation time; keep the vop_stat() default. */
	vap->va_birthtime.tv_sec = -1;
	vap->va_birthtime.tv_nsec = 0;
	vap->va_type = vp->v_type;
	vap->va_mode = vi->mode & ALLPERMS;
	vap->va_nlink = vi->nlink;
	vap->va_uid = vi->uid;
	vap->va_gid = vi->gid;
	vap->va_fsid = vp->v_mount->mnt_stat.f_fsid.val[0];
	vap->va_fileid = erofs_nid_to_ino64(sbi, vi->nid);
	vap->va_size = vi->size;
	vap->va_blocksize = sbi->block_size;
	vap->va_atime.tv_sec = vi->mtime;
	vap->va_mtime.tv_sec = vi->mtime;
	vap->va_ctime.tv_sec = vi->mtime;
	vap->va_atime.tv_nsec = vi->mtime_nsec;
	vap->va_mtime.tv_nsec = vi->mtime_nsec;
	vap->va_ctime.tv_nsec = vi->mtime_nsec;
	vap->va_gen = vi->generation;
	vap->va_flags = 0;
	vap->va_rdev = VN_ISDEV(vp) ? vi->rdev : NODEV;
	/* A 48-bit block count of 64 KiB blocks, or about size bytes. */
	vap->va_bytes = vi->data_blocks << sbi->blkszbits;
	vap->va_filerev = 0;
	return (0);
}

static int
erofs_getextattr(struct vop_getextattr_args *ap __unused)
{
	int error;

	if (VN_ISDEV(ap->a_vp))
		return (EOPNOTSUPP);
	if (ap->a_attrnamespace == EXTATTR_NAMESPACE_USER &&
	    !test_opt(&MTOE(ap->a_vp->v_mount)->opt, XATTR_USER))
		return (EOPNOTSUPP);
	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace, ap->a_cred,
	    ap->a_td, VREAD);
	if (error != 0)
		return (error);
	if (ap->a_name == NULL || ap->a_name[0] == '\0')
		return (EINVAL);
	if (strlen(ap->a_name) > EXTATTR_MAXNAMELEN)
		return (EINVAL);

	switch (ap->a_attrnamespace) {
	case EXTATTR_NAMESPACE_USER:
	case EXTATTR_NAMESPACE_SYSTEM:
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (erofs_getxattr(ap->a_vp, ap->a_attrnamespace, ap->a_name,
	    ap->a_uio, ap->a_size));
}

static int
erofs_listextattr(struct vop_listextattr_args *ap __unused)
{
	int error;

	if (VN_ISDEV(ap->a_vp))
		return (EOPNOTSUPP);
	if (ap->a_attrnamespace == EXTATTR_NAMESPACE_USER &&
	    !test_opt(&MTOE(ap->a_vp->v_mount)->opt, XATTR_USER))
		return (EOPNOTSUPP);
	error = extattr_check_cred(ap->a_vp, ap->a_attrnamespace, ap->a_cred,
	    ap->a_td, VREAD);
	if (error != 0)
		return (error);

	switch (ap->a_attrnamespace) {
	case EXTATTR_NAMESPACE_USER:
	case EXTATTR_NAMESPACE_SYSTEM:
		break;
	default:
		return (EOPNOTSUPP);
	}

	return (erofs_listxattr(ap->a_vp, ap->a_attrnamespace, ap->a_uio,
	    ap->a_size));
}

static int
erofs_deleteextattr(struct vop_deleteextattr_args *ap __unused)
{
	if (VN_ISDEV(ap->a_vp))
		return (EOPNOTSUPP);
	return (EROFS);
}

static int
erofs_setextattr(struct vop_setextattr_args *ap __unused)
{
	if (VN_ISDEV(ap->a_vp))
		return (EOPNOTSUPP);
	return (EROFS);
}

/*
 * EROFS is read-only; mutations on regular files/dirs/symlinks are denied, size
 * changes on special vnodes are treated as no-ops per read-only convention.
 */
static int
erofs_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp;
	struct vattr *vap;

	vp = ap->a_vp;
	vap = ap->a_vap;
	if (vap->va_mode != (mode_t)VNOVAL || vap->va_uid != (uid_t)VNOVAL ||
	    vap->va_gid != (gid_t)VNOVAL || vap->va_atime.tv_sec != VNOVAL ||
	    vap->va_atime.tv_nsec != VNOVAL || vap->va_mtime.tv_sec != VNOVAL ||
	    vap->va_mtime.tv_nsec != VNOVAL || vap->va_flags != VNOVAL)
		return (EROFS);
	if (vap->va_size != VNOVAL) {
		switch (vp->v_type) {
		case VDIR:
			return (EISDIR);
		case VLNK:
		case VREG:
			return (EROFS);
		case VCHR:
		case VBLK:
		case VSOCK:
		case VFIFO:
		case VNON:
		case VBAD:
		case VMARKER:
			return (0);
		}
	}
	return (0);
}

static int
erofs_read(struct vop_read_args *read_args)
{
	switch (read_args->a_vp->v_type) {
	case VREG:
		return (erofs_read_file(read_args->a_vp, read_args->a_uio,
		    read_args->a_ioflag));
	case VDIR:
		return (EISDIR);
	default:
		return (EINVAL);
	}
}

static daddr_t
erofs_pager_lbn(struct vnode *file_vnode, vm_ooffset_t file_offset)
{
	return (file_offset / erofs_vmio_bufsize(file_vnode));
}

static int
erofs_pager_bsize(struct vnode *file_vnode, daddr_t file_lbn __unused,
    long *size)
{
	*size = erofs_vmio_bufsize(file_vnode);
	return (0);
}

/* Read the image directly while the caller owns the exclusive page busy. */
static int
erofs_getpage_raw(struct vnode *file_vnode, vm_page_t page)
{
	struct erofs_inode *vi;
	struct sf_buf *page_mapping;
	erofs_off_t file_offset;
	size_t file_bytes;
	void *file_data;
	char *page_addr;
	int error;

	vi = VTOE(file_vnode);
	file_offset = IDX_TO_OFF(page->pindex);
	if (file_offset >= vi->size)
		return (VM_PAGER_BAD);
	file_bytes = MIN(vi->size - file_offset, PAGE_SIZE);
	error = erofs_read_data(MTOE(file_vnode->v_mount), vi, file_offset,
	    file_bytes, &file_data);
	if (error != 0)
		return (VM_PAGER_ERROR);
	page_mapping = sf_buf_alloc(page, 0);
	page_addr = (char *)sf_buf_kva(page_mapping);
	memcpy(page_addr, file_data, file_bytes);
	bzero(page_addr + file_bytes, PAGE_SIZE - file_bytes);
	sf_buf_free(page_mapping);
	erofs_brelse(file_data);
	vm_page_valid(page);
	VM_CNT_INC(v_vnodein);
	VM_CNT_INC(v_vnodepgsin);
	return (VM_PAGER_OK);
}

static int
erofs_getpages(struct vop_getpages_args *getpages_args)
{
	struct erofs_vmio_extent extent;
	struct vnode *file_vnode;
	vm_page_t *pages;
	vm_ooffset_t first_offset;
	size_t offset_in_buf;
	int error, page_slot, prefix_slots, scan_slot;

	file_vnode = getpages_args->a_vp;
	if (VN_IS_DOOMED(file_vnode))
		return (VM_PAGER_BAD);
	if (erofs_inode_is_data_compressed(VTOE(file_vnode)->datalayout))
		return (z_erofs_getpages(file_vnode, getpages_args->a_m,
		    getpages_args->a_count, getpages_args->a_rbehind,
		    getpages_args->a_rahead));
	if (getpages_args->a_rbehind != NULL)
		*getpages_args->a_rbehind = 0;
	if (getpages_args->a_rahead != NULL)
		*getpages_args->a_rahead = 0;
	pages = getpages_args->a_m;
	first_offset = IDX_TO_OFF(pages[0]->pindex);
	error = erofs_vmio_map(file_vnode,
	    erofs_pager_lbn(file_vnode, first_offset), &extent);
	page_slot = 0;
	if (error == 0) {
		offset_in_buf = first_offset &
		    (erofs_vmio_bufsize(file_vnode) - 1);
		prefix_slots = MIN((size_t)getpages_args->a_count,
		    atop(extent.mapped_bytes - offset_in_buf));
		/* A sendfile array may have a bogus page at the split. */
		while (
		    prefix_slots > 0 && pages[prefix_slots - 1] == bogus_page)
			prefix_slots--;
		if (prefix_slots > 0) {
			error = vfs_bio_getpages(file_vnode, pages,
			    prefix_slots, NULL, NULL, erofs_pager_lbn,
			    erofs_pager_bsize);
			if (error != VM_PAGER_OK)
				return (error);
		}
		page_slot = prefix_slots;
	} else {
		if (error != EOPNOTSUPP)
			return (VM_PAGER_ERROR);
		/*
		 * The only VMIO range is a prefix.  With an unsupported first
		 * page the old pager can read this request with VOP_READ.
		 * Its fallback loop does not skip sendfile's bogus pages.
		 */
		for (scan_slot = 0; scan_slot < getpages_args->a_count;
		    scan_slot++) {
			if (pages[scan_slot] == bogus_page)
				break;
		}
		if (scan_slot == getpages_args->a_count)
			return (vnode_pager_local_getpages(getpages_args));
	}
	for (; page_slot < getpages_args->a_count; page_slot++) {
		if (pages[page_slot] == bogus_page)
			continue;
		error = erofs_getpage_raw(file_vnode, pages[page_slot]);
		if (error != VM_PAGER_OK)
			return (error);
	}
	return (VM_PAGER_OK);
}

static int
erofs_ioctl(struct vop_ioctl_args *ap)
{
	struct vnode *vp;
	bool seek_data;
	int error;

	switch (ap->a_command) {
	case FIOSEEKDATA:
		seek_data = true;
		break;
	case FIOSEEKHOLE:
		seek_data = false;
		break;
	default:
		return (ENOTTY);
	}

	vp = ap->a_vp;
	error = vn_lock(vp, LK_SHARED);
	if (error != 0)
		return (EBADF);
	error = erofs_file_llseek(vp, (off_t *)ap->a_data, seek_data);
	VOP_UNLOCK(vp);
	return (error);
}

static int
erofs_readdir(struct vop_readdir_args *ap)
{
	if (ap->a_vp->v_type != VDIR)
		return (ENOTDIR);
	return (erofs_readdir_block(ap->a_vp, ap->a_uio, ap->a_eofflag,
	    ap->a_ncookies, ap->a_cookies));
}

static int
erofs_readlink(struct vop_readlink_args *ap)
{
	if (ap->a_vp->v_type != VLNK)
		return (EINVAL);
	return (erofs_readlink_target(ap->a_vp, ap->a_uio));
}

static int
erofs_pathconf(struct vop_pathconf_args *ap)
{
	switch (ap->a_name) {
	case _PC_NAME_MAX:
		*ap->a_retval = EROFS_NAME_LEN;
		return (0);
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return (0);
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;
		return (0);
	case _PC_LINK_MAX:
		*ap->a_retval = INT_MAX;
		return (0);
	case _PC_CHOWN_RESTRICTED:
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return (0);
#ifdef UFS_ACL
	case _PC_ACL_EXTENDED:
		*ap->a_retval = ((ap->a_vp->v_mount->mnt_flag & MNT_ACLS) !=
				    0) ?
		    1 :
		    0;
		return (0);
	case _PC_ACL_PATH_MAX:
		*ap->a_retval = ((ap->a_vp->v_mount->mnt_flag & MNT_ACLS) !=
				    0) ?
		    ACL_MAX_ENTRIES :
		    3;
		return (0);
	case _PC_ACL_NFS4:
		*ap->a_retval = 0;
		return (0);
#else
	case _PC_ACL_EXTENDED:
	case _PC_ACL_NFS4:
		*ap->a_retval = 0;
		return (0);
	case _PC_ACL_PATH_MAX:
		*ap->a_retval = 3;
		return (0);
#endif
	default:
		return (vop_stdpathconf(ap));
	}
}

#ifdef UFS_ACL
static int
erofs_vop_getacl(struct vop_getacl_args *ap)
{
	if (VN_ISDEV(ap->a_vp))
		return (EOPNOTSUPP);
	if ((ap->a_vp->v_mount->mnt_flag & MNT_ACLS) == 0)
		return (EOPNOTSUPP);
	return (erofs_get_acl(ap->a_vp, ap->a_type, ap->a_aclp));
}

static int
erofs_aclcheck(struct vop_aclcheck_args *ap)
{
	if (VN_ISDEV(ap->a_vp))
		return (EOPNOTSUPP);
	if ((ap->a_vp->v_mount->mnt_flag & MNT_ACLS) == 0)
		return (EOPNOTSUPP);
	if (ap->a_aclp == NULL)
		return (EINVAL);
	switch (ap->a_type) {
	case ACL_TYPE_ACCESS:
		break;
	case ACL_TYPE_DEFAULT:
		if (ap->a_vp->v_type != VDIR)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}
	return (acl_posix1e_check(ap->a_aclp));
}

static int
erofs_setacl(struct vop_setacl_args *ap)
{
	if (VN_ISDEV(ap->a_vp))
		return (EOPNOTSUPP);
	return (EROFS);
}
#endif

static u_int
erofs_vfs_hash(erofs_nid_t nid)
{
	return (fnv_32_buf(&nid, sizeof(nid), FNV1_32_INIT));
}

static int
erofs_vfs_hash_cmp(struct vnode *vp, void *pnid)
{
	struct erofs_inode *vi;

	vi = VTOE(vp);
	return (vi == NULL || vi->nid != *(erofs_nid_t *)pnid);
}

static void
erofs_fill_vnode(struct erofs_sb_info *sbi, struct vnode *vp,
    const struct erofs_inode *vi)
{
	vp->v_type = vi->vtype;
	if (vp->v_type == VFIFO)
		vp->v_op = &erofs_fifoops;
	else
		VN_LOCK_ASHARE(vp);
	if (vi->nid == sbi->root_nid)
		vp->v_vflag |= VV_ROOT;
}

int
erofs_vget_raw(struct mount *mp, erofs_nid_t nid, int flags, struct vnode **vpp)
{
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	struct thread *td;
	struct vnode *vp;
	u_int hash;
	bool shared;
	int error;

	*vpp = NULL;
	td = curthread;
	shared = (flags & LK_TYPE_MASK) == LK_SHARED;
	hash = erofs_vfs_hash(nid);
	error = vfs_hash_get(mp, hash, flags, td, vpp, erofs_vfs_hash_cmp,
	    &nid);
	if (error != 0 || *vpp != NULL)
		return (error);

	sbi = MTOE(mp);
	vi = malloc(sizeof(*vi), M_EROFS, M_WAITOK | M_ZERO);
	error = getnewvnode("erofs", mp, &erofs_vnodeops, &vp);
	if (error != 0) {
		free(vi, M_EROFS);
		*vpp = NULL;
		return (error);
	}
	vp->v_data = vi;
	vi->nid = nid;
	lockmgr(vp->v_vnlock, LK_EXCLUSIVE, NULL);
	error = insmntque(vp, mp);
	if (error != 0) {
		free(vi, M_EROFS);
		*vpp = NULL;
		return (error);
	}
	error = vfs_hash_insert(vp, hash, flags, td, vpp, erofs_vfs_hash_cmp,
	    &nid);
	if (error != 0 || *vpp != NULL)
		return (error);

	error = erofs_read_inode(sbi, nid, vi);
	if (error != 0) {
		*vpp = NULL;
		vgone(vp);
		vput(vp);
		return (error);
	}
	erofs_xattr_cache_init(vi);
	erofs_fill_vnode(sbi, vp, vi);
	vn_set_state(vp, VSTATE_CONSTRUCTED);
	if (shared)
		VOP_LOCK(vp, LK_DOWNGRADE);
	*vpp = vp;
	return (0);
}

int
erofs_vget_raw_alloc(struct mount *mp, void *arg, int flags, struct vnode **vpp)
{
	return (erofs_vget_raw(mp, *(erofs_nid_t *)arg, flags, vpp));
}

int
erofs_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp)
{
	struct erofs_sb_info *sbi;
	erofs_nid_t nid;
	int error;

	*vpp = NULL;
	sbi = MTOE(mp);
	error = erofs_ino_to_nid(sbi, ino, &nid);
	if (error != 0)
		return (error);
	if (!erofs_nid_is_valid(sbi, nid))
		return (ESTALE);
	return (erofs_vget_raw(mp, nid, flags, vpp));
}

static int
erofs_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp;
	struct erofs_inode *vi;

	vp = ap->a_vp;
	vi = VTOE(vp);
	if (vi != NULL) {
		vfs_hash_remove(vp);
		erofs_xattr_cache_fini(MTOE(vp->v_mount), vi);
		free(vi, M_EROFS);
		vp->v_data = NULL;
	}
	return (0);
}

/* Vnode pointer to persistent EROFS file handle. */
static int
erofs_vptofh(struct vop_vptofh_args *ap)
{
	struct erofs_fid efid;
	struct erofs_inode *vi;

	vi = VTOE(ap->a_vp);
	bzero(&efid, sizeof(efid));
	efid.len = sizeof(efid);
	efid.nid_hi = vi->nid >> 32;
	efid.nid_lo = vi->nid;
	efid.gen = vi->generation;
	memcpy(ap->a_fhp, &efid, sizeof(efid));
	return (0);
}

struct vop_vector erofs_vnodeops = {
	.vop_default = &default_vnodeops,
	.vop_inactive = erofs_inactive,
	.vop_reclaim = erofs_reclaim,

	.vop_lookup = vfs_cache_lookup,
	.vop_cachedlookup = erofs_lookup,
	.vop_readdir = erofs_readdir,
	.vop_readlink = erofs_readlink,

	.vop_open = erofs_open,
	.vop_read = erofs_read,
	.vop_bmap = erofs_bmap,
	.vop_strategy = erofs_strategy,
	.vop_ioctl = erofs_ioctl,
	.vop_getpages = erofs_getpages,

	.vop_getattr = erofs_getattr,
	.vop_setattr = erofs_setattr,
	.vop_access = erofs_access,
	.vop_pathconf = erofs_pathconf,

	.vop_getextattr = erofs_getextattr,
	.vop_listextattr = erofs_listextattr,
	.vop_deleteextattr = erofs_deleteextattr,
	.vop_setextattr = erofs_setextattr,
#ifdef UFS_ACL
	.vop_getacl = erofs_vop_getacl,
	.vop_aclcheck = erofs_aclcheck,
	.vop_setacl = erofs_setacl,
#endif

	.vop_vptofh = erofs_vptofh,
};
VFS_VOP_VECTOR_REGISTER(erofs_vnodeops);

struct vop_vector erofs_fifoops = {
	.vop_default = &fifo_specops,
	.vop_access = erofs_access,
#ifdef UFS_ACL
	.vop_aclcheck = erofs_aclcheck,
#endif
	.vop_deleteextattr = erofs_deleteextattr,
#ifdef UFS_ACL
	.vop_getacl = erofs_vop_getacl,
#endif
	.vop_getextattr = erofs_getextattr,
	.vop_getattr = erofs_getattr,
	.vop_listextattr = erofs_listextattr,
	.vop_pathconf = erofs_pathconf,
	.vop_reclaim = erofs_reclaim,
#ifdef UFS_ACL
	.vop_setacl = erofs_setacl,
#endif
	.vop_setattr = erofs_setattr,
	.vop_setextattr = erofs_setextattr,
	.vop_vptofh = erofs_vptofh,
};
VFS_VOP_VECTOR_REGISTER(erofs_fifoops);
