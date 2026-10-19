/* SPDX-License-Identifier: BSD-2-Clause */

#include "opt_ufs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/extattr.h>
#include <sys/filio.h>
#include <sys/fnv_hash.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/vnode.h>

#ifdef UFS_ACL
#include <sys/acl.h>
#endif

#include <vm/vm.h>
#include <vm/vnode_pager.h>

#include <fs/erofs/internal.h>
#include <fs/erofs/xattr.h>

static vop_inactive_t erofs_inactive;
static vop_reclaim_t erofs_reclaim;

static vop_open_t erofs_open;
static vop_bmap_t erofs_bmap;

static vop_getattr_t erofs_getattr;
static vop_setattr_t erofs_setattr;
static vop_access_t erofs_access;
static vop_pathconf_t erofs_pathconf;

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

/*
 * Tell the generic pager that EROFS does not provide block-level bmap.
 *
 * Returning EOPNOTSUPP prevents the pager from assuming a bufobj/strategy is
 * available, avoiding "No strategy for buffer" errors.  VM will correctly
 * fall back to the VOP_READ-based page-in path.  The default async VOP wrapper
 * must remain in use so synchronous fallback completion still calls iodone.
 */
static int
erofs_bmap(struct vop_bmap_args *ap)
{
	if (ap->a_bop != NULL)
		*ap->a_bop = NULL;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = -1;
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
	if (ap->a_runb != NULL)
		*ap->a_runb = 0;
	return (EOPNOTSUPP);
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

	.vop_open = erofs_open,
	.vop_bmap = erofs_bmap,

	.vop_getattr = erofs_getattr,
	.vop_setattr = erofs_setattr,
	.vop_access = erofs_access,
	.vop_pathconf = erofs_pathconf,

	.vop_vptofh = erofs_vptofh,
};
VFS_VOP_VECTOR_REGISTER(erofs_vnodeops);

struct vop_vector erofs_fifoops = {
	.vop_default = &fifo_specops,
	.vop_access = erofs_access,
	.vop_getattr = erofs_getattr,
	.vop_pathconf = erofs_pathconf,
	.vop_reclaim = erofs_reclaim,
	.vop_setattr = erofs_setattr,
	.vop_vptofh = erofs_vptofh,
};
VFS_VOP_VECTOR_REGISTER(erofs_fifoops);
