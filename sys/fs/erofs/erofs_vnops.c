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

/* vop_fhtovp removed in FreeBSD 15.0 */
static vop_vptofh_t erofs_vptofh;

/* No dirty writeback on last ref release, so inactive is a no-op. */
static int
erofs_inactive(struct vop_inactive_args *ap __unused)
{
	return (0);
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

	.vop_vptofh = erofs_vptofh,
};
VFS_VOP_VECTOR_REGISTER(erofs_vnodeops);

struct vop_vector erofs_fifoops = {
	.vop_default = &fifo_specops,
	.vop_reclaim = erofs_reclaim,
	.vop_vptofh = erofs_vptofh,
};
VFS_VOP_VECTOR_REGISTER(erofs_fifoops);
