// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */

#include "opt_ufs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/_maxphys.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/fnv_hash.h>
#include <sys/gsb_crc32.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/refcount.h>
#include <sys/stat.h>
#include <sys/stdarg.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <sys/ucred.h>
#include <sys/vnode.h>

#include <vm/vm.h>

#include <fs/erofs/internal.h>
#include <fs/erofs/trace.h>
#include <fs/erofs/xattr.h>
#include <geom/geom.h>
#include <geom/geom_vfs.h>

MALLOC_DEFINE(M_EROFS, "erofs", "EROFS filesystem");

/*
 * At most EROFS_ERR_MAXPPS lines a second for the whole module, so a bad
 * directory cannot flood the log.  The DTrace probe is not rate limited.
 */
#define EROFS_ERR_MAXPPS 5
static struct timeval erofs_err_lasttime;
static int erofs_err_curpps;

static const char *
erofs_mntonname(const struct erofs_sb_info *sbi)
{
	if (sbi == NULL || sbi->mnt == NULL)
		return ("?");
	return (sbi->mnt->mnt_stat.f_mntonname);
}

void
erofs_log_err(const struct erofs_sb_info *sbi, const char *func,
    const char *fmt, ...)
{
	char msg[128];
	va_list ap;

	if (ppsratecheck(&erofs_err_lasttime, &erofs_err_curpps,
		EROFS_ERR_MAXPPS) == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	log(LOG_ERR, "erofs (%s): %s: %s\n", erofs_mntonname(sbi), func, msg);
}

int
erofs_log_corrupt(const struct erofs_sb_info *sbi, uint64_t nid,
    const char *func, int line, const char *fmt, ...)
{
	char msg[128];
	va_list ap;

	EROFS_TRACE_CORRUPT(nid, line, EINTEGRITY);
	if (ppsratecheck(&erofs_err_lasttime, &erofs_err_curpps,
		EROFS_ERR_MAXPPS) != 0) {
		va_start(ap, fmt);
		vsnprintf(msg, sizeof(msg), fmt, ap);
		va_end(ap);
		if (nid == EROFS_NID_NONE)
			log(LOG_ERR, "erofs (%s): %s: %s\n",
			    erofs_mntonname(sbi), func, msg);
		else
			log(LOG_ERR, "erofs (%s): %s: %s @ nid %ju\n",
			    erofs_mntonname(sbi), func, msg, (uintmax_t)nid);
	}
	return (EINTEGRITY);
}

struct erofs_device_handle {
	struct vnode *devvp;  /* block: private mntfs vnode; file: the file */
	struct vnode *odevvp; /* block: the devfs vnode, reference only */
	struct cdev *dev;
	struct g_consumer *cp;
	struct mount *source_mp;
	struct mount_upper_node source_upper;
	volatile u_int refs;
};

static void
erofs_destroy_device_handle(struct erofs_device_handle *handle)
{
	if (handle == NULL)
		return;
	if (handle->source_mp != NULL) {
		vfs_unregister_upper(handle->source_mp, &handle->source_upper);
		handle->source_mp = NULL;
	}
	if (handle->odevvp != NULL) {
		/*
		 * Block device: close the consumer and free the private vnode
		 * with the vnode locked, then drop the devfs vnode reference.
		 */
		if (handle->devvp != NULL) {
			vn_lock(handle->devvp, LK_EXCLUSIVE | LK_RETRY);
			if (handle->cp != NULL) {
				g_topology_lock();
				g_vfs_close(handle->cp);
				g_topology_unlock();
			}
			mntfs_freevp(handle->devvp);
		}
		vrele(handle->odevvp);
	} else if (handle->devvp != NULL) {
		vrele(handle->devvp);
	}
	if (handle->dev != NULL)
		dev_rel(handle->dev);
	free(handle, M_EROFS);
}

static void
erofs_release_device_info(struct erofs_device_info *dif)
{
	struct erofs_device_handle *handle;

	handle = dif->handle;
	dif->handle = NULL;
	dif->cp = NULL;
	dif->devvp = NULL;
	dif->dev = NULL;
	if (dif->source_cred != NULL) {
		crfree(dif->source_cred);
		dif->source_cred = NULL;
	}
	dif->source_kind = EROFS_SOURCE_NONE;
	if (handle == NULL || !refcount_release(&handle->refs))
		return;
	erofs_destroy_device_handle(handle);
}

static struct erofs_device_handle *
erofs_find_device_handle(struct erofs_sb_info *sbi, struct g_provider *pp)
{
	unsigned int i;

	if (sbi == NULL)
		return (NULL);
	if (sbi->dif0.cp != NULL && sbi->dif0.cp->provider == pp)
		return (sbi->dif0.handle);
	for (i = 0; i < sbi->extra_devices; ++i) {
		if (sbi->devs[i].cp != NULL && sbi->devs[i].cp->provider == pp)
			return (sbi->devs[i].handle);
	}
	return (NULL);
}

static int
erofs_open_device(struct mount *mp, struct erofs_sb_info *sbi, const char *path,
    struct erofs_device_info *dif)
{
	struct erofs_device_handle *handle, *shared;
	struct g_provider *pp;
	struct nameidata nd;
	struct vnode *devvp, *mdevvp;
	struct cdev *dev;
	bool reused, need_open;
	int error;

	bzero(dif, sizeof(*dif));
	handle = malloc(sizeof(*handle), M_EROFS, M_WAITOK | M_ZERO);
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, path);
	error = namei(&nd);
	if (error != 0) {
		free(handle, M_EROFS);
		return (error);
	}
	devvp = nd.ni_vp;
	NDFREE_PNBUF(&nd);
	if (devvp->v_type == VREG) {
		struct vattr va;

		error = VOP_ACCESS(devvp, VREAD, curthread->td_ucred,
		    curthread);
		if (error == 0)
			error = VOP_GETATTR(devvp, &va, curthread->td_ucred);
		if (error != 0) {
			vput(devvp);
			free(handle, M_EROFS);
			return (error);
		}
		dif->source_cred = crhold(curthread->td_ucred);
		handle->devvp = devvp;
		refcount_init(&handle->refs, 1);
		dif->handle = handle;
		dif->devvp = devvp;
		dif->source_kind = EROFS_SOURCE_FILE;
		dif->mediasize = (uint64_t)va.va_size;
		dif->sectorsize = 1;
		VOP_UNLOCK(devvp);
		return (0);
	}
	if (devvp->v_type != VCHR) {
		vput(devvp);
		free(handle, M_EROFS);
		return (EINVAL);
	}
	if (!vn_isdisk_error(devvp, &error)) {
		vput(devvp);
		free(handle, M_EROFS);
		return (error);
	}
	error = VOP_ACCESS(devvp, VREAD, curthread->td_ucred, curthread);
	if (error != 0)
		error = priv_check(curthread, PRIV_VFS_MOUNT_PERM);
	if (error != 0) {
		vput(devvp);
		free(handle, M_EROFS);
		return (error);
	}
	dev = devvp->v_rdev;
	dev_ref(dev);
	handle->odevvp = devvp;
	handle->dev = dev;
	refcount_init(&handle->refs, 1);
	reused = false;
	need_open = false;
	g_topology_lock();
	pp = g_dev_getprovider(dev);
	if (pp == NULL)
		error = ENXIO;
	else if ((shared = erofs_find_device_handle(sbi, pp)) != NULL) {
		refcount_acquire(&shared->refs);
		dif->handle = shared;
		dif->cp = shared->cp;
		dif->devvp = shared->devvp;
		dif->dev = shared->dev;
		dif->source_kind = EROFS_SOURCE_BLOCK;
		dif->mediasize = dif->cp->provider->mediasize;
		dif->sectorsize = dif->cp->provider->sectorsize;
		reused = true;
		error = 0;
	} else {
		need_open = true;
		error = 0;
	}
	g_topology_unlock();
	if (need_open) {
		/*
		 * Use a private vnode: devfs vgone()s its own when the device
		 * goes away, with the buffer cache state this mount still uses.
		 */
		mdevvp = mntfs_allocvp(mp, devvp);
		/*
		 * Readahead holds this lock across breadn(), so allow sharing.
		 */
		VN_LOCK_ASHARE(mdevvp);
		g_topology_lock();
		error = g_vfs_open(mdevvp, &handle->cp, "erofs", 0);
		if (error == 0) {
			handle->devvp = mdevvp;
			dif->handle = handle;
			dif->cp = handle->cp;
			dif->devvp = mdevvp;
			dif->dev = handle->dev;
			dif->source_kind = EROFS_SOURCE_BLOCK;
			dif->mediasize = dif->cp->provider->mediasize;
			dif->sectorsize = dif->cp->provider->sectorsize;
		}
		g_topology_unlock();
		if (error == 0)
			VOP_UNLOCK(mdevvp);
		else
			mntfs_freevp(mdevvp);
	} else {
		VOP_UNLOCK(devvp);
	}
	if (error != 0 || reused) {
		erofs_destroy_device_handle(handle);
	}
	if (error != 0) {
		return (error);
	}
	if (dif->sectorsize == 0 ||
	    (dif->sectorsize & (dif->sectorsize - 1)) != 0) {
		erofs_release_device_info(dif);
		return (EINVAL);
	}
	return (0);
}

static void
erofs_update_iosize_max(struct mount *mp, const struct erofs_device_info *dif)
{
	u_long iosize;

	iosize = dif->dev != NULL && dif->dev->si_iosize_max != 0 ?
	    dif->dev->si_iosize_max :
	    MAXPHYS;
	mp->mnt_iosize_max = (int)MIN((u_long)mp->mnt_iosize_max,
	    MIN(iosize, (u_long)MAXPHYS));
}

static void
erofs_free_dev_context(struct erofs_sb_info *sbi)
{
	unsigned int i;

	if (sbi->devs != NULL) {
		for (i = sbi->extra_devices; i > 0; --i)
			erofs_release_device_info(&sbi->devs[i - 1]);
		free(sbi->devs, M_EROFS);
	}
}
