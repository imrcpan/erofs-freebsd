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

#define EROFS_DEVICE_OPT_PREFIX "device."

struct erofs_device_arg {
	uint16_t slot;
	char *path;
};

static void
erofs_free_device_args(struct erofs_device_arg *args, unsigned int count)
{
	unsigned int i;

	if (args == NULL)
		return;
	for (i = 0; i < count; ++i)
		free(args[i].path, M_EROFS);
	free(args, M_EROFS);
}

static int
erofs_parse_device_slot(const char *name, uint16_t *slotp)
{
	const char *p;
	unsigned int slot;

	if (strncmp(name, EROFS_DEVICE_OPT_PREFIX,
		sizeof(EROFS_DEVICE_OPT_PREFIX) - 1) != 0)
		return (ENOENT);
	p = name + sizeof(EROFS_DEVICE_OPT_PREFIX) - 1;
	if (*p < '1' || *p > '9')
		return (EINVAL);
	slot = 0;
	for (; *p != '\0'; ++p) {
		if (*p < '0' || *p > '9' ||
		    slot > (unsigned int)(UINT16_MAX - (*p - '0')) / 10)
			return (EINVAL);
		slot = slot * 10 + (*p - '0');
	}
	*slotp = slot;
	return (0);
}

static int
erofs_parse_device_options(struct mount *mp, struct erofs_device_arg **argsp,
    unsigned int *countp)
{
	struct erofs_device_arg *args;
	struct vfsopt *opt;
	char name[32];
	unsigned int count, device_count, slot_count, i;
	uint16_t slot;
	int error;

	*argsp = NULL;
	*countp = 0;
	count = 0;
	device_count = 0;
	slot_count = 0;
	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "device") == 0) {
			if (opt->value == NULL || opt->len == 0 ||
			    ((char *)opt->value)[opt->len - 1] != '\0') {
				vfs_mount_error(mp,
				    "erofs: invalid external device option %s",
				    opt->name);
				return (EINVAL);
			}
			if (device_count == UINT16_MAX)
				return (E2BIG);
			++device_count;
			continue;
		}
		error = erofs_parse_device_slot(opt->name, &slot);
		if (error == ENOENT)
			continue;
		if (error != 0 || opt->value == NULL || opt->len <= 1 ||
		    ((char *)opt->value)[opt->len - 1] != '\0') {
			vfs_mount_error(mp,
			    "erofs: invalid external device option %s",
			    opt->name);
			return (EINVAL);
		}
		if (slot_count == UINT16_MAX)
			return (E2BIG);
		++slot_count;
	}
	if (device_count != 0 && slot_count != 0) {
		vfs_mount_error(mp,
		    "erofs: device and device.N options cannot be combined");
		return (EINVAL);
	}
	count = device_count != 0 ? device_count : slot_count;
	if (count == 0)
		return (0);

	args = mallocarray(count, sizeof(*args), M_EROFS, M_WAITOK | M_ZERO);
	if (device_count != 0) {
		i = 0;
		TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
			if (strcmp(opt->name, "device") != 0)
				continue;
			args[i].slot = i + 1;
			args[i].path = malloc(opt->len, M_EROFS, M_WAITOK);
			memcpy(args[i].path, opt->value, opt->len);
			++i;
		}
		vfs_deleteopt(mp->mnt_optnew, "device");
	} else {
		i = 0;
		TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
			error = erofs_parse_device_slot(opt->name, &slot);
			if (error == ENOENT)
				continue;
			KASSERT(error == 0,
			    ("validated EROFS device option changed"));
			args[i].slot = slot;
			args[i].path = malloc(opt->len, M_EROFS, M_WAITOK);
			memcpy(args[i].path, opt->value, opt->len);
			++i;
		}
		for (i = 0; i < count; ++i) {
			unsigned int j;

			for (j = 0; j < i; ++j) {
				if (args[i].slot != args[j].slot)
					continue;
				vfs_mount_error(mp,
				    "erofs: external device slot %u was "
				    "specified more than once",
				    args[i].slot);
				erofs_free_device_args(args, count);
				return (EINVAL);
			}
		}
		for (i = 0; i < count; ++i) {
			snprintf(name, sizeof(name),
			    EROFS_DEVICE_OPT_PREFIX "%u", args[i].slot);
			vfs_deleteopt(mp->mnt_optnew, name);
		}
	}
	*argsp = args;
	*countp = count;
	return (0);
}

static int
erofs_reject_device_update(struct mount *mp)
{
	struct vfsopt *opt;

	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "device") != 0 &&
		    strncmp(opt->name, EROFS_DEVICE_OPT_PREFIX,
			sizeof(EROFS_DEVICE_OPT_PREFIX) - 1) != 0)
			continue;
		vfs_mount_error(mp,
		    "erofs: external devices cannot be changed on update");
		return (EOPNOTSUPP);
	}
	return (0);
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

/*
 * A block-backed primary device may come with file-backed extra devices.
 */
static bool
erofs_mount_has_file_source(const struct erofs_sb_info *sbi)
{
	unsigned int i;

	if (erofs_source_is_file(&sbi->dif0))
		return (true);
	for (i = 0; i < sbi->extra_devices; ++i) {
		if (erofs_source_is_file(&sbi->devs[i]))
			return (true);
	}
	return (false);
}

/*
 * Judge the mount that really holds the data.  VOP_GETLOWVNODE() looks
 * through nullfs and unionfs; where it cannot, unionfs is refused by name.
 */
static int
erofs_check_source_stacking(struct erofs_sb_info *sbi, struct vnode *devvp)
{
	struct erofs_sb_info *lower;
	struct vnode *lowvp;
	struct mount *lowmp;
	int error;

	error = VOP_GETLOWVNODE(devvp, &lowvp, FREAD);
	if (error != 0)
		return (error);
	lowmp = lowvp->v_mount;
	error = 0;
	if (lowmp == NULL) {
		vfs_mount_error(sbi->mnt,
		    "erofs: file-backed source filesystem is being unmounted");
		error = EBUSY;
	} else if (strcmp(lowmp->mnt_vfc->vfc_name, "unionfs") == 0) {
		vfs_mount_error(sbi->mnt,
		    "erofs: file-backed mounts cannot be applied to stacked "
		    "fses");
		error = ENOTBLK;
	} else if (lowmp->mnt_vfc == sbi->mnt->mnt_vfc) {
		lower = lowmp->mnt_data;
		if (lower != NULL && erofs_mount_has_file_source(lower)) {
			vfs_mount_error(sbi->mnt,
			    "erofs: file-backed mounts cannot be applied to "
			    "file-backed EROFS mounts");
			error = ENOTBLK;
		}
	}
	vrele(lowvp);
	return (error);
}

static int
erofs_register_source_upper(struct erofs_sb_info *sbi,
    struct erofs_device_info *dif)
{
	struct mount *source_mnt, *covered_mnt;
	struct mount *source_mp;
	int error;

	if (!erofs_source_is_file(dif))
		return (0);
	if (sbi == NULL || sbi->mnt == NULL || dif->handle == NULL ||
	    dif->devvp == NULL)
		return (EINVAL);
	/*
	 * Reject these before registering, which asserts that the lower mount
	 * is not the one being built.
	 */
	source_mnt = dif->devvp->v_mount;
	if (source_mnt == sbi->mnt) {
		vfs_mount_error(sbi->mnt,
		    "erofs: file-backed source resolves to the mount being "
		    "built");
		return (EDEADLK);
	}
	covered_mnt = sbi->mnt->mnt_vnodecovered != NULL ?
	    sbi->mnt->mnt_vnodecovered->v_mount :
	    NULL;
	if (covered_mnt != NULL && source_mnt == covered_mnt &&
	    source_mnt->mnt_vfc == sbi->mnt->mnt_vfc) {
		vfs_mount_error(sbi->mnt,
		    "erofs: file-backed source and mount target are on the "
		    "same mount");
		return (ELOOP);
	}
	source_mp = vfs_register_upper_from_vp(dif->devvp, sbi->mnt,
	    &dif->handle->source_upper);
	if (source_mp == NULL) {
		vfs_mount_error(sbi->mnt,
		    "erofs: file-backed source filesystem is being unmounted");
		return (EBUSY);
	}
	dif->handle->source_mp = source_mp;
	/*
	 * Registering pins source_mp until this mount is torn down.  Reading
	 * a file-backed source re-enters VOP_READ on it, so another
	 * file-backed EROFS level is refused.
	 */
	error = erofs_check_source_stacking(sbi, dif->devvp);
	if (error != 0) {
		vfs_unregister_upper(source_mp, &dif->handle->source_upper);
		dif->handle->source_mp = NULL;
		return (error);
	}
	return (0);
}

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

static void
erofs_sb_blocks_root(const struct erofs_super_block *dsb, uint32_t incompat,
    uint64_t *blocks, erofs_nid_t *root_nid)
{
	*blocks = le32toh(dsb->blocks_lo);
	if ((incompat & EROFS_FEATURE_INCOMPAT_48BIT) != 0 &&
	    dsb->rootnid_8b != 0) {
		*blocks |= (uint64_t)le16toh(dsb->rb.blocks_hi) << 32;
		*root_nid = le64toh(dsb->rootnid_8b);
	} else {
		*root_nid = le16toh(dsb->rb.rootnid_2b);
	}
}

static int
erofs_validate_device_size(struct erofs_sb_info *sbi,
    struct erofs_device_info *dif, erofs_blk_t blocks)
{
	uint64_t bytes, end;

	/*
	 * The sector size is a power of two, so a block that is not smaller
	 * is a multiple of it.
	 */
	if (sbi->block_size < dif->sectorsize)
		return (EINVAL);
	bytes = blocks << sbi->blkszbits;
	if (__builtin_add_overflow(dif->fsoff, bytes, &end))
		return (EOVERFLOW);
	if (end > dif->mediasize)
		return (ENXIO);
	return (0);
}

static int
erofs_init_device(struct erofs_sb_info *sbi, struct erofs_device_info *dif,
    const char *path)
{
	struct erofs_device_info opened;
	erofs_blk_t blocks, uniaddr;
	int error;

	blocks = dif->blocks;
	uniaddr = dif->uniaddr;
	error = erofs_open_device(sbi->mnt, sbi, path, &opened);
	if (error != 0)
		return (error);
	erofs_update_iosize_max(sbi->mnt, &opened);
	opened.blocks = blocks;
	opened.uniaddr = uniaddr;
	error = erofs_validate_device_size(sbi, &opened, opened.blocks);
	if (error != 0) {
		erofs_release_device_info(&opened);
		return (error);
	}
	error = erofs_register_source_upper(sbi, &opened);
	if (error != 0) {
		erofs_release_device_info(&opened);
		return (error);
	}
	*dif = opened;
	return (0);
}

static const char *
erofs_device_arg_path(const struct erofs_device_arg *args, unsigned int count,
    unsigned int slot)
{
	unsigned int i;

	for (i = 0; i < count; ++i) {
		if (args[i].slot == slot)
			return (args[i].path);
	}
	return (NULL);
}

static int
erofs_scan_devices(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb, const struct erofs_device_arg *args,
    unsigned int arg_count)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_deviceslot *slots;
	struct erofs_device_info *dif;
	const char *path;
	erofs_off_t devt_off;
	uint64_t devt_size, image_size, end;
	erofs_blk_t maxend;
	unsigned int i, mask;
	int err;

	sbi->total_blocks = sbi->dif0.blocks;
	sbi->flatdev_blocks = sbi->dif0.blocks;
	if (sbi->extra_devices == 0) {
		if (arg_count != 0) {
			vfs_mount_error(sbi->mnt,
			    "erofs: external devices given without a device "
			    "table");
			return (EINVAL);
		}
		return (0);
	}
	devt_off = (uint64_t)le16toh(dsb->devt_slotoff) * EROFS_DEVT_SLOT_SIZE;
	devt_size = (uint64_t)sbi->extra_devices * EROFS_DEVT_SLOT_SIZE;
	if (sbi->dif0.blocks > (UINT64_MAX >> sbi->blkszbits)) {
		vfs_mount_error(sbi->mnt, "erofs: image size overflows");
		return (EINTEGRITY);
	}
	image_size = sbi->dif0.blocks << sbi->blkszbits;
	if (devt_off > image_size || devt_size > image_size - devt_off) {
		vfs_mount_error(sbi->mnt,
		    "erofs: device table of %ju bytes at %ju is outside the "
		    "image",
		    (uintmax_t)devt_size, (uintmax_t)devt_off);
		return (EINTEGRITY);
	}
	err = erofs_read_metadata_range(sbi, 0, devt_off, (size_t)devt_size,
	    &buf);
	if (err != 0)
		return (err);
	slots = buf.data;
	sbi->devs = mallocarray(sbi->extra_devices, sizeof(*sbi->devs), M_EROFS,
	    M_WAITOK | M_ZERO);
	maxend = sbi->dif0.blocks;
	for (i = 0; i < sbi->extra_devices; ++i) {
		dif = &sbi->devs[i];
		dif->blocks = le32toh(slots[i].blocks_lo);
		dif->uniaddr = le32toh(slots[i].uniaddr_lo);
		if (erofs_sb_has_48bit(sbi)) {
			dif->blocks |= (uint64_t)le16toh(slots[i].blocks_hi)
			    << 32;
			dif->uniaddr |= (uint64_t)le16toh(slots[i].uniaddr_hi)
			    << 32;
		}
		/*
		 * blocks == 0 is valid: mkfs.erofs --blobdev leaves such an
		 * empty device.
		 */
		if (__builtin_add_overflow(dif->uniaddr, dif->blocks, &end)) {
			vfs_mount_error(sbi->mnt,
			    "erofs: device %u: unified address plus size "
			    "overflows",
			    i + 1);
			err = EINTEGRITY;
			goto out;
		}
		if (__builtin_add_overflow(sbi->total_blocks, dif->blocks,
			&sbi->total_blocks)) {
			err = EOVERFLOW;
			goto out;
		}
		maxend = MAX(maxend, (erofs_blk_t)end);
	}
	erofs_put_metabuf(&buf);
	sbi->flatdev_blocks = maxend;
	mask = 1;
	while (mask < (unsigned int)sbi->extra_devices + 1)
		mask <<= 1;
	sbi->device_id_mask = mask - 1;
	sbi->flatdev = arg_count == 0;
	if (sbi->flatdev) {
		/*
		 * A split image mounted without device options still mounts;
		 * reads beyond the provider fail with ENXIO.
		 */
		return (0);
	}
	if (arg_count != sbi->extra_devices) {
		vfs_mount_error(sbi->mnt,
		    "erofs: external devices don't match (ondisk %u, given %u)",
		    sbi->extra_devices, arg_count);
		return (arg_count < sbi->extra_devices ? ENXIO : EINVAL);
	}
	for (i = 0; i < arg_count; ++i) {
		if (args[i].slot == 0 || args[i].slot > sbi->extra_devices)
			return (EINVAL);
	}
	for (i = 0; i < sbi->extra_devices; ++i) {
		path = erofs_device_arg_path(args, arg_count, i + 1);
		if (path == NULL)
			return (ENXIO);
		err = erofs_init_device(sbi, &sbi->devs[i], path);
		if (err != 0)
			return (err);
	}
	return (0);
out:
	erofs_put_metabuf(&buf);
	return (err);
}
