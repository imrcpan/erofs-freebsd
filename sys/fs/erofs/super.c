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

static const uint32_t erofs_crc32c_seed = 0x5045b54aU;

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

static int
erofs_superblock_csum_verify(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	uint32_t expected, crc;
	size_t len;
	int error;

	if (!erofs_sb_has_sb_chksum(sbi))
		return (0);

	len = 1u << dsb->blkszbits;
	if (len > EROFS_SUPER_OFFSET)
		len -= EROFS_SUPER_OFFSET;

	error = erofs_read_metadata_range(sbi, 0, EROFS_SUPER_OFFSET, len,
	    &buf);
	if (error != 0)
		return (error);

	crc = calculate_crc32c(erofs_crc32c_seed,
	    (const uint8_t *)buf.data +
		offsetof(struct erofs_super_block, checksum) +
		sizeof(dsb->checksum),
	    len - offsetof(struct erofs_super_block, checksum) -
		sizeof(dsb->checksum));
	expected = le32toh(dsb->checksum);
	erofs_put_metabuf(&buf);

	if (crc != expected) {
		vfs_mount_error(sbi->mnt,
		    "erofs: invalid superblock checksum 0x%08x, "
		    "0x%08x expected",
		    crc, expected);
		return (EBADMSG);
	}
	return (0);
}

static const char *erofs_opts[] = {
	"acl",
	"device",
	"export",
	"from",
	"dir_ra_bytes",
	"directio",
	"cache_strategy",
	"sync_decompress",
	"worker_queue_priority",
	"fsoffset",
	"nodirectio",
	"user_xattr",
	/* Generic VFS options that other file systems accept. */
	"async",
	"noatime",
	"noclusterr",
	"noclusterw",
	"nosymfollow",
	"sync",
	"union",
	NULL,
};

static vfs_mount_t erofs_mount;
static vfs_root_t erofs_root;
static vfs_statfs_t erofs_statfs;
static vfs_unmount_t erofs_unmount;
static vfs_fhtovp_t erofs_fhtovp;

static int
erofs_parse_fsoffset(struct mount *mp, uint64_t *fsoffsetp, bool *presentp)
{
	struct vfsopt *opt;
	const unsigned char *value;
	uint64_t fsoffset;
	size_t i;

	*fsoffsetp = 0;
	*presentp = false;
	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "fsoffset") != 0)
			continue;
		*presentp = true;
		if (opt->value == NULL || opt->len <= 1 ||
		    ((char *)opt->value)[opt->len - 1] != '\0')
			goto invalid;
		value = opt->value;
		fsoffset = 0;
		for (i = 0; i < (size_t)opt->len - 1; ++i) {
			if (value[i] < '0' || value[i] > '9')
				goto invalid;
			if (fsoffset > (UINT64_MAX - (value[i] - '0')) / 10)
				goto overflow;
			fsoffset = fsoffset * 10 + (value[i] - '0');
		}
		*fsoffsetp = fsoffset;
	}
	return (0);

invalid:
	vfs_mount_error(mp, "erofs: fsoffset requires an unsigned byte offset");
	return (EINVAL);
overflow:
	vfs_mount_error(mp, "erofs: fsoffset value is too large");
	return (ERANGE);
}

static int
erofs_parse_directio_options(struct mount *mp, bool *enabledp, bool *presentp)
{
	struct vfsopt *opt;

	*enabledp = false;
	*presentp = false;
	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "directio") != 0 &&
		    strcmp(opt->name, "nodirectio") != 0)
			continue;
		if (opt->value != NULL || opt->len != 0) {
			vfs_mount_error(mp,
			    "erofs: directio/nodirectio take no value");
			return (EINVAL);
		}
		*presentp = true;
		*enabledp = strcmp(opt->name, "directio") == 0;
	}
	return (0);
}

static int
erofs_parse_zip_mount_options(struct mount *mp,
    struct erofs_sb_info_opts *opts __unused, unsigned int *syncp __unused,
    bool *cache_presentp, bool *sync_presentp, bool *priority_presentp)
{
	struct vfsopt *opt;
	int error;

	*priority_presentp = false;
	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "worker_queue_priority") == 0)
			*priority_presentp = true;
	}
	error = erofs_parse_zip_options(mp, opts, syncp, cache_presentp,
	    sync_presentp);
	if (error != 0) {
		vfs_mount_error(mp,
		    "erofs: invalid cache_strategy, sync_decompress, or "
		    "worker_queue_priority option");
		return (error);
	}
	return (0);
}

#define EROFS_DEVICE_OPT_PREFIX "device."

struct erofs_device_arg {
	uint16_t slot;
	char *path;
};

static int
erofs_load_generation_seed(struct erofs_sb_info *sbi, uint32_t sb_size,
    uint32_t *seedp)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	uint32_t seed;
	int error;

	error = erofs_read_metadata_range(sbi, 0, EROFS_SUPER_OFFSET, sb_size,
	    &buf);
	if (error != 0)
		return (error);
	seed = fnv_32_buf(buf.data, sb_size, FNV1_32_INIT);
	erofs_put_metabuf(&buf);
	*seedp = seed != 0 ? seed : 1;
	return (0);
}

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

static int
erofs_parse_acl_options(struct mount *mp, bool default_enabled, bool *enabledp)
{
	struct vfsopt *opt;
	bool enabled;

	enabled = default_enabled;
	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "acl") != 0 &&
		    strcmp(opt->name, "noacl") != 0)
			continue;
		if (opt->value != NULL || opt->len != 0) {
			vfs_mount_error(mp, "erofs: acl/noacl take no value");
			return (EINVAL);
		}
#ifdef UFS_ACL
		enabled = strcmp(opt->name, "acl") == 0;
#else
		vfs_mount_error(mp, "erofs: POSIX ACL support is not built");
		return (EOPNOTSUPP);
#endif
	}
#ifndef UFS_ACL
	enabled = false;
#endif
	*enabledp = enabled;
	return (0);
}

static int
erofs_parse_xattr_options(struct mount *mp, bool default_enabled,
    bool *enabledp)
{
	struct vfsopt *opt;
	bool enabled;

	enabled = default_enabled;
	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "user_xattr") != 0 &&
		    strcmp(opt->name, "nouser_xattr") != 0)
			continue;
		if (opt->value != NULL || opt->len != 0) {
			vfs_mount_error(mp,
			    "erofs: user_xattr/nouser_xattr take no value");
			return (EINVAL);
		}
		enabled = strcmp(opt->name, "user_xattr") == 0;
	}
	*enabledp = enabled;
	return (0);
}

static void
erofs_set_xattr_state(struct erofs_sb_info *sbi, bool enabled)
{
	if (enabled)
		set_opt(&sbi->opt, XATTR_USER);
	else
		clear_opt(&sbi->opt, XATTR_USER);
}

static void
erofs_set_acl_state(struct erofs_sb_info *sbi, bool enabled)
{
	struct mount *mp;

	mp = sbi->mnt;
	if (enabled) {
		set_opt(&sbi->opt, POSIX_ACL);
		MNT_ILOCK(mp);
		mp->mnt_flag |= MNT_ACLS;
		MNT_IUNLOCK(mp);
	} else {
		MNT_ILOCK(mp);
		mp->mnt_flag &= ~MNT_ACLS;
		MNT_IUNLOCK(mp);
		clear_opt(&sbi->opt, POSIX_ACL);
	}
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
erofs_drop_internal_inodes(struct erofs_sb_info *sbi)
{
	if (sbi->metabox_en != NULL)
		free(sbi->metabox_en, M_EROFS);
	if (sbi->packed_inode != NULL)
		free(sbi->packed_inode, M_EROFS);
}

static int
erofs_sb_free(struct erofs_sb_info *sbi)
{
	int error;

	if (sbi == NULL)
		return (0);
	error = erofs_unregister_sysfs(sbi);
	if (error != 0)
		return (error);
	z_erofs_extent_cache_fini(sbi);
	z_erofs_stream_pool_fini(sbi);
	erofs_xattr_prefixes_cleanup(sbi);
	erofs_drop_internal_inodes(sbi);
	erofs_free_dev_context(sbi);
	erofs_release_device_info(&sbi->dif0);
	erofs_management_fini(sbi);
	free(sbi, M_EROFS);
	return (0);
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

static int
erofs_init_packed_inode(struct erofs_sb_info *sbi)
{
	int error;

	/* Load the packed carrier before any fragment-backed metabox inode. */
	if (erofs_sb_has_fragments(sbi) && sbi->packed_nid > 0) {
		sbi->packed_inode = malloc(sizeof(*sbi->packed_inode), M_EROFS,
		    M_WAITOK | M_ZERO);
		error = erofs_read_inode(sbi, sbi->packed_nid,
		    sbi->packed_inode);
		if (error != 0) {
			free(sbi->packed_inode, M_EROFS);
			sbi->packed_inode = NULL;
			return (error);
		}
		/*
		 * The type of the packed inode is not checked, and neither is
		 * whether it has fragments of its own: every read of it is
		 * bounded, and z_erofs_do_read() refuses a fragment that points
		 * into the packed inode itself.
		 */
	}
	return (0);
}

static int
erofs_init_metabox_inode(struct erofs_sb_info *sbi)
{
	int error;

	/*
	 * METABOX NIDs address inode slots in this backing inode's data.  The
	 * packed carrier is ready first so a compressed metabox may legally end
	 * in a fragment pcluster without reading an uninitialized dependency.
	 */
	if (erofs_sb_has_metabox(sbi)) {
		sbi->metabox_en = malloc(sizeof(*sbi->metabox_en), M_EROFS,
		    M_WAITOK | M_ZERO);
		error = erofs_read_inode(sbi, sbi->metabox_nid,
		    sbi->metabox_en);
		if (error != 0)
			return (error);
	}
	return (0);
}

static int
erofs_read_superblock(struct erofs_sb_info *sbi, struct erofs_super_block *dsb)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	uint32_t unsupported;
	int ret;

	ret = erofs_read_metadata_range(sbi, 0, EROFS_SUPER_OFFSET,
	    sizeof(*dsb), &buf);
	if (ret != 0)
		return (ret);
	memcpy(dsb, buf.data, sizeof(*dsb));
	erofs_put_metabuf(&buf);

	if (le32toh(dsb->magic) != EROFS_SUPER_MAGIC_V1)
		return (EINVAL);
	if (dsb->blkszbits < 9 || dsb->blkszbits > PAGE_SHIFT)
		return (EINVAL);
	sbi->blkszbits = dsb->blkszbits;
	sbi->block_size = 1u << sbi->blkszbits;
	if ((sbi->dif0.fsoff & (sbi->block_size - 1)) != 0) {
		vfs_mount_error(sbi->mnt,
		    "erofs: fsoffset %ju is not aligned to block size %u",
		    (uintmax_t)sbi->dif0.fsoff, sbi->block_size);
		return (EINVAL);
	}
	if (dsb->dirblkbits != 0) {
		vfs_mount_error(sbi->mnt,
		    "erofs: dirblkbits %u isn't supported", dsb->dirblkbits);
		return (EINVAL);
	}
	sbi->feature_compat = le32toh(dsb->feature_compat);
	ret = erofs_superblock_csum_verify(sbi, dsb);
	if (ret != 0)
		return (ret);

	sbi->feature_incompat = le32toh(dsb->feature_incompat);
	sbi->packed_nid = le64toh(dsb->packed_nid);
	sbi->extra_devices = erofs_sb_has_device_table(sbi) ?
	    le16toh(dsb->extra_devices) :
	    0;
	unsupported = sbi->feature_incompat & ~EROFS_ALL_FEATURE_INCOMPAT;
	if (unsupported != 0) {
		vfs_mount_error(sbi->mnt,
		    "erofs: unidentified incompatible feature %x, please "
		    "upgrade kernel",
		    unsupported);
		return (EINVAL);
	}
	sbi->sb_size = 128 + dsb->sb_extslots * EROFS_SB_EXTSLOT_SIZE;
	if (sbi->sb_size > PAGE_SIZE - EROFS_SUPER_OFFSET)
		return (EINVAL);
	sbi->meta_blkaddr = le32toh(dsb->meta_blkaddr);
	sbi->xattr_blkaddr = le32toh(dsb->xattr_blkaddr);
	sbi->xattr_prefix_start = le32toh(dsb->xattr_prefix_start);
	sbi->xattr_prefix_count = dsb->xattr_prefix_count;
	sbi->xattr_filter_reserved = dsb->xattr_filter_reserved;
	erofs_sb_blocks_root(dsb, sbi->feature_incompat, &sbi->blocks,
	    &sbi->root_nid);
	sbi->dif0.blocks = sbi->blocks;
	if (sbi->dif0.blocks == 0) {
		vfs_mount_error(sbi->mnt, "erofs: the image declares 0 blocks");
		return (EINTEGRITY);
	}
	ret = erofs_validate_device_size(sbi, &sbi->dif0, sbi->dif0.blocks);
	if (ret != 0)
		return (ret);
	sbi->inos = le64toh(dsb->inos);
	sbi->epoch = (int64_t)le64toh(dsb->epoch);
	/* Not checked here: erofs_set_timestamp() checks it for each inode. */
	sbi->fixed_nsec = le32toh(dsb->fixed_nsec);
	ret = erofs_load_generation_seed(sbi, sbi->sb_size,
	    &sbi->generation_seed);
	if (ret != 0)
		return (ret);
	if (erofs_sb_has_metabox(sbi)) {
		if (sbi->sb_size <=
		    offsetof(struct erofs_super_block, metabox_nid)) {
			vfs_mount_error(sbi->mnt,
			    "erofs: the superblock has no room for "
			    "metabox_nid");
			return (EINTEGRITY);
		}
		sbi->metabox_nid = le64toh(dsb->metabox_nid);
		if (erofs_nid_in_metabox(sbi->metabox_nid)) {
			vfs_mount_error(sbi->mnt,
			    "erofs: metabox nid %ju is in the metabox",
			    (uintmax_t)sbi->metabox_nid);
			return (EINTEGRITY);
		}
	}

	return (z_erofs_parse_cfgs(sbi, dsb));
}

static int
erofs_mountfs(struct erofs_device_info *primary, struct mount *mp,
    const struct erofs_device_arg *args, unsigned int arg_count,
    bool xattr_user_enabled, bool acl_enabled, bool directio_enabled)
{
	struct erofs_sb_info *sbi;
	struct erofs_inode root;
	struct erofs_super_block dsb;
	bool cache_present, sync_present, priority_present;
	int cleanup_error, error;

	sbi = malloc(sizeof(*sbi), M_EROFS, M_WAITOK | M_ZERO);
	sbi->mnt = mp;
	erofs_management_init(sbi);
	sbi->opt.cache_strategy = EROFS_ZIP_CACHE_READAROUND;
	sbi->sync_decompress = EROFS_SYNC_DECOMPRESS_AUTO;
	error = erofs_parse_zip_mount_options(mp, &sbi->opt,
	    &sbi->sync_decompress, &cache_present, &sync_present,
	    &priority_present);
	if (error != 0)
		goto fail;
	mtx_lock(&sbi->control_lock);
	sbi->decompress_queue_priority = sbi->opt.worker_queue_priority;
	mtx_unlock(&sbi->control_lock);
	z_erofs_extent_cache_init(sbi);
	z_erofs_stream_pool_init(sbi);
	sbi->dif0 = *primary;
	bzero(primary, sizeof(*primary));
	if (directio_enabled)
		set_opt(&sbi->opt, DIRECT_IO);
	error = erofs_register_source_upper(sbi, &sbi->dif0);
	if (error != 0)
		goto fail;

	error = erofs_read_superblock(sbi, &dsb);
	if (error != 0)
		goto fail;
	error = erofs_parse_dir_ra_option(sbi, mp->mnt_optnew);
	if (error != 0) {
		vfs_mount_error(mp, "erofs: invalid dir_ra_bytes option");
		goto fail;
	}
	vfs_deleteopt(mp->mnt_optnew, "dir_ra_bytes");
	error = erofs_scan_devices(sbi, &dsb, args, arg_count);
	if (error != 0)
		goto fail;

	error = erofs_init_packed_inode(sbi);
	if (error != 0)
		goto fail;
	error = erofs_init_metabox_inode(sbi);
	if (error != 0)
		goto fail;
	error = erofs_read_inode(sbi, sbi->root_nid, &root);
	if (error != 0)
		goto fail;
	if (root.vtype != VDIR) {
		vfs_mount_error(mp,
		    "erofs: root inode nid=%ju is not a directory",
		    (uintmax_t)sbi->root_nid);
		error = EINVAL;
		goto fail;
	}
	error = erofs_xattr_prefixes_init(sbi);
	if (error != 0)
		goto fail;

	mp->mnt_data = sbi;
	if (sbi->dif0.source_kind == EROFS_SOURCE_FILE)
		vfs_getnewfsid(mp);
	else {
		mp->mnt_stat.f_fsid.val[0] = dev2udev(sbi->dif0.devvp->v_rdev);
		mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	}
	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_LOCAL | MNT_RDONLY;
	mp->mnt_kern_flag |= MNTK_LOOKUP_SHARED | MNTK_EXTENDED_SHARED |
	    MNTK_USES_BCACHE;
	MNT_IUNLOCK(mp);
	erofs_set_xattr_state(sbi, xattr_user_enabled);
	erofs_set_acl_state(sbi, acl_enabled);
	error = erofs_register_sysfs(sbi);
	if (error != 0)
		goto fail;
	return (0);
fail:
	cleanup_error = erofs_sb_free(sbi);
	if (mp->mnt_data == sbi)
		mp->mnt_data = NULL;
	return (cleanup_error != 0 ? cleanup_error : error);
}

static int
erofs_mount(struct mount *mp)
{
	struct erofs_device_arg *args;
	struct erofs_device_info primary;
	struct erofs_sb_info *sbi;
	struct erofs_sb_info_opts next_opt;
	char *fspec;
	uint64_t fsoffset, new_dir_ra;
	unsigned int next_sync;
	unsigned int arg_count;
	bool directio_enabled, directio_present;
	bool fsoffset_present, xattr_user_enabled, acl_enabled;
	bool cache_present, sync_present, priority_present, dir_ra_present;
	int error, len;

	MNT_ILOCK(mp);
	mp->mnt_flag |= MNT_RDONLY;
	MNT_IUNLOCK(mp);
	if (mp->mnt_flag & MNT_UPDATE) {
		sbi = MTOE(mp);
		if (sbi == NULL)
			return (EINVAL);
		if (mp->mnt_flag & MNT_RELOAD)
			return (EOPNOTSUPP);
		error = erofs_reject_device_update(mp);
		if (error != 0)
			return (error);
		error = erofs_parse_fsoffset(mp, &fsoffset, &fsoffset_present);
		if (error != 0)
			goto update_fail;
		error = erofs_parse_directio_options(mp, &directio_enabled,
		    &directio_present);
		if (error != 0)
			goto update_fail;
		if (fsoffset_present && fsoffset != sbi->dif0.fsoff) {
			vfs_mount_error(mp,
			    "erofs: fsoffset cannot be changed on update");
			error = EOPNOTSUPP;
			goto update_fail;
		}
		error = vfs_filteropt(mp->mnt_optnew, erofs_opts);
		if (error != 0)
			goto update_fail;
		mtx_lock(&sbi->control_lock);
		bzero(&next_opt, sizeof(next_opt));
		next_opt.cache_strategy = sbi->opt.cache_strategy;
		next_opt.worker_queue_priority = sbi->opt.worker_queue_priority;
		next_sync = sbi->sync_decompress;
		mtx_unlock(&sbi->control_lock);
		error = erofs_parse_zip_mount_options(mp, &next_opt, &next_sync,
		    &cache_present, &sync_present, &priority_present);
		if (error != 0)
			goto update_fail;
		error = erofs_parse_acl_options(mp,
		    test_opt(&sbi->opt, POSIX_ACL) != 0, &acl_enabled);
		if (error != 0)
			goto update_fail;
		error = erofs_parse_xattr_options(mp,
		    test_opt(&sbi->opt, XATTR_USER) != 0, &xattr_user_enabled);
		if (error != 0)
			goto update_fail;
		new_dir_ra = 0;
		error = erofs_parse_dir_ra_value(sbi, mp->mnt_optnew,
		    &new_dir_ra, &dir_ra_present);
		if (error != 0) {
			vfs_mount_error(mp,
			    "erofs: invalid dir_ra_bytes option");
			goto update_fail;
		}
		vfs_deleteopt(mp->mnt_optnew, "dir_ra_bytes");
		if (dir_ra_present) {
			error = erofs_set_dir_ra_bytes(sbi, new_dir_ra);
			if (error != 0)
				goto update_fail;
		}
		mtx_lock(&sbi->control_lock);
		if (cache_present)
			sbi->opt.cache_strategy = next_opt.cache_strategy;
		if (sync_present)
			sbi->sync_decompress = next_sync;
		if (priority_present) {
			sbi->opt.worker_queue_priority =
			    next_opt.worker_queue_priority;
			sbi->decompress_queue_priority =
			    next_opt.worker_queue_priority;
		}
		mtx_unlock(&sbi->control_lock);
		erofs_set_xattr_state(sbi, xattr_user_enabled);
		erofs_set_acl_state(sbi, acl_enabled);
		if (directio_present) {
			if (directio_enabled)
				set_opt(&sbi->opt, DIRECT_IO);
			else
				clear_opt(&sbi->opt, DIRECT_IO);
		}
		return (0);
	update_fail:
		return (error);
	}
	args = NULL;
	arg_count = 0;
	error = erofs_parse_device_options(mp, &args, &arg_count);
	if (error != 0)
		return (error);
	if (vfs_filteropt(mp->mnt_optnew, erofs_opts) != 0) {
		error = EINVAL;
		goto out_args;
	}
	error = erofs_parse_fsoffset(mp, &fsoffset, &fsoffset_present);
	if (error != 0)
		goto out_args;
	error = erofs_parse_directio_options(mp, &directio_enabled,
	    &directio_present);
	if (error != 0)
		goto out_args;
	error = erofs_parse_xattr_options(mp, true, &xattr_user_enabled);
	if (error != 0)
		goto out_args;
	error = erofs_parse_acl_options(mp, true, &acl_enabled);
	if (error != 0)
		goto out_args;
	fspec = NULL;
	error = vfs_getopt(mp->mnt_optnew, "from", (void **)&fspec, &len);
	if (error != 0 || fspec == NULL || len == 0 || fspec[len - 1] != '\0') {
		error = EINVAL;
		goto out_args;
	}
	mp->mnt_iosize_max = MAXPHYS;
	error = erofs_open_device(mp, NULL, fspec, &primary);
	if (error != 0)
		goto out_args;
	primary.fsoff = fsoffset;
	erofs_update_iosize_max(mp, &primary);
	error = erofs_mountfs(&primary, mp, args, arg_count, xattr_user_enabled,
	    acl_enabled, directio_enabled);
	if (error != 0)
		erofs_release_device_info(&primary);
out_args:
	erofs_free_device_args(args, arg_count);
	if (error != 0)
		return (error);
	vfs_mountedfrom(mp, fspec);
	return (erofs_statfs(mp, &mp->mnt_stat));
}

static int
erofs_root(struct mount *mp, int flags, struct vnode **vpp)
{
	int error;

	error = erofs_vget_raw(mp, MTOE(mp)->root_nid, flags, vpp);
	if (error != 0)
		vfs_mount_error(mp,
		    "erofs: failed to load root nid %ju: error %d",
		    (uintmax_t)MTOE(mp)->root_nid, error);
	return (error);
}

static int
erofs_statfs(struct mount *mp, struct statfs *sbp)
{
	struct erofs_sb_info *sbi;

	sbi = MTOE(mp);
	sbp->f_bsize = sbi->block_size;
	sbp->f_iosize = sbi->block_size;
	sbp->f_blocks = sbi->total_blocks;
	sbp->f_bfree = 0;
	sbp->f_bavail = 0;
	sbp->f_files = INT64_MAX;
	sbp->f_ffree = sbi->inos <= (uint64_t)INT64_MAX ?
	    INT64_MAX - (int64_t)sbi->inos :
	    0;
	return (0);
}

static int
erofs_unmount(struct mount *mp, int mntflags)
{
	struct erofs_sb_info *sbi;
	int error, flags;

	sbi = MTOE(mp);
	if (sbi == NULL)
		return (EINVAL);
	flags = ((mntflags & MNT_FORCE) != 0) ? FORCECLOSE : 0;
	error = vflush(mp, 0, flags, curthread);
	if (error != 0)
		return (error);
	error = erofs_sb_free(sbi);
	if (error != 0) {
		return (error);
	}
	mp->mnt_data = NULL;
	return (0);
}

/* Persistent EROFS file handle to locked vnode. */
static int
erofs_fhtovp(struct mount *mp, struct fid *fhp, int flags, struct vnode **vpp)
{
	struct erofs_fid efid;
	struct erofs_inode *vi;
	struct vnode *vp;
	erofs_nid_t nid;
	int error;

	*vpp = NULL;
	bzero(&efid, sizeof(efid));
	memcpy(&efid, fhp, sizeof(efid));
	if (efid.len != sizeof(efid) || efid.pad != 0)
		return (EINVAL);
	nid = ((uint64_t)efid.nid_hi << 32) | efid.nid_lo;
	if (!erofs_nid_is_valid(MTOE(mp), nid))
		return (ESTALE);
	error = erofs_vget_raw(mp, nid, flags, &vp);
	if (error != 0)
		return (error);
	vi = VTOE(vp);
	if (vi->mode == 0 || vi->nlink == 0 || vi->nid != nid ||
	    vi->generation != efid.gen) {
		vput(vp);
		return (ESTALE);
	}
	*vpp = vp;
	return (0);
}

static struct vfsops erofs_vfsops = {
	.vfs_fhtovp = erofs_fhtovp,
	.vfs_mount = erofs_mount,
	.vfs_root = erofs_root,
	.vfs_statfs = erofs_statfs,
	.vfs_unmount = erofs_unmount,
	.vfs_vget = erofs_vget,
};
VFS_SET(erofs_vfsops, erofs, VFCF_READONLY);
#ifdef UFS_ACL
MODULE_DEPEND(erofs, acl_posix1e, 1, 1, 1);
#endif
MODULE_DEPEND(erofs, zlib, 1, 1, 1);
MODULE_VERSION(erofs, 1);
