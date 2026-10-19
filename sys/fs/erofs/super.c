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
