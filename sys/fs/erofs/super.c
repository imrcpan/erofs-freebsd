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
