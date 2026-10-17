// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024, Alibaba Cloud
 */

#include <sys/param.h>
#include <sys/_maxphys.h>
#include <sys/proc.h>

#include <fs/erofs/internal.h>

static int
erofs_read_file_source_vnrdwr(struct erofs_device_info *dif, erofs_off_t off,
    size_t len, void *out, int ioflag)
{
	size_t done, want;
	ssize_t resid;
	int error;

	/* The credential is taken when the file source is opened. */
	KASSERT(dif->source_cred != NULL,
	    ("erofs: file source without a credential"));
	done = 0;
	while (done < len) {
		want = MIN(len - done, (size_t)MAXPHYS);
		/* erofs_bread_device() keeps off + len within INT64_MAX + 1. */
		error = vn_rdwr(UIO_READ, dif->devvp, (char *)out + done,
		    (int)want, (off_t)(off + done), UIO_SYSSPACE, ioflag,
		    dif->source_cred, NOCRED, &resid, curthread);
		if (error != 0)
			return (error);
		if (resid != 0)
			return (EIO);
		done += want;
	}
	return (0);
}

static int
erofs_read_file_source_direct(struct erofs_device_info *dif, erofs_off_t off,
    size_t len, void *out)
{
	return (erofs_read_file_source_vnrdwr(dif, off, len, out, IO_DIRECT));
}

int
erofs_read_file_source(struct erofs_sb_info *sbi, struct erofs_device_info *dif,
    erofs_off_t off, size_t len, void *out)
{
	if (test_opt(&sbi->opt, DIRECT_IO))
		return (erofs_read_file_source_direct(dif, off, len, out));
	return (erofs_read_file_source_vnrdwr(dif, off, len, out, 0));
}
