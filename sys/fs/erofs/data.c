// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/_maxphys.h>
#include <sys/buf.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <sys/vnode.h>

#include <vm/vm.h>

#include <machine/vmparam.h>

#include <fs/erofs/internal.h>
#include <fs/erofs/trace.h>

void
erofs_put_metabuf(struct erofs_buf *buf)
{
	void (*release)(void *);
	void *data;

	if (buf == NULL)
		return;
	data = buf->data;
	release = buf->release;
	buf->data = NULL;
	buf->release = NULL;
	if (data != NULL && release != NULL)
		release(data);
}

/*
 * bread() on a device vnode needs no vnode lock, but breadn() reads ahead
 * through breada(), whose inmem() asserts that the vnode is locked.  Take the
 * lock shared (the mount's device vnode allows that) only around the request.
 *
 * A doomed vnode has become VBAD, which the buffer cache only accepts when it
 * is locked, and it no longer has a device behind it, so fail the read.
 */
static int
erofs_breadn_devvp(struct vnode *devvp, daddr_t blkno, int size,
    daddr_t *rablkno, int *rabsize, int racnt, struct buf **bpp)
{
	int error;

	vn_lock(devvp, LK_SHARED | LK_RETRY);
	if (VN_IS_DOOMED(devvp)) {
		VOP_UNLOCK(devvp);
		*bpp = NULL;
		return (ENXIO);
	}
	error = breadn(devvp, blkno, size, rablkno, rabsize, racnt, NOCRED,
	    bpp);
	VOP_UNLOCK(devvp);
	return (error);
}

static int
erofs_bread_device(struct erofs_sb_info *sbi, struct erofs_device_info *dif,
    erofs_blk_t blocks, erofs_off_t off, size_t len, daddr_t *rablkno,
    int *rabsize, int racnt, void **bufp)
{
	struct buf *bp;
	erofs_off_t device_end, device_off, end, limit;
	off_t blkoff, current;
	size_t blklen, done, iosize;
	char *out;
	int error;

	if (bufp == NULL)
		return (EINVAL);
	*bufp = NULL;
	if (len == 0) {
		return (0);
	}
	if (!erofs_source_is_open(dif))
		return (ENODEV);
	if (__builtin_add_overflow(off, (uint64_t)len, &end))
		return (erofs_corrupt(sbi, EROFS_NID_NONE,
		    "read of %zu bytes at %ju overflows", len, (uintmax_t)off));
	if (blocks != 0) {
		if (blocks > (UINT64_MAX >> sbi->blkszbits))
			return (erofs_corrupt(sbi, EROFS_NID_NONE,
			    "device size of %ju blocks overflows",
			    (uintmax_t)blocks));
		limit = blocks << sbi->blkszbits;
		if (end > limit)
			return (erofs_corrupt(sbi, EROFS_NID_NONE,
			    "read of %zu bytes at %ju is beyond the device "
			    "(%ju bytes)",
			    len, (uintmax_t)off, (uintmax_t)limit));
	}
	if (__builtin_add_overflow(dif->fsoff, off, &device_off) ||
	    __builtin_add_overflow(device_off, (uint64_t)len, &device_end))
		return (EOVERFLOW);
	if (device_end > dif->mediasize)
		return (ENXIO);
	if (device_off > INT64_MAX || device_end > (uint64_t)INT64_MAX + 1)
		return (EOVERFLOW);

	iosize = sbi->block_size != 0 ? sbi->block_size : dif->sectorsize;
	if (iosize == 0 || (iosize & (iosize - 1)) != 0)
		return (EINVAL);
	out = malloc(len, M_EROFS, M_WAITOK);
	if (erofs_source_is_file(dif)) {
		error = erofs_read_file_source(sbi, dif, device_off, len, out);
		if (error != 0) {
			free(out, M_EROFS);
			return (error);
		}
		*bufp = out;
		return (0);
	}
	done = 0;
	while (done < len) {
		current = (off_t)(device_off + done);
		blkoff = rounddown2(current, (off_t)iosize);
		blklen = MIN(iosize - (size_t)(current - blkoff), len - done);
		if (done == 0 && racnt != 0)
			error = erofs_breadn_devvp(dif->devvp, btodb(blkoff),
			    iosize, rablkno, rabsize, racnt, &bp);
		else
			error = bread(dif->devvp, btodb(blkoff), iosize, NOCRED,
			    &bp);
		if (error != 0) {
			free(out, M_EROFS);
			return (error);
		}
		if (bp->b_data == NULL) {
			brelse(bp);
			free(out, M_EROFS);
			return (EIO);
		}
		if (bp->b_resid < 0 || bp->b_bcount < 0 ||
		    (uintmax_t)bp->b_resid > (uintmax_t)bp->b_bcount ||
		    (uintmax_t)(current - blkoff) + (uintmax_t)blklen >
			(uintmax_t)bp->b_bcount - (uintmax_t)bp->b_resid) {
			brelse(bp);
			free(out, M_EROFS);
			return (EIO);
		}
		memcpy(out + done, (char *)bp->b_data + (current - blkoff),
		    blklen);
		brelse(bp);
		done += blklen;
	}
	*bufp = out;
	return (0);
}

int
erofs_bread(struct erofs_sb_info *sbi, erofs_off_t off, size_t len, void **bufp)
{
	return (erofs_bread_device(sbi, &sbi->dif0, sbi->dif0.blocks, off, len,
	    NULL, NULL, 0, bufp));
}

void
erofs_brelse(void *buf)
{
	free(buf, M_EROFS);
}

/* Read inode metadata from either the primary image or the metabox file. */
int
erofs_read_metadata_range(struct erofs_sb_info *sbi, erofs_nid_t nid,
    erofs_off_t off, size_t len, struct erofs_buf *buf)
{
	void *data;
	int error;

	if (!erofs_nid_in_metabox(nid)) {
		if (off > INT64_MAX)
			return (EOVERFLOW);
		error = erofs_bread(sbi, (off_t)off, len, &data);
	} else {
		if (!erofs_sb_has_metabox(sbi) || sbi->metabox_en == NULL)
			return (erofs_corrupt(sbi, nid,
			    "metabox nid, but the image has no metabox"));
		error = erofs_read_data(sbi, sbi->metabox_en, off, len, &data);
	}
	if (error != 0)
		return (error);
	buf->data = data;
	buf->release = erofs_brelse;
	return (0);
}
