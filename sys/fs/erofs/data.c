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

#define EROFS_DIR_READAHEAD_SLOTS 256

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

static int
erofs_map_blocks_chunk(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map)
{
	struct erofs_inode_chunk_index *idx;
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	uint64_t chunk_idx, chunk_size, entry_size;
	erofs_off_t loff, chunk_start, idx_off, idx_base;
	uint64_t image_size, addrmask;
	uint64_t blkaddr;
	uint16_t raw_device_id;
	int error;

	loff = map->m_la;
	chunk_size = 1ULL << vi->chunkbits;
	chunk_idx = loff >> vi->chunkbits;
	chunk_start = chunk_idx << vi->chunkbits;

	if ((vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES) != 0)
		entry_size = sizeof(struct erofs_inode_chunk_index);
	else
		entry_size = EROFS_BLOCK_MAP_ENTRY_SIZE;
	/*
	 * inode_off is below 2^63 (the image fits its provider, whose size is
	 * an off_t; a metabox is at most OFF_MAX), isize is 32 or 64 and
	 * xattr_isize is below 2^19; chunk_idx is below 2^54 because
	 * loff < size <= OFF_MAX and a chunk has at least 512 bytes.
	 */
	idx_base = roundup2(vi->inode_off + vi->inode_isize + vi->xattr_isize,
	    entry_size);
	idx_off = idx_base + chunk_idx * entry_size;
	if (erofs_nid_in_metabox(vi->nid)) {
		if (sbi->metabox_en == NULL ||
		    idx_off > sbi->metabox_en->size ||
		    entry_size > sbi->metabox_en->size - idx_off)
			return (erofs_corrupt(sbi, vi->nid,
			    "chunk %ju: index entry at %ju is beyond the "
			    "metabox",
			    (uintmax_t)chunk_idx, (uintmax_t)idx_off));
	} else {
		image_size = sbi->blocks << sbi->blkszbits;
		if (idx_off > image_size || entry_size > image_size - idx_off)
			return (erofs_corrupt(sbi, vi->nid,
			    "chunk %ju: index entry at %ju is beyond the image",
			    (uintmax_t)chunk_idx, (uintmax_t)idx_off));
	}

	error = erofs_read_metadata_range(sbi, vi->nid, idx_off, entry_size,
	    &buf);
	if (error != 0)
		return (error);

	idx = buf.data;
	if ((vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES) != 0) {
		blkaddr = le32toh(idx->startblk_lo);
		if ((vi->chunkformat & EROFS_CHUNK_FORMAT_48BIT) != 0)
			blkaddr |= (uint64_t)le16toh(idx->startblk_hi) << 32;
		raw_device_id = le16toh(idx->device_id);
		addrmask = (vi->chunkformat & EROFS_CHUNK_FORMAT_48BIT) != 0 ?
		    ((1ULL << 48) - 1) :
		    UINT32_MAX;
	} else {
		blkaddr = le32dec(idx);
		raw_device_id = 0;
		addrmask = UINT32_MAX;
	}
	erofs_put_metabuf(&buf);

	if (!((blkaddr ^ EROFS_NULL_ADDR) & addrmask)) {
		map->m_la = chunk_start;
		map->m_pa = 0;
		map->m_llen = MIN(chunk_size, vi->size - chunk_start);
		map->m_plen = map->m_llen;
		return (0);
	}

	map->m_la = chunk_start;
	map->m_llen = MIN(chunk_size, vi->size - chunk_start);
	map->m_plen = map->m_llen;
	map->m_deviceid = raw_device_id & sbi->device_id_mask;
	/* blkaddr has at most 48 bits and blkszbits at most 16. */
	map->m_pa = blkaddr << sbi->blkszbits;
	map->m_flags |= EROFS_MAP_MAPPED;
	return (0);
}

static erofs_off_t
erofs_inline_tail_start(const struct erofs_sb_info *sbi,
    const struct erofs_inode *vi)
{
	if (vi->size == 0)
		return (0);
	return (
	    roundup2(vi->size, (uint64_t)sbi->block_size) - sbi->block_size);
}

static int
erofs_map_blocks_flatmode(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map)
{
	erofs_off_t loff, tail_start;
	uint64_t remain, block_rem;

	loff = map->m_la;
	if (loff >= vi->size)
		return (0);

	remain = vi->size - loff;
	switch (vi->datalayout) {
	case EROFS_INODE_CHUNK_BASED:
		return (erofs_map_blocks_chunk(sbi, vi, map));
	case EROFS_INODE_FLAT_PLAIN:
		map->m_llen = remain;
		map->m_plen = map->m_llen;
		if (vi->startblk == EROFS_NULL_ADDR)
			return (0);
		if (vi->startblk > (UINT64_MAX >> sbi->blkszbits) ||
		    __builtin_add_overflow(vi->startblk << sbi->blkszbits, loff,
			&map->m_pa))
			return (erofs_corrupt(sbi, vi->nid,
			    "start block %ju overflows",
			    (uintmax_t)vi->startblk));
		map->m_flags |= EROFS_MAP_MAPPED;
		return (0);
	case EROFS_INODE_FLAT_INLINE:
		tail_start = erofs_inline_tail_start(sbi, vi);
		if (loff < tail_start) {
			map->m_llen = MIN(remain, tail_start - loff);
			map->m_plen = map->m_llen;
			if (vi->startblk == EROFS_NULL_ADDR)
				return (0);
			if (vi->startblk > (UINT64_MAX >> sbi->blkszbits) ||
			    __builtin_add_overflow(vi->startblk
				    << sbi->blkszbits,
				loff, &map->m_pa))
				return (erofs_corrupt(sbi, vi->nid,
				    "start block %ju overflows",
				    (uintmax_t)vi->startblk));
			map->m_flags |= EROFS_MAP_MAPPED;
			return (0);
		}
		block_rem = sbi->block_size -
		    ((loff - tail_start) & (sbi->block_size - 1));
		map->m_llen = MIN(remain, block_rem);
		map->m_plen = map->m_llen;
		if (__builtin_add_overflow(vi->inode_off, vi->inode_isize,
			&map->m_pa) ||
		    __builtin_add_overflow(map->m_pa, vi->xattr_isize,
			&map->m_pa) ||
		    __builtin_add_overflow(map->m_pa, loff - tail_start,
			&map->m_pa))
			return (erofs_corrupt(sbi, vi->nid,
			    "inline tail position overflows"));
		map->m_flags |= EROFS_MAP_MAPPED | EROFS_MAP_META;
		return (0);
	case EROFS_INODE_COMPRESSED_FULL:
	case EROFS_INODE_COMPRESSED_COMPACT:
		return (EOPNOTSUPP);
	default:
		return (EOPNOTSUPP);
	}
}

int
erofs_map_blocks(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map)
{
	struct erofs_map_blocks next = { .m_la = map->m_la };
	int err;

	EROFS_TRACE_MAP_BLOCKS_ENTER(vi, map, 0);
	if (erofs_inode_is_data_compressed(vi->datalayout)) {
		err = z_erofs_map_blocks(sbi, vi, &next);
	} else {
		err = erofs_map_blocks_flatmode(sbi, vi, &next);
	}
	*map = next;
	EROFS_TRACE_MAP_BLOCKS_EXIT(vi, map, err);
	return (err);
}
static int
erofs_check_device_range(const struct erofs_sb_info *sbi,
    const struct erofs_device_info *dif, erofs_off_t off, uint64_t len)
{
	erofs_off_t end, limit;

	if (dif->blocks > (UINT64_MAX >> sbi->blkszbits) ||
	    __builtin_add_overflow(off, len, &end))
		return (EINTEGRITY);
	limit = dif->blocks << sbi->blkszbits;
	return (end > limit ? EINTEGRITY : 0);
}

static void
erofs_fill_from_devinfo(struct erofs_map_dev *map,
    struct erofs_device_info *dif, erofs_off_t pa)
{
	map->m_dif = dif;
	map->m_pa = pa;
}

static int
erofs_map_dev_locate(struct erofs_sb_info *sbi, struct erofs_map_dev *map)
{
	struct erofs_device_info *dif;
	uint64_t start;
	unsigned int id;
	int error;

	erofs_fill_from_devinfo(map, &sbi->dif0, map->m_pa);
	if (map->m_deviceid != 0) {
		if (map->m_deviceid > sbi->extra_devices || sbi->devs == NULL)
			return (ENODEV);
		dif = &sbi->devs[map->m_deviceid - 1];
		error = erofs_check_device_range(sbi, dif, map->m_pa,
		    map->m_plen);
		if (error != 0)
			return (error);
		if (sbi->flatdev) {
			if (dif->uniaddr > (UINT64_MAX >> sbi->blkszbits))
				return (EINTEGRITY);
			start = dif->uniaddr << sbi->blkszbits;
			if (__builtin_add_overflow(map->m_pa, start,
				&map->m_pa))
				return (EINTEGRITY);
			return (0);
		}
		if (!erofs_source_is_open(dif))
			return (ENODEV);
		erofs_fill_from_devinfo(map, dif, map->m_pa);
		return (0);
	}

	if (sbi->extra_devices == 0)
		return (0);
	if (sbi->flatdev) {
		error = erofs_check_device_range(sbi, &sbi->dif0, map->m_pa,
		    map->m_plen);
		if (error == 0)
			return (0);
		for (id = 0; id < sbi->extra_devices; ++id) {
			dif = &sbi->devs[id];
			if (dif->uniaddr == 0 ||
			    dif->uniaddr > (UINT64_MAX >> sbi->blkszbits))
				continue;
			start = dif->uniaddr << sbi->blkszbits;
			if (map->m_pa < start)
				continue;
			error = erofs_check_device_range(sbi, dif,
			    map->m_pa - start, map->m_plen);
			if (error == 0)
				return (0);
			if (map->m_pa - start < (dif->blocks << sbi->blkszbits))
				return (error);
		}
		return (EINTEGRITY);
	}
	for (id = 0; id < sbi->extra_devices; ++id) {
		dif = &sbi->devs[id];
		if (dif->uniaddr == 0)
			continue;
		if (dif->uniaddr > (UINT64_MAX >> sbi->blkszbits))
			return (EINTEGRITY);
		start = dif->uniaddr << sbi->blkszbits;
		if (map->m_pa >= start &&
		    map->m_pa - start < (dif->blocks << sbi->blkszbits)) {
			error = erofs_check_device_range(sbi, dif,
			    map->m_pa - start, map->m_plen);
			if (error != 0)
				return (error);
			if (!erofs_source_is_open(dif))
				return (ENODEV);
			erofs_fill_from_devinfo(map, dif, map->m_pa - start);
			break;
		}
	}
	return (0);
}

/*
 * Resolve a physical range to a device.  The lookup tries several devices
 * and treats a miss on one as normal, so the corruption is reported here,
 * once, when no device is able to serve the range.
 */
static int
erofs_map_dev(struct erofs_sb_info *sbi, struct erofs_map_dev *map)
{
	uint64_t pa, plen;
	unsigned int deviceid;
	int error;

	pa = map->m_pa;
	plen = map->m_plen;
	deviceid = map->m_deviceid;
	error = erofs_map_dev_locate(sbi, map);
	if (error == EINTEGRITY)
		return (erofs_corrupt(sbi, EROFS_NID_NONE,
		    "range %ju+%ju of device %u is not backed by any device",
		    (uintmax_t)pa, (uintmax_t)plen, deviceid));
	return (error);
}

int
erofs_read_physical(struct erofs_sb_info *sbi, unsigned int device_id,
    erofs_off_t off, size_t len, void **bufp)
{
	struct erofs_map_dev map;
	erofs_blk_t blocks;
	int error;

	map = (struct erofs_map_dev) {
		.m_pa = off,
		.m_deviceid = device_id,
		.m_plen = len,
	};
	error = erofs_map_dev(sbi, &map);
	if (error != 0)
		return (error);
	blocks = map.m_dif->blocks;
	if (map.m_dif == &sbi->dif0 && sbi->flatdev)
		blocks = sbi->flatdev_blocks;
	return (erofs_bread_device(sbi, map.m_dif, blocks, map.m_pa, len, NULL,
	    NULL, 0, bufp));
}

static int
erofs_read_physical_readahead(struct erofs_sb_info *sbi, unsigned int device_id,
    erofs_off_t off, size_t len, unsigned int rablocks, void **bufp)
{
	struct erofs_map_dev current, future;
	daddr_t *rablkno;
	int *rabsize;
	erofs_off_t device_pa, step;
	erofs_blk_t blocks;
	unsigned int count;
	int error, ret;

	current = (struct erofs_map_dev) {
		.m_pa = off,
		.m_deviceid = device_id,
		.m_plen = len,
	};
	error = erofs_map_dev(sbi, &current);
	if (error != 0)
		return (error);
	blocks = current.m_dif->blocks;
	if (current.m_dif == &sbi->dif0 && sbi->flatdev)
		blocks = sbi->flatdev_blocks;
	if (rablocks == 0)
		return (erofs_bread_device(sbi, current.m_dif, blocks,
		    current.m_pa, len, NULL, NULL, 0, bufp));
	/*
	 * 256 slots are 2 KiB, which is a large part of a kernel stack inside
	 * the recursive read path, so keep the run lists off the stack.
	 */
	rablocks = MIN(rablocks, (unsigned int)EROFS_DIR_READAHEAD_SLOTS);
	rablkno = malloc(rablocks * sizeof(*rablkno), M_EROFS, M_WAITOK);
	rabsize = malloc(rablocks * sizeof(*rabsize), M_EROFS, M_WAITOK);
	for (count = 0; count < rablocks; count++) {
		step = (erofs_off_t)(count + 1) * sbi->block_size;
		if (off > UINT64_MAX - step || current.m_pa > UINT64_MAX - step)
			break;
		future = (struct erofs_map_dev) {
			.m_pa = off + step,
			.m_deviceid = device_id,
			.m_plen = sbi->block_size,
		};
		if (erofs_map_dev(sbi, &future) != 0 ||
		    future.m_dif != current.m_dif ||
		    future.m_pa != current.m_pa + step)
			break;
		if (__builtin_add_overflow(future.m_dif->fsoff, future.m_pa,
			&device_pa) ||
		    device_pa > INT64_MAX)
			break;
		rablkno[count] = btodb(device_pa);
		rabsize[count] = sbi->block_size;
	}
	ret = erofs_bread_device(sbi, current.m_dif, blocks, current.m_pa, len,
	    rablkno, rabsize, count, bufp);
	free(rabsize, M_EROFS);
	free(rablkno, M_EROFS);
	return (ret);
}

static int
erofs_read_data_impl(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, unsigned int rablocks, void **bufp)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_map_blocks map;
	char *out;
	void *blk;
	erofs_off_t mapoff, physical;
	size_t done, want;
	int error;

	if (bufp == NULL)
		return (EINVAL);
	*bufp = NULL;
	if (len == 0) {
		return (0);
	}
	EROFS_TRACE_READ_FOLIO(vi, loff, len,
	    !erofs_inode_is_data_compressed(vi->datalayout));
	if (loff > vi->size || (uint64_t)len > vi->size - loff)
		return (erofs_corrupt(sbi, vi->nid,
		    "read of %zu bytes at %ju is beyond the size %ju", len,
		    (uintmax_t)loff, (uintmax_t)vi->size));

	/* Compressed file path */
	if (erofs_inode_is_data_compressed(vi->datalayout))
		return (z_erofs_read_data(sbi, vi, loff, len, bufp));

	/* Uncompressed file path */
	out = malloc(len, M_EROFS, M_WAITOK);
	done = 0;
	while (done < len) {
		map = (struct erofs_map_blocks) { .m_la = loff + done };
		error = erofs_map_blocks(sbi, vi, &map);
		if (error != 0) {
			free(out, M_EROFS);
			return (error);
		}
		if (map.m_llen == 0 || map.m_la > loff + done ||
		    loff + done - map.m_la >= map.m_llen) {
			free(out, M_EROFS);
			return (erofs_corrupt(sbi, vi->nid,
			    "mapping of offset %ju is empty or does not cover "
			    "it",
			    (uintmax_t)(loff + done)));
		}
		mapoff = loff + done - map.m_la;
		want = MIN((size_t)MIN(map.m_llen - mapoff, (uint64_t)MAXPHYS),
		    len - done);
		if ((map.m_flags & EROFS_MAP_MAPPED) == 0) {
			bzero(out + done, want);
		} else {
			if ((map.m_flags & EROFS_MAP_META) != 0) {
				if (mapoff > UINT64_MAX - map.m_pa) {
					free(out, M_EROFS);
					return (EOVERFLOW);
				}
				physical = map.m_pa + mapoff;
				error = erofs_read_metadata_range(sbi, vi->nid,
				    physical, want, &buf);
			} else if (done == 0 && mapoff == 0 && rablocks != 0 &&
			    map.m_flags == EROFS_MAP_MAPPED) {
				error = erofs_read_physical_readahead(sbi,
				    map.m_deviceid, map.m_pa, want, rablocks,
				    &blk);
			} else {
				if (mapoff > UINT64_MAX - map.m_pa) {
					free(out, M_EROFS);
					return (EOVERFLOW);
				}
				physical = map.m_pa + mapoff;
				error = erofs_read_physical(sbi, map.m_deviceid,
				    physical, want, &blk);
			}
			if (error != 0) {
				free(out, M_EROFS);
				return (error);
			}
			if ((map.m_flags & EROFS_MAP_META) != 0) {
				memcpy(out + done, buf.data, want);
				erofs_put_metabuf(&buf);
			} else {
				memcpy(out + done, blk, want);
				erofs_brelse(blk);
			}
		}
		done += want;
	}
	*bufp = out;
	return (0);
}

int
erofs_read_data(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, void **bufp)
{
	return (erofs_read_data_impl(sbi, vi, loff, len, 0, bufp));
}

int
erofs_read_data_readahead(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, bool sequential, void **bufp)
{
	uint64_t dir_ra_bytes, total_blocks;
	uint64_t remaining;
	unsigned int rablocks;
	int error;

	rablocks = 0;
	if (sequential && vi->datalayout == EROFS_INODE_FLAT_PLAIN &&
	    sbi->block_size != 0 && (loff & (sbi->block_size - 1)) == 0 &&
	    len <= sbi->block_size && loff <= vi->size &&
	    len <= vi->size - loff) {
		dir_ra_bytes = erofs_dir_ra_bytes(sbi);
		total_blocks = dir_ra_bytes / sbi->block_size;
		if (total_blocks > 1) {
			remaining = vi->size - loff - len;
			rablocks = MIN(total_blocks - 1,
			    howmany(remaining, sbi->block_size));
			rablocks = MIN(rablocks,
			    (unsigned int)EROFS_DIR_READAHEAD_SLOTS);
		}
	}
	EROFS_TRACE_READAHEAD(vi, loff >> PAGE_SHIFT,
	    howmany((uint64_t)len +
		    (uint64_t)rablocks * (uint64_t)sbi->block_size,
		PAGE_SIZE),
	    !erofs_inode_is_data_compressed(vi->datalayout));
	error = erofs_read_data_impl(sbi, vi, loff, len, rablocks, bufp);
	if (error == 0 && rablocks != 0)
		erofs_record_dir_readahead(sbi, rablocks);
	return (error);
}
