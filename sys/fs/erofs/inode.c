// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/fnv_hash.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#include <fs/erofs/trace.h>

static uint64_t
erofs_addrmask(const struct erofs_sb_info *sbi)
{
	if (erofs_sb_has_48bit(sbi))
		return ((1ULL << 48) - 1);
	return (UINT32_MAX);
}

static dev_t
erofs_decode_dev(uint32_t dev)
{
	unsigned int major, minor;

	major = (dev & 0xfff00) >> 8;
	minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	return (makedev(major, minor));
}

static uint32_t
erofs_inode_generation(const struct erofs_sb_info *sbi, erofs_nid_t nid,
    const void *inode, size_t inode_size)
{
	uint8_t encoded_nid[sizeof(nid)];
	uint32_t generation;

	le64enc(encoded_nid, nid);
	generation = fnv_32_buf(encoded_nid, sizeof(encoded_nid),
	    sbi->generation_seed);
	generation = fnv_32_buf(inode, inode_size, generation);
	return (generation != 0 ? generation : 1);
}

static int
erofs_set_timestamp(struct erofs_inode *vi, int64_t seconds,
    uint32_t nanoseconds)
{
	/* Keep va_mtime a valid timespec; mkfs.erofs never writes this. */
	if (nanoseconds >= 1000000000)
		return (EINTEGRITY);
	vi->mtime = seconds;
	vi->mtime_nsec = nanoseconds;
	return (0);
}

static void
erofs_set_data_blocks(const struct erofs_sb_info *sbi, struct erofs_inode *vi,
    uint64_t compressed_blocks)
{
	if (erofs_inode_is_data_compressed(vi->datalayout))
		vi->data_blocks = compressed_blocks;
	else if (vi->size == 0)
		vi->data_blocks = 0;
	else
		/* size is at most OFF_MAX (checked by the caller). */
		vi->data_blocks = roundup2(vi->size,
				      (uint64_t)sbi->block_size) >>
		    sbi->blkszbits;
}

static int
erofs_validate_inline_data(const struct erofs_sb_info *sbi,
    const struct erofs_inode *vi)
{
	uint64_t image_size, inline_end, inline_off, inline_size, tail_start;

	if (vi->datalayout != EROFS_INODE_FLAT_INLINE || vi->size == 0)
		return (0);
	tail_start = roundup2(vi->size, (uint64_t)sbi->block_size) -
	    sbi->block_size;
	inline_size = vi->size - tail_start;
	if (__builtin_add_overflow(vi->inode_off, vi->inode_isize,
		&inline_off) ||
	    __builtin_add_overflow(inline_off, vi->xattr_isize, &inline_off) ||
	    __builtin_add_overflow(inline_off, inline_size, &inline_end))
		return (erofs_corrupt(sbi, vi->nid,
		    "inline tail offset overflows"));
	if ((inline_off & (sbi->block_size - 1)) + inline_size >
	    sbi->block_size)
		return (erofs_corrupt(sbi, vi->nid,
		    "inline tail of %ju bytes crosses its block",
		    (uintmax_t)inline_size));
	if (erofs_nid_in_metabox(vi->nid)) {
		if (sbi->metabox_en == NULL ||
		    inline_end > sbi->metabox_en->size)
			return (erofs_corrupt(sbi, vi->nid,
			    "inline tail ends at %ju, beyond the metabox",
			    (uintmax_t)inline_end));
		return (0);
	}
	/* The image fits its provider; see erofs_nid_is_valid(). */
	image_size = sbi->blocks << sbi->blkszbits;
	if (inline_end > image_size)
		return (erofs_corrupt(sbi, vi->nid,
		    "inline tail ends at %ju, beyond the image",
		    (uintmax_t)inline_end));
	return (0);
}

/*
 * Convert a logical nid to its inode-table byte offset.  Normal NIDs are
 * relative to the primary metadata area.  For metabox NIDs, bit 63 selects
 * the metabox backing inode and the remaining bits are relative to its data.
 * EROFS_NULL_ADDR is returned when the address cannot be represented.
 */
static erofs_off_t
erofs_iloc(struct erofs_sb_info *sbi, erofs_nid_t nid)
{
	erofs_off_t meta_offset;
	erofs_nid_t nid_lo;
	erofs_off_t result;
	bool in_metabox;

	in_metabox = erofs_nid_in_metabox(nid);
	if (in_metabox && !erofs_sb_has_metabox(sbi))
		return (EROFS_NULL_ADDR);
	nid_lo = nid & EROFS_DIRENT_NID_MASK;
	if (nid_lo > (UINT64_MAX >> 5))
		return (EROFS_NULL_ADDR);
	result = nid_lo << 5;
	if (in_metabox)
		return (result);

	meta_offset = (uint64_t)sbi->meta_blkaddr << sbi->blkszbits;
	if (result > UINT64_MAX - meta_offset)
		return (EROFS_NULL_ADDR);

	return (meta_offset + result);
}

/*
 * Check that a NID can address at least one compact inode slot without
 * crossing the declared primary image or metabox backing-file boundary.
 */
bool
erofs_nid_is_valid(struct erofs_sb_info *sbi, erofs_nid_t nid)
{
	erofs_off_t image_size, off;

	off = erofs_iloc(sbi, nid);
	if (off == EROFS_NULL_ADDR)
		return (false);
	if (erofs_nid_in_metabox(nid)) {
		if (sbi->metabox_en == NULL || off > sbi->metabox_en->size)
			return (false);
		return (sizeof(struct erofs_inode_compact) <=
		    sbi->metabox_en->size - off);
	}
	/*
	 * The image fits its provider (erofs_validate_device_size()), and a
	 * block count has at most 48 bits, so neither the shift nor the
	 * provider size needs a check here.
	 */
	image_size = sbi->blocks << sbi->blkszbits;
	return (off <= image_size &&
	    sizeof(struct erofs_inode_compact) <= image_size - off);
}
