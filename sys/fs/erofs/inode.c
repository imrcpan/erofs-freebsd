// SPDX-License-Identifier: MIT
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
#include <fs/erofs/xattr.h>

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

int
erofs_read_inode(struct erofs_sb_info *sbi, erofs_nid_t nid,
    struct erofs_inode *vi)
{
	struct erofs_inode_compact *dic;
	struct erofs_inode_extended *die;
	struct erofs_inode_chunk_info chunk_info;
	union erofs_inode_i_nb inode_nb;
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	uint64_t addrmask;
	int64_t mtime;
	erofs_off_t off;
	erofs_blk_t startblk;
	uint64_t compressed_blocks;
	uint32_t raw_rdev, startblk_lo;
	uint16_t ifmt, startblk_hi;
	int err;

	if (!erofs_nid_is_valid(sbi, nid))
		return (erofs_corrupt(sbi, nid, "invalid nid"));
	off = erofs_iloc(sbi, nid);
	EROFS_TRACE_FILL_INODE(nid, off >> sbi->blkszbits,
	    off & (sbi->block_size - 1));
	err = erofs_read_metadata_range(sbi, nid, off,
	    sizeof(struct erofs_inode_compact), &buf);
	if (err != 0)
		return (err);

	bzero(&vi->size, sizeof(*vi) - offsetof(struct erofs_inode, size));
	vi->nid = nid;
	vi->inode_off = off;
	ifmt = le16dec(buf.data);
	if ((ifmt & ~EROFS_I_ALL) != 0) {
		erofs_put_metabuf(&buf);
		erofs_err(sbi, "unsupported inode format %#x @ nid %ju", ifmt,
		    (uintmax_t)nid);
		return (EOPNOTSUPP);
	}
	vi->datalayout = erofs_inode_datalayout(ifmt);
	if (vi->datalayout >= EROFS_INODE_DATALAYOUT_MAX) {
		erofs_put_metabuf(&buf);
		erofs_err(sbi, "unsupported data layout %u @ nid %ju",
		    vi->datalayout, (uintmax_t)nid);
		return (EOPNOTSUPP);
	}
	vi->compact_inode = (erofs_inode_version(ifmt) == 0);
	if (!vi->compact_inode) {
		erofs_put_metabuf(&buf);
		err = erofs_read_metadata_range(sbi, nid, off,
		    sizeof(struct erofs_inode_extended), &buf);
		if (err != 0)
			return (err);
	}
	addrmask = erofs_addrmask(sbi);
	startblk = EROFS_NULL_ADDR;
	startblk_lo = 0;
	startblk_hi = 0;
	compressed_blocks = 0;
	raw_rdev = 0;
	bzero(&inode_nb, sizeof(inode_nb));
	dic = buf.data;
	if (vi->compact_inode) {
		vi->inode_isize = sizeof(struct erofs_inode_compact);
		vi->generation = erofs_inode_generation(sbi, nid, buf.data,
		    vi->inode_isize);
		vi->mode = le16toh(dic->i_mode);
		vi->size = le32toh(dic->i_size);
		vi->uid = le16toh(dic->i_uid);
		vi->gid = le16toh(dic->i_gid);
		vi->xattr_isize = erofs_xattr_ibody_size(dic->i_xattr_icount);
		if (__builtin_add_overflow(sbi->epoch,
			(int64_t)le32toh(dic->i_mtime), &mtime)) {
			erofs_put_metabuf(&buf);
			return (erofs_corrupt(sbi, nid,
			    "mtime overflows the superblock epoch"));
		}
		err = erofs_set_timestamp(vi, mtime, sbi->fixed_nsec);
		if (err != 0) {
			erofs_put_metabuf(&buf);
			return (erofs_corrupt(sbi, nid, "invalid mtime nsec %u",
			    sbi->fixed_nsec));
		}
		startblk_lo = le32toh(dic->i_u.startblk_lo);
		compressed_blocks = le32toh(dic->i_u.blocks_lo);
		raw_rdev = le32toh(dic->i_u.rdev);
		if (!S_ISDIR(vi->mode) &&
		    ((ifmt >> EROFS_I_NLINK_1_BIT) & 0x1) != 0) {
			vi->nlink = 1;
			inode_nb = dic->i_nb;
		} else {
			vi->nlink = le16toh(dic->i_nb.nlink);
			addrmask = UINT32_MAX;
		}
	} else {
		die = buf.data;
		vi->inode_isize = sizeof(struct erofs_inode_extended);
		vi->generation = erofs_inode_generation(sbi, nid, buf.data,
		    vi->inode_isize);
		vi->mode = le16toh(die->i_mode);
		vi->size = le64toh(die->i_size);
		vi->uid = le32toh(die->i_uid);
		vi->gid = le32toh(die->i_gid);
		vi->nlink = le32toh(die->i_nlink);
		inode_nb = die->i_nb;
		vi->xattr_isize = erofs_xattr_ibody_size(die->i_xattr_icount);
		err = erofs_set_timestamp(vi, (int64_t)le64toh(die->i_mtime),
		    le32toh(die->i_mtime_nsec));
		if (err != 0) {
			erofs_put_metabuf(&buf);
			return (erofs_corrupt(sbi, nid, "invalid mtime nsec %u",
			    le32toh(die->i_mtime_nsec)));
		}
		startblk_lo = le32toh(die->i_u.startblk_lo);
		compressed_blocks = le32toh(die->i_u.blocks_lo);
		raw_rdev = le32toh(die->i_u.rdev);
	}
	startblk_hi = le16toh(inode_nb.startblk_hi);
	compressed_blocks |= (uint64_t)le16toh(inode_nb.blocks_hi) << 32;
	if (vi->size > (uint64_t)OFF_MAX) {
		erofs_put_metabuf(&buf);
		return (erofs_corrupt(sbi, nid, "size %ju is too large",
		    (uintmax_t)vi->size));
	}

	vi->vtype = IFTOVT(vi->mode);
	/* A mode with an unknown file type cannot be given a vnode type. */
	if (vi->mode != 0 && vi->vtype == VNON) {
		erofs_put_metabuf(&buf);
		return (erofs_corrupt(sbi, nid, "invalid mode %#o", vi->mode));
	}
	if (vi->vtype == VLNK) {
		if (vi->size == 0) {
			erofs_put_metabuf(&buf);
			return (erofs_corrupt(sbi, nid, "empty symlink"));
		}
	}
	vi->dot_omitted = (vi->vtype == VDIR) &&
	    (((ifmt >> EROFS_I_DOT_OMITTED_BIT) & 0x1) != 0);

	if (erofs_inode_is_data_compressed(vi->datalayout)) {
		err = z_erofs_fill_inode(sbi, vi);
		if (err != 0) {
			erofs_put_metabuf(&buf);
			return (err);
		}
	} else if (vi->datalayout == EROFS_INODE_CHUNK_BASED) {
		if (vi->compact_inode)
			chunk_info = dic->i_u.c;
		else
			chunk_info = die->i_u.c;
		if (le16toh(chunk_info.reserved) != 0) {
			erofs_put_metabuf(&buf);
			return (erofs_corrupt(sbi, nid,
			    "reserved chunk field %#x is set",
			    le16toh(chunk_info.reserved)));
		}
		vi->chunkformat = le16toh(chunk_info.format);
		if (vi->chunkformat & ~EROFS_CHUNK_FORMAT_ALL) {
			erofs_put_metabuf(&buf);
			erofs_err(sbi, "unsupported chunk format %#x @ nid %ju",
			    vi->chunkformat, (uintmax_t)nid);
			return (EOPNOTSUPP);
		}
		if ((vi->chunkformat & EROFS_CHUNK_FORMAT_48BIT) != 0 &&
		    (vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES) == 0) {
			erofs_put_metabuf(&buf);
			return (erofs_corrupt(sbi, nid,
			    "chunk format %#x: 48-bit without chunk indexes",
			    vi->chunkformat));
		}
		vi->chunkbits = sbi->blkszbits +
		    (vi->chunkformat & EROFS_CHUNK_FORMAT_BLKBITS_MASK);
	} else if (vi->datalayout != EROFS_INODE_FLAT_PLAIN &&
	    vi->datalayout != EROFS_INODE_FLAT_INLINE) {
		erofs_put_metabuf(&buf);
		erofs_err(sbi, "unsupported data layout %u @ nid %ju",
		    vi->datalayout, (uintmax_t)nid);
		return (EOPNOTSUPP);
	}

	switch (vi->vtype) {
	case VREG:
	case VDIR:
	case VLNK:
		if (vi->datalayout == EROFS_INODE_CHUNK_BASED) {
			vi->startblk = EROFS_NULL_ADDR;
			vi->rdev = NODEV;
			break;
		}
		startblk = startblk_lo | ((uint64_t)startblk_hi << 32);
		if (vi->datalayout == EROFS_INODE_FLAT_PLAIN &&
		    ((startblk ^ EROFS_NULL_ADDR) & addrmask) == 0)
			startblk = EROFS_NULL_ADDR;
		vi->startblk = startblk;
		vi->rdev = NODEV;
		break;
	case VCHR:
	case VBLK:
		vi->startblk = EROFS_NULL_ADDR;
		vi->rdev = erofs_decode_dev(raw_rdev);
		break;
	case VFIFO:
	case VSOCK:
		vi->startblk = EROFS_NULL_ADDR;
		vi->rdev = NODEV;
		break;
	default:
		erofs_put_metabuf(&buf);
		return (erofs_corrupt(sbi, nid, "unknown file type, mode %#o",
		    vi->mode));
	}
	erofs_set_data_blocks(sbi, vi, compressed_blocks);
	err = erofs_validate_inline_data(sbi, vi);
	if (err != 0) {
		erofs_put_metabuf(&buf);
		return (err);
	}

	erofs_put_metabuf(&buf);
	return (0);
}
