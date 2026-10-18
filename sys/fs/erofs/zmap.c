// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             https://www.huawei.com/
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/libkern.h>

#include <fs/erofs/internal.h>

struct z_erofs_maprecorder {
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	struct erofs_map_blocks *map;
	uint64_t lcn;
	uint8_t type, headtype;
	unsigned int clusterofs;
	uint16_t delta[2];
	erofs_blk_t pblk, compressedblks;
	erofs_off_t nextpackoff;
	bool partialref;
};

_Static_assert((EROFS_MAP_MAPPED | EROFS_MAP_META | EROFS_MAP_PARTIAL_MAPPED |
		   EROFS_MAP_PARTIAL_REF | EROFS_MAP_FRAGMENT) == 0x1f,
    "map adapter must preserve every map flag");

/*
 * Offsets and shifts here are not checked for overflow.  The superblock and
 * inode readers bound blkszbits, z_lclusterbits and the inode size, and a
 * position that did wrap is still range checked when it is read.
 */

/* The map header follows the inode and its xattrs, 8-byte aligned. */
static inline erofs_off_t
z_erofs_header_pos(const struct erofs_inode *vi)
{
	return (roundup2(vi->inode_off + vi->inode_isize + vi->xattr_isize, 8));
}

static int
z_erofs_read_index(struct z_erofs_maprecorder *m, erofs_off_t pos, size_t len,
    struct erofs_buf *buf)
{
	return (erofs_read_metadata_range(m->sbi, m->vi->nid, pos, len, buf));
}

static int
z_erofs_load_full_lcluster(struct z_erofs_maprecorder *m, uint64_t lcn)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_inode *vi;
	struct z_erofs_lcluster_index *di;
	erofs_off_t base, pos;
	unsigned int advise;
	int error;

	vi = m->vi;
	base = z_erofs_header_pos(vi) + sizeof(struct z_erofs_map_header) + 8;
	pos = base + lcn * sizeof(*di);
	m->nextpackoff = pos + sizeof(*di);
	error = z_erofs_read_index(m, pos, sizeof(*di), &buf);
	if (error != 0)
		return (error);

	di = buf.data;
	m->lcn = lcn;
	advise = le16toh(di->di_advise);
	m->type = advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK;
	if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
		m->clusterofs = 1U << vi->z_lclusterbits;
		m->delta[0] = le16toh(di->di_u.delta[0]);
		if ((m->delta[0] & Z_EROFS_LI_D0_CBLKCNT) != 0) {
			if ((vi->z_advise &
				(Z_EROFS_ADVISE_BIG_PCLUSTER_1 |
				    Z_EROFS_ADVISE_BIG_PCLUSTER_2)) == 0) {
				erofs_put_metabuf(&buf);
				return (erofs_corrupt(m->sbi, vi->nid,
				    "lcn %ju has a compressed block count but "
				    "the inode has no big pclusters",
				    (uintmax_t)lcn));
			}
			m->compressedblks = m->delta[0] &
			    ~Z_EROFS_LI_D0_CBLKCNT;
			m->delta[0] = 1;
		}
		m->delta[1] = le16toh(di->di_u.delta[1]);
	} else {
		m->partialref = (advise & Z_EROFS_LI_PARTIAL_REF) != 0;
		m->clusterofs = le16toh(di->di_clusterofs);
		m->pblk = le32toh(di->di_u.blkaddr);
	}
	erofs_put_metabuf(&buf);
	return (0);
}

static unsigned int
decode_compactedbits(unsigned int lobits, const uint8_t *in, unsigned int pos,
    uint8_t *type)
{
	uint32_t v;
	unsigned int lo;

	v = le32dec(in + pos / 8) >> (pos & 7);
	lo = v & ((1U << lobits) - 1);
	*type = (v >> lobits) & 3;
	return (lo);
}

static unsigned int
get_compacted_la_distance(unsigned int lobits, unsigned int encodebits,
    unsigned int vcnt, const uint8_t *in, int i)
{
	unsigned int lo, d1;
	uint8_t type;

	d1 = 0;
	do {
		lo = decode_compactedbits(lobits, in, encodebits * i, &type);
		if (type != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
			return (d1);
		++d1;
	} while (++i < (int)vcnt);

	/* vcnt - 1 (Z_EROFS_LCLUSTER_TYPE_NONHEAD) item */
	if ((lo & Z_EROFS_LI_D0_CBLKCNT) == 0)
		d1 += lo - 1;
	return (d1);
}

static int
z_erofs_load_compact_lcluster(struct z_erofs_maprecorder *m, uint64_t lcn,
    bool lookahead)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_inode *vi;
	erofs_off_t ebase, pos;
	uint64_t compacted_2b, totalidx, original_lcn;
	unsigned int compacted_4b_initial, amortizedshift;
	unsigned int vcnt, lo, lobits, encodebits, nblk, bytes, packsize;
	bool big_pcluster;
	uint8_t *in, type;
	int error, i;

	vi = m->vi;
	/*
	 * A compact index entry is 16 bits (4-byte units) or 14 bits (2-byte
	 * units): a 2-bit type and the offset in the lcluster.  Linux has the
	 * same limit.
	 */
	if (vi->z_lclusterbits > 14)
		return (erofs_corrupt(m->sbi, vi->nid,
		    "invalid lcluster bits %u", vi->z_lclusterbits));
	ebase = z_erofs_header_pos(vi) + sizeof(struct z_erofs_map_header);
	totalidx = (vi->size + (1ULL << vi->z_lclusterbits) - 1) >>
	    vi->z_lclusterbits;
	if (lcn >= totalidx)
		return (EINVAL);

	original_lcn = lcn;
	m->lcn = lcn;
	compacted_4b_initial = ((32 - ebase % 32) / 4) & 7;
	compacted_2b = 0;
	if ((vi->z_advise & Z_EROFS_ADVISE_COMPACTED_2B) != 0 &&
	    compacted_4b_initial < totalidx)
		compacted_2b = rounddown2(totalidx - compacted_4b_initial, 16);

	pos = ebase;
	amortizedshift = 2;
	if (lcn >= compacted_4b_initial) {
		pos += compacted_4b_initial * 4;
		lcn -= compacted_4b_initial;
		if (lcn < compacted_2b) {
			amortizedshift = 1;
		} else {
			pos += compacted_2b * 2;
			lcn -= compacted_2b;
		}
	}
	pos += lcn << amortizedshift;

	if (amortizedshift == 2 && vi->z_lclusterbits <= 14)
		vcnt = 2;
	else if (amortizedshift == 1 && vi->z_lclusterbits <= 12)
		vcnt = 16;
	else {
		erofs_err(m->sbi, "unsupported lcluster bits %u @ nid %ju",
		    vi->z_lclusterbits, (uintmax_t)vi->nid);
		return (EOPNOTSUPP);
	}

	packsize = vcnt << amortizedshift;
	bytes = pos & (packsize - 1);
	pos -= bytes;
	m->nextpackoff = pos + packsize;
	error = z_erofs_read_index(m, pos, packsize, &buf);
	if (error != 0)
		return (error);
	in = buf.data;
	lobits = MAX(vi->z_lclusterbits, fls(Z_EROFS_LI_D0_CBLKCNT));
	encodebits = (packsize - sizeof(uint32_t)) * 8 / vcnt;
	i = bytes >> amortizedshift;

	lo = decode_compactedbits(lobits, in, encodebits * i, &type);
	m->type = type;
	if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
		m->clusterofs = 1U << vi->z_lclusterbits;
		if (lookahead) {
			m->delta[1] = get_compacted_la_distance(lobits,
			    encodebits, vcnt, in, i);
		}
		big_pcluster = (vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1) !=
		    0;
		if ((lo & Z_EROFS_LI_D0_CBLKCNT) != 0) {
			if (!big_pcluster) {
				erofs_put_metabuf(&buf);
				return (erofs_corrupt(m->sbi, vi->nid,
				    "lcn %ju has a compressed block count but "
				    "the inode has no big pclusters",
				    (uintmax_t)original_lcn));
			}
			m->compressedblks = lo & ~Z_EROFS_LI_D0_CBLKCNT;
			m->delta[0] = 1;
		} else if (i + 1 != (int)vcnt) {
			m->delta[0] = lo;
		} else {
			KASSERT(i > 0, ("erofs: pack of %u slots", vcnt));
			lo = decode_compactedbits(lobits, in,
			    encodebits * (i - 1), &type);
			if (type != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
				lo = 0;
			else if ((lo & Z_EROFS_LI_D0_CBLKCNT) != 0)
				lo = 1;
			m->delta[0] = lo + 1;
		}
		erofs_put_metabuf(&buf);
		return (0);
	}

	m->clusterofs = lo;
	m->delta[0] = 0;
	big_pcluster = (vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1) != 0;
	if (!big_pcluster) {
		nblk = 1;
		while (i > 0) {
			--i;
			lo = decode_compactedbits(lobits, in, encodebits * i,
			    &type);
			if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD)
				i -= lo;
			if (i >= 0)
				++nblk;
		}
	} else {
		nblk = 0;
		while (i > 0) {
			--i;
			lo = decode_compactedbits(lobits, in, encodebits * i,
			    &type);
			if (type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
				if ((lo & Z_EROFS_LI_D0_CBLKCNT) != 0) {
					--i;
					nblk += lo & ~Z_EROFS_LI_D0_CBLKCNT;
					continue;
				}
				if (lo <= 1) {
					erofs_put_metabuf(&buf);
					return (erofs_corrupt(m->sbi, vi->nid,
					    "invalid delta %u before lcn %ju",
					    lo, (uintmax_t)original_lcn));
				}
				i -= lo - 2;
				continue;
			}
			++nblk;
		}
	}
	m->pblk = (erofs_blk_t)le32dec(in + packsize - sizeof(uint32_t)) + nblk;
	erofs_put_metabuf(&buf);
	m->lcn = original_lcn;
	return (0);
}

static int
z_erofs_load_lcluster_from_disk(struct z_erofs_maprecorder *m, uint64_t lcn,
    bool lookahead)
{
	int err;

	KASSERT(m->vi->datalayout == EROFS_INODE_COMPRESSED_COMPACT ||
		m->vi->datalayout == EROFS_INODE_COMPRESSED_FULL,
	    ("erofs: data layout %u is not compressed", m->vi->datalayout));
	if (m->vi->datalayout == EROFS_INODE_COMPRESSED_COMPACT)
		err = z_erofs_load_compact_lcluster(m, lcn, lookahead);
	else
		err = z_erofs_load_full_lcluster(m, lcn);
	if (err != 0)
		return (err);
	/* The type is a 2-bit field, so it is always below TYPE_MAX. */
	if (m->type != Z_EROFS_LCLUSTER_TYPE_NONHEAD &&
	    m->clusterofs >= (1U << m->vi->z_lclusterbits))
		return (erofs_corrupt(m->sbi, m->vi->nid,
		    "clusterofs %u of lcn %ju is out of range", m->clusterofs,
		    (uintmax_t)lcn));
	return (0);
}

static int
z_erofs_extent_lookback(struct z_erofs_maprecorder *m,
    unsigned int lookback_distance)
{
	uint64_t lcn;
	int err;

	while (lookback_distance != 0 && m->lcn >= lookback_distance) {
		lcn = m->lcn - lookback_distance;
		err = z_erofs_load_lcluster_from_disk(m, lcn, false);
		if (err != 0)
			return (err);
		if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
			lookback_distance = m->delta[0];
			continue;
		}
		m->headtype = m->type;
		m->map->m_la = (lcn << m->vi->z_lclusterbits) + m->clusterofs;
		return (0);
	}
	return (erofs_corrupt(m->sbi, m->vi->nid,
	    "no head lcluster found looking back from lcn %ju",
	    (uintmax_t)m->lcn));
}

static int
z_erofs_get_extent_compressedlen(struct z_erofs_maprecorder *m)
{
	struct erofs_inode *vi;
	bool bigpcl1, bigpcl2;
	uint64_t lcn, lcnpos;
	int err;

	vi = m->vi;
	bigpcl1 = (vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_1) != 0;
	bigpcl2 = (vi->z_advise & Z_EROFS_ADVISE_BIG_PCLUSTER_2) != 0;
	lcn = m->lcn + 1;
	lcnpos = lcn << vi->z_lclusterbits;
	if ((m->headtype == Z_EROFS_LCLUSTER_TYPE_HEAD1 && !bigpcl1) ||
	    ((m->headtype == Z_EROFS_LCLUSTER_TYPE_PLAIN ||
		 m->headtype == Z_EROFS_LCLUSTER_TYPE_HEAD2) &&
		!bigpcl2) ||
	    lcnpos >= vi->size)
		m->compressedblks = 1;
	if (m->compressedblks == 0) {
		err = z_erofs_load_lcluster_from_disk(m, lcn, false);
		if (err != 0)
			return (err);
		if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD &&
		    m->delta[0] != 1)
			return (erofs_corrupt(m->sbi, vi->nid,
			    "lcn %ju: delta %u should be 1 for the compressed "
			    "block count",
			    (uintmax_t)lcn, m->delta[0]));
		if (m->type != Z_EROFS_LCLUSTER_TYPE_NONHEAD ||
		    m->compressedblks == 0)
			m->compressedblks = 1;
	}
	m->map->m_plen = m->compressedblks * m->sbi->block_size;
	return (0);
}

static int
z_erofs_get_extent_decompressedlen(struct z_erofs_maprecorder *m)
{
	struct erofs_inode *vi;
	struct erofs_map_blocks *map;
	uint64_t lcn, headlcn, lend, lcnpos;
	int err;

	vi = m->vi;
	map = m->map;
	lcn = m->lcn;
	headlcn = map->m_la >> vi->z_lclusterbits;
	for (;;) {
		lcnpos = lcn << vi->z_lclusterbits;
		if (lcnpos >= vi->size) {
			KASSERT(map->m_la <= vi->size,
			    ("erofs: extent at %ju beyond the size %ju",
				(uintmax_t)map->m_la, (uintmax_t)vi->size));
			map->m_llen = vi->size - map->m_la;
			return (0);
		}
		err = z_erofs_load_lcluster_from_disk(m, lcn, true);
		if (err != 0)
			return (err);
		if (m->type == Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
			if (m->delta[1] == 0)
				m->delta[1] = 1;
		} else {
			if (lcn != headlcn)
				break;
			m->delta[1] = 1;
		}
		lcn += m->delta[1];
	}
	lend = (lcn << vi->z_lclusterbits) + m->clusterofs;
	KASSERT(lend >= map->m_la,
	    ("erofs: extent ends at %ju, before its start %ju", (uintmax_t)lend,
		(uintmax_t)map->m_la));
	map->m_llen = lend - map->m_la;
	return (0);
}

static inline erofs_off_t
z_erofs_extent_table_pos(const struct erofs_inode *vi, unsigned int recsz)
{
	return (
	    roundup2(z_erofs_header_pos(vi) + sizeof(struct z_erofs_map_header),
		recsz));
}

static inline erofs_off_t
z_erofs_extent_record_pos(erofs_off_t table_pos, unsigned int recsz,
    uint64_t index)
{
	return (table_pos + index * recsz);
}

static int
z_erofs_read_extent(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t pos, unsigned int recsz, struct z_erofs_extent *ext)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	int error;

	bzero(ext, sizeof(*ext));
	error = erofs_read_metadata_range(sbi, vi->nid, pos, recsz, &buf);
	if (error != 0)
		return (error);
	memcpy(ext, buf.data, recsz);
	erofs_put_metabuf(&buf);
	return (0);
}

static uint64_t
z_erofs_extent_lstart(const struct z_erofs_extent *ext, unsigned int recsz)
{
	uint64_t lstart;

	lstart = le32toh(ext->lstart_lo);
	if (recsz > offsetof(struct z_erofs_extent, lstart_hi))
		lstart |= (uint64_t)le32toh(ext->lstart_hi) << 32;
	return (lstart);
}

static int
z_erofs_map_blocks_fo(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map, int flags)
{
	bool fragment, ztailpacking;
	struct z_erofs_maprecorder m;
	uint64_t initial_lcn, ofs, end;
	unsigned int endoff;
	int err;

	fragment = (vi->z_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER) != 0;
	ztailpacking = vi->z_idata_size != 0;
	bzero(&m, sizeof(m));
	m.sbi = sbi;
	m.vi = vi;
	m.map = map;

	if (vi->size == 0) {
		map->m_la = 0;
		map->m_llen = 0;
		map->m_flags = 0;
		return (0);
	}
	ofs = (flags & EROFS_GET_BLOCKS_FINDTAIL) != 0 ? vi->size - 1 :
							 map->m_la;
	if (fragment && (flags & EROFS_GET_BLOCKS_FINDTAIL) == 0 &&
	    vi->z_tailextent_headlcn == 0) {
		map->m_la = 0;
		map->m_llen = vi->size;
		map->m_flags = EROFS_MAP_FRAGMENT;
		return (0);
	}
	initial_lcn = ofs >> vi->z_lclusterbits;
	endoff = ofs & ((1U << vi->z_lclusterbits) - 1);
	err = z_erofs_load_lcluster_from_disk(&m, initial_lcn, false);
	if (err != 0)
		return (err);
	if ((flags & EROFS_GET_BLOCKS_FINDTAIL) != 0 && ztailpacking)
		vi->z_fragmentoff = m.nextpackoff;

	map->m_flags = EROFS_MAP_MAPPED | EROFS_MAP_PARTIAL_MAPPED;
	end = (m.lcn + 1) << vi->z_lclusterbits;
	if (m.type != Z_EROFS_LCLUSTER_TYPE_NONHEAD && endoff >= m.clusterofs) {
		m.headtype = m.type;
		map->m_la = (m.lcn << vi->z_lclusterbits) + m.clusterofs;
		if (ztailpacking && end > vi->size)
			end = vi->size;
	} else {
		if (m.type != Z_EROFS_LCLUSTER_TYPE_NONHEAD) {
			end = (m.lcn << vi->z_lclusterbits) + m.clusterofs;
			map->m_flags &= ~EROFS_MAP_PARTIAL_MAPPED;
			m.delta[0] = 1;
		}
		err = z_erofs_extent_lookback(&m, m.delta[0]);
		if (err != 0)
			return (err);
	}
	if (m.partialref)
		map->m_flags |= EROFS_MAP_PARTIAL_REF;
	KASSERT(end >= map->m_la,
	    ("erofs: extent ends at %ju, before its start %ju", (uintmax_t)end,
		(uintmax_t)map->m_la));
	map->m_llen = end - map->m_la;

	if ((flags & EROFS_GET_BLOCKS_FINDTAIL) != 0) {
		vi->z_tailextent_headlcn = m.lcn;
		if (fragment && vi->datalayout == EROFS_INODE_COMPRESSED_FULL) {
			/* Both are 32-bit fields of the on-disk index. */
			vi->z_fragmentoff |= m.pblk << 32;
		}
	}
	if (ztailpacking && m.lcn == vi->z_tailextent_headlcn) {
		map->m_flags |= EROFS_MAP_META;
		map->m_pa = vi->z_fragmentoff;
		map->m_plen = vi->z_idata_size;
		/* Same rule as Linux: inline data does not cross a block. */
		if ((map->m_pa & (sbi->block_size - 1)) + map->m_plen >
		    sbi->block_size)
			return (erofs_corrupt(sbi, vi->nid,
			    "inline pcluster of %ju bytes crosses its block",
			    (uintmax_t)map->m_plen));
	} else if (fragment && m.lcn == vi->z_tailextent_headlcn) {
		map->m_flags = EROFS_MAP_FRAGMENT;
	} else {
		map->m_pa = m.pblk * sbi->block_size;
		err = z_erofs_get_extent_compressedlen(&m);
		if (err != 0)
			return (err);
	}

	if (m.headtype == Z_EROFS_LCLUSTER_TYPE_PLAIN) {
		/*
		 * Interlaced pclusters are block-aligned on disk.  An inline
		 * (ztailpacking) pcluster is not, so it can only be shifted,
		 * whatever the inode advises.
		 */
		map->m_algorithmformat =
		    (vi->z_advise & Z_EROFS_ADVISE_INTERLACED_PCLUSTER) != 0 &&
			(map->m_flags & EROFS_MAP_META) == 0 ?
		    Z_EROFS_COMPRESSION_INTERLACED :
		    Z_EROFS_COMPRESSION_SHIFTED;
	} else if (m.headtype == Z_EROFS_LCLUSTER_TYPE_HEAD2) {
		map->m_algorithmformat = vi->z_algorithmtype[1];
	} else {
		map->m_algorithmformat = vi->z_algorithmtype[0];
	}

	if ((flags & EROFS_GET_BLOCKS_FIEMAP) != 0) {
		err = z_erofs_get_extent_decompressedlen(&m);
		if (err == 0)
			map->m_flags &= ~EROFS_MAP_PARTIAL_MAPPED;
		return (err);
	}
	return (0);
}

/*
 * The table is not scanned on load, as it grows with the file.  The search
 * range checks each record it visits, so a bad table can only give a hole
 * or the wrong extent.
 */
static int
z_erofs_map_blocks_ext(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct z_erofs_extent ext;
	unsigned int recsz, bmask;
	uint8_t fmt;
	uint64_t cluster_size, extent_idx;
	erofs_off_t extent_pos, pos, table_pos;
	uint64_t lend, l, r, mid, pa, la, lstart;
	bool interlaced, last;
	int error;

	interlaced = (vi->z_advise & Z_EROFS_ADVISE_INTERLACED_PCLUSTER) != 0;
	recsz = z_erofs_extent_recsize(vi->z_advise);
	table_pos = z_erofs_extent_table_pos(vi, recsz);
	pos = table_pos;
	bmask = sbi->block_size - 1;
	lend = vi->size;
	cluster_size = 1ULL << vi->z_lclusterbits;
	map->m_flags = 0;

	if (recsz <= offsetof(struct z_erofs_extent, pstart_hi)) {
		if (recsz <= offsetof(struct z_erofs_extent, pstart_lo)) {
			error = erofs_read_metadata_range(sbi, vi->nid, pos,
			    sizeof(uint64_t), &buf);
			if (error != 0)
				return (error);
			pa = le64dec(buf.data);
			erofs_put_metabuf(&buf);
			pos += sizeof(uint64_t);
			lstart = 0;
			extent_idx = 0;
		} else {
			lstart = rounddown2(map->m_la, cluster_size);
			extent_idx = lstart >> vi->z_lclusterbits;
			pa = EROFS_NULL_ADDR;
		}
		for (;;) {
			KASSERT(extent_idx < vi->z_extents,
			    ("erofs: extent %ju of %ju", (uintmax_t)extent_idx,
				(uintmax_t)vi->z_extents));
			extent_pos = z_erofs_extent_record_pos(pos, recsz,
			    extent_idx);
			error = z_erofs_read_extent(sbi, vi, extent_pos, recsz,
			    &ext);
			if (error != 0)
				return (error);
			map->m_plen = le32toh(ext.plen);
			if (pa != EROFS_NULL_ADDR) {
				map->m_pa = pa;
				pa += map->m_plen & Z_EROFS_EXTENT_PLEN_MASK;
			} else {
				map->m_pa = le32toh(ext.pstart_lo);
			}
			extent_idx++;
			lstart += cluster_size;
			if (lstart > map->m_la)
				break;
		}
		last = lstart >= roundup2(lend, cluster_size);
		lend = MIN(lstart, lend);
		lstart -= cluster_size;
	} else {
		lstart = lend;
		for (l = 0, r = vi->z_extents; l < r;) {
			mid = l + (r - l) / 2;
			extent_pos = z_erofs_extent_record_pos(table_pos, recsz,
			    mid);
			error = z_erofs_read_extent(sbi, vi, extent_pos, recsz,
			    &ext);
			if (error != 0)
				return (error);
			la = z_erofs_extent_lstart(&ext, recsz);
			pa = le32toh(ext.pstart_lo) |
			    ((uint64_t)le32toh(ext.pstart_hi) << 32);
			if (la > map->m_la) {
				r = mid;
				/*
				 * The records are not compared with each
				 * other, but this one must not start past the
				 * next one or the size: m_llen stays within the
				 * file.
				 */
				if (la > lend)
					return (erofs_corrupt(sbi, vi->nid,
					    "extent %ju starts at %ju, past "
					    "the following extent or the size "
					    "%ju",
					    (uintmax_t)mid, (uintmax_t)la,
					    (uintmax_t)lend));
				lend = la;
			} else {
				l = mid + 1;
				if (map->m_la == la)
					r = MIN(l + 1, r);
				lstart = la;
				map->m_plen = le32toh(ext.plen);
				map->m_pa = pa;
			}
		}
		last = l >= vi->z_extents;
	}

	if (lstart < lend) {
		map->m_la = lstart;
		if (last &&
		    (vi->z_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER) != 0) {
			map->m_flags = EROFS_MAP_FRAGMENT;
			if (recsz >
			    offsetof(struct z_erofs_extent, pstart_lo)) {
				vi->z_fragmentoff = map->m_plen |
				    (map->m_pa << 32);
			} else {
				vi->z_fragmentoff = map->m_plen;
			}
		} else if ((map->m_plen & Z_EROFS_EXTENT_PLEN_MASK) != 0) {
			map->m_flags = EROFS_MAP_MAPPED;
			fmt = (uint8_t)(map->m_plen >>
			    Z_EROFS_EXTENT_PLEN_FMT_BIT);
			if ((map->m_plen & Z_EROFS_EXTENT_PLEN_PARTIAL) != 0)
				map->m_flags |= EROFS_MAP_PARTIAL_REF;
			map->m_plen &= Z_EROFS_EXTENT_PLEN_MASK;
			if (fmt != 0) {
				if (fmt - 1 >= Z_EROFS_COMPRESSION_MAX) {
					erofs_err(sbi,
					    "unsupported compression "
					    "algorithm %u @ nid %ju",
					    fmt - 1, (uintmax_t)vi->nid);
					return (EOPNOTSUPP);
				}
				map->m_algorithmformat = (uint8_t)(fmt - 1);
			} else if (interlaced &&
			    ((map->m_pa | map->m_plen) & bmask) == 0)
				map->m_algorithmformat =
				    Z_EROFS_COMPRESSION_INTERLACED;
			else
				map->m_algorithmformat =
				    Z_EROFS_COMPRESSION_SHIFTED;
		}
	}
	map->m_llen = lend - map->m_la;
	return (0);
}
