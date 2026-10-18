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
