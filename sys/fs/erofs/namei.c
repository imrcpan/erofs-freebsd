// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2022, Alibaba Cloud
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/dirent.h>
#include <sys/libkern.h>
#include <sys/namei.h>
#include <sys/vnode.h>

#include <fs/erofs/trace.h>

struct erofs_qstr {
	const unsigned char *name;
	const unsigned char *end;
};

/*
 * Names are bounded by ->end and may lack a terminating NUL.  *matched is
 * the prefix already known to be equal, so a binary search need not
 * rescan it.
 */
static int
erofs_dirnamecmp(const struct erofs_qstr *qn, const struct erofs_qstr *qd,
    unsigned int *matched)
{
	size_t dname_span, qname_span;
	unsigned int i;

	qname_span = qn->end - qn->name;
	dname_span = qd->end - qd->name;
	i = MIN(*matched, qname_span);
	i = MIN(i, dname_span);
	while (i < qname_span && i < dname_span && qd->name[i] != '\0') {
		if (qn->name[i] != qd->name[i]) {
			*matched = i;
			return (qn->name[i] > qd->name[i] ? 1 : -1);
		}
		++i;
	}
	*matched = i;
	if (i == qname_span)
		return (i == dname_span || qd->name[i] == '\0' ? 0 : -1);
	return (1);
}

static int
erofs_dirent_qstr(const char *data, uint32_t datasize, uint32_t ndirents,
    uint32_t idx, struct erofs_qstr *name)
{
	uint32_t endoff, nameoff;
	int error;

	error = erofs_dirent_span(data, datasize, ndirents, idx, &nameoff,
	    &endoff);
	if (error != 0)
		return (error);
	name->name = (const unsigned char *)data + nameoff;
	name->end = (const unsigned char *)data + endoff;
	return (0);
}

static int
find_target_dirent(const struct erofs_qstr *name, char *data, uint32_t datasize,
    uint32_t ndirents, struct erofs_dirent **dep)
{
	uint32_t head, back;
	unsigned int startprfx, endprfx;
	struct erofs_dirent *const de = (struct erofs_dirent *)data;
	int error;

	*dep = NULL;
	/* The 1st dirent has already been evaluated by the caller. */
	head = 1;
	back = ndirents - 1;
	startprfx = endprfx = 0;

	while (head <= back) {
		const uint32_t mid = head + (back - head) / 2;
		unsigned int matched = MIN(startprfx, endprfx);
		struct erofs_qstr dname;
		int ret;

		error = erofs_dirent_qstr(data, datasize, ndirents, mid,
		    &dname);
		if (error != 0)
			return (error);

		/* String comparison without already matched prefix */
		ret = erofs_dirnamecmp(name, &dname, &matched);

		if (ret == 0) {
			*dep = de + mid;
			return (0);
		} else if (ret > 0) {
			head = mid + 1;
			startprfx = matched;
		} else {
			back = mid - 1;
			endprfx = matched;
		}
	}

	return (0);
}

static int
erofs_read_dirblock(struct erofs_sb_info *sbi, struct erofs_inode *dir,
    uint64_t block, char **datap, uint32_t *datasizep, uint32_t *ndirentsp)
{
	erofs_off_t block_off;
	uint32_t datasize;
	char *data;
	int error;

	*datap = NULL;
	/* The only caller searches the blocks that hold dir->size bytes. */
	block_off = block * sbi->block_size;
	KASSERT(block_off < dir->size,
	    ("erofs: directory block %ju beyond the size", (uintmax_t)block));
	datasize = MIN((uint64_t)sbi->block_size, dir->size - block_off);
	error = erofs_read_data(sbi, dir, block_off, datasize, (void **)&data);
	if (error != 0)
		return (error);
	error = erofs_dirblock_ndirents(data, datasize, ndirentsp);
	if (error != 0) {
		erofs_brelse(data);
		return (erofs_corrupt(sbi, dir->nid,
		    "invalid dirent array in block %ju", (uintmax_t)block));
	}
	*datap = data;
	*datasizep = datasize;
	return (0);
}

/*
 * Directory blocks are sorted, so the name can only be in the last block
 * whose first name is not greater than it.  If that first name is an exact
 * match, *_ndirents is 0 and the caller need not search the block.  NULL
 * with *errorp 0 means there is no such block.  The caller releases the
 * block with erofs_brelse().
 */
static char *
erofs_find_target_block(struct erofs_sb_info *sbi, struct erofs_inode *dir,
    const struct erofs_qstr *name, uint32_t *_ndirents, uint32_t *_datasize,
    int *errorp)
{
	uint32_t bsz = sbi->block_size;
	uint64_t head, back;
	unsigned int startprfx = 0, endprfx = 0;
	char *candidate = NULL;
	int error;

	*errorp = 0;
	*_ndirents = 0;
	*_datasize = 0;

	if (dir->size == 0)
		return (NULL);

	head = 0;
	back = (dir->size - 1) / bsz;

	while (head <= back) {
		const uint64_t mid = head + (back - head) / 2;
		uint32_t maxsize;
		char *blk;
		int diff;
		uint32_t ndirents;
		unsigned int matched;
		struct erofs_qstr dname;

		error = erofs_read_dirblock(sbi, dir, mid, &blk, &maxsize,
		    &ndirents);
		if (error != 0) {
			*errorp = error;
			goto out;
		}
		error = erofs_dirent_qstr(blk, maxsize, ndirents, 0, &dname);
		if (error != 0) {
			erofs_brelse(blk);
			*errorp = erofs_corrupt(sbi, dir->nid,
			    "invalid name span of the first dirent in block "
			    "%ju",
			    (uintmax_t)mid);
			goto out;
		}

		matched = MIN(startprfx, endprfx);
		/* String comparison without already matched prefix */
		diff = erofs_dirnamecmp(name, &dname, &matched);

		if (diff < 0) {
			erofs_brelse(blk);
			if (mid == 0)
				break;
			back = mid - 1;
			endprfx = matched;
			continue;
		}

		/* diff >= 0: this block is a candidate. */
		if (candidate != NULL)
			erofs_brelse(candidate);
		candidate = blk;
		if (diff == 0) {
			*_ndirents = 0;
			*_datasize = maxsize;
			return (candidate);
		}
		head = mid + 1;
		startprfx = matched;
		*_ndirents = ndirents;
		*_datasize = maxsize;
	}
	return (candidate);
out:
	if (candidate != NULL)
		erofs_brelse(candidate);
	return (NULL);
}

static int
erofs_namei(struct erofs_sb_info *sbi, struct erofs_inode *dir,
    const struct erofs_qstr *name, erofs_nid_t *nid)
{
	int error;
	uint32_t ndirents;
	uint32_t datasize;
	char *blk;
	struct erofs_dirent *de;

	blk = erofs_find_target_block(sbi, dir, name, &ndirents, &datasize,
	    &error);
	if (blk == NULL)
		return (error != 0 ? error : ENOENT);

	de = (struct erofs_dirent *)blk;
	if (ndirents > 0) {
		error = find_target_dirent(name, blk, datasize, ndirents, &de);
		if (error != 0)
			error = erofs_corrupt(sbi, dir->nid,
			    "invalid name span in a dirent block");
	}

	if (error == 0 && de != NULL) {
		erofs_nid_t found_nid;

		found_nid = le64toh(de->nid);
		if (!erofs_nid_is_valid(sbi, found_nid)) {
			error = erofs_corrupt(sbi, dir->nid,
			    "dirent points to invalid nid %ju",
			    (uintmax_t)found_nid);
		} else {
			*nid = found_nid;
		}
	}
	erofs_brelse(blk);
	if (error != 0)
		return (error);
	return (de != NULL ? 0 : ENOENT);
}

/*
 * Directory name lookup (VOP_CACHEDLOOKUP entry point).
 *
 * FreeBSD-side API requirements:
 * - "." must be returned under the caller's requested lock mode;
 * - ".." must go through vn_vget_ino() to avoid holding a child lock while
 *   acquiring the parent directory lock in reverse;
 * - Both hit and miss must correctly update the namecache.
 */
int
erofs_lookup(struct vop_cachedlookup_args *ap)
{
	struct erofs_qstr qname;
	struct vnode *dvp, *vp;
	struct erofs_inode *dir;
	struct erofs_sb_info *sbi;
	struct componentname *cnp;
	erofs_nid_t nid;
	int error, ltype;

	dvp = ap->a_dvp;
	cnp = ap->a_cnp;
	*ap->a_vpp = NULL;
	if ((cnp->cn_flags & ISLASTCN) != 0 &&
	    (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME))
		return (EROFS);
	if (cnp->cn_namelen > EROFS_NAME_LEN)
		return (ENAMETOOLONG);
	erofs_trace_lookup(VTOE(dvp), cnp->cn_nameptr, (size_t)cnp->cn_namelen,
	    (uint32_t)cnp->cn_flags);
	if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		vref(dvp);
		ltype = cnp->cn_lkflags & LK_TYPE_MASK;
		if (ltype != VOP_ISLOCKED(dvp)) {
			if (ltype == LK_EXCLUSIVE)
				vn_lock(dvp, LK_UPGRADE | LK_RETRY);
			else if (ltype == LK_SHARED)
				vn_lock(dvp, LK_DOWNGRADE | LK_RETRY);
		}
		*ap->a_vpp = dvp;
		return (0);
	}

	dir = VTOE(dvp);
	sbi = MTOE(dvp->v_mount);
	qname.name = (const unsigned char *)cnp->cn_nameptr;
	qname.end = qname.name + cnp->cn_namelen;
	error = erofs_namei(sbi, dir, &qname, &nid);
	if (error != 0) {
		if (error == ENOENT && (cnp->cn_flags & MAKEENTRY) != 0)
			cache_enter(dvp, NULL, cnp);
		if (error == ENOENT && (cnp->cn_flags & ISLASTCN) != 0 &&
		    cnp->cn_nameiop == CREATE)
			return (EROFS);
		return (error);
	}
	if ((cnp->cn_flags & ISDOTDOT) != 0 && nid == dir->nid) {
		if (nid != sbi->root_nid)
			return (erofs_corrupt(sbi, dir->nid,
			    "'..' of a non-root directory points to itself"));
		vref(dvp);
		ltype = cnp->cn_lkflags & LK_TYPE_MASK;
		if (ltype != VOP_ISLOCKED(dvp)) {
			if (ltype == LK_EXCLUSIVE)
				vn_lock(dvp, LK_UPGRADE | LK_RETRY);
			else if (ltype == LK_SHARED)
				vn_lock(dvp, LK_DOWNGRADE | LK_RETRY);
		}
		*ap->a_vpp = dvp;
		return (0);
	}
	if ((cnp->cn_flags & ISDOTDOT) == 0 && nid == dir->nid)
		return (erofs_corrupt(sbi, dir->nid,
		    "directory contains an entry pointing to itself"));

	if ((cnp->cn_flags & ISDOTDOT) != 0)
		error = vn_vget_ino_gen(dvp, erofs_vget_raw_alloc, &nid,
		    cnp->cn_lkflags, &vp);
	else
		error = erofs_vget_raw(dvp->v_mount, nid, cnp->cn_lkflags, &vp);
	if (error != 0)
		return (error);
	if ((cnp->cn_flags & ISDOTDOT) != 0 && VTOE(vp)->vtype != VDIR) {
		vput(vp);
		return (erofs_corrupt(sbi, dir->nid,
		    "'..' does not lead to a directory (nid %ju)",
		    (uintmax_t)nid));
	}
	*ap->a_vpp = vp;
	if ((cnp->cn_flags & MAKEENTRY) != 0)
		cache_enter(dvp, vp, cnp);
	return (0);
}
