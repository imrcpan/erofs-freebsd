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
