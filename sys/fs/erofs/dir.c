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
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/vnode.h>

#include <fs/erofs/internal.h>

/*
 * Names are not required to be sorted or unique: that is fsck.erofs's job,
 * and a directory that violates it can only make a lookup miss.
 */

/* The first name offset is also the size of the dirent array. */
int
erofs_dirblock_ndirents(const char *blk, uint32_t maxsize, uint32_t *ndirentsp)
{
	uint32_t first_nameoff;

	if (maxsize < sizeof(struct erofs_dirent))
		return (EINTEGRITY);
	first_nameoff = le16toh(((const struct erofs_dirent *)blk)->nameoff);
	if (first_nameoff < sizeof(struct erofs_dirent) ||
	    first_nameoff >= maxsize ||
	    (first_nameoff % sizeof(struct erofs_dirent)) != 0)
		return (EINTEGRITY);
	*ndirentsp = first_nameoff / sizeof(struct erofs_dirent);
	return (0);
}

/*
 * Names are not NUL terminated: a name ends where the next one starts, and
 * the last one at the end of the block.
 */
int
erofs_dirent_span(const char *blk, uint32_t maxsize, uint32_t ndirents,
    uint32_t idx, uint32_t *nameoffp, uint32_t *endoffp)
{
	const struct erofs_dirent *de;
	uint32_t endoff, nameoff;

	de = (const struct erofs_dirent *)blk;
	nameoff = le16toh(de[idx].nameoff);
	endoff = idx + 1 < ndirents ? le16toh(de[idx + 1].nameoff) : maxsize;
	if (endoff > maxsize || endoff <= nameoff)
		return (EINTEGRITY);
	*nameoffp = nameoff;
	*endoffp = endoff;
	return (0);
}

/*
 * Only readdir checks the name: it hands the name to userland, while lookup
 * only compares it.
 */
static int
erofs_dirent_namelen(const char *blk, uint32_t nameoff, uint32_t endoff,
    bool trailing, size_t *namelenp)
{
	size_t namelen, span;

	span = endoff - nameoff;
	if (trailing) {
		namelen = strnlen(blk + nameoff, span);
	} else {
		namelen = span;
		if (memchr(blk + nameoff, '\0', span) != NULL)
			return (EINTEGRITY);
	}
	if (namelen == 0 || namelen > EROFS_NAME_LEN)
		return (EINTEGRITY);
	for (size_t i = 0; i < namelen; i++) {
		if (blk[nameoff + i] == '/')
			return (EINTEGRITY);
	}
	*namelenp = namelen;
	return (0);
}

static int
erofs_dirent_name(const char *blk, uint32_t maxsize, uint32_t idx,
    uint32_t ndirents, char *name, size_t namesz __unused, erofs_nid_t *nid,
    uint8_t *ftype, size_t *namelenp)
{
	const struct erofs_dirent *de;
	uint32_t nameoff, endoff;
	size_t namelen;
	int error;

	error = erofs_dirent_span(blk, maxsize, ndirents, idx, &nameoff,
	    &endoff);
	if (error != 0)
		return (error);
	error = erofs_dirent_namelen(blk, nameoff, endoff, idx + 1 == ndirents,
	    &namelen);
	if (error != 0)
		return (error);
	/* erofs_dirent_namelen() caps the name at EROFS_NAME_LEN. */
	KASSERT(namelen < namesz,
	    ("erofs: dirent name of %zu bytes exceeds buffer", namelen));
	de = (const struct erofs_dirent *)blk;
	memcpy(name, blk + nameoff, namelen);
	name[namelen] = '\0';
	*nid = le64toh(de[idx].nid);
	*ftype = de[idx].file_type;
	*namelenp = namelen;
	return (0);
}
