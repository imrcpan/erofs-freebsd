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

static unsigned char
erofs_ftype_to_dtype(uint8_t ftype)
{
	switch (ftype) {
	case EROFS_FT_REG_FILE:
		return (DT_REG);
	case EROFS_FT_DIR:
		return (DT_DIR);
	case EROFS_FT_CHRDEV:
		return (DT_CHR);
	case EROFS_FT_BLKDEV:
		return (DT_BLK);
	case EROFS_FT_FIFO:
		return (DT_FIFO);
	case EROFS_FT_SOCK:
		return (DT_SOCK);
	case EROFS_FT_SYMLINK:
		return (DT_LNK);
	default:
		return (DT_UNKNOWN);
	}
}

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

/* Per-call state for readdir dirent/cookie output. */
struct erofs_uiodir {
	struct dirent *dirent;
	uint64_t *cookies;
	uint64_t last_cookie;
	int ncookies;
	int acookies;
	int eofflag;
};

enum erofs_uiodir_result {
	EROFS_UIODIR_BUFFER_FULL = -1,
	EROFS_UIODIR_OK = 0,
};

/* Push a dirent and its cookie to the caller, modelled after UDF. */
static int
erofs_uiodir(struct erofs_uiodir *uiodir, int de_size, struct uio *uio,
    uint64_t cookie)
{
	int error;

	/*
	 * Cookies are block offsets we computed, and grow with the entry
	 * index whatever the block contains.
	 */
	KASSERT(cookie > uiodir->last_cookie,
	    ("erofs: readdir cookie %ju not above %ju", (uintmax_t)cookie,
		(uintmax_t)uiodir->last_cookie));
	if (uio->uio_resid < de_size ||
	    (uiodir->cookies != NULL && uiodir->acookies >= uiodir->ncookies)) {
		return (EROFS_UIODIR_BUFFER_FULL);
	}
	error = uiomove(uiodir->dirent, de_size, uio);
	if (error != 0)
		return (error);
	uiodir->last_cookie = cookie;
	if (uiodir->cookies != NULL)
		uiodir->cookies[uiodir->acookies++] = cookie;
	return (EROFS_UIODIR_OK);
}

/*
 * Process directory entries within a single block and output them to uio.
 * Returns 0 on success (all entries consumed), -1 if uio is full, or a
 * positive error code on corruption.
 */
static int
erofs_fill_dentries(struct erofs_sb_info *sbi, erofs_nid_t dirnid,
    struct erofs_uiodir *uiodir, struct uio *uio, struct dirent *d,
    const char *blk, uint32_t maxsize, uint32_t start_idx, uint32_t ndirents,
    erofs_off_t block_off, uint64_t *logical_offp)
{
	char name[EROFS_NAME_LEN + 1];
	uint32_t idx;
	uint64_t curpos, nextoff;
	erofs_nid_t nid;
	size_t namelen;
	uint8_t ftype;
	int error;

	for (idx = start_idx; idx < ndirents; idx++) {
		curpos = block_off + idx * sizeof(struct erofs_dirent);
		nextoff = (idx + 1 < ndirents) ?
		    (curpos + sizeof(struct erofs_dirent)) :
		    (block_off + maxsize);
		error = erofs_dirent_name(blk, maxsize, idx, ndirents, name,
		    sizeof(name), &nid, &ftype, &namelen);
		if (error != 0)
			return (erofs_corrupt(sbi, dirnid,
			    "invalid name of dirent %u in the block at offset "
			    "%ju",
			    idx, (uintmax_t)block_off));
		/*
		 * The nid is only reported as d_fileno; lookup checks it
		 * (erofs_read_inode()) before it is used for anything else.
		 */
		bzero(d, sizeof(*d));
		d->d_fileno = erofs_nid_to_ino64(sbi, nid);
		d->d_type = erofs_ftype_to_dtype(ftype);
		d->d_namlen = namelen;
		d->d_reclen = GENERIC_DIRSIZ(d);
		d->d_off = nextoff;
		strlcpy(d->d_name, name, sizeof(d->d_name));
		error = erofs_uiodir(uiodir, d->d_reclen, uio, d->d_off);
		if (error != 0)
			return (error);
		*logical_offp = nextoff;
		uio->uio_offset = *logical_offp;
	}
	return (0);
}
