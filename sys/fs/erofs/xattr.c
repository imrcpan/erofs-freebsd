/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021-2022, Alibaba Cloud
 */

#include "opt_ufs.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/extattr.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/vnode.h>

#ifdef UFS_ACL
#include <sys/acl.h>
#endif

#include <machine/atomic.h>

#include <fs/erofs/xattr.h>

static uint32_t
erofs_xxh32_rotl(uint32_t value, unsigned int count)
{
	return ((value << count) | (value >> (32 - count)));
}

static uint32_t
erofs_xxh32_round(uint32_t seed, uint32_t input)
{
	seed += input * UINT32_C(2246822519);
	seed = erofs_xxh32_rotl(seed, 13);
	return (seed * UINT32_C(2654435761));
}

static uint32_t
erofs_xxh32(const void *input, size_t length, uint32_t seed)
{
	const uint8_t *cursor, *end;
	uint32_t hash;

	cursor = input;
	end = cursor + length;
	if (length >= 16) {
		const uint8_t *limit;
		uint32_t v1, v2, v3, v4;

		limit = end - 16;
		v1 = seed + UINT32_C(2654435761) + UINT32_C(2246822519);
		v2 = seed + UINT32_C(2246822519);
		v3 = seed;
		v4 = seed - UINT32_C(2654435761);
		do {
			v1 = erofs_xxh32_round(v1, le32dec(cursor));
			cursor += 4;
			v2 = erofs_xxh32_round(v2, le32dec(cursor));
			cursor += 4;
			v3 = erofs_xxh32_round(v3, le32dec(cursor));
			cursor += 4;
			v4 = erofs_xxh32_round(v4, le32dec(cursor));
			cursor += 4;
		} while (cursor <= limit);
		hash = erofs_xxh32_rotl(v1, 1) + erofs_xxh32_rotl(v2, 7) +
		    erofs_xxh32_rotl(v3, 12) + erofs_xxh32_rotl(v4, 18);
	} else {
		hash = seed + UINT32_C(374761393);
	}
	hash += (uint32_t)length;
	while (cursor + 4 <= end) {
		hash += le32dec(cursor) * UINT32_C(3266489917);
		hash = erofs_xxh32_rotl(hash, 17) * UINT32_C(668265263);
		cursor += 4;
	}
	while (cursor < end) {
		hash += *cursor++ * UINT32_C(374761393);
		hash = erofs_xxh32_rotl(hash, 11) * UINT32_C(2654435761);
	}
	hash ^= hash >> 15;
	hash *= UINT32_C(2246822519);
	hash ^= hash >> 13;
	hash *= UINT32_C(3266489917);
	hash ^= hash >> 16;
	return (hash);
}

static bool
erofs_xattr_filter_name(int attrnamespace, const char *name, size_t name_len,
    uint8_t *indexp, const char **filter_namep, size_t *filter_name_lenp)
{
#ifdef UFS_ACL
	static const char acl_access[] = "posix_acl_access";
	static const char acl_default[] = "posix_acl_default";
#endif
	static const char security[] = "security.";
	static const char trusted[] = "trusted.";

	if (attrnamespace == EXTATTR_NAMESPACE_USER) {
		*indexp = EROFS_XATTR_INDEX_USER;
		*filter_namep = name;
		*filter_name_lenp = name_len;
		return (true);
	}
	if (attrnamespace != EXTATTR_NAMESPACE_SYSTEM)
		return (false);
#ifdef UFS_ACL
	if (name_len == sizeof(acl_access) - 1 &&
	    memcmp(name, acl_access, sizeof(acl_access) - 1) == 0) {
		*indexp = EROFS_XATTR_INDEX_POSIX_ACL_ACCESS;
		*filter_namep = name + name_len;
		*filter_name_lenp = 0;
		return (true);
	}
	if (name_len == sizeof(acl_default) - 1 &&
	    memcmp(name, acl_default, sizeof(acl_default) - 1) == 0) {
		*indexp = EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT;
		*filter_namep = name + name_len;
		*filter_name_lenp = 0;
		return (true);
	}
#endif
	if (name_len >= sizeof(trusted) - 1 &&
	    memcmp(name, trusted, sizeof(trusted) - 1) == 0) {
		*indexp = EROFS_XATTR_INDEX_TRUSTED;
		*filter_namep = name + sizeof(trusted) - 1;
		*filter_name_lenp = name_len - (sizeof(trusted) - 1);
		return (true);
	}
	if (name_len >= sizeof(security) - 1 &&
	    memcmp(name, security, sizeof(security) - 1) == 0) {
		*indexp = EROFS_XATTR_INDEX_SECURITY;
		*filter_namep = name + sizeof(security) - 1;
		*filter_name_lenp = name_len - (sizeof(security) - 1);
		return (true);
	}
	return (false);
}

static int
erofs_xattr_read_backing(struct erofs_sb_info *sbi,
    struct erofs_inode *backing_en, erofs_off_t off, size_t len,
    struct erofs_buf *buf)
{
	void *data;
	int error;

	/* Both reads check the range (and report it) themselves. */
	if (backing_en != NULL)
		error = erofs_read_data(sbi, backing_en, off, len, &data);
	else
		error = erofs_bread(sbi, off, len, &data);
	if (error != 0)
		return (error);
	buf->data = data;
	buf->release = erofs_brelse;
	return (0);
}

/*
 * Read one prefix table metadata record.
 *
 * When backing_en == NULL the record is in the physical metadata area;
 * otherwise it lives in the selected metadata carrier's logical data stream.
 */
static int
erofs_xattr_read_metadata(struct erofs_sb_info *sbi,
    struct erofs_inode *backing_en, erofs_off_t *offp, struct erofs_buf *buf,
    size_t *lenp)
{
	struct erofs_buf hdrbuf = EROFS_BUF_INITIALIZER;
	uint16_t raw_len;
	erofs_off_t off;
	size_t len;
	int error;

	/* The offset is below 2^35: 255 records of at most 64 KiB each. */
	off = roundup2(*offp, sizeof(struct erofs_xattr_entry));
	error = erofs_xattr_read_backing(sbi, backing_en, off, sizeof(raw_len),
	    &hdrbuf);
	if (error != 0)
		return (error);
	raw_len = le16dec(hdrbuf.data);
	erofs_put_metabuf(&hdrbuf);
	len = (raw_len == 0) ? (size_t)UINT16_MAX + 1 : raw_len;
	if (len < sizeof(struct erofs_xattr_long_prefix) ||
	    len > EROFS_NAME_LEN + sizeof(struct erofs_xattr_long_prefix))
		return (erofs_corrupt(sbi, EROFS_NID_NONE,
		    "xattr prefix record of %zu bytes at %ju has an invalid "
		    "size",
		    len, (uintmax_t)off));
	error = erofs_xattr_read_backing(sbi, backing_en, off + sizeof(raw_len),
	    len, buf);
	if (error != 0)
		return (error);
	*offp = off + sizeof(raw_len) + len;
	*lenp = len;
	return (0);
}

static int
erofs_xattr_load_body_uncached(struct erofs_sb_info *sbi,
    struct erofs_inode *vi, struct erofs_buf *bodybuf,
    struct erofs_xattr_ibody_header **ihp, size_t *header_sizep)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_xattr_ibody_header *ih;
	char *body;
	uint64_t body_off;
	size_t header_size;
	int error;

	if (vi->xattr_isize < sizeof(*ih))
		return (erofs_corrupt(sbi, vi->nid,
		    "xattr area of %zu bytes is smaller than its header",
		    (size_t)vi->xattr_isize));
	body_off = vi->inode_off + vi->inode_isize;
	error = erofs_xattr_read_backing(sbi,
	    erofs_nid_in_metabox(vi->nid) ? sbi->metabox_en : NULL, body_off,
	    vi->xattr_isize, &buf);
	if (error != 0)
		return (error);
	body = buf.data;
	ih = (struct erofs_xattr_ibody_header *)body;
	if (vi->xattr_isize == sizeof(*ih)) {
		error = EOPNOTSUPP;
		goto fail;
	}
	header_size = sizeof(*ih) + sizeof(uint32_t) * ih->h_shared_count;
	if (header_size > vi->xattr_isize) {
		error = erofs_corrupt(sbi, vi->nid,
		    "%u shared xattr ids do not fit the xattr area of %zu "
		    "bytes",
		    ih->h_shared_count, (size_t)vi->xattr_isize);
		goto fail;
	}
	*bodybuf = buf;
	*ihp = ih;
	*header_sizep = header_size;
	return (0);
fail:
	erofs_put_metabuf(&buf);
	return (error);
}
