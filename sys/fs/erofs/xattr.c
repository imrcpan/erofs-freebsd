/* SPDX-License-Identifier: MIT */
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

#ifdef UFS_ACL
struct posix_acl_xattr_entry {
	uint16_t e_tag;
	uint16_t e_perm;
	uint32_t e_id;
};

struct posix_acl_xattr_header {
	uint32_t a_version;
};

#define POSIX_ACL_XATTR_VERSION	     0x0002
#define EROFS_XATTR_FILTER_POSIX_ACL ((1U << 21) | (1U << 30))
#endif
#define EROFS_XATTR_CACHE_BODY_LIMIT   (64UL * 1024)
#define EROFS_XATTR_CACHE_MOUNT_BUDGET (1024UL * 1024)

struct erofs_xattr_iter {
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	int attrnamespace;
	const char *name;
	size_t name_len;
	struct uio *uio;
	size_t *sizep;
};

static int erofs_xattr_load_body(struct erofs_sb_info *sbi,
    struct erofs_inode *vi, struct erofs_buf *bodybuf,
    struct erofs_xattr_ibody_header **ihp, size_t *header_sizep);

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

static int
erofs_xattr_filter_negative(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    int attrnamespace, const char *name, size_t name_len, bool *negativep)
{
	struct erofs_buf body = EROFS_BUF_INITIALIZER;
	struct erofs_xattr_ibody_header *ih;
	const char *filter_name;
	size_t filter_name_len, header_size;
	uint32_t hashbit, name_filter;
	uint8_t index;
	int error;

	*negativep = false;
	if (!erofs_sb_has_xattr_filter_v1(sbi) ||
	    !erofs_xattr_filter_name(attrnamespace, name, name_len, &index,
		&filter_name, &filter_name_len))
		return (0);
	error = erofs_xattr_load_body(sbi, vi, &body, &ih, &header_size);
	if (error != 0)
		return (error);
	name_filter = le32toh(ih->h_name_filter);
	hashbit = erofs_xxh32(filter_name, filter_name_len,
	    EROFS_XATTR_FILTER_SEED + index);
	hashbit &= EROFS_XATTR_FILTER_BITS - 1;
	*negativep = (name_filter & (1U << hashbit)) != 0;
	error = 0;
	erofs_put_metabuf(&body);
	return (error);
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
erofs_xattr_move(void *value, size_t value_size, struct uio *uio, size_t *sizep)
{
	if (sizep != NULL)
		*sizep = value_size;
	if (uio == NULL || value_size == 0)
		return (0);
	return (uiomove(value, value_size, uio));
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

static int
erofs_xattr_validate_entry(struct erofs_xattr_entry *entry, size_t remaining,
    size_t *entry_sizep, size_t *value_sizep)
{
	size_t entry_size, value_size;

	if (remaining < sizeof(*entry))
		return (EINTEGRITY);
	value_size = le16toh(entry->e_value_size);
	/* The aligned size covers the header, the name and the value. */
	entry_size = erofs_xattr_entry_size(entry);
	if (entry_size > remaining)
		return (EINTEGRITY);
	if (entry_sizep != NULL)
		*entry_sizep = entry_size;
	if (value_sizep != NULL)
		*value_sizep = value_size;
	return (0);
}

static bool
erofs_xattr_prefix(uint8_t base_index, int *namespacep, const char **prefixp,
    size_t *prefix_lenp)
{
	switch (base_index) {
	case EROFS_XATTR_INDEX_USER:
		*namespacep = EXTATTR_NAMESPACE_USER;
		*prefixp = NULL;
		*prefix_lenp = 0;
		return (true);
#ifdef UFS_ACL
	case EROFS_XATTR_INDEX_POSIX_ACL_ACCESS:
		*namespacep = EXTATTR_NAMESPACE_SYSTEM;
		*prefixp = "posix_acl_access";
		*prefix_lenp = sizeof("posix_acl_access") - 1;
		return (true);
	case EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT:
		*namespacep = EXTATTR_NAMESPACE_SYSTEM;
		*prefixp = "posix_acl_default";
		*prefix_lenp = sizeof("posix_acl_default") - 1;
		return (true);
#endif
	case EROFS_XATTR_INDEX_TRUSTED:
		*namespacep = EXTATTR_NAMESPACE_SYSTEM;
		*prefixp = "trusted.";
		*prefix_lenp = sizeof("trusted.") - 1;
		return (true);
	case EROFS_XATTR_INDEX_SECURITY:
		*namespacep = EXTATTR_NAMESPACE_SYSTEM;
		*prefixp = "security.";
		*prefix_lenp = sizeof("security.") - 1;
		return (true);
	case EROFS_XATTR_INDEX_LUSTRE:
	default:
		return (false);
	}
}

static int
erofs_xattr_namespace_prefix(int attrnamespace, uint8_t base_index,
    const char **prefixp, size_t *prefix_lenp)
{
	int mapped_namespace;

	if (attrnamespace != EXTATTR_NAMESPACE_USER &&
	    attrnamespace != EXTATTR_NAMESPACE_SYSTEM)
		return (EOPNOTSUPP);
	if (!erofs_xattr_prefix(base_index, &mapped_namespace, prefixp,
		prefix_lenp))
		return (ENOATTR);
	if (mapped_namespace != attrnamespace)
		return (ENOATTR);
	return (0);
}

static int
erofs_xattr_list_move(const char *namespace_prefix, size_t namespace_prefix_len,
    const char *infix, size_t infix_len, const char *name, uint8_t name_len,
    struct uio *uio, size_t *sizep)
{
	uint8_t total_name_len;
	int error;

	if (namespace_prefix_len + infix_len + name_len > EROFS_NAME_LEN)
		return (EINTEGRITY);
	total_name_len = namespace_prefix_len + infix_len + name_len;
	if (sizep != NULL) {
		*sizep += total_name_len + 1;
		return (0);
	}
	if (uio == NULL)
		return (0);
	error = uiomove(__DECONST(void *, &total_name_len), 1, uio);
	if (error != 0)
		return (error);
	if (namespace_prefix_len != 0) {
		error = uiomove(__DECONST(void *, namespace_prefix),
		    namespace_prefix_len, uio);
		if (error != 0)
			return (error);
	}
	if (infix_len != 0) {
		error = uiomove(__DECONST(void *, infix), infix_len, uio);
		if (error != 0)
			return (error);
	}
	return (uiomove(__DECONST(void *, name), name_len, uio));
}

static int
erofs_xattr_resolve_name(struct erofs_sb_info *sbi,
    const struct erofs_xattr_entry *entry, uint8_t *base_indexp,
    const char **infixp, size_t *infix_lenp)
{
	struct erofs_xattr_prefix_item *prefix;
	uint8_t prefix_id;

	if ((entry->e_name_index & EROFS_XATTR_LONG_PREFIX) == 0) {
		*base_indexp = entry->e_name_index;
		*infixp = NULL;
		*infix_lenp = 0;
		return (0);
	}
	if (sbi->xattr_prefixes == NULL)
		return (ENOATTR);
	prefix_id = entry->e_name_index & EROFS_XATTR_LONG_PREFIX_MASK;
	if (prefix_id >= sbi->xattr_prefix_count)
		return (ENOATTR);
	prefix = &sbi->xattr_prefixes[prefix_id];
	*base_indexp = prefix->base_index;
	*infixp = prefix->infix;
	*infix_lenp = prefix->infix_len;
	return (0);
}

static bool
erofs_xattr_name_match(const char *namespace_prefix,
    size_t namespace_prefix_len, const char *infix, size_t infix_len,
    const struct erofs_xattr_entry *entry, const char *name, size_t name_len)
{
	if (name_len != namespace_prefix_len + infix_len + entry->e_name_len)
		return (false);
	if (namespace_prefix_len != 0 &&
	    memcmp(name, namespace_prefix, namespace_prefix_len) != 0)
		return (false);
	if (infix_len != 0 &&
	    memcmp(name + namespace_prefix_len, infix, infix_len) != 0)
		return (false);
	return (memcmp(name + namespace_prefix_len + infix_len, entry->e_name,
		    entry->e_name_len) == 0);
}

static erofs_off_t
erofs_xattr_shared_entry_offset(const struct erofs_sb_info *sbi,
    uint32_t shared_id)
{
	/* A 32-bit block address and a 16-bit shift: below 2^48. */
	return (((erofs_off_t)sbi->xattr_blkaddr << sbi->blkszbits) +
	    (erofs_off_t)shared_id * sizeof(uint32_t));
}

static int
erofs_xattr_load_shared_entry(struct erofs_sb_info *sbi, uint32_t shared_id,
    struct erofs_buf *entrybuf, size_t *value_sizep)
{
	struct erofs_buf hdrbuf = EROFS_BUF_INITIALIZER;
	struct erofs_xattr_entry *entry;
	struct erofs_inode *backing_en;
	erofs_off_t off;
	size_t entry_size, value_size;
	int error;

	backing_en = erofs_sb_has_shared_ea_in_metabox(sbi) ? sbi->metabox_en :
							      NULL;
	if (erofs_sb_has_shared_ea_in_metabox(sbi) && backing_en == NULL)
		return (erofs_corrupt(sbi, EROFS_NID_NONE,
		    "shared xattrs are in the metabox, but the image has "
		    "none"));

	off = erofs_xattr_shared_entry_offset(sbi, shared_id);
	error = erofs_xattr_read_backing(sbi, backing_en, off, sizeof(*entry),
	    &hdrbuf);
	if (error != 0)
		return (error);
	entry = hdrbuf.data;
	value_size = le16toh(entry->e_value_size);
	entry_size = erofs_xattr_entry_size(entry);

	erofs_put_metabuf(&hdrbuf);

	/*
	 * The entry is read whole, so the name and the value are inside it by
	 * construction (entry_size covers both).
	 */
	error = erofs_xattr_read_backing(sbi, backing_en, off, entry_size,
	    entrybuf);
	if (error != 0)
		return (error);
	if (value_sizep != NULL)
		*value_sizep = value_size;
	return (0);
}

static int
erofs_listxattr_foreach(struct erofs_xattr_iter *it,
    struct erofs_xattr_entry *entry)
{
	const char *infix, *namespace_prefix;
	size_t infix_len, namespace_prefix_len;
	uint8_t base_index;
	int err;

	err = erofs_xattr_resolve_name(it->sbi, entry, &base_index, &infix,
	    &infix_len);
	if (err == ENOATTR)
		return (0);
	if (err != 0)
		return (err);
	err = erofs_xattr_namespace_prefix(it->attrnamespace, base_index,
	    &namespace_prefix, &namespace_prefix_len);
	if (err == ENOATTR)
		return (0);
	if (err != 0)
		return (err);
	err = erofs_xattr_list_move(namespace_prefix, namespace_prefix_len,
	    infix, infix_len, entry->e_name, entry->e_name_len, it->uio,
	    it->sizep);
	if (err == EINTEGRITY)
		return (erofs_corrupt(it->sbi, it->vi->nid,
		    "xattr name is longer than %d bytes", EROFS_NAME_LEN));
	return (err);
}

static int
erofs_getxattr_foreach(struct erofs_xattr_iter *it,
    struct erofs_xattr_entry *entry, size_t value_size)
{
	const char *infix, *namespace_prefix;
	size_t infix_len, namespace_prefix_len;
	uint8_t base_index;
	int error;

	error = erofs_xattr_resolve_name(it->sbi, entry, &base_index, &infix,
	    &infix_len);
	if (error != 0)
		return (error);
	error = erofs_xattr_namespace_prefix(it->attrnamespace, base_index,
	    &namespace_prefix, &namespace_prefix_len);
	if (error != 0)
		return (error);
	if (!erofs_xattr_name_match(namespace_prefix, namespace_prefix_len,
		infix, infix_len, entry, it->name, it->name_len))
		return (ENOATTR);
	return (erofs_xattr_move(entry->e_name + entry->e_name_len, value_size,
	    it->uio, it->sizep));
}

static int
erofs_xattr_iter_inline(struct erofs_xattr_iter *it, char *body,
    size_t header_size, bool get)
{
	struct erofs_xattr_entry *entry;
	char *cursor;
	size_t entry_size, remaining, value_size;
	int ret;

	remaining = it->vi->xattr_isize - header_size;
	cursor = body + header_size;
	while (remaining != 0) {
		entry = (struct erofs_xattr_entry *)cursor;
		ret = erofs_xattr_validate_entry(entry, remaining, &entry_size,
		    get ? &value_size : NULL);
		if (ret != 0)
			return (erofs_corrupt(it->sbi, it->vi->nid,
			    "invalid xattr entry at offset %zu of the xattr "
			    "area",
			    (size_t)(cursor - body)));
		if (get)
			ret = erofs_getxattr_foreach(it, entry, value_size);
		else
			ret = erofs_listxattr_foreach(it, entry);
		if (get) {
			if (ret != ENOATTR)
				return (ret);
		} else if (ret != 0) {
			return (ret);
		}
		cursor += entry_size;
		remaining -= entry_size;
	}
	return (get ? ENOATTR : 0);
}

static int
erofs_xattr_iter_shared(struct erofs_xattr_iter *it,
    struct erofs_xattr_ibody_header *ih, bool get)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_xattr_entry *entry;
	uint32_t shared_id;
	size_t value_size;
	int ret;

	for (uint8_t i = 0; i < ih->h_shared_count; i++) {
		shared_id = le32toh(ih->h_shared_xattrs[i]);
		ret = erofs_xattr_load_shared_entry(it->sbi, shared_id, &buf,
		    get ? &value_size : NULL);
		if (ret != 0)
			return (ret);
		entry = buf.data;
		if (get)
			ret = erofs_getxattr_foreach(it, entry, value_size);
		else
			ret = erofs_listxattr_foreach(it, entry);
		erofs_put_metabuf(&buf);
		if (get) {
			if (ret != ENOATTR)
				return (ret);
		} else if (ret != 0) {
			return (ret);
		}
	}
	return (get ? ENOATTR : 0);
}

int
erofs_getxattr(struct vnode *vp, int attrnamespace, const char *name,
    struct uio *uio, size_t *sizep)
{
	struct erofs_buf body = EROFS_BUF_INITIALIZER;
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	struct erofs_xattr_ibody_header *ih;
	struct erofs_xattr_iter it;
	size_t header_size, name_len;
	bool filter_negative;
	int ret;

	sbi = MTOE(vp->v_mount);
	vi = VTOE(vp);
	if (name == NULL || name[0] == '\0')
		return (EINVAL);
	name_len = strlen(name);
	if (name_len > EROFS_NAME_LEN)
		return (EINVAL);
	if (vi->xattr_isize == 0)
		return (ENOATTR);
	ret = erofs_xattr_filter_negative(sbi, vi, attrnamespace, name,
	    name_len, &filter_negative);
	if (ret != 0)
		return (ret);
	if (filter_negative)
		return (ENOATTR);
	ret = erofs_xattr_load_body(sbi, vi, &body, &ih, &header_size);
	if (ret != 0)
		return (ret);
	it.sbi = sbi;
	it.vi = vi;
	it.attrnamespace = attrnamespace;
	it.name = name;
	it.name_len = name_len;
	it.uio = uio;
	it.sizep = sizep;
	ret = erofs_xattr_iter_inline(&it, body.data, header_size, true);
	if (ret == ENOATTR)
		ret = erofs_xattr_iter_shared(&it, ih, true);
	erofs_put_metabuf(&body);
	return (ret);
}

int
erofs_listxattr(struct vnode *vp, int attrnamespace, struct uio *uio,
    size_t *sizep)
{
	struct erofs_buf body = EROFS_BUF_INITIALIZER;
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	struct erofs_xattr_ibody_header *ih;
	struct erofs_xattr_iter it;
	size_t header_size;
	int ret;

	sbi = MTOE(vp->v_mount);
	vi = VTOE(vp);
	if (sizep != NULL)
		*sizep = 0;
	if (vi->xattr_isize == 0)
		return (0);
	ret = erofs_xattr_load_body(sbi, vi, &body, &ih, &header_size);
	if (ret != 0)
		return (ret);
	it.sbi = sbi;
	it.vi = vi;
	it.attrnamespace = attrnamespace;
	it.name = NULL;
	it.name_len = 0;
	it.uio = uio;
	it.sizep = sizep;
	ret = erofs_xattr_iter_inline(&it, body.data, header_size, false);
	if (ret == 0)
		ret = erofs_xattr_iter_shared(&it, ih, false);
	erofs_put_metabuf(&body);
	return (ret);
}

static bool
erofs_xattr_cache_reserve(struct erofs_sb_info *sbi, size_t size)
{
	u_long resident;

	for (;;) {
		resident = atomic_load_acq_long(&sbi->xattr_cache_resident);
		if (resident > EROFS_XATTR_CACHE_MOUNT_BUDGET ||
		    size > EROFS_XATTR_CACHE_MOUNT_BUDGET - resident)
			return (false);
		if (atomic_cmpset_acq_long(&sbi->xattr_cache_resident, resident,
			resident + size))
			return (true);
	}
}

static void
erofs_xattr_cache_release(struct erofs_sb_info *sbi, size_t size)
{
	KASSERT(size <= EROFS_XATTR_CACHE_MOUNT_BUDGET,
	    ("erofs xattr cache release exceeds mount budget"));
	atomic_subtract_rel_long(&sbi->xattr_cache_resident, size);
}

static void *
erofs_xattr_cache_invalidate_locked(struct erofs_sb_info *sbi,
    struct erofs_xattr_cache *cache)
{
	void *data;

	data = cache->data;
	if (cache->charged_bytes != 0) {
		erofs_xattr_cache_release(sbi, cache->charged_bytes);
		cache->charged_bytes = 0;
	}
	cache->data = NULL;
	cache->error = 0;
	cache->state = EROFS_XATTR_CACHE_EMPTY;
	return (data);
}

void
erofs_xattr_cache_init(struct erofs_inode *vi)
{
	struct erofs_xattr_cache *cache;

	cache = &vi->xattr_cache;
	bzero(cache, sizeof(*cache));
	mtx_init(&cache->lock, "erofs xattr", NULL, MTX_DEF);
	cv_init(&cache->cv, "erofs xattr");
	cache->state = EROFS_XATTR_CACHE_EMPTY;
	cache->initialized = true;
}

void
erofs_xattr_cache_fini(struct erofs_sb_info *sbi, struct erofs_inode *vi)
{
	struct erofs_xattr_cache *cache;
	void *data;

	cache = &vi->xattr_cache;
	if (!cache->initialized)
		return;
	mtx_lock(&cache->lock);
	cache->closing = true;
	while (
	    cache->state == EROFS_XATTR_CACHE_INFLIGHT || cache->waiters != 0)
		cv_wait(&cache->cv, &cache->lock);
	data = erofs_xattr_cache_invalidate_locked(sbi, cache);
	cache->initialized = false;
	mtx_unlock(&cache->lock);
	free(data, M_EROFS);
	cv_destroy(&cache->cv);
	mtx_destroy(&cache->lock);
}

static int
erofs_xattr_load_body(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_buf *bodybuf, struct erofs_xattr_ibody_header **ihp,
    size_t *header_sizep)
{
	struct erofs_xattr_cache *cache;
	bool reserved;
	int error;

	cache = &vi->xattr_cache;
	if (!cache->initialized ||
	    vi->xattr_isize > EROFS_XATTR_CACHE_BODY_LIMIT)
		return (erofs_xattr_load_body_uncached(sbi, vi, bodybuf, ihp,
		    header_sizep));
	mtx_lock(&cache->lock);
	if (cache->closing) {
		mtx_unlock(&cache->lock);
		return (ENXIO);
	}
	if (cache->state == EROFS_XATTR_CACHE_READY) {
		KASSERT(cache->data != NULL,
		    ("erofs xattr ready cache has no body"));
		bodybuf->data = cache->data;
		*ihp = bodybuf->data;
		*header_sizep = sizeof(**ihp) +
		    sizeof(uint32_t) * (*ihp)->h_shared_count;
		mtx_unlock(&cache->lock);
		return (0);
	}
	if (cache->state == EROFS_XATTR_CACHE_INFLIGHT) {
		cache->waiters++;
		do {
			cv_wait(&cache->cv, &cache->lock);
		} while (cache->state == EROFS_XATTR_CACHE_INFLIGHT);
		if (cache->state == EROFS_XATTR_CACHE_READY) {
			bodybuf->data = cache->data;
			*ihp = bodybuf->data;
			*header_sizep = sizeof(**ihp) +
			    sizeof(uint32_t) * (*ihp)->h_shared_count;
			error = 0;
		} else {
			KASSERT(cache->state == EROFS_XATTR_CACHE_FAILED &&
				cache->error > 0,
			    ("erofs xattr failed cache has no typed error"));
			error = cache->error;
		}
		cache->waiters--;
		if (cache->state == EROFS_XATTR_CACHE_FAILED &&
		    cache->waiters == 0)
			(void)erofs_xattr_cache_invalidate_locked(sbi, cache);
		if (cache->waiters == 0)
			cv_broadcast(&cache->cv);
		mtx_unlock(&cache->lock);
		return (error);
	}
	if (cache->state == EROFS_XATTR_CACHE_FAILED) {
		if (cache->waiters != 0) {
			mtx_unlock(&cache->lock);
			return (erofs_xattr_load_body_uncached(sbi, vi, bodybuf,
			    ihp, header_sizep));
		}
		(void)erofs_xattr_cache_invalidate_locked(sbi, cache);
	}
	reserved = erofs_xattr_cache_reserve(sbi, vi->xattr_isize);
	if (!reserved) {
		mtx_unlock(&cache->lock);
		return (erofs_xattr_load_body_uncached(sbi, vi, bodybuf, ihp,
		    header_sizep));
	}
	cache->state = EROFS_XATTR_CACHE_INFLIGHT;
	cache->error = 0;
	mtx_unlock(&cache->lock);

	error = erofs_xattr_load_body_uncached(sbi, vi, bodybuf, ihp,
	    header_sizep);
	mtx_lock(&cache->lock);
	if (error == 0 && !cache->closing) {
		cache->data = bodybuf->data;
		cache->charged_bytes = vi->xattr_isize;
		cache->state = EROFS_XATTR_CACHE_READY;
		bodybuf->release = NULL;
		cv_broadcast(&cache->cv);
		mtx_unlock(&cache->lock);
		return (0);
	}
	if (error == 0)
		error = ENXIO;
	erofs_xattr_cache_release(sbi, vi->xattr_isize);
	cache->error = error;
	cache->state = EROFS_XATTR_CACHE_FAILED;
	if (cache->waiters == 0)
		(void)erofs_xattr_cache_invalidate_locked(sbi, cache);
	cv_broadcast(&cache->cv);
	mtx_unlock(&cache->lock);
	erofs_put_metabuf(bodybuf);
	return (error);
}

void
erofs_xattr_prefixes_cleanup(struct erofs_sb_info *sbi)
{
	if (sbi->xattr_prefixes == NULL)
		return;
	for (uint8_t i = 0; i < sbi->xattr_prefix_count; i++)
		free(sbi->xattr_prefixes[i].infix, M_EROFS);
	free(sbi->xattr_prefixes, M_EROFS);
	sbi->xattr_prefixes = NULL;
}

int
erofs_xattr_prefixes_init(struct erofs_sb_info *sbi)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_xattr_long_prefix *prefix = NULL;
	struct erofs_inode *prefix_en;
	erofs_off_t off;
	size_t infix_len, len;
	int ret;

	if (!erofs_sb_has_xattr_prefixes(sbi) || sbi->xattr_prefix_count == 0)
		return (0);
	prefix_en = NULL;
	if (!erofs_sb_has_plain_xattr_pfx(sbi)) {
		if (erofs_sb_has_metabox(sbi)) {
			if (sbi->metabox_en == NULL)
				return (erofs_corrupt(sbi, EROFS_NID_NONE,
				    "xattr prefixes are in the metabox, but "
				    "the image has none"));
			prefix_en = sbi->metabox_en;
		} else if (sbi->packed_inode != NULL) {
			prefix_en = sbi->packed_inode;
		}
	}
	sbi->xattr_prefixes = malloc(sizeof(*sbi->xattr_prefixes) *
		sbi->xattr_prefix_count,
	    M_EROFS, M_WAITOK | M_ZERO);
	off = (uint64_t)sbi->xattr_prefix_start << 2;
	for (uint8_t i = 0; i < sbi->xattr_prefix_count; i++) {
		ret = erofs_xattr_read_metadata(sbi, prefix_en, &off, &buf,
		    &len);
		if (ret != 0)
			goto fail;
		prefix = buf.data;
		infix_len = len - sizeof(*prefix);
		sbi->xattr_prefixes[i].base_index = prefix->base_index;
		sbi->xattr_prefixes[i].infix_len = infix_len;
		sbi->xattr_prefixes[i].infix = malloc(infix_len + 1, M_EROFS,
		    M_WAITOK);
		memcpy(sbi->xattr_prefixes[i].infix, prefix->infix, infix_len);
		sbi->xattr_prefixes[i].infix[infix_len] = '\0';
		erofs_put_metabuf(&buf);
	}
	return (0);
fail:
	erofs_put_metabuf(&buf);
	erofs_xattr_prefixes_cleanup(sbi);
	return (ret);
}

#ifdef UFS_ACL
static int
erofs_inode_has_noacl(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    bool *noaclp)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	struct erofs_xattr_ibody_header *ih;
	struct erofs_inode *backing_en;
	erofs_off_t body_off;
	uint32_t name_filter;
	int error;

	*noaclp = false;
	if (vi->xattr_isize < sizeof(*ih)) {
		*noaclp = true;
		return (0);
	}
	if (!erofs_sb_has_xattr_filter(sbi) || sbi->xattr_filter_reserved != 0)
		return (0);
	body_off = vi->inode_off + vi->inode_isize;
	backing_en = erofs_nid_in_metabox(vi->nid) ? sbi->metabox_en : NULL;
	error = erofs_xattr_read_backing(sbi, backing_en, body_off, sizeof(*ih),
	    &buf);
	if (error != 0)
		return (error);
	ih = buf.data;
	name_filter = le32toh(ih->h_name_filter);
	erofs_put_metabuf(&buf);
	*noaclp = (name_filter & EROFS_XATTR_FILTER_POSIX_ACL) ==
	    EROFS_XATTR_FILTER_POSIX_ACL;
	return (0);
}

static void
erofs_acl_from_mode(mode_t mode, acl_type_t type, struct acl *aclp)
{
	if (type == ACL_TYPE_DEFAULT) {
		aclp->acl_cnt = 0;
		return;
	}
	aclp->acl_cnt = 3;
	aclp->acl_entry[0].ae_tag = ACL_USER_OBJ;
	aclp->acl_entry[0].ae_id = ACL_UNDEFINED_ID;
	aclp->acl_entry[0].ae_perm = acl_posix1e_mode_to_perm(ACL_USER_OBJ,
	    mode);
	aclp->acl_entry[1].ae_tag = ACL_GROUP_OBJ;
	aclp->acl_entry[1].ae_id = ACL_UNDEFINED_ID;
	aclp->acl_entry[1].ae_perm = acl_posix1e_mode_to_perm(ACL_GROUP_OBJ,
	    mode);
	aclp->acl_entry[2].ae_tag = ACL_OTHER;
	aclp->acl_entry[2].ae_id = ACL_UNDEFINED_ID;
	aclp->acl_entry[2].ae_perm = acl_posix1e_mode_to_perm(ACL_OTHER, mode);
}

static int
erofs_posix_acl_from_xattr(const void *value, size_t size, mode_t mode,
    acl_type_t type, struct acl *aclp)
{
	const uint8_t *buf;
	struct posix_acl_xattr_header hdr;
	struct posix_acl_xattr_entry entry;
	uint32_t id;
	int count, i;

	buf = value;
	if (size < sizeof(hdr) || (size - sizeof(hdr)) % sizeof(entry) != 0)
		return (EINTEGRITY);

	memcpy(&hdr, buf, sizeof(hdr));
	if (le32toh(hdr.a_version) != POSIX_ACL_XATTR_VERSION)
		return (EINTEGRITY);

	count = (size - sizeof(hdr)) / sizeof(entry);
	if (count > ACL_MAX_ENTRIES)
		return (EINTEGRITY);
	if (count == 0) {
		erofs_acl_from_mode(mode, type, aclp);
		return (0);
	}

	aclp->acl_cnt = count;
	for (i = 0; i < count; i++) {
		memcpy(&entry, buf + sizeof(hdr) + i * sizeof(entry),
		    sizeof(entry));
		id = le32toh(entry.e_id);
		aclp->acl_entry[i].ae_tag = le16toh(entry.e_tag);
		aclp->acl_entry[i].ae_perm = le16toh(entry.e_perm);
		aclp->acl_entry[i].ae_id = (id == UINT32_MAX) ?
		    ACL_UNDEFINED_ID :
		    id;
	}
	/*
	 * Tags, their counts, permission bits and unnamed ids are the
	 * kernel's ACL contract: acl_posix1e_check() enforces them.  Entry
	 * order and duplicate ids are not checked: vaccess_acl_posix1e()
	 * does not depend on either, and Linux accepts both.
	 */
	if (acl_posix1e_check(aclp) != 0)
		return (EINTEGRITY);

	return (0);
}

int
erofs_get_acl(struct vnode *vp, acl_type_t type, struct acl *aclp)
{
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	const char *xattr_name;
	struct uio auio;
	struct iovec aiov;
	uint8_t buf[sizeof(struct posix_acl_xattr_header) +
	    sizeof(struct posix_acl_xattr_entry) * ACL_MAX_ENTRIES];
	size_t size;
	bool noacl;
	int error;

	sbi = MTOE(vp->v_mount);
	if (!test_opt(&sbi->opt, POSIX_ACL))
		return (EOPNOTSUPP);

	vi = VTOE(vp);

	switch (type) {
	case ACL_TYPE_ACCESS:
		xattr_name = "posix_acl_access";
		break;
	case ACL_TYPE_DEFAULT:
		if (vp->v_type != VDIR)
			return (EINVAL);
		xattr_name = "posix_acl_default";
		break;
	default:
		return (EINVAL);
	}
	error = erofs_inode_has_noacl(sbi, vi, &noacl);
	if (error != 0)
		return (error);
	if (noacl) {
		erofs_acl_from_mode(vi->mode, type, aclp);
		return (0);
	}

	error = erofs_getxattr(vp, EXTATTR_NAMESPACE_SYSTEM, xattr_name, NULL,
	    &size);
	if (error == ENOATTR) {
		erofs_acl_from_mode(vi->mode, type, aclp);
		return (0);
	}
	if (error != 0)
		return (error);
	if (size > sizeof(buf))
		return (erofs_corrupt(sbi, vi->nid,
		    "ACL xattr of %zu bytes is too large", size));

	aiov.iov_base = buf;
	aiov.iov_len = size;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_offset = 0;
	auio.uio_resid = size;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_td = curthread;
	error = erofs_getxattr(vp, EXTATTR_NAMESPACE_SYSTEM, xattr_name, &auio,
	    NULL);
	if (error != 0)
		return (error);
	if (auio.uio_resid != 0)
		return (
		    erofs_corrupt(sbi, vi->nid, "short read of the ACL xattr"));

	error = erofs_posix_acl_from_xattr(buf, size, vi->mode, type, aclp);
	if (error == EINTEGRITY)
		return (erofs_corrupt(sbi, vi->nid,
		    "invalid ACL xattr of %zu bytes", size));
	return (error);
}
#endif
