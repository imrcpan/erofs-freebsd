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
