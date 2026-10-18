// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             https://www.huawei.com/
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/_maxphys.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/smp.h>
#include <sys/uio.h>

#include <fs/erofs/compress.h>

static void
z_erofs_decode_length(const struct erofs_map_blocks *map, erofs_off_t mapoff,
    size_t want, size_t *decoded_len, bool *partial)
{
	size_t end;

	/* z_erofs_do_read() has checked that [mapoff, mapoff + want) fits. */
	KASSERT(mapoff <= map->m_llen && want <= map->m_llen - mapoff,
	    ("erofs: bad decode range"));
	end = (size_t)mapoff + want;
	*partial = (map->m_flags & EROFS_MAP_PARTIAL_REF) != 0;
	*decoded_len = *partial ? end : (size_t)map->m_llen;
}

int
z_erofs_decode_extent(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map, size_t decoded_len, bool partial, void **bufp)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	const void *input;
	void *compressed, *decoded;
	int error;

	*bufp = NULL;
	/*
	 * z_erofs_do_read() handles fragment and unmapped extents itself and
	 * gets decoded_len from z_erofs_decode_length().
	 */
	KASSERT((map->m_flags & (EROFS_MAP_FRAGMENT | EROFS_MAP_MAPPED)) ==
		EROFS_MAP_MAPPED,
	    ("erofs: decoding a map with flags %#x",
		(unsigned int)map->m_flags));
	KASSERT(decoded_len != 0 && decoded_len <= map->m_llen &&
		(partial || decoded_len == map->m_llen),
	    ("erofs: bad decoded length %zu", decoded_len));

	if ((map->m_flags & EROFS_MAP_META) != 0) {
		error = erofs_read_metadata_range(sbi, vi->nid, map->m_pa,
		    (size_t)map->m_plen, &buf);
	} else {
		error = erofs_read_physical(sbi, map->m_deviceid, map->m_pa,
		    (size_t)map->m_plen, &compressed);
	}
	if (error != 0)
		return (error);
	input = (map->m_flags & EROFS_MAP_META) != 0 ? buf.data : compressed;

	decoded = malloc(decoded_len, M_EROFS, M_WAITOK | M_ZERO);
	error = z_erofs_decompress(sbi, map, input, (size_t)map->m_plen,
	    decoded, decoded_len, partial);
	if ((map->m_flags & EROFS_MAP_META) != 0)
		erofs_put_metabuf(&buf);
	else
		erofs_brelse(compressed);
	if (error != 0) {
		free(decoded, M_EROFS);
		return (error);
	}
	*bufp = decoded;
	return (0);
}
