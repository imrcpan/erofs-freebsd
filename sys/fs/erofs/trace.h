/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _FS_EROFS_TRACE_H_
#define _FS_EROFS_TRACE_H_

#include <sys/sdt.h>

#include <fs/erofs/internal.h>

SDT_PROVIDER_DECLARE(erofs);

SDT_PROBE_DECLARE(erofs, data, map_blocks, enter);
SDT_PROBE_DECLARE(erofs, data, map_blocks, exit);
SDT_PROBE_DECLARE(erofs, data, read_folio, entry);
SDT_PROBE_DECLARE(erofs, data, readahead, entry);
SDT_PROBE_DECLARE(erofs, inode, fill_inode, entry);
SDT_PROBE_DECLARE(erofs, namei, lookup, entry);
SDT_PROBE_DECLARE(erofs, , , corrupt);

#define EROFS_TRACE_CORRUPT(nid, line, error) \
	SDT_PROBE3(erofs, , , corrupt, (nid), (line), (error))

#define EROFS_TRACE_MAP_BLOCKS_ENTER(vi, map, flags)                       \
	SDT_PROBE4(erofs, data, map_blocks, enter, (vi)->nid, (map)->m_la, \
	    (map)->m_llen, (flags))

#ifdef KDTRACE_HOOKS
#define EROFS_TRACE_MAP_BLOCKS_EXIT(vi, map, error)                          \
	do {                                                                 \
		uint64_t erofs_trace_status;                                 \
		if (SDT_PROBES_ENABLED()) {                                  \
			erofs_trace_status = ((uint64_t)(uint32_t)(error)    \
						 << 32) |                    \
			    (uint64_t)(uint32_t)(map)->m_flags;              \
			SDT_PROBE6(erofs, data, map_blocks, exit, (vi)->nid, \
			    (map)->m_la, (map)->m_pa, (map)->m_llen,         \
			    (map)->m_plen, erofs_trace_status);              \
		}                                                            \
	} while (0)
#else
#define EROFS_TRACE_MAP_BLOCKS_EXIT(vi, map, error) \
	do {                                        \
		(void)(vi);                         \
		(void)(map);                        \
		(void)(error);                      \
	} while (0)
#endif

#define EROFS_TRACE_READ_FOLIO(vi, offset, length, raw)                  \
	SDT_PROBE5(erofs, data, read_folio, entry, (vi)->nid,            \
	    (uint64_t)(offset), (uint64_t)(length), (vi)->vtype == VDIR, \
	    (raw))

#define EROFS_TRACE_READAHEAD(vi, start, nrpages, raw)       \
	SDT_PROBE4(erofs, data, readahead, entry, (vi)->nid, \
	    (uint64_t)(start), (uint64_t)(nrpages), (raw))

#define EROFS_TRACE_FILL_INODE(nid, blkaddr, offset)       \
	SDT_PROBE3(erofs, inode, fill_inode, entry, (nid), \
	    (uint64_t)(blkaddr), (uint32_t)(offset))

static __inline void
erofs_trace_lookup(const struct erofs_inode *dir, const char *name,
    size_t length, uint32_t flags)
{
#ifdef KDTRACE_HOOKS
	uint32_t hash;
	size_t i;

	if (!SDT_PROBES_ENABLED())
		return;
	hash = UINT32_C(2166136261);
	for (i = 0; i < length; ++i) {
		hash ^= (uint8_t)name[i];
		hash *= UINT32_C(16777619);
	}
	SDT_PROBE4(erofs, namei, lookup, entry, dir->nid, hash,
	    (uint64_t)length, flags);
#else
	(void)dir;
	(void)name;
	(void)length;
	(void)flags;
#endif
}

#endif
