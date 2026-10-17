/* SPDX-License-Identifier: BSD-2-Clause */

#include <fs/erofs/internal.h>
#include <fs/erofs/trace.h>

SDT_PROVIDER_DEFINE(erofs);

SDT_PROBE_DEFINE4(erofs, data, map_blocks, enter, "uint64_t", "uint64_t",
    "uint64_t", "uint32_t");
SDT_PROBE_DEFINE6(erofs, data, map_blocks, exit, "uint64_t", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t", "uint64_t");
SDT_PROBE_DEFINE5(erofs, data, read_folio, entry, "uint64_t", "uint64_t",
    "uint64_t", "int", "bool");
SDT_PROBE_DEFINE4(erofs, data, readahead, entry, "uint64_t", "uint64_t",
    "uint64_t", "bool");
SDT_PROBE_DEFINE3(erofs, inode, fill_inode, entry, "uint64_t", "uint64_t",
    "uint32_t");
SDT_PROBE_DEFINE4(erofs, namei, lookup, entry, "uint64_t", "uint32_t",
    "uint64_t", "uint32_t");
SDT_PROBE_DEFINE3(erofs, , , corrupt, "uint64_t", "int", "int");
