/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef _FS_EROFS_COMPRESS_H_
#define _FS_EROFS_COMPRESS_H_

#include <fs/erofs/internal.h>

struct z_erofs_decompress_req {
	struct erofs_sb_info *sbi;
	const struct erofs_map_blocks *map;
	const void *in;
	size_t inputsize;
	void *out;
	size_t outputsize;
	bool partial_decoding;
};

struct z_erofs_decompressor {
	/* Callbacks return zero or a positive FreeBSD errno. */
	int (*config)(struct erofs_sb_info *, const struct erofs_super_block *,
	    const void *, size_t);
	int (*decompress)(const struct z_erofs_decompress_req *);
};

int z_erofs_lz4_buffer_decompress(const struct z_erofs_decompress_req *rq);
extern const struct z_erofs_decompressor z_erofs_lz4_decomp;
extern const struct z_erofs_decompressor z_erofs_deflate_decomp;

#endif
