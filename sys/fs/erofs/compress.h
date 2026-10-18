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
	int (*decompress)(const struct z_erofs_decompress_req *);
};

#endif
