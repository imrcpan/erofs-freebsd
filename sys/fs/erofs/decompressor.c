// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2019 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2024 Alibaba Cloud
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/libkern.h>

#include <fs/erofs/compress.h>

static int
z_erofs_load_lz4_config(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb, const void *data, size_t size)
{
	const struct z_erofs_lz4_cfgs *lz4;
	uint32_t max_pclusterblks;
	uint16_t distance;

	if (data != NULL) {
		if (size < sizeof(*lz4))
			return (EINTEGRITY);
		lz4 = data;
		max_pclusterblks = le16toh(lz4->max_pclusterblks);
		if (max_pclusterblks >
		    (Z_EROFS_PCLUSTER_MAX_SIZE >> sbi->blkszbits))
			return (EOPNOTSUPP);
	} else {
		distance = le16toh(dsb->u1.lz4_max_distance);
		if (distance == 0 && !erofs_sb_has_lz4_0padding(sbi))
			return (0);
		sbi->available_compr_algs = 1U << Z_EROFS_COMPRESSION_LZ4;
	}
	return (0);
}

static int
z_erofs_transform_plain(const struct z_erofs_decompress_req *rq)
{
	const uint8_t *src;
	uint8_t *dst;
	size_t first, offset, span;

	if (rq->outputsize > rq->inputsize)
		return (EINTEGRITY);
	src = rq->in;
	dst = rq->out;
	if (rq->map->m_algorithmformat == Z_EROFS_COMPRESSION_SHIFTED) {
		memmove(dst, src, rq->outputsize);
		return (0);
	}
	span = rq->sbi->block_size -
	    (rq->map->m_la & (rq->sbi->block_size - 1));
	if (span > rq->inputsize)
		return (EINTEGRITY);
	first = MIN(span, rq->outputsize);
	offset = rq->inputsize - span;
	if (offset > rq->inputsize || first > rq->inputsize - offset)
		return (EINTEGRITY);
	memmove(dst, src + offset, first);
	if (first < rq->outputsize)
		memmove(dst + first, src, rq->outputsize - first);
	return (0);
}

static const struct z_erofs_decompressor z_erofs_shifted_decomp = {
	.decompress = z_erofs_transform_plain,
};

static const struct z_erofs_decompressor z_erofs_interlaced_decomp = {
	.decompress = z_erofs_transform_plain,
};

const struct z_erofs_decompressor z_erofs_lz4_decomp = {
	.config = z_erofs_load_lz4_config,
	.decompress = z_erofs_lz4_buffer_decompress,
};

static const struct z_erofs_decompressor *const z_erofs_decomp[] = {
	[Z_EROFS_COMPRESSION_SHIFTED] = &z_erofs_shifted_decomp,
	[Z_EROFS_COMPRESSION_INTERLACED] = &z_erofs_interlaced_decomp,
	[Z_EROFS_COMPRESSION_LZ4] = &z_erofs_lz4_decomp,
};

int
z_erofs_decompress(struct erofs_sb_info *sbi,
    const struct erofs_map_blocks *map, const void *src0, size_t srclen,
    void *dst, size_t dstlen, bool partial)
{
	const struct z_erofs_decompressor *decompressor;
	struct z_erofs_decompress_req rq;
	const uint8_t *src;
	uint8_t algorithm;
	size_t padding, padding_limit;

	algorithm = map->m_algorithmformat;
	if (algorithm >= nitems(z_erofs_decomp) ||
	    z_erofs_decomp[algorithm] == NULL ||
	    z_erofs_decomp[algorithm]->decompress == NULL)
		return (EOPNOTSUPP);
	decompressor = z_erofs_decomp[algorithm];
	rq = (struct z_erofs_decompress_req) {
		.sbi = sbi,
		.map = map,
		.in = src0,
		.inputsize = srclen,
		.out = dst,
		.outputsize = dstlen,
		.partial_decoding = partial,
	};
	if (algorithm == Z_EROFS_COMPRESSION_SHIFTED ||
	    algorithm == Z_EROFS_COMPRESSION_INTERLACED)
		return (decompressor->decompress(&rq));

	src = src0;
	if (map->m_algorithmformat != Z_EROFS_COMPRESSION_LZ4 ||
	    erofs_sb_has_lz4_0padding(sbi)) {
		padding_limit = MIN(srclen,
		    sbi->block_size - (map->m_pa & (sbi->block_size - 1)));
		for (padding = 0; padding < padding_limit && src[padding] == 0;
		    ++padding)
			;
		if (padding == padding_limit)
			return (EINTEGRITY);
		src += padding;
		srclen -= padding;
	}
	rq.in = src;
	rq.inputsize = srclen;
	return (decompressor->decompress(&rq));
}
