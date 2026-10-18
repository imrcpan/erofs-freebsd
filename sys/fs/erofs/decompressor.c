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
	[Z_EROFS_COMPRESSION_DEFLATE] = &z_erofs_deflate_decomp,
};

static int
z_erofs_read_cfg(struct erofs_sb_info *sbi, uint64_t *offset,
    struct erofs_buf *buf, size_t *sizep)
{
	struct erofs_buf metabuf = EROFS_BUF_INITIALIZER;
	uint8_t length_buf[2];
	uint64_t aligned;
	uint16_t length;
	int error;

	/*
	 * At most one configuration per algorithm, each at most 64 KiB, follows
	 * the superblock, so the offset stays far below the overflow limit; the
	 * reads are range checked.
	 */
	aligned = roundup2(*offset, 4);
	error = erofs_read_metadata_range(sbi, 0, aligned, sizeof(length_buf),
	    &metabuf);
	if (error != 0)
		return (error);
	memcpy(length_buf, metabuf.data, sizeof(length_buf));
	erofs_put_metabuf(&metabuf);
	length = le16dec(length_buf);
	*sizep = length != 0 ? length : UINT16_MAX + 1U;
	*offset = aligned + sizeof(length_buf);
	error = erofs_read_metadata_range(sbi, 0, *offset, *sizep, buf);
	if (error == 0)
		*offset += *sizep;
	return (error);
}

int
z_erofs_parse_cfgs(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb)
{
	struct erofs_buf data = EROFS_BUF_INITIALIZER;
	const struct z_erofs_decompressor *decompressor;
	uint64_t offset;
	uint16_t algorithms;
	size_t size;
	int algorithm, ret;

	if (!erofs_sb_has_compr_cfgs(sbi))
		return (z_erofs_lz4_decomp.config(sbi, dsb, NULL, 0));
	algorithms = le16toh(dsb->u1.available_compr_algs);
	sbi->available_compr_algs = algorithms;
	if ((algorithms & ~Z_EROFS_ALL_COMPR_ALGS) != 0)
		return (EOPNOTSUPP);
	offset = EROFS_SUPER_OFFSET + sbi->sb_size;
	for (algorithm = 0; algorithm < Z_EROFS_COMPRESSION_MAX; ++algorithm) {
		if ((algorithms & (1U << algorithm)) == 0)
			continue;
		ret = z_erofs_read_cfg(sbi, &offset, &data, &size);
		if (ret != 0)
			return (ret);
		decompressor = z_erofs_decomp[algorithm];
		if (decompressor == NULL || decompressor->config == NULL)
			ret = EOPNOTSUPP;
		else
			ret = decompressor->config(sbi, dsb, data.data, size);
		erofs_put_metabuf(&data);
		if (ret != 0)
			return (ret);
	}
	return (0);
}

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
