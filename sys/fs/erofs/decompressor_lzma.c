// SPDX-License-Identifier: MIT
/*
 * EROFS MicroLZMA wrapper around FreeBSD's bundled XZ Embedded decoder.
 * The decoder source is compiled with private symbol names because the
 * stock xz.ko does not enable its optional MicroLZMA entry points.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include <fs/erofs/compress.h>

#define XZ_DEC_MICROLZMA
#define xz_dec_lzma2_create    erofs_xz_dec_lzma2_create
#define xz_dec_lzma2_reset     erofs_xz_dec_lzma2_reset
#define xz_dec_lzma2_run       erofs_xz_dec_lzma2_run
#define xz_dec_lzma2_end       erofs_xz_dec_lzma2_end
#define xz_dec_microlzma_alloc erofs_xz_dec_microlzma_alloc
#define xz_dec_microlzma_reset erofs_xz_dec_microlzma_reset
#define xz_dec_microlzma_run   erofs_xz_dec_microlzma_run
#define xz_dec_microlzma_end   erofs_xz_dec_microlzma_end
#define xz_malloc	       erofs_xz_malloc
#define xz_free		       erofs_xz_free

static void *
erofs_xz_malloc(unsigned long size)
{
	return (malloc(size, M_EROFS, M_WAITOK));
}

static void
erofs_xz_free(void *ptr)
{
	free(ptr, M_EROFS);
}

#include <contrib/xz-embedded/linux/lib/xz/xz_dec_lzma2.c>

#undef bool
#undef false
#undef true
#undef min

struct z_erofs_lzma_ctx {
	struct erofs_stream_ctx pool;
	struct xz_dec_microlzma *state;
	size_t state_bytes;
};

_Static_assert(sizeof(struct z_erofs_lzma_ctx) <= EROFS_STREAM_CTX_WRAPPER_SIZE,
    "LZMA stream wrapper exceeds UMA item");

static void
z_erofs_lzma_ctx_fini(struct erofs_stream_ctx *pool)
{
	struct z_erofs_lzma_ctx *ctx;

	ctx = (struct z_erofs_lzma_ctx *)pool;
	if (ctx->state != NULL) {
		xz_dec_microlzma_end(ctx->state);
		ctx->state = NULL;
	}
	if (ctx->state_bytes != 0) {
		z_erofs_stream_ctx_uncharge(pool, ctx->state_bytes);
		ctx->state_bytes = 0;
	}
}

static int
z_erofs_lzma_ctx_init(struct erofs_stream_ctx *pool)
{
	struct z_erofs_lzma_ctx *ctx;
	int error;

	ctx = (struct z_erofs_lzma_ctx *)pool;
	ctx->state_bytes = sizeof(*ctx->state);
	error = z_erofs_stream_ctx_charge(pool, ctx->state_bytes);
	if (error != 0) {
		ctx->state_bytes = 0;
		return (error);
	}
	ctx->state = xz_dec_microlzma_alloc(XZ_SINGLE,
	    pool->sbi->lzma_dict_size);
	if (ctx->state == NULL) {
		z_erofs_stream_ctx_uncharge(pool, ctx->state_bytes);
		ctx->state_bytes = 0;
		pool->allocation_failed = 1;
		return (ENOMEM);
	}
	return (0);
}

static int
z_erofs_load_lzma_config(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb __unused, const void *data, size_t size)
{
	const struct z_erofs_lzma_cfgs *lzma;
	uint32_t dict_size;

	if (size < sizeof(*lzma))
		return (EINTEGRITY);
	lzma = data;
	if (le16toh(lzma->format) != 0)
		return (EOPNOTSUPP);
	dict_size = le32toh(lzma->dict_size);
	if (dict_size < 4096)
		return (EINTEGRITY);
	if (dict_size > Z_EROFS_LZMA_MAX_DICT_SIZE)
		return (EOPNOTSUPP);
	sbi->lzma_dict_size = dict_size;
	return (0);
}

static int
z_erofs_lzma_error(enum xz_ret ret)
{
	switch (ret) {
	case XZ_MEM_ERROR:
		return (ENOMEM);
	case XZ_MEMLIMIT_ERROR:
	case XZ_OPTIONS_ERROR:
	case XZ_UNSUPPORTED_CHECK:
		return (EOPNOTSUPP);
	default:
		return (EINTEGRITY);
	}
}

static int
z_erofs_lzma_finish(const struct z_erofs_decompress_req *rq, enum xz_ret ret,
    size_t input_pos)
{
	if (rq->partial_decoding && (ret == XZ_OK || ret == XZ_STREAM_END))
		return (0);
	if (!rq->partial_decoding && ret == XZ_STREAM_END &&
	    input_pos == rq->inputsize)
		return (0);
	return (z_erofs_lzma_error(ret));
}

static int
z_erofs_lzma_decompress(const struct z_erofs_decompress_req *rq)
{
	struct erofs_stream_ctx *pool;
	struct z_erofs_lzma_ctx *ctx;
	struct xz_buf buffer;
	enum xz_ret ret;
	int error;

	/* At most 1 MiB and 12 MiB (z_erofs_map_sanity_check()). */
	KASSERT(rq->inputsize <= UINT32_MAX && rq->outputsize <= UINT32_MAX,
	    ("erofs: lzma sizes"));
	error = z_erofs_stream_ctx_get(rq->sbi, Z_EROFS_COMPRESSION_LZMA,
	    sizeof(*ctx), z_erofs_lzma_ctx_init, z_erofs_lzma_ctx_fini, &pool);
	if (error != 0)
		return (error);
	ctx = (struct z_erofs_lzma_ctx *)pool;
	bzero(&buffer, sizeof(buffer));
	buffer.in = rq->in;
	buffer.in_size = rq->inputsize;
	buffer.out = rq->out;
	buffer.out_size = rq->outputsize;
	xz_dec_microlzma_reset(ctx->state, (uint32_t)rq->inputsize,
	    (uint32_t)rq->outputsize, !rq->partial_decoding);
	ret = xz_dec_microlzma_run(ctx->state, &buffer);
	if (buffer.out_pos != rq->outputsize)
		error = EINTEGRITY;
	else
		error = z_erofs_lzma_finish(rq, ret, buffer.in_pos);
	z_erofs_stream_ctx_put(pool, error == 0);
	return (error);
}

const struct z_erofs_decompressor z_erofs_lzma_decomp = {
	.config = z_erofs_load_lzma_config,
	.decompress = z_erofs_lzma_decompress,
};
