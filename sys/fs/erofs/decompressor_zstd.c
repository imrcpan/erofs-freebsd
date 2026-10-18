/* SPDX-License-Identifier: BSD-2-Clause */
/* Minimal zstd decompressor for EROFS FreeBSD */
#include "opt_zstdio.h"

#include <sys/param.h>
#include <sys/systm.h>

#include <fs/erofs/compress.h>

#ifdef ZSTDIO
#define ZSTD_STATIC_LINKING_ONLY
#include <contrib/zstd/lib/zstd.h>

struct z_erofs_zstd_ctx {
	struct erofs_stream_ctx pool;
	ZSTD_DCtx *dctx;
};

_Static_assert(sizeof(struct z_erofs_zstd_ctx) <= EROFS_STREAM_CTX_WRAPPER_SIZE,
    "Zstd stream wrapper exceeds UMA item");
#endif

static bool
erofs_zstd_available(void)
{
#ifdef ZSTDIO
	return (true);
#else
	return (false);
#endif
}

static int
z_erofs_load_zstd_config(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb __unused, const void *data, size_t size)
{
	const struct z_erofs_zstd_cfgs *zstd;

	if (!erofs_zstd_available()) {
		vfs_mount_error(sbi->mnt,
		    "erofs: ZSTD compression requires ZSTDIO support");
		return (EOPNOTSUPP);
	}
	if (data == NULL || size < sizeof(*zstd))
		return (EINTEGRITY);
	zstd = data;
	if (zstd->format != 0 || zstd->windowlog > 10)
		return (EOPNOTSUPP);
	sbi->zstd_windowlog = zstd->windowlog;
	return (0);
}

#ifdef ZSTDIO
static void *
zstd_alloc(void *opaque, size_t size)
{
	return (z_erofs_stream_ctx_alloc(opaque, size));
}

static void
zstd_free(void *opaque, void *address)
{
	z_erofs_stream_ctx_free(opaque, address);
}

static void
z_erofs_zstd_ctx_fini(struct erofs_stream_ctx *pool)
{
	struct z_erofs_zstd_ctx *ctx;

	ctx = (struct z_erofs_zstd_ctx *)pool;
	if (ctx->dctx != NULL) {
		(void)ZSTD_freeDCtx(ctx->dctx);
		ctx->dctx = NULL;
	}
}

static int
z_erofs_zstd_ctx_init(struct erofs_stream_ctx *pool)
{
	struct z_erofs_zstd_ctx *ctx;
	ZSTD_customMem alloc;
	size_t ret;

	ctx = (struct z_erofs_zstd_ctx *)pool;
	alloc = (ZSTD_customMem) {
		.customAlloc = zstd_alloc,
		.customFree = zstd_free,
		.opaque = pool,
	};
	ctx->dctx = ZSTD_createDCtx_advanced(alloc);
	if (ctx->dctx == NULL)
		return (ENOMEM);
	ret = ZSTD_DCtx_setParameter(ctx->dctx, ZSTD_d_windowLogMax,
	    pool->sbi->zstd_windowlog + 10);
	if (ZSTD_isError(ret))
		return (pool->allocation_failed ? ENOMEM : EOPNOTSUPP);
	return (0);
}

static int
z_erofs_zstd_finish(const struct z_erofs_decompress_req *rq, size_t ret,
    size_t input_pos, size_t input_size)
{
	if (rq->partial_decoding)
		return (0);
	if (ret != 0 || input_pos != input_size)
		return (EINTEGRITY);
	return (0);
}

static int
z_erofs_zstd_decompress(const struct z_erofs_decompress_req *rq)
{
	struct erofs_stream_ctx *pool;
	struct z_erofs_zstd_ctx *ctx;
	ZSTD_inBuffer input;
	ZSTD_outBuffer output;
	size_t in_before, out_before, ret;
	int error;

	error = z_erofs_stream_ctx_get(rq->sbi, Z_EROFS_COMPRESSION_ZSTD,
	    sizeof(*ctx), z_erofs_zstd_ctx_init, z_erofs_zstd_ctx_fini, &pool);
	if (error != 0)
		return (error);
	ctx = (struct z_erofs_zstd_ctx *)pool;
	pool->allocation_failed = false;

	input = (ZSTD_inBuffer) {
		.src = rq->in,
		.size = rq->inputsize,
	};
	output = (ZSTD_outBuffer) {
		.dst = rq->out,
		.size = rq->outputsize,
	};
	error = 0;
	ret = 1;
	while (output.pos != output.size) {
		in_before = input.pos;
		out_before = output.pos;
		ret = ZSTD_decompressStream(ctx->dctx, &output, &input);
		if (ZSTD_isError(ret)) {
			error = pool->allocation_failed ? ENOMEM : EINTEGRITY;
			break;
		}
		if (input.pos == in_before && output.pos == out_before) {
			error = EINTEGRITY;
			break;
		}
		if (ret == 0)
			break;
	}
	if (error == 0 && output.pos != output.size)
		error = EINTEGRITY;
	else if (error == 0)
		error = z_erofs_zstd_finish(rq, ret, input.pos, input.size);
	z_erofs_stream_ctx_put(pool, error == 0 && !rq->partial_decoding);
	return (error);
}
#else
static int
z_erofs_zstd_decompress(const struct z_erofs_decompress_req *rq __unused)
{
	return (EOPNOTSUPP);
}
#endif

const struct z_erofs_decompressor z_erofs_zstd_decomp = {
	.config = z_erofs_load_zstd_config,
	.decompress = z_erofs_zstd_decompress,
};
