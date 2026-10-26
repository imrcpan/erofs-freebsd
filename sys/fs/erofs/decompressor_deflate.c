/* SPDX-License-Identifier: MIT */
/* Minimal DEFLATE decompressor for EROFS FreeBSD */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/limits.h>

#include <contrib/zlib/zlib.h>
#include <fs/erofs/compress.h>

struct z_erofs_deflate_ctx {
	struct erofs_stream_ctx pool;
	z_stream stream;
	bool initialized;
};

_Static_assert(sizeof(struct z_erofs_deflate_ctx) <=
	EROFS_STREAM_CTX_WRAPPER_SIZE,
    "Deflate stream wrapper exceeds UMA item");

static voidpf
z_erofs_deflate_alloc(voidpf opaque, uInt items, uInt size)
{
	struct erofs_stream_ctx *pool;
	pool = opaque;
	/* Two 32-bit factors cannot overflow a 64-bit size_t. */
	return (z_erofs_stream_ctx_alloc(pool, (size_t)items * size));
}

static void
z_erofs_deflate_free(voidpf opaque, voidpf address)
{
	z_erofs_stream_ctx_free(opaque, address);
}

static int
z_erofs_load_deflate_config(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb __unused, const void *data, size_t size)
{
	const struct z_erofs_deflate_cfgs *deflate;

	if (size < sizeof(*deflate))
		return (EINTEGRITY);
	deflate = data;
	if (deflate->windowbits > MAX_WBITS)
		return (EOPNOTSUPP);
	return (0);
}

static int
z_erofs_deflate_error(int ret)
{
	switch (ret) {
	case Z_MEM_ERROR:
		return (ENOMEM);
	case Z_VERSION_ERROR:
		return (EOPNOTSUPP);
	case Z_NEED_DICT:
	case Z_DATA_ERROR:
	case Z_BUF_ERROR:
		return (EINTEGRITY);
	default:
		return (EIO);
	}
}

static void
z_erofs_deflate_ctx_fini(struct erofs_stream_ctx *pool)
{
	struct z_erofs_deflate_ctx *ctx;

	ctx = (struct z_erofs_deflate_ctx *)pool;
	if (ctx->initialized) {
		(void)inflateEnd(&ctx->stream);
		ctx->initialized = false;
	}
}

static int
z_erofs_deflate_ctx_init(struct erofs_stream_ctx *pool)
{
	struct z_erofs_deflate_ctx *ctx;
	int ret;

	ctx = (struct z_erofs_deflate_ctx *)pool;
	bzero(&ctx->stream, sizeof(ctx->stream));
	ctx->stream.zalloc = z_erofs_deflate_alloc;
	ctx->stream.zfree = z_erofs_deflate_free;
	ctx->stream.opaque = pool;
	ret = inflateInit2(&ctx->stream, -MAX_WBITS);
	if (ret != Z_OK)
		return (z_erofs_deflate_error(ret));
	ctx->initialized = true;
	return (0);
}

static int
z_erofs_deflate_finish(const struct z_erofs_decompress_req *rq, int ret,
    uInt avail_in)
{
	if (rq->partial_decoding)
		return (0);
	if (ret != Z_STREAM_END || avail_in != 0)
		return (EINTEGRITY);
	return (0);
}

static int
z_erofs_deflate_decompress(const struct z_erofs_decompress_req *rq)
{
	struct erofs_stream_ctx *pool;
	struct z_erofs_deflate_ctx *ctx;
	z_stream *strm;
	uInt in_before, out_before;
	int error, ret;

	/* At most 1 MiB and 12 MiB (z_erofs_map_sanity_check()). */
	KASSERT(rq->inputsize <= UINT_MAX && rq->outputsize <= UINT_MAX,
	    ("erofs: deflate sizes"));

	error = z_erofs_stream_ctx_get(rq->sbi, Z_EROFS_COMPRESSION_DEFLATE,
	    sizeof(*ctx), z_erofs_deflate_ctx_init, z_erofs_deflate_ctx_fini,
	    &pool);
	if (error != 0)
		return (error);
	ctx = (struct z_erofs_deflate_ctx *)pool;
	strm = &ctx->stream;
	pool->allocation_failed = false;
	ret = inflateReset2(strm, -MAX_WBITS);
	if (ret != Z_OK) {
		error = z_erofs_deflate_error(ret);
		z_erofs_stream_ctx_put(pool, false);
		return (error);
	}
	strm->next_in = __DECONST(void *, rq->in);
	strm->avail_in = rq->inputsize;
	strm->next_out = rq->out;
	strm->avail_out = rq->outputsize;

	error = 0;
	ret = Z_OK;
	while (strm->avail_out != 0) {
		in_before = strm->avail_in;
		out_before = strm->avail_out;
		ret = inflate(strm, Z_SYNC_FLUSH);
		if (ret == Z_STREAM_END)
			break;
		if (ret != Z_OK) {
			error = z_erofs_deflate_error(ret);
			break;
		}
		if (strm->avail_in == in_before &&
		    strm->avail_out == out_before) {
			error = EINTEGRITY;
			break;
		}
	}
	if (error == 0 && strm->avail_out != 0)
		error = EINTEGRITY;
	else if (error == 0)
		error = z_erofs_deflate_finish(rq, ret, strm->avail_in);
	if (pool->allocation_failed)
		error = ENOMEM;
	z_erofs_stream_ctx_put(pool, error == 0);
	return (error);
}

const struct z_erofs_decompressor z_erofs_deflate_decomp = {
	.config = z_erofs_load_deflate_config,
	.decompress = z_erofs_deflate_decompress,
};
