// SPDX-License-Identifier: BSD-2-Clause
/* FreeBSD stream context pool and compression runtime accounting. */

#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/sysctl.h>

#include <vm/uma.h>

#include <fs/erofs/internal.h>

#define EROFS_STREAM_MOUNT_HARD_BUDGET	     (32UL * 1024 * 1024)
#define EROFS_STREAM_GLOBAL_HARD_BUDGET	     (128UL * 1024 * 1024)
#define EROFS_STREAM_ALLOCATION_HARD_MAX     (4UL * 1024 * 1024)
#define EROFS_STREAM_MOUNT_HARD_CONTEXTS     (16U)
#define EROFS_STREAM_GLOBAL_HARD_CONTEXTS    (64U)
#define EROFS_STREAM_MOUNT_CACHED_PER_CODEC  (2U)
#define EROFS_STREAM_GLOBAL_CACHED_PER_CODEC (16U)

static unsigned long erofs_stream_mount_budget = EROFS_STREAM_MOUNT_HARD_BUDGET;
static unsigned long erofs_stream_global_budget =
    EROFS_STREAM_GLOBAL_HARD_BUDGET;
static int erofs_stream_mount_contexts = EROFS_STREAM_MOUNT_HARD_CONTEXTS;
static int erofs_stream_global_contexts_limit =
    EROFS_STREAM_GLOBAL_HARD_CONTEXTS;
static int erofs_stream_mount_cached = EROFS_STREAM_MOUNT_CACHED_PER_CODEC;
static int erofs_stream_global_cached = EROFS_STREAM_GLOBAL_CACHED_PER_CODEC;

TUNABLE_ULONG("vfs.erofs.stream_pool.mount_budget", &erofs_stream_mount_budget);
TUNABLE_ULONG("vfs.erofs.stream_pool.global_budget",
    &erofs_stream_global_budget);
TUNABLE_INT("vfs.erofs.stream_pool.mount_contexts",
    &erofs_stream_mount_contexts);
TUNABLE_INT("vfs.erofs.stream_pool.global_contexts",
    &erofs_stream_global_contexts_limit);
TUNABLE_INT("vfs.erofs.stream_pool.mount_cached_per_codec",
    &erofs_stream_mount_cached);
TUNABLE_INT("vfs.erofs.stream_pool.global_cached_per_codec",
    &erofs_stream_global_cached);

static struct mtx erofs_stream_lock;
static struct cv erofs_stream_global_cv;
static unsigned int erofs_stream_global_waiters;
static LIST_HEAD(, erofs_sb_info) erofs_stream_mounts = LIST_HEAD_INITIALIZER(
    erofs_stream_mounts);
static uma_zone_t erofs_stream_zone;
static size_t erofs_stream_global_resident;
static unsigned int erofs_stream_global_contexts;
static unsigned int
    erofs_stream_global_cached_by_codec[Z_EROFS_COMPRESSION_MAX];
static unsigned long erofs_stream_cached_contexts;
static unsigned long erofs_stream_borrowed_contexts;
static unsigned long erofs_stream_idle_contexts;
static unsigned long erofs_stream_creations;
static unsigned long erofs_stream_reuses;
static unsigned long erofs_stream_fallbacks;
static unsigned long erofs_stream_exhaustions;
static unsigned long erofs_stream_waits;
static unsigned long erofs_stream_destroys;
static unsigned long erofs_stream_reclaims;

MTX_SYSINIT(erofs_stream_pool, &erofs_stream_lock, "erofs stream pool",
    MTX_DEF);

SYSCTL_DECL(_vfs_erofs);
SYSCTL_NODE(_vfs_erofs, OID_AUTO, stream_pool, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "EROFS stream context pool");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, mount_budget, CTLFLAG_RD,
    &erofs_stream_mount_budget, 0, "Effective per-mount byte budget");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, global_budget, CTLFLAG_RD,
    &erofs_stream_global_budget, 0, "Effective global byte budget");
SYSCTL_INT(_vfs_erofs_stream_pool, OID_AUTO, mount_contexts, CTLFLAG_RD,
    &erofs_stream_mount_contexts, 0,
    "Effective per-mount, per-algorithm context limit");
SYSCTL_INT(_vfs_erofs_stream_pool, OID_AUTO, global_contexts_limit, CTLFLAG_RD,
    &erofs_stream_global_contexts_limit, 0, "Effective global context limit");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, resident_bytes, CTLFLAG_RD,
    &erofs_stream_global_resident, 0, "Currently charged global bytes");
SYSCTL_UINT(_vfs_erofs_stream_pool, OID_AUTO, contexts, CTLFLAG_RD,
    &erofs_stream_global_contexts, 0, "Currently allocated contexts");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, cached, CTLFLAG_RD,
    &erofs_stream_cached_contexts, 0, "Currently cacheable contexts");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, borrowed, CTLFLAG_RD,
    &erofs_stream_borrowed_contexts, 0, "Currently borrowed contexts");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, idle, CTLFLAG_RD,
    &erofs_stream_idle_contexts, 0, "Currently idle contexts");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, creations, CTLFLAG_RD,
    &erofs_stream_creations, 0, "Successful context creations");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, reuses, CTLFLAG_RD,
    &erofs_stream_reuses, 0, "Idle context acquisitions");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, fallbacks, CTLFLAG_RD,
    &erofs_stream_fallbacks, 0, "Bounded temporary context fallbacks");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, exhaustions, CTLFLAG_RD,
    &erofs_stream_exhaustions, 0, "Unsatisfiable limit or budget rejections");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, waits, CTLFLAG_RD,
    &erofs_stream_waits, 0, "Sleeps waiting for a context or budget release");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, destroys, CTLFLAG_RD,
    &erofs_stream_destroys, 0, "Destroyed contexts");
SYSCTL_ULONG(_vfs_erofs_stream_pool, OID_AUTO, reclaims, CTLFLAG_RD,
    &erofs_stream_reclaims, 0, "Low-memory idle context reclaims");

struct erofs_stream_alloc_header {
	struct erofs_stream_ctx *ctx;
	size_t bytes;
};

static bool
erofs_stream_mount_budget_available_locked(const struct erofs_sb_info *sbi,
    size_t bytes)
{
	mtx_assert(&erofs_stream_lock, MA_OWNED);
	return (bytes <= erofs_stream_mount_budget &&
	    sbi->stream_pool.resident_bytes <=
		erofs_stream_mount_budget - bytes);
}

static bool
erofs_stream_global_budget_available_locked(size_t bytes)
{
	mtx_assert(&erofs_stream_lock, MA_OWNED);
	return (bytes <= erofs_stream_global_budget &&
	    erofs_stream_global_resident <= erofs_stream_global_budget - bytes);
}

static bool
erofs_stream_reserve_locked(struct erofs_sb_info *sbi, size_t bytes)
{
	struct erofs_stream_pool *pool;

	mtx_assert(&erofs_stream_lock, MA_OWNED);
	pool = &sbi->stream_pool;
	if (!erofs_stream_mount_budget_available_locked(sbi, bytes) ||
	    !erofs_stream_global_budget_available_locked(bytes))
		return (false);
	pool->resident_bytes += bytes;
	erofs_stream_global_resident += bytes;
	return (true);
}

/*
 * Wake threads sleeping in z_erofs_stream_ctx_get() after a context or byte
 * budget was released.  Mount-level sleepers and the unmount drain share the
 * per-mount cv; sleepers blocked on a global limit use the global cv.
 */
static void
erofs_stream_wake_locked(struct erofs_sb_info *sbi)
{
	mtx_assert(&erofs_stream_lock, MA_OWNED);
	if (sbi->stream_pool.waiters != 0 || sbi->stream_pool.closing)
		cv_broadcast(&sbi->stream_pool.cv);
	if (erofs_stream_global_waiters != 0)
		cv_broadcast(&erofs_stream_global_cv);
}

static void
erofs_stream_release_locked(struct erofs_sb_info *sbi, size_t bytes)
{
	mtx_assert(&erofs_stream_lock, MA_OWNED);
	KASSERT(bytes <= sbi->stream_pool.resident_bytes &&
		bytes <= erofs_stream_global_resident,
	    ("erofs stream pool byte accounting underflow"));
	sbi->stream_pool.resident_bytes -= bytes;
	erofs_stream_global_resident -= bytes;
}

static struct erofs_stream_ctx *
erofs_stream_take_idle_locked(struct erofs_sb_info *sbi)
{
	struct erofs_stream_pool_codec *codec;
	struct erofs_stream_ctx *ctx;
	unsigned int algorithm;

	mtx_assert(&erofs_stream_lock, MA_OWNED);
	for (algorithm = 0; algorithm < Z_EROFS_COMPRESSION_MAX; ++algorithm) {
		codec = &sbi->stream_pool.codec[algorithm];
		ctx = STAILQ_FIRST(&codec->idle);
		if (ctx == NULL)
			continue;
		STAILQ_REMOVE_HEAD(&codec->idle, link);
		KASSERT(codec->idle_count != 0 &&
			erofs_stream_idle_contexts != 0,
		    ("erofs stream idle accounting underflow"));
		--codec->idle_count;
		--erofs_stream_idle_contexts;
		++codec->borrowed;
		++erofs_stream_borrowed_contexts;
		return (ctx);
	}
	return (NULL);
}

/*
 * Detach one idle context so that the caller can destroy it after dropping
 * the lock.  Idle contexts of this mount are preferred; other mounts are only
 * considered when the limit being hit is a global one.
 */
static struct erofs_stream_ctx *
erofs_stream_take_reclaimable_locked(struct erofs_sb_info *sbi, bool global)
{
	struct erofs_stream_ctx *ctx;
	struct erofs_sb_info *other;

	ctx = erofs_stream_take_idle_locked(sbi);
	if (ctx != NULL || !global)
		return (ctx);
	LIST_FOREACH(other, &erofs_stream_mounts, stream_pool_link) {
		ctx = erofs_stream_take_idle_locked(other);
		if (ctx != NULL)
			break;
	}
	return (ctx);
}

static void erofs_stream_ctx_destroy(struct erofs_stream_ctx *ctx);

/*
 * Charging never sleeps for budget: the caller already owns a context, and
 * waiting here would hold part of the budget while waiting for the rest.  Idle
 * contexts are the only budget that can be returned immediately, so reclaim
 * them first and fail with ENOMEM only when the budget is truly exhausted.
 */
int
z_erofs_stream_ctx_charge(struct erofs_stream_ctx *ctx, size_t bytes)
{
	struct erofs_stream_ctx *idle;
	bool reserved;

	if (bytes == 0 || bytes > EROFS_STREAM_ALLOCATION_HARD_MAX) {
		ctx->allocation_failed = true;
		mtx_lock(&erofs_stream_lock);
		++erofs_stream_exhaustions;
		mtx_unlock(&erofs_stream_lock);
		return (ENOMEM);
	}
	mtx_lock(&erofs_stream_lock);
	for (;;) {
		if (ctx->charged_bytes > SIZE_MAX - bytes ||
		    bytes > erofs_stream_mount_budget ||
		    bytes > erofs_stream_global_budget) {
			reserved = false;
			break;
		}
		reserved = erofs_stream_reserve_locked(ctx->sbi, bytes);
		if (reserved)
			break;
		idle = erofs_stream_take_reclaimable_locked(ctx->sbi,
		    erofs_stream_mount_budget_available_locked(ctx->sbi,
			bytes));
		if (idle == NULL)
			break;
		mtx_unlock(&erofs_stream_lock);
		erofs_stream_ctx_destroy(idle);
		mtx_lock(&erofs_stream_lock);
	}
	if (reserved)
		ctx->charged_bytes += bytes;
	else
		++erofs_stream_exhaustions;
	mtx_unlock(&erofs_stream_lock);
	if (!reserved) {
		ctx->allocation_failed = true;
		return (ENOMEM);
	}
	return (0);
}

void
z_erofs_stream_ctx_uncharge(struct erofs_stream_ctx *ctx, size_t bytes)
{
	mtx_lock(&erofs_stream_lock);
	KASSERT(bytes <= ctx->charged_bytes,
	    ("erofs stream context byte accounting underflow"));
	ctx->charged_bytes -= bytes;
	erofs_stream_release_locked(ctx->sbi, bytes);
	erofs_stream_wake_locked(ctx->sbi);
	mtx_unlock(&erofs_stream_lock);
}

void *
z_erofs_stream_ctx_alloc(struct erofs_stream_ctx *ctx, size_t bytes)
{
	struct erofs_stream_alloc_header *header;
	size_t total;

	if (__builtin_add_overflow(bytes, sizeof(*header), &total) ||
	    z_erofs_stream_ctx_charge(ctx, total) != 0)
		return (NULL);
	header = malloc(total, M_EROFS, M_WAITOK | M_ZERO);
	header->ctx = ctx;
	header->bytes = total;
	return (header + 1);
}

void
z_erofs_stream_ctx_free(struct erofs_stream_ctx *ctx, void *address)
{
	struct erofs_stream_alloc_header *header;
	size_t bytes;

	if (address == NULL)
		return;
	header = (struct erofs_stream_alloc_header *)address - 1;
	KASSERT(header->ctx == ctx, ("erofs stream allocation owner mismatch"));
	bytes = header->bytes;
	free(header, M_EROFS);
	z_erofs_stream_ctx_uncharge(ctx, bytes);
}

static void
erofs_stream_ctx_destroy(struct erofs_stream_ctx *ctx)
{
	struct erofs_stream_pool_codec *codec;
	struct erofs_sb_info *sbi;
	bool cached;
	uint8_t algorithm;

	sbi = ctx->sbi;
	algorithm = ctx->algorithm;
	cached = ctx->cached;
	ctx->fini(ctx);
	KASSERT(ctx->charged_bytes == EROFS_STREAM_CTX_WRAPPER_SIZE,
	    ("erofs stream backend allocation leaked"));
	uma_zfree(erofs_stream_zone, ctx);

	mtx_lock(&erofs_stream_lock);
	codec = &sbi->stream_pool.codec[algorithm];
	KASSERT(codec->contexts != 0 && codec->borrowed != 0 &&
		erofs_stream_global_contexts != 0 &&
		erofs_stream_borrowed_contexts != 0,
	    ("erofs stream context accounting underflow"));
	--codec->contexts;
	--codec->borrowed;
	--erofs_stream_global_contexts;
	--erofs_stream_borrowed_contexts;
	if (cached) {
		KASSERT(codec->cached != 0 &&
			erofs_stream_global_cached_by_codec[algorithm] != 0 &&
			erofs_stream_cached_contexts != 0,
		    ("erofs stream cache accounting underflow"));
		--codec->cached;
		--erofs_stream_global_cached_by_codec[algorithm];
		--erofs_stream_cached_contexts;
	}
	erofs_stream_release_locked(sbi, EROFS_STREAM_CTX_WRAPPER_SIZE);
	++erofs_stream_destroys;
	erofs_stream_wake_locked(sbi);
	mtx_unlock(&erofs_stream_lock);
}
