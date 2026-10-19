/* SPDX-License-Identifier: BSD-2-Clause */
/* FreeBSD per-mount management controls for EROFS. */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>

#include <fs/erofs/compress.h>
#include <fs/erofs/internal.h>

#define EROFS_DIR_RA_DEFAULT_BYTES  (16UL * 1024)
#define EROFS_DIR_RA_HARD_MAX_BYTES (1024UL * 1024)
#define EROFS_DIR_RA_SLOTS	    256UL

enum erofs_cache_metric {
	EROFS_CACHE_HITS,
	EROFS_CACHE_MISSES,
	EROFS_CACHE_BYPASSES,
	EROFS_CACHE_EVICTIONS,
	EROFS_CACHE_RECLAIMS,
	EROFS_CACHE_WAITER_MERGES,
	EROFS_CACHE_ENTRIES,
	EROFS_CACHE_BYTES,
};

void
erofs_management_init(struct erofs_sb_info *sbi)
{
	mtx_init(&sbi->control_lock, "erofs control", NULL, MTX_DEF);
	sbi->dir_ra_bytes = EROFS_DIR_RA_DEFAULT_BYTES;
	sbi->dir_ra_max_bytes = EROFS_DIR_RA_HARD_MAX_BYTES;
	sbi->control_initialized = true;
}

void
erofs_management_fini(struct erofs_sb_info *sbi)
{
	if (!sbi->control_initialized)
		return;
	KASSERT(!sbi->sysctl_registered,
	    ("erofs management sysctls remain registered"));
	mtx_destroy(&sbi->control_lock);
	sbi->control_initialized = false;
}

uint64_t
erofs_dir_ra_bytes(struct erofs_sb_info *sbi)
{
	uint64_t value;

	mtx_lock(&sbi->control_lock);
	value = sbi->dir_ra_bytes;
	mtx_unlock(&sbi->control_lock);
	return (value);
}

/* The readahead is limited by the size of the per-directory run lists. */
static uint64_t
erofs_dir_ra_limit(const struct erofs_sb_info *sbi)
{
	return (MIN((uint64_t)EROFS_DIR_RA_HARD_MAX_BYTES,
	    (uint64_t)sbi->block_size * EROFS_DIR_RA_SLOTS));
}

int
erofs_set_dir_ra_bytes(struct erofs_sb_info *sbi, uint64_t value)
{
	if (sbi->block_size == 0 || value > erofs_dir_ra_limit(sbi) ||
	    (value != 0 && value % sbi->block_size != 0))
		return (EINVAL);
	mtx_lock(&sbi->control_lock);
	if (sbi->control_closing) {
		mtx_unlock(&sbi->control_lock);
		return (ENXIO);
	}
	sbi->dir_ra_bytes = value;
	mtx_unlock(&sbi->control_lock);
	return (0);
}

void
erofs_record_dir_readahead(struct erofs_sb_info *sbi, unsigned int blocks)
{
	mtx_lock(&sbi->control_lock);
	++sbi->dir_ra_requests;
	sbi->dir_ra_blocks += blocks;
	mtx_unlock(&sbi->control_lock);
}

static int
erofs_parse_uint64(const char *value, size_t len, uint64_t *result)
{
	size_t i;
	uint64_t parsed;

	if (value == NULL || len <= 1 || value[len - 1] != '\0' ||
	    strnlen(value, len) != len - 1)
		return (EINVAL);
	parsed = 0;
	for (i = 0; i < len - 1; ++i) {
		if (value[i] < '0' || value[i] > '9')
			return (EINVAL);
		if (parsed > (UINT64_MAX - (value[i] - '0')) / 10)
			return (ERANGE);
		parsed = parsed * 10 + (value[i] - '0');
	}
	*result = parsed;
	return (0);
}

int
erofs_parse_dir_ra_value(struct erofs_sb_info *sbi, struct vfsoptlist *opts,
    uint64_t *valuep, bool *presentp)
{
	struct vfsopt *opt;
	uint64_t value;
	int error;

	*presentp = false;
	TAILQ_FOREACH(opt, opts, link) {
		if (strcmp(opt->name, "dir_ra_bytes") != 0)
			continue;
		error = erofs_parse_uint64(opt->value, opt->len, &value);
		if (error != 0)
			return (error);
		if (sbi->block_size == 0 || value > erofs_dir_ra_limit(sbi) ||
		    (value != 0 && value % sbi->block_size != 0))
			return (EINVAL);
		*valuep = value;
		*presentp = true;
		return (0);
	}
	return (0);
}

int
erofs_parse_dir_ra_option(struct erofs_sb_info *sbi, struct vfsoptlist *opts)
{
	uint64_t value;
	bool present;
	int error;

	error = erofs_parse_dir_ra_value(sbi, opts, &value, &present);
	if (error != 0 || !present)
		return (error);
	return (erofs_set_dir_ra_bytes(sbi, value));
}

static int
erofs_sysctl_dir_ra(SYSCTL_HANDLER_ARGS)
{
	struct erofs_sb_info *sbi;
	uint64_t value;
	int error;

	sbi = arg1;
	value = erofs_dir_ra_bytes(sbi);
	error = sysctl_handle_64(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	return (erofs_set_dir_ra_bytes(sbi, value));
}

static int
erofs_sysctl_dir_ra_metric(SYSCTL_HANDLER_ARGS)
{
	struct erofs_sb_info *sbi;
	uint64_t value;

	sbi = arg1;
	mtx_lock(&sbi->control_lock);
	value = arg2 == 0 ? sbi->dir_ra_requests : sbi->dir_ra_blocks;
	mtx_unlock(&sbi->control_lock);
	return (sysctl_handle_64(oidp, &value, 0, req));
}

static int
erofs_validate_zip_value(const char *value, int len)
{
	if (value == NULL || len <= 1 || value[len - 1] != '\0' ||
	    strnlen(value, (size_t)len) != (size_t)len - 1)
		return (EINVAL);
	return (0);
}

static int
erofs_parse_zip_uint(const char *value, int len, unsigned int *result)
{
	size_t i;
	unsigned int parsed;

	if (erofs_validate_zip_value(value, len) != 0)
		return (EINVAL);
	parsed = 0;
	for (i = 0; i < (size_t)len - 1; ++i) {
		if (value[i] < '0' || value[i] > '9' ||
		    parsed > (UINT_MAX - (value[i] - '0')) / 10)
			return (EINVAL);
		parsed = parsed * 10 + (value[i] - '0');
	}
	*result = parsed;
	return (0);
}

int
erofs_parse_zip_options(struct mount *mp, struct erofs_sb_info_opts *opts,
    unsigned int *syncp, bool *cache_presentp, bool *sync_presentp)
{
	struct vfsopt *opt;
	unsigned int value;
	bool queue_priority_present;
	int error;

	*cache_presentp = false;
	*sync_presentp = false;
	queue_priority_present = false;
	TAILQ_FOREACH(opt, mp->mnt_optnew, link) {
		if (strcmp(opt->name, "cache_strategy") == 0) {
			if (opt->value == NULL || opt->len <= 1 ||
			    ((char *)opt->value)[opt->len - 1] != '\0' ||
			    strnlen(opt->value, opt->len) !=
				(size_t)opt->len - 1)
				return (EINVAL);
			if (strcmp(opt->value, "disabled") == 0)
				opts->cache_strategy = EROFS_ZIP_CACHE_DISABLED;
			else if (strcmp(opt->value, "readahead") == 0)
				opts->cache_strategy =
				    EROFS_ZIP_CACHE_READAHEAD;
			else if (strcmp(opt->value, "readaround") == 0)
				opts->cache_strategy =
				    EROFS_ZIP_CACHE_READAROUND;
			else
				return (EINVAL);
			*cache_presentp = true;
			continue;
		}
		if (strcmp(opt->name, "worker_queue_priority") == 0) {
			error = erofs_parse_zip_uint(opt->value, opt->len,
			    &value);
			if (error != 0 || value > UINT8_MAX)
				return (EINVAL);
			opts->worker_queue_priority = (uint8_t)value;
			queue_priority_present = true;
			continue;
		}
		if (strcmp(opt->name, "sync_decompress") != 0)
			continue;
		error = erofs_validate_zip_value(opt->value, opt->len);
		if (error != 0)
			return (error);
		if (strcmp(opt->value, "auto") == 0)
			value = EROFS_SYNC_DECOMPRESS_AUTO;
		else if (strcmp(opt->value, "on") == 0)
			value = EROFS_SYNC_DECOMPRESS_FORCE_ON;
		else if (strcmp(opt->value, "off") == 0)
			value = EROFS_SYNC_DECOMPRESS_FORCE_OFF;
		else {
			error = erofs_parse_zip_uint(opt->value, opt->len,
			    &value);
			if (error != 0 ||
			    value > EROFS_SYNC_DECOMPRESS_FORCE_OFF)
				return (EINVAL);
		}
		*syncp = value;
		*sync_presentp = true;
	}
	if (*cache_presentp)
		vfs_deleteopt(mp->mnt_optnew, "cache_strategy");
	if (*sync_presentp)
		vfs_deleteopt(mp->mnt_optnew, "sync_decompress");
	if (queue_priority_present)
		vfs_deleteopt(mp->mnt_optnew, "worker_queue_priority");
	return (0);
}

static int
erofs_sysctl_drop_caches(SYSCTL_HANDLER_ARGS)
{
	struct erofs_sb_info *sbi;
	uint64_t value;
	int error;

	if (req->newptr == NULL)
		return (EPERM);
	sbi = arg1;
	value = 0;
	error = sysctl_handle_64(oidp, &value, 0, req);
	if (error != 0)
		return (error);
	if (value != 1)
		return (EINVAL);
	return (z_erofs_extent_cache_drop(sbi));
}

static int
erofs_sysctl_cache_metric(SYSCTL_HANDLER_ARGS)
{
	struct erofs_cache_stats stats;
	struct erofs_sb_info *sbi;
	uint64_t value;

	sbi = arg1;
	z_erofs_extent_cache_stats(sbi, &stats);
	switch (arg2) {
	case EROFS_CACHE_HITS:
		value = stats.hits;
		break;
	case EROFS_CACHE_MISSES:
		value = stats.misses;
		break;
	case EROFS_CACHE_BYPASSES:
		value = stats.bypasses;
		break;
	case EROFS_CACHE_EVICTIONS:
		value = stats.evictions;
		break;
	case EROFS_CACHE_RECLAIMS:
		value = stats.reclaims;
		break;
	case EROFS_CACHE_WAITER_MERGES:
		value = stats.waiter_merges;
		break;
	case EROFS_CACHE_ENTRIES:
		value = stats.entries;
		break;
	case EROFS_CACHE_BYTES:
		value = stats.bytes;
		break;
	default:
		return (EINVAL);
	}
	return (sysctl_handle_64(oidp, &value, 0, req));
}

static int
erofs_sysctl_zip_setting(SYSCTL_HANDLER_ARGS)
{
	struct erofs_sb_info *sbi;
	int value;
	int error;

	sbi = arg1;
	mtx_lock(&sbi->control_lock);
	value = arg2 == 0 ? (int)sbi->sync_decompress :
			    (int)sbi->opt.cache_strategy;
	mtx_unlock(&sbi->control_lock);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (arg2 == 0) {
		if (value < EROFS_SYNC_DECOMPRESS_AUTO ||
		    value > EROFS_SYNC_DECOMPRESS_FORCE_OFF)
			return (EINVAL);
	} else {
		if (value < EROFS_ZIP_CACHE_DISABLED ||
		    value > EROFS_ZIP_CACHE_READAROUND)
			return (EINVAL);
	}
	mtx_lock(&sbi->control_lock);
	if (sbi->control_closing) {
		mtx_unlock(&sbi->control_lock);
		return (ENXIO);
	}
	if (arg2 == 0)
		sbi->sync_decompress = (unsigned int)value;
	else
		sbi->opt.cache_strategy = (uint8_t)value;
	mtx_unlock(&sbi->control_lock);
	return (0);
}

static int
erofs_sysctl_worker_queue_priority(SYSCTL_HANDLER_ARGS)
{
	struct erofs_sb_info *sbi;
	int error, value;

	sbi = arg1;
	mtx_lock(&sbi->control_lock);
	value = sbi->decompress_queue_priority;
	mtx_unlock(&sbi->control_lock);
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	if (value < 0 || value > UINT8_MAX)
		return (EINVAL);
	mtx_lock(&sbi->control_lock);
	if (sbi->control_closing) {
		mtx_unlock(&sbi->control_lock);
		return (ENXIO);
	}
	sbi->decompress_queue_priority = (uint8_t)value;
	sbi->opt.worker_queue_priority = (uint8_t)value;
	mtx_unlock(&sbi->control_lock);
	return (0);
}
