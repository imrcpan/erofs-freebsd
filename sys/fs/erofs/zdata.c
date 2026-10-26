// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             https://www.huawei.com/
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/_maxphys.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/rwlock.h>
#include <sys/sf_buf.h>
#include <sys/smp.h>
#include <sys/uio.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <fs/erofs/compress.h>
#include <fs/erofs/trace.h>

enum z_erofs_cache_lookup {
	Z_EROFS_CACHE_BYPASS,
	Z_EROFS_CACHE_HIT,
	Z_EROFS_CACHE_OWNER,
	Z_EROFS_CACHE_ERROR,
};

#define EROFS_ZCACHE_MOUNT_HARD_BUDGET	(256UL * 1024)
#define EROFS_ZCACHE_GLOBAL_HARD_BUDGET (512UL * 1024)
#define EROFS_ZCACHE_MIN_DECODE_WORK	(128UL * 1024)
#define EROFS_ZCACHE_WORKER_HARD_LIMIT	EROFS_ZCACHE_MAX_ENTRIES

static int z_erofs_cache_enabled = 1;
static unsigned long z_erofs_cache_mount_budget =
    EROFS_ZCACHE_MOUNT_HARD_BUDGET;
static unsigned long z_erofs_cache_global_budget =
    EROFS_ZCACHE_GLOBAL_HARD_BUDGET;
static unsigned long z_erofs_cache_minimum_decode_work =
    EROFS_ZCACHE_MIN_DECODE_WORK;
static unsigned long z_erofs_cache_worker_limit =
    EROFS_ZCACHE_WORKER_HARD_LIMIT;

TUNABLE_INT("vfs.erofs.decoded_cache.enabled", &z_erofs_cache_enabled);
TUNABLE_ULONG("vfs.erofs.decoded_cache.mount_budget",
    &z_erofs_cache_mount_budget);
TUNABLE_ULONG("vfs.erofs.decoded_cache.global_budget",
    &z_erofs_cache_global_budget);
TUNABLE_ULONG("vfs.erofs.decoded_cache.minimum_decode_work",
    &z_erofs_cache_minimum_decode_work);
TUNABLE_ULONG("vfs.erofs.decoded_cache.worker_limit",
    &z_erofs_cache_worker_limit);

static struct mtx z_erofs_cache_list_lock;
static struct mtx z_erofs_cache_budget_lock;
static LIST_HEAD(, erofs_sb_info) z_erofs_cache_mounts = LIST_HEAD_INITIALIZER(
    z_erofs_cache_mounts);
static size_t z_erofs_cache_global_charged;
static eventhandler_tag z_erofs_cache_lowmem_tag;

MTX_SYSINIT(erofs_zcache_list, &z_erofs_cache_list_lock, "erofs zcache list",
    MTX_DEF);
MTX_SYSINIT(erofs_zcache_budget, &z_erofs_cache_budget_lock,
    "erofs zcache budget", MTX_DEF);

static size_t
z_erofs_extent_cache_global_limit(void)
{
	return (
	    MIN(z_erofs_cache_global_budget, EROFS_ZCACHE_GLOBAL_HARD_BUDGET));
}

static bool
z_erofs_extent_cache_reserve(size_t bytes)
{
	size_t limit;
	bool reserved;

	reserved = false;
	mtx_lock(&z_erofs_cache_budget_lock);
	limit = z_erofs_extent_cache_global_limit();
	if (bytes <= limit && z_erofs_cache_global_charged <= limit - bytes) {
		z_erofs_cache_global_charged += bytes;
		reserved = true;
	}
	mtx_unlock(&z_erofs_cache_budget_lock);
	return (reserved);
}

static void
z_erofs_extent_cache_release(size_t bytes)
{
	mtx_lock(&z_erofs_cache_budget_lock);
	KASSERT(bytes <= z_erofs_cache_global_charged,
	    ("erofs decoded cache budget underflow"));
	z_erofs_cache_global_charged -= bytes;
	mtx_unlock(&z_erofs_cache_budget_lock);
}

static bool
z_erofs_extent_cache_match(const struct erofs_zextent_cache_entry *entry,
    const struct erofs_inode *vi, const struct erofs_map_blocks *map,
    size_t decoded_size)
{
	const struct erofs_zextent_key *key = &entry->key;

	return (entry->active && entry->state != EROFS_ZCACHE_EMPTY &&
	    key->nid == vi->nid && key->decoded_size == decoded_size &&
	    key->map.m_pa == map->m_pa && key->map.m_la == map->m_la &&
	    key->map.m_plen == map->m_plen && key->map.m_llen == map->m_llen &&
	    key->map.m_deviceid == map->m_deviceid &&
	    key->map.m_algorithmformat == map->m_algorithmformat &&
	    key->map.m_flags == map->m_flags);
}

static void
z_erofs_extent_cache_reset_locked(struct erofs_zextent_cache *cache,
    struct erofs_zextent_cache_entry *entry)
{
	KASSERT(entry->state != EROFS_ZCACHE_INFLIGHT && entry->waiters == 0,
	    ("erofs cache entry reset while busy"));
	if (entry->active) {
		KASSERT(cache->entry_count != 0,
		    ("erofs cache entry underflow"));
		--cache->entry_count;
	}
	entry->active = false;
	entry->state = EROFS_ZCACHE_EMPTY;
	entry->error = 0;
	entry->lru = 0;
	bzero(&entry->key, sizeof(entry->key));
}

static void *
z_erofs_extent_cache_drop_entry_locked(struct erofs_sb_info *sbi __unused,
    struct erofs_zextent_cache *cache, struct erofs_zextent_cache_entry *entry,
    bool evicted, bool reclaimed)
{
	struct erofs_zextent_cache_metrics *metrics;
	void *data;

	KASSERT(entry->state == EROFS_ZCACHE_READY && entry->waiters == 0,
	    ("erofs cache drop of busy entry"));
	data = entry->data;
	metrics = &cache->metrics[entry->key.map.m_algorithmformat];
	KASSERT(metrics->resident_bytes >= entry->charged_bytes,
	    ("erofs decoded cache codec accounting mismatch"));
	metrics->resident_bytes -= entry->charged_bytes;
	if (evicted)
		++metrics->evictions;
	if (reclaimed)
		++metrics->reclaims;
	KASSERT(cache->charged_bytes >= entry->charged_bytes,
	    ("erofs decoded cache mount accounting underflow"));
	cache->charged_bytes -= entry->charged_bytes;
	z_erofs_extent_cache_release(entry->charged_bytes);
	entry->data = NULL;
	entry->charged_bytes = 0;
	z_erofs_extent_cache_reset_locked(cache, entry);
	cv_broadcast(&entry->cv);
	return (data);
}

static enum z_erofs_cache_lookup
z_erofs_extent_cache_claim(struct erofs_sb_info *sbi,
    const struct erofs_inode *vi, const struct erofs_map_blocks *map,
    size_t decoded_size, erofs_off_t mapoff, size_t len, void *dst, int *errorp)
{
	struct erofs_zextent_cache *cache;
	struct erofs_zextent_cache_metrics *metrics;
	struct erofs_zextent_cache_entry *entry, *victim;
	void *old;
	enum z_erofs_cache_lookup result;
	unsigned int i;

	KASSERT(len <= MAXPHYS, ("erofs extent cache copy exceeds MAXPHYS"));
	KASSERT(mapoff <= decoded_size && len <= decoded_size - mapoff,
	    ("erofs extent cache copy exceeds decoded extent"));
	*errorp = 0;
	if (!sbi->z_extent_cache_initialized)
		return (Z_EROFS_CACHE_BYPASS);
	cache = &sbi->z_extent_cache;
	KASSERT(map->m_algorithmformat < Z_EROFS_COMPRESSION_MAX,
	    ("erofs decoded cache claim has unknown codec"));
	metrics = &cache->metrics[map->m_algorithmformat];
	entry = NULL;
	victim = NULL;
	old = NULL;
	mtx_lock(&sbi->z_extent_cache_lock);
	if (cache->closing) {
		++metrics->bypasses;
		goto bypass;
	}
	for (i = 0; i < nitems(cache->entries); ++i) {
		if (z_erofs_extent_cache_match(&cache->entries[i], vi, map,
			decoded_size)) {
			entry = &cache->entries[i];
			break;
		}
	}
	if (entry != NULL) {
		if (entry->state == EROFS_ZCACHE_READY) {
			KASSERT(entry->data != NULL,
			    ("erofs ready extent cache has no data"));
			memcpy(dst, (char *)entry->data + (size_t)mapoff, len);
			entry->lru = ++cache->lru_clock;
			++metrics->hits;
			mtx_unlock(&sbi->z_extent_cache_lock);
			return (Z_EROFS_CACHE_HIT);
		}
		if (entry->state == EROFS_ZCACHE_INFLIGHT) {
			++metrics->waiter_merges;
			++entry->waiters;
			do {
				cv_wait(&entry->cv, &sbi->z_extent_cache_lock);
			} while (entry->state == EROFS_ZCACHE_INFLIGHT);
			if (entry->state == EROFS_ZCACHE_READY) {
				memcpy(dst,
				    (char *)entry->data + (size_t)mapoff, len);
				entry->lru = ++cache->lru_clock;
				++metrics->hits;
				result = Z_EROFS_CACHE_HIT;
			} else {
				KASSERT(entry->state == EROFS_ZCACHE_FAILED &&
					entry->error > 0,
				    ("erofs inflight cache has no typed "
				     "result"));
				*errorp = entry->error;
				result = Z_EROFS_CACHE_ERROR;
			}
			--entry->waiters;
			if (entry->state == EROFS_ZCACHE_FAILED &&
			    entry->waiters == 0)
				z_erofs_extent_cache_reset_locked(cache, entry);
			if (entry->waiters == 0)
				cv_broadcast(&entry->cv);
			mtx_unlock(&sbi->z_extent_cache_lock);
			return (result);
		}
		if (entry->waiters != 0) {
			++metrics->bypasses;
			goto bypass;
		}
		z_erofs_extent_cache_reset_locked(cache, entry);
	}
	for (i = 0; i < nitems(cache->entries); ++i) {
		if (!cache->entries[i].active) {
			entry = &cache->entries[i];
			break;
		}
		if (cache->entries[i].state == EROFS_ZCACHE_READY &&
		    cache->entries[i].waiters == 0 &&
		    (victim == NULL || cache->entries[i].lru < victim->lru))
			victim = &cache->entries[i];
	}
	if (entry == NULL && victim != NULL) {
		entry = victim;
		old = z_erofs_extent_cache_drop_entry_locked(sbi, cache, entry,
		    true, false);
	}
	if (entry == NULL || decoded_size > cache->budget_bytes ||
	    cache->charged_bytes > cache->budget_bytes - decoded_size ||
	    !z_erofs_extent_cache_reserve(decoded_size)) {
		++metrics->bypasses;
		goto bypass;
	}
	entry->key.map = *map;
	entry->key.nid = vi->nid;
	entry->key.decoded_size = decoded_size;
	entry->charged_bytes = decoded_size;
	entry->error = 0;
	entry->state = EROFS_ZCACHE_INFLIGHT;
	entry->active = true;
	entry->lru = ++cache->lru_clock;
	++cache->entry_count;
	cache->charged_bytes += decoded_size;
	++metrics->misses;
	mtx_unlock(&sbi->z_extent_cache_lock);
	free(old, M_EROFS);
	return (Z_EROFS_CACHE_OWNER);

bypass:
	mtx_unlock(&sbi->z_extent_cache_lock);
	free(old, M_EROFS);
	return (Z_EROFS_CACHE_BYPASS);
}

static void
z_erofs_extent_cache_complete(struct erofs_sb_info *sbi,
    const struct erofs_inode *vi, const struct erofs_map_blocks *map,
    size_t decoded_size, void *decoded, int error)
{
	struct erofs_zextent_cache *cache;
	struct erofs_zextent_cache_entry *entry;
	struct erofs_zextent_cache_metrics *metrics;
	unsigned int i;

	KASSERT((error == 0) == (decoded != NULL),
	    ("erofs extent cache completion is untyped"));
	cache = &sbi->z_extent_cache;
	mtx_lock(&sbi->z_extent_cache_lock);
	entry = NULL;
	for (i = 0; i < nitems(cache->entries); ++i) {
		if (z_erofs_extent_cache_match(&cache->entries[i], vi, map,
			decoded_size)) {
			entry = &cache->entries[i];
			break;
		}
	}
	KASSERT(entry != NULL && entry->state == EROFS_ZCACHE_INFLIGHT,
	    ("erofs extent cache owner lost its key"));
	metrics = &cache->metrics[map->m_algorithmformat];
	if (error == 0) {
		KASSERT(entry->charged_bytes == decoded_size,
		    ("erofs decoded cache success accounting mismatch"));
		entry->data = decoded;
		metrics->resident_bytes += decoded_size;
		entry->error = 0;
		entry->state = EROFS_ZCACHE_READY;
		entry->lru = ++cache->lru_clock;
	} else {
		KASSERT(error > 0,
		    ("erofs extent cache published negative errno"));
		KASSERT(cache->charged_bytes >= entry->charged_bytes,
		    ("erofs decoded cache accounting underflow"));
		cache->charged_bytes -= entry->charged_bytes;
		z_erofs_extent_cache_release(entry->charged_bytes);
		entry->charged_bytes = 0;
		entry->error = error;
		entry->state = EROFS_ZCACHE_FAILED;
		if (entry->waiters == 0)
			z_erofs_extent_cache_reset_locked(cache, entry);
	}
	cv_broadcast(&entry->cv);
	mtx_unlock(&sbi->z_extent_cache_lock);
}

static void
z_erofs_extent_cache_lowmem(void *arg __unused, int howto __unused)
{
	struct erofs_zextent_cache *cache;
	struct erofs_sb_info *sbi;
	void *data[EROFS_ZCACHE_MAX_ENTRIES];
	unsigned int count, i;

	mtx_lock(&z_erofs_cache_list_lock);
	LIST_FOREACH(sbi, &z_erofs_cache_mounts, z_extent_cache_link) {
		count = 0;
		if (!mtx_trylock(&sbi->z_extent_cache_lock))
			continue;
		cache = &sbi->z_extent_cache;
		for (i = 0; i < nitems(cache->entries); ++i) {
			if (cache->entries[i].state == EROFS_ZCACHE_READY &&
			    cache->entries[i].waiters == 0)
				data[count++] =
				    z_erofs_extent_cache_drop_entry_locked(sbi,
					cache, &cache->entries[i], true, true);
		}
		mtx_unlock(&sbi->z_extent_cache_lock);
		while (count != 0)
			free(data[--count], M_EROFS);
	}
	mtx_unlock(&z_erofs_cache_list_lock);
}

static void
z_erofs_extent_cache_global_init(void *arg __unused)
{
	z_erofs_cache_lowmem_tag = EVENTHANDLER_REGISTER(vm_lowmem,
	    z_erofs_extent_cache_lowmem, NULL, LOWMEM_PRI_DEFAULT);
}

static void
z_erofs_extent_cache_global_fini(void *arg __unused)
{
	if (z_erofs_cache_lowmem_tag != NULL)
		EVENTHANDLER_DEREGISTER(vm_lowmem, z_erofs_cache_lowmem_tag);
	KASSERT(LIST_EMPTY(&z_erofs_cache_mounts),
	    ("erofs decoded cache mounts remain at unload"));
	KASSERT(z_erofs_cache_global_charged == 0,
	    ("erofs decoded cache bytes remain at unload"));
}

SYSINIT(erofs_zcache_global, SI_SUB_VFS, SI_ORDER_FIRST,
    z_erofs_extent_cache_global_init, NULL);
SYSUNINIT(erofs_zcache_global, SI_SUB_VFS, SI_ORDER_FIRST,
    z_erofs_extent_cache_global_fini, NULL);

static unsigned int
z_erofs_decode_worker_count(void)
{
	unsigned long count;

	count = z_erofs_cache_worker_limit;
	if (count == 0)
		count = 1;
	count = MIN(count, (unsigned long)EROFS_ZCACHE_WORKER_HARD_LIMIT);
	count = MIN(count, (unsigned long)MAX(1, mp_ncpus));
	return ((unsigned int)count);
}

/* Runs without the lock: decompress_taskqueue_creating excludes other users. */
static void
z_erofs_decode_taskqueue_create(struct erofs_sb_info *sbi)
{
	unsigned int worker_count;

	worker_count = z_erofs_decode_worker_count();
	sbi->decompress_taskqueue = taskqueue_create("erofs decode", M_WAITOK,
	    taskqueue_thread_enqueue, &sbi->decompress_taskqueue);
	if (sbi->decompress_taskqueue == NULL)
		return;
	if (taskqueue_start_threads_cpuset(&sbi->decompress_taskqueue,
		(int)worker_count, PWAIT, &all_cpus, "erofs decode") == 0) {
		sbi->decompress_worker_count = worker_count;
		sbi->decompress_worker_cpu_bound = true;
		return;
	}
	taskqueue_free(sbi->decompress_taskqueue);
	sbi->decompress_taskqueue = taskqueue_create("erofs decode", M_WAITOK,
	    taskqueue_thread_enqueue, &sbi->decompress_taskqueue);
	if (sbi->decompress_taskqueue == NULL)
		return;
	if (taskqueue_start_threads(&sbi->decompress_taskqueue,
		(int)worker_count, PWAIT, "erofs decode") != 0) {
		taskqueue_free(sbi->decompress_taskqueue);
		sbi->decompress_taskqueue = NULL;
		return;
	}
	sbi->decompress_worker_count = worker_count;
}

static struct taskqueue *
z_erofs_decode_taskqueue_acquire(struct erofs_sb_info *sbi)
{
	struct taskqueue *taskqueue;

	mtx_lock(&sbi->z_extent_cache_lock);
	while (sbi->decompress_taskqueue_creating)
		cv_wait(&sbi->decompress_taskqueue_cv,
		    &sbi->z_extent_cache_lock);
	if (sbi->z_extent_cache.closing) {
		taskqueue = NULL;
	} else if (sbi->decompress_taskqueue != NULL ||
	    sbi->decompress_taskqueue_tried) {
		taskqueue = sbi->decompress_taskqueue;
		if (taskqueue != NULL)
			++sbi->decompress_taskqueue_users;
	} else {
		/* The user count keeps z_erofs_extent_cache_fini() waiting. */
		sbi->decompress_taskqueue_tried = true;
		sbi->decompress_taskqueue_creating = true;
		++sbi->decompress_taskqueue_users;
		mtx_unlock(&sbi->z_extent_cache_lock);
		z_erofs_decode_taskqueue_create(sbi);
		mtx_lock(&sbi->z_extent_cache_lock);
		sbi->decompress_taskqueue_creating = false;
		taskqueue = sbi->decompress_taskqueue;
		if (taskqueue == NULL)
			--sbi->decompress_taskqueue_users;
		cv_broadcast(&sbi->decompress_taskqueue_cv);
	}
	mtx_unlock(&sbi->z_extent_cache_lock);
	return (taskqueue);
}

static void
z_erofs_decode_taskqueue_release(struct erofs_sb_info *sbi)
{
	mtx_lock(&sbi->z_extent_cache_lock);
	KASSERT(sbi->decompress_taskqueue_users != 0,
	    ("erofs decode taskqueue user underflow"));
	if (--sbi->decompress_taskqueue_users == 0)
		cv_broadcast(&sbi->decompress_taskqueue_cv);
	mtx_unlock(&sbi->z_extent_cache_lock);
}

void
z_erofs_extent_cache_init(struct erofs_sb_info *sbi)
{
	bzero(&sbi->z_extent_cache, sizeof(sbi->z_extent_cache));
	sbi->z_extent_cache.budget_bytes = MIN(z_erofs_cache_mount_budget,
	    EROFS_ZCACHE_MOUNT_HARD_BUDGET);
	sbi->z_extent_cache.minimum_decode_work =
	    z_erofs_cache_minimum_decode_work;
	mtx_init(&sbi->z_extent_cache_lock, "erofs zextent", NULL, MTX_DEF);
	cv_init(&sbi->decompress_taskqueue_cv, "erofs decode tq");
	for (unsigned int i = 0; i < nitems(sbi->z_extent_cache.entries); ++i)
		cv_init(&sbi->z_extent_cache.entries[i].cv, "erofs zextent");
	sbi->z_extent_cache_initialized = true;
	mtx_lock(&z_erofs_cache_list_lock);
	LIST_INSERT_HEAD(&z_erofs_cache_mounts, sbi, z_extent_cache_link);
	mtx_unlock(&z_erofs_cache_list_lock);
}

void
z_erofs_extent_cache_fini(struct erofs_sb_info *sbi)
{
	struct erofs_zextent_cache *cache;
	struct taskqueue *taskqueue;
	void *data[EROFS_ZCACHE_MAX_ENTRIES];
	unsigned int count, i;

	if (!sbi->z_extent_cache_initialized)
		return;
	cache = &sbi->z_extent_cache;
	mtx_lock(&z_erofs_cache_list_lock);
	LIST_REMOVE(sbi, z_extent_cache_link);
	mtx_unlock(&z_erofs_cache_list_lock);
	mtx_lock(&sbi->z_extent_cache_lock);
	cache->closing = true;
	sbi->z_extent_cache_initialized = false;
	for (;;) {
		bool busy = false;
		unsigned int wait_index = 0;
		for (i = 0; i < nitems(cache->entries); ++i)
			if (cache->entries[i].state == EROFS_ZCACHE_INFLIGHT ||
			    cache->entries[i].waiters != 0) {
				busy = true;
				wait_index = i;
				break;
			}
		if (!busy)
			break;
		cv_wait(&cache->entries[wait_index].cv,
		    &sbi->z_extent_cache_lock);
	}
	/* A reader that is starting the threads holds a user reference. */
	while (sbi->decompress_taskqueue_users != 0)
		cv_wait(&sbi->decompress_taskqueue_cv,
		    &sbi->z_extent_cache_lock);
	/*
	 * Workers read &sbi->decompress_taskqueue when they first run, possibly
	 * after this point, so it is cleared only after taskqueue_free().
	 */
	taskqueue = sbi->decompress_taskqueue;
	sbi->decompress_worker_count = 0;
	sbi->decompress_worker_cpu_bound = false;
	mtx_unlock(&sbi->z_extent_cache_lock);
	if (taskqueue != NULL) {
		taskqueue_drain_all(taskqueue);
		taskqueue_free(taskqueue);
	}
	mtx_lock(&sbi->z_extent_cache_lock);
	sbi->decompress_taskqueue = NULL;
	count = 0;
	for (i = 0; i < nitems(cache->entries); ++i) {
		if (cache->entries[i].state == EROFS_ZCACHE_READY)
			data[count++] = z_erofs_extent_cache_drop_entry_locked(
			    sbi, cache, &cache->entries[i], false, false);
		else if (cache->entries[i].active)
			z_erofs_extent_cache_reset_locked(cache,
			    &cache->entries[i]);
	}
	mtx_unlock(&sbi->z_extent_cache_lock);
	while (count != 0)
		free(data[--count], M_EROFS);
	for (i = 0; i < nitems(cache->entries); ++i)
		cv_destroy(&cache->entries[i].cv);
	cv_destroy(&sbi->decompress_taskqueue_cv);
	mtx_destroy(&sbi->z_extent_cache_lock);
}

int
z_erofs_extent_cache_drop(struct erofs_sb_info *sbi)
{
	struct erofs_zextent_cache *cache;
	void *data[EROFS_ZCACHE_MAX_ENTRIES];
	unsigned int count, i;

	if (!sbi->z_extent_cache_initialized)
		return (ENXIO);
	cache = &sbi->z_extent_cache;
	mtx_lock(&sbi->z_extent_cache_lock);
	if (cache->closing) {
		mtx_unlock(&sbi->z_extent_cache_lock);
		return (ENXIO);
	}
	for (;;) {
		bool busy = false;
		unsigned int wait_index = 0;
		for (i = 0; i < nitems(cache->entries); ++i)
			if (cache->entries[i].state == EROFS_ZCACHE_INFLIGHT ||
			    cache->entries[i].waiters != 0) {
				busy = true;
				wait_index = i;
				break;
			}
		if (!busy)
			break;
		cv_wait(&cache->entries[wait_index].cv,
		    &sbi->z_extent_cache_lock);
	}
	count = 0;
	for (i = 0; i < nitems(cache->entries); ++i) {
		if (cache->entries[i].state == EROFS_ZCACHE_READY)
			data[count++] = z_erofs_extent_cache_drop_entry_locked(
			    sbi, cache, &cache->entries[i], true, false);
		else if (cache->entries[i].active)
			z_erofs_extent_cache_reset_locked(cache,
			    &cache->entries[i]);
	}
	mtx_unlock(&sbi->z_extent_cache_lock);
	while (count != 0)
		free(data[--count], M_EROFS);
	return (0);
}

void
z_erofs_extent_cache_stats(struct erofs_sb_info *sbi,
    struct erofs_cache_stats *stats)
{
	struct erofs_zextent_cache *cache;
	unsigned int algorithm;

	bzero(stats, sizeof(*stats));
	if (!sbi->z_extent_cache_initialized)
		return;
	cache = &sbi->z_extent_cache;
	mtx_lock(&sbi->z_extent_cache_lock);
	for (algorithm = 0; algorithm < Z_EROFS_COMPRESSION_MAX; ++algorithm) {
		stats->hits += cache->metrics[algorithm].hits;
		stats->misses += cache->metrics[algorithm].misses;
		stats->bypasses += cache->metrics[algorithm].bypasses;
		stats->evictions += cache->metrics[algorithm].evictions;
		stats->reclaims += cache->metrics[algorithm].reclaims;
		stats->waiter_merges += cache->metrics[algorithm].waiter_merges;
		stats->bytes += cache->metrics[algorithm].resident_bytes;
	}
	stats->entries = cache->entry_count;
	mtx_unlock(&sbi->z_extent_cache_lock);
}

static bool
z_erofs_extent_cache_eligible(const struct erofs_sb_info *sbi,
    const struct erofs_inode *vi, const struct erofs_map_blocks *map,
    size_t len)
{
	const struct erofs_zextent_cache *cache;
	uint64_t decode_work;

	cache = &sbi->z_extent_cache;
	decode_work = map->m_plen + len; /* at most 1 MiB + 12 MiB */
	return (z_erofs_cache_enabled != 0 &&
	    sbi->opt.cache_strategy != EROFS_ZIP_CACHE_DISABLED &&
	    len <= MAXPHYS && len <= cache->budget_bytes &&
	    decode_work >= cache->minimum_decode_work &&
	    (map->m_flags &
		(EROFS_MAP_META | EROFS_MAP_PARTIAL_MAPPED |
		    EROFS_MAP_PARTIAL_REF | EROFS_MAP_FRAGMENT)) == 0 &&
	    map->m_algorithmformat < Z_EROFS_COMPRESSION_MAX &&
	    sbi->z_extent_cache_initialized && vi != sbi->packed_inode &&
	    vi != sbi->metabox_en);
}

static void
z_erofs_extent_cache_record_bypass(struct erofs_sb_info *sbi,
    const struct erofs_map_blocks *map)
{
	struct erofs_zextent_cache *cache;

	if (!sbi->z_extent_cache_initialized ||
	    map->m_algorithmformat >= Z_EROFS_COMPRESSION_MAX)
		return;
	cache = &sbi->z_extent_cache;
	mtx_lock(&sbi->z_extent_cache_lock);
	++cache->metrics[map->m_algorithmformat].bypasses;
	mtx_unlock(&sbi->z_extent_cache_lock);
}

static void
z_erofs_decode_length(const struct erofs_map_blocks *map, erofs_off_t mapoff,
    size_t want, size_t *decoded_len, bool *partial)
{
	size_t end;

	/* z_erofs_do_read() has checked that [mapoff, mapoff + want) fits. */
	KASSERT(mapoff <= map->m_llen && want <= map->m_llen - mapoff,
	    ("erofs: bad decode range"));
	end = (size_t)mapoff + want;
	*partial = (map->m_flags & EROFS_MAP_PARTIAL_REF) != 0;
	*decoded_len = *partial ? end : (size_t)map->m_llen;
}

int
z_erofs_decode_extent(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map, size_t decoded_len, bool partial, void **bufp)
{
	struct erofs_buf buf = EROFS_BUF_INITIALIZER;
	const void *input;
	void *compressed, *decoded;
	int error;

	*bufp = NULL;
	/*
	 * z_erofs_do_read() handles fragment and unmapped extents itself and
	 * gets decoded_len from z_erofs_decode_length().
	 */
	KASSERT((map->m_flags & (EROFS_MAP_FRAGMENT | EROFS_MAP_MAPPED)) ==
		EROFS_MAP_MAPPED,
	    ("erofs: decoding a map with flags %#x",
		(unsigned int)map->m_flags));
	KASSERT(decoded_len != 0 && decoded_len <= map->m_llen &&
		(partial || decoded_len == map->m_llen),
	    ("erofs: bad decoded length %zu", decoded_len));

	if ((map->m_flags & EROFS_MAP_META) != 0) {
		error = erofs_read_metadata_range(sbi, vi->nid, map->m_pa,
		    (size_t)map->m_plen, &buf);
	} else {
		error = erofs_read_physical(sbi, map->m_deviceid, map->m_pa,
		    (size_t)map->m_plen, &compressed);
	}
	if (error != 0)
		return (error);
	input = (map->m_flags & EROFS_MAP_META) != 0 ? buf.data : compressed;

	decoded = malloc(decoded_len, M_EROFS, M_WAITOK | M_ZERO);
	error = z_erofs_decompress(sbi, map, input, (size_t)map->m_plen,
	    decoded, decoded_len, partial);
	if ((map->m_flags & EROFS_MAP_META) != 0)
		erofs_put_metabuf(&buf);
	else
		erofs_brelse(compressed);
	if (error != 0) {
		free(decoded, M_EROFS);
		return (error);
	}
	*bufp = decoded;
	return (0);
}

static void
z_erofs_decode_task_run(void *context, int pending __unused)
{
	struct erofs_decompress_task *task = context;

	task->error = z_erofs_decode_extent(task->sbi, task->vi, &task->map,
	    task->decoded_len, task->partial, &task->decoded);
	mtx_lock(&task->lock);
	atomic_add_64(&task->sbi->decompress_worker_runs, 1);
	task->done = true;
	cv_signal(&task->cv);
	mtx_unlock(&task->lock);
}

static uint8_t
z_erofs_decode_queue_priority(struct erofs_sb_info *sbi)
{
	uint8_t priority;

	mtx_lock(&sbi->control_lock);
	priority = sbi->decompress_queue_priority;
	mtx_unlock(&sbi->control_lock);
	return (priority);
}

int
z_erofs_decode_extent_dispatch(struct erofs_sb_info *sbi,
    struct erofs_inode *vi, struct erofs_map_blocks *map, size_t decoded_len,
    bool partial, void **bufp)
{
	struct erofs_decompress_task *task;
	struct taskqueue *taskqueue;
	int error;
	uint8_t queue_priority;
	bool queued;

	if (sbi->sync_decompress != EROFS_SYNC_DECOMPRESS_FORCE_OFF)
		return (z_erofs_decode_extent(sbi, vi, map, decoded_len,
		    partial, bufp));
	taskqueue = z_erofs_decode_taskqueue_acquire(sbi);
	if (taskqueue == NULL) {
		atomic_add_64(&sbi->decompress_queue_fallbacks, 1);
		return (z_erofs_decode_extent(sbi, vi, map, decoded_len,
		    partial, bufp));
	}
	/*
	 * A decode worker can get here again: reading the inline input of a
	 * metabox inode reads the (compressed) metabox.  Waiting for another
	 * task from inside a worker could use up every worker, so decode in
	 * place.
	 */
	if (taskqueue_member(taskqueue, curthread)) {
		z_erofs_decode_taskqueue_release(sbi);
		atomic_add_64(&sbi->decompress_queue_fallbacks, 1);
		return (z_erofs_decode_extent(sbi, vi, map, decoded_len,
		    partial, bufp));
	}
	task = malloc(sizeof(*task), M_EROFS, M_WAITOK | M_ZERO);
	task->sbi = sbi;
	task->vi = vi;
	task->map = *map;
	task->decoded_len = decoded_len;
	task->partial = partial;
	mtx_init(&task->lock, "erofs decomp task", NULL, MTX_DEF);
	cv_init(&task->cv, "erofs decomp task");
	queue_priority = z_erofs_decode_queue_priority(sbi);
	TASK_INIT(&task->task, queue_priority, z_erofs_decode_task_run, task);
	error = taskqueue_enqueue(taskqueue, &task->task);
	queued = error == 0;
	if (queued) {
		atomic_add_64(&sbi->decompress_submissions, 1);
		mtx_lock(&task->lock);
		while (!task->done)
			cv_wait(&task->cv, &task->lock);
		mtx_unlock(&task->lock);
		taskqueue_drain(taskqueue, &task->task);
		error = task->error;
		*bufp = task->decoded;
	} else {
		atomic_add_64(&sbi->decompress_queue_fallbacks, 1);
		error = z_erofs_decode_extent(sbi, vi, map, decoded_len,
		    partial, bufp);
	}
	cv_destroy(&task->cv);
	mtx_destroy(&task->lock);
	free(task, M_EROFS);
	z_erofs_decode_taskqueue_release(sbi);
	return (error);
}

static int
z_erofs_map_pos(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t pos, struct erofs_map_blocks *map)
{
	int error;

	*map = (struct erofs_map_blocks) { .m_la = pos };
	error = erofs_map_blocks(sbi, vi, map);
	if (error != 0)
		return (error);
	if (map->m_llen == 0 || map->m_la > pos ||
	    pos - map->m_la >= map->m_llen)
		return (EINTEGRITY);
	return (0);
}

static int
z_erofs_read_fragment(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t mapoff, size_t len, void *out)
{
	void *fragment;
	int error;

	if (sbi->packed_inode == NULL || sbi->packed_inode->nid == vi->nid ||
	    vi->z_fragmentoff > UINT64_MAX - mapoff)
		return (EINTEGRITY);
	error = erofs_read_data(sbi, sbi->packed_inode,
	    vi->z_fragmentoff + mapoff, len, &fragment);
	if (error != 0)
		return (error);
	memcpy(out, fragment, len);
	erofs_brelse(fragment);
	return (0);
}

static int
z_erofs_do_read(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, char *out)
{
	struct erofs_map_blocks map;
	void *decoded;
	erofs_off_t mapoff;
	size_t decoded_len, done, want;
	bool cache_eligible, partial;
	enum z_erofs_cache_lookup cache_lookup;
	int error;

	done = 0;
	while (done < len) {
		error = z_erofs_map_pos(sbi, vi, loff + done, &map);
		if (error != 0)
			return (error);
		mapoff = loff + done - map.m_la;
		want = MIN((size_t)(map.m_llen - mapoff), len - done);

		if ((map.m_flags & EROFS_MAP_FRAGMENT) != 0) {
			error = z_erofs_read_fragment(sbi, vi, mapoff, want,
			    out + done);
			if (error != 0)
				return (error);
		} else if ((map.m_flags & EROFS_MAP_MAPPED) == 0) {
			bzero(out + done, want);
		} else {
			z_erofs_decode_length(&map, mapoff, want, &decoded_len,
			    &partial);
			cache_eligible = !partial &&
			    z_erofs_extent_cache_eligible(sbi, vi, &map,
				decoded_len);
			cache_lookup = Z_EROFS_CACHE_BYPASS;
			if (cache_eligible) {
				cache_lookup = z_erofs_extent_cache_claim(sbi,
				    vi, &map, decoded_len, mapoff, want,
				    out + done, &error);
				if (cache_lookup == Z_EROFS_CACHE_HIT) {
					done += want;
					continue;
				}
				if (cache_lookup == Z_EROFS_CACHE_ERROR)
					return (error);
			} else
				z_erofs_extent_cache_record_bypass(sbi, &map);
			error = z_erofs_decode_extent_dispatch(sbi, vi, &map,
			    decoded_len, partial, &decoded);
			if (error != 0) {
				if (cache_lookup == Z_EROFS_CACHE_OWNER)
					z_erofs_extent_cache_complete(sbi, vi,
					    &map, decoded_len, NULL, error);
				return (error);
			}
			memcpy(out + done, (char *)decoded + (size_t)mapoff,
			    want);
			if (cache_lookup == Z_EROFS_CACHE_OWNER)
				z_erofs_extent_cache_complete(sbi, vi, &map,
				    decoded_len, decoded, 0);
			else
				free(decoded, M_EROFS);
		}
		done += want;
	}
	return (0);
}

int
z_erofs_read_data(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, void **bufp)
{
	char *out;
	int error;

	/* erofs_read_data_impl() has checked the arguments and the range. */
	KASSERT(len != 0 && loff <= vi->size && len <= vi->size - loff,
	    ("erofs: bad compressed read"));
	*bufp = NULL;
	out = malloc(len, M_EROFS, M_WAITOK);
	error = z_erofs_do_read(sbi, vi, loff, len, out);
	if (error != 0) {
		free(out, M_EROFS);
		return (error);
	}
	*bufp = out;
	return (0);
}

int
z_erofs_read_uio(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct uio *uio)
{
	char *buf;
	size_t want;
	int error;

	/* erofs_read_uio() has rejected a negative offset. */
	while (uio->uio_resid > 0 && (uint64_t)uio->uio_offset < vi->size) {
		want = MIN((size_t)uio->uio_resid,
		    (size_t)MIN((uint64_t)MAXPHYS,
			vi->size - (uint64_t)uio->uio_offset));
		buf = malloc(want, M_EROFS, M_WAITOK);
		error = z_erofs_do_read(sbi, vi, (uint64_t)uio->uio_offset,
		    want, buf);
		if (error == 0)
			error = uiomove(buf, want, uio);
		free(buf, M_EROFS);
		if (error != 0)
			return (error);
	}
	return (0);
}

/* An extent can only be decoded as a whole. */
struct z_erofs_decoded_extent {
	struct erofs_map_blocks map;
	/* NULL for a hole or a fragment. */
	void *data;
};

static bool
z_erofs_decoded_covers(const struct z_erofs_decoded_extent *ext,
    erofs_off_t pos)
{
	return (ext->map.m_llen != 0 && pos >= ext->map.m_la &&
	    pos - ext->map.m_la < ext->map.m_llen);
}

static int
z_erofs_decoded_load(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t pos, struct z_erofs_decoded_extent *ext)
{
	struct erofs_map_blocks *map;
	int error;

	free(ext->data, M_EROFS);
	ext->data = NULL;
	map = &ext->map;
	error = z_erofs_map_pos(sbi, vi, pos, map);
	if (error != 0)
		return (error);
	if ((map->m_flags & (EROFS_MAP_FRAGMENT | EROFS_MAP_MAPPED)) !=
	    EROFS_MAP_MAPPED)
		return (0);
	return (z_erofs_decode_extent_dispatch(sbi, vi, map, map->m_llen,
	    (map->m_flags & EROFS_MAP_PARTIAL_REF) != 0, &ext->data));
}

static int
z_erofs_decoded_copy(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    const struct z_erofs_decoded_extent *ext, erofs_off_t pos, size_t len,
    char *out)
{
	erofs_off_t mapoff;

	mapoff = pos - ext->map.m_la;
	if ((ext->map.m_flags & EROFS_MAP_FRAGMENT) != 0)
		return (z_erofs_read_fragment(sbi, vi, mapoff, len, out));
	if (ext->data == NULL)
		bzero(out, len);
	else
		memcpy(out, (const char *)ext->data + mapoff, len);
	return (0);
}

static int
z_erofs_fill_page(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    vm_page_t m, struct z_erofs_decoded_extent *ext)
{
	struct sf_buf *sf;
	erofs_off_t end, pos;
	size_t done, len;
	char *va;
	int error;

	pos = IDX_TO_OFF(m->pindex);
	end = MIN(pos + PAGE_SIZE, vi->size);
	sf = sf_buf_alloc(m, 0);
	va = (char *)sf_buf_kva(sf);
	error = 0;
	for (done = 0; pos + done < end; done += len) {
		if (!z_erofs_decoded_covers(ext, pos + done)) {
			error = z_erofs_decoded_load(sbi, vi, pos + done, ext);
			if (error != 0)
				break;
		}
		len = MIN(end, ext->map.m_la + ext->map.m_llen) - (pos + done);
		error = z_erofs_decoded_copy(sbi, vi, ext, pos + done, len,
		    va + done);
		if (error != 0)
			break;
	}
	if (error == 0) {
		bzero(va + done, PAGE_SIZE - done);
		vm_page_valid(m);
	}
	sf_buf_free(sf);
	return (error);
}

/* rbehind and rahead count contiguous pages, so the caller stops at a miss. */
static bool
z_erofs_fill_extra_page(vm_object_t obj, vm_pindex_t pindex,
    const struct z_erofs_decoded_extent *ext, erofs_off_t size)
{
	struct sf_buf *sf;
	erofs_off_t end, extent_end, pos;
	vm_page_t m;
	char *va;

	pos = IDX_TO_OFF(pindex);
	extent_end = ext->map.m_la + ext->map.m_llen;
	end = MIN(pos + PAGE_SIZE, extent_end);
	if (ext->data == NULL || pos < ext->map.m_la || pos >= end ||
	    (end - pos < PAGE_SIZE && extent_end != size))
		return (false);
	m = vm_page_grab_unlocked(obj, pindex,
	    VM_ALLOC_NORMAL | VM_ALLOC_NOWAIT);
	if (m == NULL)
		return (false);
	if (!vm_page_none_valid(m)) {
		vm_page_xunbusy(m);
		return (true);
	}
	sf = sf_buf_alloc(m, 0);
	va = (char *)sf_buf_kva(sf);
	memcpy(va, (const char *)ext->data + (pos - ext->map.m_la), end - pos);
	bzero(va + (end - pos), PAGE_SIZE - (end - pos));
	sf_buf_free(sf);
	vm_page_valid(m);
	vm_page_readahead_finish(m);
	return (true);
}

static int
z_erofs_fill_behind(vm_object_t obj, vm_pindex_t first,
    const struct z_erofs_decoded_extent *ext, erofs_off_t size)
{
	vm_pindex_t n;

	for (n = 0; n < first; n++) {
		if (!z_erofs_fill_extra_page(obj, first - 1 - n, ext, size))
			break;
	}
	return (n);
}

static int
z_erofs_fill_ahead(vm_object_t obj, vm_pindex_t last,
    const struct z_erofs_decoded_extent *ext, erofs_off_t size)
{
	vm_pindex_t n;

	for (n = 0; z_erofs_fill_extra_page(obj, last + 1 + n, ext, size); n++)
		;
	return (n);
}

int
z_erofs_getpages(struct vnode *vp, vm_page_t *ma, int count, int *rbehind,
    int *rahead)
{
	struct z_erofs_decoded_extent ext;
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	vm_object_t obj;
	int ahead, behind, error, i;

	if (VN_IS_DOOMED(vp))
		return (VM_PAGER_BAD);
	sbi = MTOE(vp->v_mount);
	vi = VTOE(vp);
	obj = ma[0]->object;
	KASSERT(IDX_TO_OFF(ma[0]->pindex) < vi->size,
	    ("erofs: page %ju is beyond the size %ju of the file",
		(uintmax_t)ma[0]->pindex, (uintmax_t)vi->size));
	EROFS_TRACE_READ_FOLIO(vi, IDX_TO_OFF(ma[0]->pindex), ptoa(count),
	    false);

	bzero(&ext, sizeof(ext));
	behind = 0;
	ahead = 0;
	error = z_erofs_decoded_load(sbi, vi, IDX_TO_OFF(ma[0]->pindex), &ext);
	if (error == 0)
		behind = z_erofs_fill_behind(obj, ma[0]->pindex, &ext,
		    vi->size);
	/* sendfile(2) passes the valid pages as bogus_page. */
	for (i = 0; error == 0 && i < count; i++) {
		if (ma[i] != bogus_page)
			error = z_erofs_fill_page(sbi, vi, ma[i], &ext);
	}
	if (error == 0)
		ahead = z_erofs_fill_ahead(obj, ma[count - 1]->pindex, &ext,
		    vi->size);
	free(ext.data, M_EROFS);
	if (error != 0)
		return (VM_PAGER_ERROR);

	if (rbehind != NULL)
		*rbehind = MIN(*rbehind, behind);
	if (rahead != NULL)
		*rahead = MIN(*rahead, ahead);
	VM_CNT_INC(v_vnodein);
	VM_CNT_ADD(v_vnodepgsin, count + behind + ahead);
	return (VM_PAGER_OK);
}

static int
z_erofs_read_zeroes(struct uio *uio, size_t len)
{
	size_t zlen;
	int error;

	while (len > 0) {
		zlen = MIN(len, ZERO_REGION_SIZE);
		error = uiomove(__DECONST(void *, zero_region), zlen, uio);
		if (error != 0)
			return (error);
		len -= zlen;
	}
	return (0);
}

int
z_erofs_read_pages(struct vnode *vp, struct uio *uio)
{
	struct erofs_map_blocks map;
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	vm_object_t obj;
	vm_page_t m;
	erofs_off_t off;
	size_t len, poff;
	int error, rv;

	sbi = MTOE(vp->v_mount);
	vi = VTOE(vp);
	obj = vp->v_object;
	while (uio->uio_resid > 0 && (uint64_t)uio->uio_offset < vi->size) {
		off = uio->uio_offset;
		poff = off & PAGE_MASK;
		len = MIN(MIN(PAGE_SIZE - poff, (size_t)uio->uio_resid),
		    vi->size - off);
		rv = vm_page_grab_valid_unlocked(&m, obj, OFF_TO_IDX(off),
		    VM_ALLOC_NORMAL | VM_ALLOC_SBUSY | VM_ALLOC_IGN_SBUSY |
			VM_ALLOC_NOCREAT);
		if (rv != VM_PAGER_OK) {
			/* Sparse files can be huge: do not cache the holes. */
			error = z_erofs_map_pos(sbi, vi, off, &map);
			if (error != 0)
				return (error);
			if ((map.m_flags &
				(EROFS_MAP_FRAGMENT | EROFS_MAP_MAPPED)) == 0) {
				error = z_erofs_read_zeroes(uio,
				    MIN(map.m_la + map.m_llen - off,
					(size_t)uio->uio_resid));
				if (error != 0)
					return (error);
				continue;
			}
			rv = vm_page_grab_valid_unlocked(&m, obj,
			    OFF_TO_IDX(off),
			    VM_ALLOC_NORMAL | VM_ALLOC_SBUSY |
				VM_ALLOC_IGN_SBUSY);
			if (rv != VM_PAGER_OK)
				return (EIO);
		}
		error = uiomove_fromphys(&m, poff, len, uio);
		vm_page_activate(m);
		vm_page_sunbusy(m);
		if (error != 0)
			return (error);
	}
	return (0);
}
