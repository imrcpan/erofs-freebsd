// SPDX-License-Identifier: BSD-2-Clause
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
#include <sys/smp.h>
#include <sys/uio.h>

#include <fs/erofs/compress.h>

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

static void
z_erofs_decode_taskqueue_init(struct erofs_sb_info *sbi __unused)
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
	if (sbi->z_extent_cache.closing || sbi->decompress_taskqueue == NULL) {
		taskqueue = NULL;
	} else {
		taskqueue = sbi->decompress_taskqueue;
		++sbi->decompress_taskqueue_users;
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
