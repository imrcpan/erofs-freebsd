/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */

#ifndef _FS_EROFS_INTERNAL_H_
#define _FS_EROFS_INTERNAL_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/vnode.h>

#include <fs/erofs/erofs_defs.h>
#include <fs/erofs/erofs_fs.h>

/*
 * Check the sizes and field offsets of the on-disk structures.
 * This catches a layout that differs from the format when the kernel is
 * built, so that the structures can be accessed directly through pointers
 * into the data read from the image.
 */
_Static_assert(sizeof(struct erofs_deviceslot) == 128,
    "EROFS device slot ABI size");
_Static_assert(sizeof(struct erofs_super_block) == 144,
    "EROFS super block ABI size");
_Static_assert(sizeof(struct erofs_inode_compact) == 32,
    "EROFS compact inode ABI size");
_Static_assert(sizeof(struct erofs_inode_extended) == 64,
    "EROFS extended inode ABI size");
_Static_assert(sizeof(struct erofs_xattr_ibody_header) == 12,
    "EROFS xattr ibody header ABI size");
_Static_assert(sizeof(struct erofs_xattr_entry) == 4,
    "EROFS xattr entry ABI size");
_Static_assert(sizeof(struct erofs_inode_chunk_info) == 4,
    "EROFS chunk info ABI size");
_Static_assert(sizeof(struct erofs_inode_chunk_index) == 8,
    "EROFS chunk index ABI size");
_Static_assert(sizeof(struct z_erofs_map_header) == 8,
    "EROFS zmap header ABI size");
_Static_assert(sizeof(struct z_erofs_lcluster_index) == 8,
    "EROFS lcluster index ABI size");
_Static_assert(sizeof(struct z_erofs_extent) == 32,
    "EROFS compression extent ABI size");
_Static_assert(sizeof(struct erofs_dirent) == 12, "EROFS dirent ABI size");
_Static_assert(sizeof(struct erofs_deviceslot) == EROFS_DEVT_SLOT_SIZE,
    "EROFS device slot ABI macro");
_Static_assert(__builtin_offsetof(struct erofs_super_block, extra_devices) ==
	86,
    "EROFS extra device count ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_super_block, devt_slotoff) == 88,
    "EROFS device table slot offset ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_super_block, rootnid_8b) == 112,
    "EROFS 48-bit root nid ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_super_block, metabox_nid) == 128,
    "EROFS metabox nid ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_inode_compact, i_u) == 16,
    "EROFS compact inode union ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_inode_extended, i_u) == 16,
    "EROFS extended inode union ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_inode_extended, i_reserved2) ==
	48,
    "EROFS extended inode reserved ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_inode_chunk_index, device_id) ==
	2,
    "EROFS chunk device id ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_inode_chunk_index,
		   startblk_lo) == 4,
    "EROFS chunk start block ABI offset");
_Static_assert(__builtin_offsetof(struct z_erofs_map_header, h_advise) == 4,
    "EROFS zmap advise ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_deviceslot, blocks_lo) == 64,
    "EROFS device blocks ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_deviceslot, uniaddr_lo) == 68,
    "EROFS device unified address ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_deviceslot, blocks_hi) == 72,
    "EROFS device blocks high ABI offset");
_Static_assert(__builtin_offsetof(struct erofs_deviceslot, uniaddr_hi) == 74,
    "EROFS device unified address high ABI offset");

MALLOC_DECLARE(M_EROFS);

/*
 * Diagnostics.  erofs_corrupt() goes where bad on-disk data is first
 * noticed, not in the callers that pass the error up.  It logs one
 * rate-limited line (mount point, function, what was wrong, inode), fires
 * the erofs:::corrupt DTrace probe (arguments: nid, source line, error)
 * and returns EINTEGRITY, so a check reads
 *
 *	return (erofs_corrupt(sbi, nid, "bad foo %u", foo));
 *
 * erofs_err() is the same without the probe, for errors that are not
 * corruption, such as an unsupported feature.
 */
struct erofs_sb_info;
/* The error is not about an inode. */
/* clang-format off */
#define EROFS_NID_NONE	((erofs_nid_t)-1)
/* clang-format on */
void erofs_log_err(const struct erofs_sb_info *sbi, const char *func,
    const char *fmt, ...) __printflike(3, 4);
int erofs_log_corrupt(const struct erofs_sb_info *sbi, uint64_t nid,
    const char *func, int line, const char *fmt, ...) __printflike(5, 6);
#define erofs_err(sbi, fmt, ...) \
	erofs_log_err((sbi), __func__, fmt, ##__VA_ARGS__)
#define erofs_corrupt(sbi, nid, fmt, ...) \
	erofs_log_corrupt((sbi), (nid), __func__, __LINE__, fmt, ##__VA_ARGS__)

struct cdev;
struct g_consumer;
struct erofs_device_info;

typedef uint64_t erofs_nid_t;
typedef uint64_t erofs_off_t;
typedef uint64_t erofs_blk_t;

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__)
#error EROFS requires compiler byte-order definitions
#elif __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error EROFS requires a little-endian FreeBSD kernel ABI
#endif
/*
 * The module is LP64-only (see also the architecture list in the Makefile),
 * so size_t, off_t, ino_t, time_t and erofs_blk_t are all 64 bits wide.
 * Code below relies on this: do not add 32-bit overflow guards.
 */
_Static_assert(sizeof(uintptr_t) == sizeof(uint64_t),
    "EROFS requires a 64-bit pointer ABI");
_Static_assert(sizeof(ino_t) >= sizeof(uint64_t),
    "EROFS requires a 64-bit inode number ABI");
_Static_assert(sizeof(off_t) >= sizeof(uint64_t),
    "EROFS requires a 64-bit file offset ABI");
_Static_assert(sizeof(time_t) >= sizeof(int64_t),
    "EROFS requires a 64-bit timestamp ABI");
_Static_assert(sizeof(u_long) == sizeof(uint64_t),
    "EROFS requires 64-bit FreeBSD atomic long operations");
/*
 * The block count of the image and of each device has at most 48 bits, so
 * (blocks << blkszbits) fits in 64 bits.  This does not hold for
 * flatdev_blocks, a sum of two such counts: erofs_bread_device() checks it.
 */
_Static_assert(PAGE_SHIFT <= 16, "EROFS block sizes are at most 64 KiB");

#define EROFS_MOUNT_POSIX_ACL  0x00000020
#define EROFS_MOUNT_XATTR_USER 0x00000080
#define EROFS_MOUNT_DIRECT_IO  0x00000100
#define test_opt(opt, option)  ((opt)->mount_opt & EROFS_MOUNT_##option)

struct erofs_sb_info_opts {
	unsigned int mount_opt;
	uint8_t cache_strategy;
	uint8_t worker_queue_priority;
};

enum erofs_sync_decompress {
	EROFS_SYNC_DECOMPRESS_AUTO,
	EROFS_SYNC_DECOMPRESS_FORCE_ON,
	EROFS_SYNC_DECOMPRESS_FORCE_OFF,
};

enum erofs_zip_cache_strategy {
	EROFS_ZIP_CACHE_DISABLED,
	EROFS_ZIP_CACHE_READAHEAD,
	EROFS_ZIP_CACHE_READAROUND,
};

struct erofs_device_handle;

enum erofs_source_kind {
	EROFS_SOURCE_NONE,
	EROFS_SOURCE_BLOCK,
	EROFS_SOURCE_FILE,
};

struct erofs_device_info {
	struct vnode *devvp;
	struct cdev *dev;
	struct g_consumer *cp;
	struct erofs_device_handle *handle;
	struct ucred *source_cred;
	enum erofs_source_kind source_kind;
	uint64_t mediasize;
	uint32_t sectorsize;
	uint64_t fsoff;

	erofs_blk_t blocks;
	erofs_blk_t uniaddr;
};

static inline bool
erofs_source_is_open(const struct erofs_device_info *dif)
{
	return (dif != NULL && dif->devvp != NULL && dif->handle != NULL &&
	    (dif->source_kind == EROFS_SOURCE_BLOCK ||
		dif->source_kind == EROFS_SOURCE_FILE));
}

static inline bool
erofs_source_is_file(const struct erofs_device_info *dif)
{
	return (
	    erofs_source_is_open(dif) && dif->source_kind == EROFS_SOURCE_FILE);
}

struct erofs_xattr_prefix_item {
	uint8_t base_index;
	uint8_t infix_len;
	char *infix;
};

struct erofs_map_blocks {
	erofs_off_t m_pa, m_la;
	uint64_t m_plen, m_llen;

	unsigned short m_deviceid;
	uint8_t m_algorithmformat;
	unsigned int m_flags;
};

enum erofs_zextent_cache_state {
	EROFS_ZCACHE_EMPTY,
	EROFS_ZCACHE_INFLIGHT,
	EROFS_ZCACHE_READY,
	EROFS_ZCACHE_FAILED,
};

#define EROFS_ZCACHE_MAX_ENTRIES 8

struct erofs_zextent_key {
	struct erofs_map_blocks map;
	erofs_nid_t nid;
	size_t decoded_size;
};

struct erofs_zextent_cache_metrics {
	uint64_t hits;
	uint64_t misses;
	uint64_t bypasses;
	uint64_t evictions;
	uint64_t reclaims;
	uint64_t waiter_merges;
	size_t resident_bytes;
};

struct erofs_cache_stats {
	uint64_t hits;
	uint64_t misses;
	uint64_t bypasses;
	uint64_t evictions;
	uint64_t reclaims;
	uint64_t waiter_merges;
	uint64_t entries;
	uint64_t bytes;
};

struct erofs_zextent_cache_entry {
	struct erofs_zextent_key key;
	void *data;
	size_t charged_bytes;
	unsigned int waiters;
	int error;
	enum erofs_zextent_cache_state state;
	struct cv cv;
	uint64_t lru;
	bool active;
};

struct erofs_zextent_cache {
	struct erofs_zextent_cache_entry entries[EROFS_ZCACHE_MAX_ENTRIES];
	size_t charged_bytes;
	size_t budget_bytes;
	uint64_t minimum_decode_work;
	struct erofs_zextent_cache_metrics metrics[Z_EROFS_COMPRESSION_MAX];
	uint64_t lru_clock;
	unsigned int entry_count;
	bool closing;
};

struct erofs_decompress_task {
	struct task task;
	struct mtx lock;
	struct cv cv;
	struct erofs_sb_info *sbi;
	struct erofs_inode *vi;
	struct erofs_map_blocks map;
	size_t decoded_len;
	bool partial;
	void *decoded;
	int error;
	bool done;
};

enum erofs_xattr_cache_state {
	EROFS_XATTR_CACHE_EMPTY,
	EROFS_XATTR_CACHE_INFLIGHT,
	EROFS_XATTR_CACHE_READY,
	EROFS_XATTR_CACHE_FAILED,
};

struct erofs_xattr_cache {
	struct mtx lock;
	struct cv cv;
	void *data;
	size_t charged_bytes;
	unsigned int waiters;
	int error;
	enum erofs_xattr_cache_state state;
	bool closing;
	bool initialized;
};

#define EROFS_STREAM_CTX_WRAPPER_SIZE 256

struct erofs_stream_ctx;
typedef int erofs_stream_ctx_init_t(struct erofs_stream_ctx *ctx);
typedef void erofs_stream_ctx_fini_t(struct erofs_stream_ctx *ctx);

struct erofs_stream_ctx {
	STAILQ_ENTRY(erofs_stream_ctx) link;
	struct erofs_sb_info *sbi;
	erofs_stream_ctx_fini_t *fini;
	size_t charged_bytes;
	uint8_t algorithm;
	bool cached;
	bool allocation_failed;
};

STAILQ_HEAD(erofs_stream_ctx_head, erofs_stream_ctx);

struct erofs_stream_pool_codec {
	struct erofs_stream_ctx_head idle;
	unsigned int contexts;
	unsigned int cached;
	unsigned int borrowed;
	unsigned int idle_count;
};

struct erofs_stream_pool {
	struct erofs_stream_pool_codec codec[Z_EROFS_COMPRESSION_MAX];
	size_t resident_bytes;
	unsigned int waiters;
	struct cv cv;
	bool closing;
};

struct erofs_sb_info {
	struct mount *mnt;
	struct erofs_device_info dif0;
	struct mtx control_lock;
	struct sysctl_ctx_list sysctl_ctx;
	uint64_t control_id;
	uint64_t dir_ra_bytes;
	uint64_t dir_ra_max_bytes;
	uint64_t dir_ra_requests;
	uint64_t dir_ra_blocks;
	bool control_initialized;
	bool sysctl_registered;
	bool control_closing;

	uint32_t block_size;
	uint32_t sb_size;
	uint8_t blkszbits;
	uint32_t meta_blkaddr;
	uint32_t xattr_blkaddr;
	uint32_t xattr_prefix_start;
	uint8_t xattr_prefix_count;
	uint8_t xattr_filter_reserved;
	erofs_nid_t packed_nid;
	struct erofs_inode *metabox_en;
	struct erofs_inode *packed_inode;
	struct erofs_xattr_prefix_item *xattr_prefixes;
	erofs_blk_t blocks;
	erofs_nid_t root_nid;
	int64_t epoch;
	uint32_t fixed_nsec;
	uint32_t generation_seed;
	uint32_t feature_compat;
	uint32_t feature_incompat;

	struct erofs_sb_info_opts opt;
	uint16_t available_compr_algs;
	uint32_t lzma_dict_size;
	uint8_t zstd_windowlog;
	unsigned int sync_decompress;

	/* Device table */
	uint16_t extra_devices;
	uint16_t device_id_mask;
	bool flatdev;
	erofs_blk_t flatdev_blocks;
	struct erofs_device_info *devs;
	struct mtx z_extent_cache_lock;
	struct erofs_zextent_cache z_extent_cache;
	LIST_ENTRY(erofs_sb_info) z_extent_cache_link;
	bool z_extent_cache_initialized;
	struct taskqueue *decompress_taskqueue;
	struct cv decompress_taskqueue_cv;
	unsigned int decompress_taskqueue_users;
	unsigned int decompress_worker_count;
	bool decompress_worker_cpu_bound;
	uint8_t decompress_queue_priority;
	uint64_t decompress_submissions;
	uint64_t decompress_worker_runs;
	uint64_t decompress_queue_fallbacks;
	struct erofs_stream_pool stream_pool;
	LIST_ENTRY(erofs_sb_info) stream_pool_link;
	bool stream_pool_initialized;
	volatile u_long xattr_cache_resident;
};

#define MTOE(mp) ((struct erofs_sb_info *)(mp)->mnt_data)

#define EROFS_FEATURE_FUNCS(name, compat, feature)                           \
	static inline bool erofs_sb_has_##name(                              \
	    const struct erofs_sb_info *sbi)                                 \
	{                                                                    \
		return (                                                     \
		    (sbi->feature_##compat & EROFS_FEATURE_##feature) != 0); \
	}

EROFS_FEATURE_FUNCS(lz4_0padding, incompat, INCOMPAT_LZ4_0PADDING)
EROFS_FEATURE_FUNCS(compr_cfgs, incompat, INCOMPAT_COMPR_CFGS)
EROFS_FEATURE_FUNCS(big_pcluster, incompat, INCOMPAT_BIG_PCLUSTER)
EROFS_FEATURE_FUNCS(chunked_file, incompat, INCOMPAT_CHUNKED_FILE)
EROFS_FEATURE_FUNCS(fragments, incompat, INCOMPAT_FRAGMENTS)
EROFS_FEATURE_FUNCS(dedupe, incompat, INCOMPAT_DEDUPE)
EROFS_FEATURE_FUNCS(xattr_prefixes, incompat, INCOMPAT_XATTR_PREFIXES)
EROFS_FEATURE_FUNCS(48bit, incompat, INCOMPAT_48BIT)
EROFS_FEATURE_FUNCS(metabox, incompat, INCOMPAT_METABOX)
EROFS_FEATURE_FUNCS(xattr_filter, compat, COMPAT_XATTR_FILTER)
EROFS_FEATURE_FUNCS(shared_ea_in_metabox, compat, COMPAT_SHARED_EA_IN_METABOX)
EROFS_FEATURE_FUNCS(plain_xattr_pfx, compat, COMPAT_PLAIN_XATTR_PFX)

static inline bool
erofs_sb_has_xattr_filter_v1(const struct erofs_sb_info *sbi)
{
	return (
	    erofs_sb_has_xattr_filter(sbi) && sbi->xattr_filter_reserved == 0);
}

struct erofs_inode {
	erofs_nid_t nid;
	uint64_t size;
	uint64_t data_blocks;
	/* Byte offset in the device, or in the metabox for a metabox nid. */
	erofs_off_t inode_off;
	erofs_blk_t startblk;
	uint32_t generation;
	uint32_t nlink;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	__enum_uint8(vtype) vtype;
	dev_t rdev;
	time_t mtime;
	uint32_t mtime_nsec;
	uint8_t datalayout;
	uint8_t inode_isize;
	uint32_t xattr_isize;
	bool compact_inode;
	bool dot_omitted;
	/* Compression fields */
	uint16_t z_advise;
	uint8_t z_algorithmtype[2];
	uint8_t z_lclusterbits;
	uint16_t z_idata_size;
	erofs_off_t z_fragmentoff;
	uint64_t z_tailextent_headlcn;
	uint64_t z_extents;
	bool z_initialized;
	/* Chunk-based fields */
	uint16_t chunkformat;
	uint8_t chunkbits;
	/* Fragment fields */
	struct erofs_xattr_cache xattr_cache;
};

struct erofs_fid {
	uint16_t len;
	uint32_t nid_hi;
	uint32_t nid_lo;
	uint32_t gen;
};

_Static_assert(sizeof(struct erofs_fid) == 16,
    "EROFS file handle ABI must be 16 bytes");
_Static_assert(sizeof(struct erofs_fid) <= sizeof(struct fid),
    "struct erofs_fid must fit within struct fid");

#define VTOE(vp) ((struct erofs_inode *)(vp)->v_data)

static inline unsigned int
erofs_inode_version(unsigned int ifmt)
{
	return ((ifmt >> EROFS_I_VERSION_BIT) & EROFS_I_VERSION_MASK);
}

static inline unsigned int
erofs_inode_datalayout(unsigned int ifmt)
{
	return ((ifmt >> EROFS_I_DATALAYOUT_BIT) & EROFS_I_DATALAYOUT_MASK);
}

static inline bool
erofs_nid_in_metabox(erofs_nid_t nid)
{
	return ((nid & BIT_ULL(EROFS_DIRENT_NID_METABOX_BIT)) != 0);
}

static inline uint64_t
erofs_nid_to_ino64(const struct erofs_sb_info *sbi, erofs_nid_t nid)
{
	if (!erofs_sb_has_metabox(sbi))
		return (nid);
	return ((nid << 1) & 0xffffffff00000000ULL) |
	    (nid & 0x000000007fffffffULL) |
	    ((nid >> EROFS_DIRENT_NID_METABOX_BIT) << 31);
}

static inline int
erofs_ino_to_nid(const struct erofs_sb_info *sbi, ino_t ino, erofs_nid_t *nidp)
{
	uint64_t ino64;
	erofs_nid_t nid;

	ino64 = (uint64_t)ino;
	if (!erofs_sb_has_metabox(sbi))
		nid = ino64;
	else
		nid = ((ino64 >> 1) & UINT64_C(0x7fffffff80000000)) |
		    (ino64 & UINT64_C(0x000000007fffffff)) |
		    ((ino64 & UINT64_C(0x0000000080000000)) << 32);
	if (erofs_nid_to_ino64(sbi, nid) != ino64)
		return (EOVERFLOW);
	*nidp = nid;
	return (0);
}

/* Allocated on disk at m_pa. */
#define EROFS_MAP_MAPPED 0x0001
/* Located in metadata. */
#define EROFS_MAP_META		 0x0002
#define EROFS_MAP_PARTIAL_MAPPED 0x0004
#define EROFS_MAP_PARTIAL_REF	 0x0008
#define EROFS_MAP_FRAGMENT	 0x0010
#define EROFS_MAP_FULL(f) \
	(!((f) & (EROFS_MAP_PARTIAL_MAPPED | EROFS_MAP_PARTIAL_REF)))

#define EROFS_GET_BLOCKS_FIEMAP	  0x0001
#define EROFS_GET_BLOCKS_FINDTAIL 0x0004

enum {
	Z_EROFS_COMPRESSION_SHIFTED = Z_EROFS_COMPRESSION_MAX,
	Z_EROFS_COMPRESSION_INTERLACED,
	Z_EROFS_COMPRESSION_RUNTIME_MAX
};

_Static_assert(Z_EROFS_COMPRESSION_RUNTIME_MAX <= UINT8_MAX,
    "algorithm format must fit in uint8_t");

struct erofs_map_dev {
	struct erofs_device_info *m_dif;

	erofs_off_t m_pa;
	unsigned int m_deviceid;
	uint64_t m_plen;
};

struct erofs_buf {
	void *data;
	void (*release)(void *);
};

#define EROFS_BUF_INITIALIZER { .data = NULL, .release = NULL }

/* Buffer and device I/O. */
void erofs_put_metabuf(struct erofs_buf *buf);
int erofs_bread(struct erofs_sb_info *sbi, erofs_off_t off, size_t len,
    void **bufp);
int erofs_read_physical(struct erofs_sb_info *sbi, unsigned int device_id,
    erofs_off_t off, size_t len, void **bufp);
void erofs_brelse(void *buf);
int erofs_read_metadata_range(struct erofs_sb_info *sbi, erofs_nid_t nid,
    erofs_off_t off, size_t len, struct erofs_buf *buf);
/* Logical mapping and file data. */
int erofs_map_blocks(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map);
int erofs_read_data(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, void **bufp);
int erofs_read_data_readahead(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, bool sequential, void **bufp);
uint64_t erofs_dir_ra_bytes(struct erofs_sb_info *sbi);
int erofs_set_dir_ra_bytes(struct erofs_sb_info *sbi, uint64_t value);
void erofs_record_dir_readahead(struct erofs_sb_info *sbi, unsigned int blocks);
int erofs_read_file(struct vnode *vp, struct uio *uio);
int erofs_file_llseek(struct vnode *vp, off_t *offset, bool seek_data);
int erofs_readlink_target(struct vnode *vp, struct uio *uio);

/* File-backed source I/O is owned by fileio.c. */
int erofs_read_file_source(struct erofs_sb_info *sbi,
    struct erofs_device_info *dif, erofs_off_t off, size_t len, void *out);

/* Inode and vnode lifecycle. */
bool erofs_nid_is_valid(struct erofs_sb_info *sbi, erofs_nid_t nid);
int erofs_read_inode(struct erofs_sb_info *sbi, erofs_nid_t nid,
    struct erofs_inode *vi);
int erofs_vget_raw(struct mount *mp, erofs_nid_t nid, int flags,
    struct vnode **vpp);
int erofs_vget_raw_alloc(struct mount *mp, void *arg, int flags,
    struct vnode **vpp);
int erofs_vget(struct mount *mp, ino_t ino, int flags, struct vnode **vpp);

/* Directory operations. */
int erofs_readdir_block(struct vnode *vp, struct uio *uio, int *eofflag,
    int *ncookies, uint64_t **cookies);
int erofs_dirblock_ndirents(const char *blk, uint32_t maxsize,
    uint32_t *ndirentsp);
int erofs_dirent_span(const char *blk, uint32_t maxsize, uint32_t ndirents,
    uint32_t idx, uint32_t *nameoffp, uint32_t *endoffp);
int erofs_lookup(struct vop_cachedlookup_args *ap);

/* Compressed mapping and data. */
int z_erofs_fill_inode(struct erofs_sb_info *sbi, struct erofs_inode *vi);
int z_erofs_map_blocks(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map);
void z_erofs_extent_cache_init(struct erofs_sb_info *sbi);
void z_erofs_extent_cache_fini(struct erofs_sb_info *sbi);
int z_erofs_extent_cache_drop(struct erofs_sb_info *sbi);
void z_erofs_extent_cache_stats(struct erofs_sb_info *sbi,
    struct erofs_cache_stats *stats);
void z_erofs_stream_pool_init(struct erofs_sb_info *sbi);
void z_erofs_stream_pool_fini(struct erofs_sb_info *sbi);
int z_erofs_stream_ctx_get(struct erofs_sb_info *sbi, uint8_t algorithm,
    size_t context_size, erofs_stream_ctx_init_t *init,
    erofs_stream_ctx_fini_t *fini, struct erofs_stream_ctx **ctxp);
void z_erofs_stream_ctx_put(struct erofs_stream_ctx *ctx, bool reusable);
int z_erofs_stream_ctx_charge(struct erofs_stream_ctx *ctx, size_t bytes);
void z_erofs_stream_ctx_uncharge(struct erofs_stream_ctx *ctx, size_t bytes);
void *z_erofs_stream_ctx_alloc(struct erofs_stream_ctx *ctx, size_t bytes);
void z_erofs_stream_ctx_free(struct erofs_stream_ctx *ctx, void *address);
int z_erofs_read_data(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    erofs_off_t loff, size_t len, void **bufp);
int z_erofs_read_uio(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct uio *uio);
int z_erofs_decompress(struct erofs_sb_info *sbi,
    const struct erofs_map_blocks *map, const void *src, size_t srclen,
    void *dst, size_t dstlen, bool partial);
int z_erofs_decode_extent(struct erofs_sb_info *sbi, struct erofs_inode *vi,
    struct erofs_map_blocks *map, size_t decoded_len, bool partial,
    void **bufp);
int z_erofs_decode_extent_dispatch(struct erofs_sb_info *sbi,
    struct erofs_inode *vi, struct erofs_map_blocks *map, size_t decoded_len,
    bool partial, void **bufp);

/* Compression configuration. */
int z_erofs_parse_cfgs(struct erofs_sb_info *sbi,
    const struct erofs_super_block *dsb);

int erofs_parse_zip_options(struct mount *mp, struct erofs_sb_info_opts *opts,
    unsigned int *syncp, bool *cache_presentp, bool *sync_presentp);

int erofs_parse_dir_ra_option(struct erofs_sb_info *sbi,
    struct vfsoptlist *opts);
int erofs_parse_dir_ra_value(struct erofs_sb_info *sbi, struct vfsoptlist *opts,
    uint64_t *valuep, bool *presentp);
void erofs_management_init(struct erofs_sb_info *sbi);
void erofs_management_fini(struct erofs_sb_info *sbi);
int erofs_register_sysfs(struct erofs_sb_info *sbi);
int erofs_unregister_sysfs(struct erofs_sb_info *sbi);

/* VOP vectors. */
extern struct vop_vector erofs_vnodeops;
extern struct vop_vector erofs_fifoops;

#endif /* _FS_EROFS_INTERNAL_H_ */
