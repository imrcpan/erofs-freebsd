/* SPDX-License-Identifier: MIT */
/*
 * EROFS (Enhanced ROM File System) on-disk format definition
 *
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */
#ifndef __EROFS_FS_H
#define __EROFS_FS_H

/* to allow for x86 boot sectors and other oddities. */
#define EROFS_SUPER_OFFSET			  1024

#define EROFS_FEATURE_COMPAT_SB_CHKSUM		  0x00000001
#define EROFS_FEATURE_COMPAT_MTIME		  0x00000002
#define EROFS_FEATURE_COMPAT_XATTR_FILTER	  0x00000004
#define EROFS_FEATURE_COMPAT_SHARED_EA_IN_METABOX 0x00000008
#define EROFS_FEATURE_COMPAT_PLAIN_XATTR_PFX	  0x00000010
#define EROFS_FEATURE_COMPAT_ISHARE_XATTRS	  0x00000020

/*
 * Any bits that aren't in EROFS_ALL_FEATURE_INCOMPAT should
 * be incompatible with this kernel version.
 */
#define EROFS_FEATURE_INCOMPAT_LZ4_0PADDING   0x00000001
#define EROFS_FEATURE_INCOMPAT_COMPR_CFGS     0x00000002
#define EROFS_FEATURE_INCOMPAT_BIG_PCLUSTER   0x00000002
#define EROFS_FEATURE_INCOMPAT_CHUNKED_FILE   0x00000004
#define EROFS_FEATURE_INCOMPAT_DEVICE_TABLE   0x00000008
#define EROFS_FEATURE_INCOMPAT_COMPR_HEAD2    0x00000008
#define EROFS_FEATURE_INCOMPAT_ZTAILPACKING   0x00000010
#define EROFS_FEATURE_INCOMPAT_FRAGMENTS      0x00000020
#define EROFS_FEATURE_INCOMPAT_DEDUPE	      0x00000020
#define EROFS_FEATURE_INCOMPAT_XATTR_PREFIXES 0x00000040
#define EROFS_FEATURE_INCOMPAT_48BIT	      0x00000080
#define EROFS_FEATURE_INCOMPAT_METABOX	      0x00000100
#define EROFS_ALL_FEATURE_INCOMPAT	      ((EROFS_FEATURE_INCOMPAT_METABOX << 1) - 1)

#define EROFS_SB_EXTSLOT_SIZE		      16

struct erofs_deviceslot {
	uint8_t tag[64];     /* digest(sha256), etc. */
	uint32_t blocks_lo;  /* total blocks count of this device */
	uint32_t uniaddr_lo; /* unified starting block of this device */
	uint16_t blocks_hi;  /* total blocks count MSB */
	uint16_t uniaddr_hi; /* unified starting block MSB */
	uint8_t reserved[52];
};
#define EROFS_DEVT_SLOT_SIZE sizeof(struct erofs_deviceslot)

/* erofs on-disk super block (currently 144 bytes at maximum) */
struct erofs_super_block {
	uint32_t magic;	   /* file system magic number */
	uint32_t checksum; /* crc32c to avoid unexpected on-disk overlap */
	uint32_t feature_compat;
	uint8_t blkszbits;   /* filesystem block size in bit shift */
	uint8_t sb_extslots; /* superblock size = 128 + sb_extslots * 16 */
	union {
		uint16_t rootnid_2b; /* nid of root directory */
		uint16_t blocks_hi;  /* (48BIT on) blocks count MSB */
	} __packed rb;
	uint64_t inos;		 /* total valid ino # (== f_files - f_favail) */
	uint64_t epoch;		 /* base seconds used for compact inodes */
	uint32_t fixed_nsec;	 /* fixed nanoseconds for compact inodes */
	uint32_t blocks_lo;	 /* blocks count LSB */
	uint32_t meta_blkaddr;	 /* start block address of metadata area */
	uint32_t xattr_blkaddr;	 /* start block address of shared xattr area */
	uint8_t uuid[16];	 /* 128-bit uuid for volume */
	uint8_t volume_name[16]; /* volume name */
	uint32_t feature_incompat;
	union {
		/* bitmap for available compression algorithms */
		uint16_t available_compr_algs;
		/* customized sliding window size instead of 64k by default */
		uint16_t lz4_max_distance;
	} __packed u1;
	uint16_t extra_devices; /* # of devices besides the primary device */
	uint16_t devt_slotoff;	/* startoff = devt_slotoff * devt_slotsize */
	uint8_t dirblkbits;	/* directory block size in bit shift */
	uint8_t xattr_prefix_count;    /* # of long xattr name prefixes */
	uint32_t xattr_prefix_start;   /* start of long xattr prefixes */
	uint64_t packed_nid;	       /* nid of the special packed inode */
	uint8_t xattr_filter_reserved; /* reserved for xattr name filter */
	uint8_t ishare_xattr_prefix_id;
	uint8_t reserved[2];
	uint32_t build_time; /* seconds added to epoch for mkfs time */
	uint64_t rootnid_8b; /* (48BIT on) nid of root directory */
	uint64_t reserved2;
	uint64_t metabox_nid; /* (METABOX on) nid of the metabox inode */
	uint64_t reserved3;   /* [align to extslot 1] */
};

/*
 * EROFS inode datalayout (i_format in on-disk inode):
 * 0 - uncompressed flat inode without tail-packing inline data:
 * 1 - compressed inode with non-compact indexes:
 * 2 - uncompressed flat inode with tail-packing inline data:
 * 3 - compressed inode with compact indexes:
 * 4 - chunk-based inode with (optional) multi-device support:
 * 5~7 - reserved
 */
enum {
	EROFS_INODE_FLAT_PLAIN = 0,
	EROFS_INODE_COMPRESSED_FULL = 1,
	EROFS_INODE_FLAT_INLINE = 2,
	EROFS_INODE_COMPRESSED_COMPACT = 3,
	EROFS_INODE_CHUNK_BASED = 4,
	EROFS_INODE_DATALAYOUT_MAX
};

static inline bool
erofs_inode_is_data_compressed(unsigned int datamode)
{
	return (datamode == EROFS_INODE_COMPRESSED_COMPACT ||
	    datamode == EROFS_INODE_COMPRESSED_FULL);
}

/* bit definitions of inode i_format */
#define EROFS_I_VERSION_MASK	0x01
#define EROFS_I_DATALAYOUT_MASK 0x07

#define EROFS_I_VERSION_BIT	0
#define EROFS_I_DATALAYOUT_BIT	1
#define EROFS_I_NLINK_1_BIT	4 /* non-directory compact inodes only */
#define EROFS_I_DOT_OMITTED_BIT 4 /* (directories) omit the `.` dirent */
#define EROFS_I_ALL		((1 << (EROFS_I_NLINK_1_BIT + 1)) - 1)

/* indicate chunk blkbits, thus 'chunksize = blocksize << chunk blkbits' */
#define EROFS_CHUNK_FORMAT_BLKBITS_MASK 0x001F
/* with chunk indexes or just a 4-byte block array */
#define EROFS_CHUNK_FORMAT_INDEXES 0x0020
#define EROFS_CHUNK_FORMAT_48BIT   0x0040

#define EROFS_CHUNK_FORMAT_ALL	   ((EROFS_CHUNK_FORMAT_48BIT << 1) - 1)

/* 32-byte on-disk inode */
#define EROFS_INODE_LAYOUT_COMPACT 0
/* 64-byte on-disk inode */
#define EROFS_INODE_LAYOUT_EXTENDED 1

struct erofs_inode_chunk_info {
	uint16_t format; /* chunk blkbits, etc. */
	uint16_t reserved;
};

union erofs_inode_i_u {
	uint32_t blocks_lo;   /* total blocks count (if compressed inodes) */
	uint32_t startblk_lo; /* starting block number (if flat inodes) */
	uint32_t rdev;	      /* device ID (if special inodes) */
	struct erofs_inode_chunk_info c;
};

union erofs_inode_i_nb {
	uint16_t nlink;	      /* if EROFS_I_NLINK_1_BIT is unset */
	uint16_t blocks_hi;   /* total blocks count MSB */
	uint16_t startblk_hi; /* starting block number MSB */
} __packed;

/* 32-byte reduced form of an ondisk inode */
struct erofs_inode_compact {
	uint16_t i_format; /* inode format hints */
	uint16_t i_xattr_icount;
	uint16_t i_mode;
	union erofs_inode_i_nb i_nb;
	uint32_t i_size;
	uint32_t i_mtime;
	union erofs_inode_i_u i_u;

	uint32_t i_ino; /* only used for 32-bit stat compatibility */
	uint16_t i_uid;
	uint16_t i_gid;
	uint32_t i_reserved;
};

/* 64-byte complete form of an ondisk inode */
struct erofs_inode_extended {
	uint16_t i_format; /* inode format hints */
	uint16_t i_xattr_icount;
	uint16_t i_mode;
	union erofs_inode_i_nb i_nb;
	uint64_t i_size;
	union erofs_inode_i_u i_u;

	uint32_t i_ino; /* only used for 32-bit stat compatibility */
	uint32_t i_uid;
	uint32_t i_gid;
	uint64_t i_mtime;
	uint32_t i_mtime_nsec;
	uint32_t i_nlink;
	uint8_t i_reserved2[16];
};

/*
 * inline xattrs (n == i_xattr_icount):
 * erofs_xattr_ibody_header(1) + (n - 1) * 4 bytes
 *          12 bytes           /                   \
 *                            /                     \
 *                           /-----------------------\
 *                           |  erofs_xattr_entries+ |
 *                           +-----------------------+
 * inline xattrs must starts in erofs_xattr_ibody_header,
 * for read-only fs, no need to introduce h_refcount
 */
struct erofs_xattr_ibody_header {
	uint32_t h_name_filter; /* bit value 1 indicates not-present */
	uint8_t h_shared_count;
	uint8_t h_reserved2[7];
	uint32_t h_shared_xattrs[]; /* shared xattr id array */
};

/* Name indexes */
#define EROFS_XATTR_INDEX_USER		    1
#define EROFS_XATTR_INDEX_POSIX_ACL_ACCESS  2
#define EROFS_XATTR_INDEX_POSIX_ACL_DEFAULT 3
#define EROFS_XATTR_INDEX_TRUSTED	    4
#define EROFS_XATTR_INDEX_LUSTRE	    5
#define EROFS_XATTR_INDEX_SECURITY	    6

/*
 * bit 7 of e_name_index is set when it refers to a long xattr name prefix,
 * while the remained lower bits represent the index of the prefix.
 */
#define EROFS_XATTR_LONG_PREFIX	     0x80
#define EROFS_XATTR_LONG_PREFIX_MASK 0x7f

#define EROFS_XATTR_FILTER_BITS	     32
#define EROFS_XATTR_FILTER_DEFAULT   UINT32_MAX
#define EROFS_XATTR_FILTER_SEED	     0x25BBE08F

/* xattr entry (for both inline & shared xattrs) */
struct erofs_xattr_entry {
	uint8_t e_name_len;    /* length of name */
	uint8_t e_name_index;  /* attribute name index */
	uint16_t e_value_size; /* size of attribute value */
	/* followed by e_name and e_value */
	char e_name[]; /* attribute name */
};

/* long xattr name prefix */
struct erofs_xattr_long_prefix {
	uint8_t base_index; /* short xattr name prefix index */
	char infix[];	    /* infix apart from short prefix */
};

static inline unsigned int
erofs_xattr_ibody_size(uint16_t i_xattr_icount)
{
	if (!i_xattr_icount)
		return (0);

	/* 1 header + n-1 * 4 bytes inline xattr to keep continuity */
	return (sizeof(struct erofs_xattr_ibody_header) +
	    sizeof(uint32_t) * (le16toh(i_xattr_icount) - 1));
}

#define EROFS_XATTR_ALIGN(size) round_up(size, sizeof(struct erofs_xattr_entry))

static inline unsigned int
erofs_xattr_entry_size(struct erofs_xattr_entry *e)
{
	return (EROFS_XATTR_ALIGN(sizeof(struct erofs_xattr_entry) +
	    e->e_name_len + le16toh(e->e_value_size)));
}

/* represent a zeroed chunk (hole) */
#define EROFS_NULL_ADDR -1

/* 4-byte block address array */
#define EROFS_BLOCK_MAP_ENTRY_SIZE sizeof(uint32_t)

/* 8-byte inode chunk index */
struct erofs_inode_chunk_index {
	uint16_t startblk_hi; /* starting block number MSB */
	uint16_t device_id;   /* back-end storage id (with bits masked) */
	uint32_t startblk_lo; /* starting block number of this chunk */
};

#define EROFS_DIRENT_NID_METABOX_BIT 63
#define EROFS_DIRENT_NID_MASK	     (BIT_ULL(EROFS_DIRENT_NID_METABOX_BIT) - 1)

/* dirent sorts in alphabet order, thus we can do binary search */
struct erofs_dirent {
	uint64_t nid;	   /* node number */
	uint16_t nameoff;  /* start offset of file name */
	uint8_t file_type; /* file type */
	uint8_t reserved;  /* reserved */
} __packed;

/*
 * EROFS file types should match generic FT_* types and
 * it seems no need to add BUILD_BUG_ONs since potential
 * unmatchness will break other fses as well...
 */

#define EROFS_NAME_LEN 255

/* maximum supported encoded size of a physical compressed cluster */
#define Z_EROFS_PCLUSTER_MAX_SIZE (1024 * 1024)

/* maximum supported decoded size of a physical compressed cluster */
#define Z_EROFS_PCLUSTER_MAX_DSIZE (12 * 1024 * 1024)

/* available compression algorithm types (for h_algorithmtype) */
enum {
	Z_EROFS_COMPRESSION_LZ4 = 0,
	Z_EROFS_COMPRESSION_LZMA = 1,
	Z_EROFS_COMPRESSION_DEFLATE = 2,
	Z_EROFS_COMPRESSION_ZSTD = 3,
	Z_EROFS_COMPRESSION_MAX
};
#define Z_EROFS_ALL_COMPR_ALGS ((1 << Z_EROFS_COMPRESSION_MAX) - 1)

/* 14 bytes (+ length field = 16 bytes) */
struct z_erofs_lz4_cfgs {
	uint16_t max_distance;
	uint16_t max_pclusterblks;
	uint8_t reserved[10];
} __packed;

/* 14 bytes (+ length field = 16 bytes) */
struct z_erofs_lzma_cfgs {
	uint32_t dict_size;
	uint16_t format;
	uint8_t reserved[8];
} __packed;

#define Z_EROFS_LZMA_MAX_DICT_SIZE (8 * Z_EROFS_PCLUSTER_MAX_SIZE)

/* 6 bytes (+ length field = 8 bytes) */
struct z_erofs_deflate_cfgs {
	uint8_t windowbits; /* 8..15 for DEFLATE */
	uint8_t reserved[5];
} __packed;

/* 6 bytes (+ length field = 8 bytes) */
struct z_erofs_zstd_cfgs {
	uint8_t format;
	uint8_t windowlog; /* windowLog - ZSTD_WINDOWLOG_ABSOLUTEMIN(10) */
	uint8_t reserved[4];
} __packed;

#define Z_EROFS_ZSTD_MAX_DICT_SIZE Z_EROFS_PCLUSTER_MAX_SIZE

/*
 * Enable COMPACTED_2B for EROFS_INODE_COMPRESSED_COMPACT inodes:
 *   4B (disabled) vs 4B+2B+4B (enabled)
 */
#define Z_EROFS_ADVISE_COMPACTED_2B 0x0001
/* Enable extent metadata for EROFS_INODE_COMPRESSED_FULL inodes */
#define Z_EROFS_ADVISE_EXTENTS		   0x0001
#define Z_EROFS_ADVISE_BIG_PCLUSTER_1	   0x0002
#define Z_EROFS_ADVISE_BIG_PCLUSTER_2	   0x0004
#define Z_EROFS_ADVISE_INLINE_PCLUSTER	   0x0008
#define Z_EROFS_ADVISE_INTERLACED_PCLUSTER 0x0010
#define Z_EROFS_ADVISE_FRAGMENT_PCLUSTER   0x0020
/* Indicate the record size for each extent if extent metadata is used */
#define Z_EROFS_ADVISE_EXTRECSZ_BIT  1
#define Z_EROFS_ADVISE_EXTRECSZ_MASK 0x3

#define Z_EROFS_FRAGMENT_INODE_BIT   7
struct z_erofs_map_header {
	union {
		/* fragment data offset in the packed inode */
		uint32_t h_fragmentoff;
		struct {
			uint16_t h_reserved1;
			/* indicates the encoded size of tailpacking data */
			uint16_t h_idata_size;
		};
		uint32_t h_extents_lo; /* extent count LSB */
	};
	uint16_t h_advise;
	union {
		struct {
			/* algorithm type (bit 0-3: HEAD1; bit 4-7: HEAD2) */
			uint8_t h_algorithmtype;
			/*
			 * bit 0-3 : logical cluster bits - blkszbits
			 * bit 4-6 : reserved
			 * bit 7   : pack the whole file into packed inode
			 */
			uint8_t h_clusterbits;
		} __packed;
		uint16_t h_extents_hi; /* extent count MSB */
	} __packed;
};

enum {
	Z_EROFS_LCLUSTER_TYPE_PLAIN = 0,
	Z_EROFS_LCLUSTER_TYPE_HEAD1 = 1,
	Z_EROFS_LCLUSTER_TYPE_NONHEAD = 2,
	Z_EROFS_LCLUSTER_TYPE_HEAD2 = 3,
	Z_EROFS_LCLUSTER_TYPE_MAX
};

#define Z_EROFS_LI_LCLUSTER_TYPE_MASK (Z_EROFS_LCLUSTER_TYPE_MAX - 1)

/* (noncompact only, HEAD) This pcluster refers to partial decompressed data */
#define Z_EROFS_LI_PARTIAL_REF (1 << 15)

/* Set on 1st non-head lcluster to store compressed block counti (in blocks) */
#define Z_EROFS_LI_D0_CBLKCNT (1 << 11)

struct z_erofs_lcluster_index {
	uint16_t di_advise;
	/* where to decompress in the head lcluster */
	uint16_t di_clusterofs;

	union {
		uint32_t blkaddr; /* for the HEAD lclusters */
		/*
		 * [0] - distance to its HEAD lcluster
		 * [1] - distance to the next HEAD lcluster
		 */
		uint16_t delta[2]; /* for the NONHEAD lclusters */
	} di_u;
};

#define Z_EROFS_MAP_HEADER_END(end) \
	(ALIGN(end, 8) + sizeof(struct z_erofs_map_header))
#define Z_EROFS_FULL_INDEX_START(end) (Z_EROFS_MAP_HEADER_END(end) + 8)

#define Z_EROFS_EXTENT_PLEN_PARTIAL   BIT(27)
#define Z_EROFS_EXTENT_PLEN_FMT_BIT   28
#define Z_EROFS_EXTENT_PLEN_MASK      ((Z_EROFS_PCLUSTER_MAX_SIZE << 1) - 1)
struct z_erofs_extent {
	uint32_t plen;	      /* encoded length */
	uint32_t pstart_lo;   /* physical offset */
	uint32_t pstart_hi;   /* physical offset MSB */
	uint32_t lstart_lo;   /* logical offset */
	uint32_t lstart_hi;   /* logical offset MSB (>= 4GiB inodes) */
	uint8_t reserved[12]; /* for future use */
};

static inline int
z_erofs_extent_recsize(unsigned int advise)
{
	return (4 << ((advise >> Z_EROFS_ADVISE_EXTRECSZ_BIT) &
		    Z_EROFS_ADVISE_EXTRECSZ_MASK));
}

/* check the EROFS on-disk layout strictly at compile time */
static inline void
erofs_check_ondisk_layout_definitions(void)
{
	const uint64_t fmh = *(uint64_t *)&(struct z_erofs_map_header) {
		.h_clusterbits = 1 << Z_EROFS_FRAGMENT_INODE_BIT
	};

	BUILD_BUG_ON(sizeof(struct erofs_super_block) != 144);
	BUILD_BUG_ON(sizeof(struct erofs_inode_compact) != 32);
	BUILD_BUG_ON(sizeof(struct erofs_inode_extended) != 64);
	BUILD_BUG_ON(sizeof(struct erofs_xattr_ibody_header) != 12);
	BUILD_BUG_ON(sizeof(struct erofs_xattr_entry) != 4);
	BUILD_BUG_ON(sizeof(struct erofs_inode_chunk_info) != 4);
	BUILD_BUG_ON(sizeof(struct erofs_inode_chunk_index) != 8);
	BUILD_BUG_ON(sizeof(struct z_erofs_map_header) != 8);
	BUILD_BUG_ON(sizeof(struct z_erofs_lcluster_index) != 8);
	BUILD_BUG_ON(sizeof(struct erofs_dirent) != 12);
	/* keep in sync between 2 index structures for better extendibility */
	BUILD_BUG_ON(sizeof(struct erofs_inode_chunk_index) !=
	    sizeof(struct z_erofs_lcluster_index));
	BUILD_BUG_ON(sizeof(struct erofs_deviceslot) != 128);

	/* exclude old compiler versions like gcc 7.5.0 */
	BUILD_BUG_ON(
	    __builtin_constant_p(fmh) ? fmh != htole64(1ULL << 63) : 0);
}

#endif
