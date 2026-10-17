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

#endif /* _FS_EROFS_INTERNAL_H_ */
