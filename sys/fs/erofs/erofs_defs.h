/* SPDX-License-Identifier: MIT */

#ifndef _FS_EROFS_DEFS_H_
#define _FS_EROFS_DEFS_H_

#include <sys/param.h>
#include <sys/endian.h>

#define BIT(n)		     (1UL << (n))
#define BIT_ULL(n)	     (1ULL << (n))
#define round_up(x, y)	     roundup2((x), (y))

#define BUILD_BUG_ON(cond)   ((void)sizeof(char[1 - 2 * !!(cond)]))

#define EROFS_SUPER_MAGIC_V1 0xE0F5E1E2

#define EROFS_FT_UNKNOWN     0
#define EROFS_FT_REG_FILE    1
#define EROFS_FT_DIR	     2
#define EROFS_FT_CHRDEV	     3
#define EROFS_FT_BLKDEV	     4
#define EROFS_FT_FIFO	     5
#define EROFS_FT_SOCK	     6
#define EROFS_FT_SYMLINK     7

#endif
