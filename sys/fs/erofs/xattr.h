/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 */
#ifndef _FS_EROFS_XATTR_H_
#define _FS_EROFS_XATTR_H_

#ifdef UFS_ACL
#include <sys/acl.h>
#endif

#include <fs/erofs/internal.h>
int erofs_listxattr(struct vnode *vp, int attrnamespace, struct uio *uio,
    size_t *sizep);
int erofs_getxattr(struct vnode *vp, int attrnamespace, const char *name,
    struct uio *uio, size_t *sizep);
#ifdef UFS_ACL
int erofs_get_acl(struct vnode *vp, acl_type_t type, struct acl *aclp);
#endif
void erofs_xattr_cache_init(struct erofs_inode *vi);
void erofs_xattr_cache_fini(struct erofs_sb_info *sbi, struct erofs_inode *vi);
#endif
