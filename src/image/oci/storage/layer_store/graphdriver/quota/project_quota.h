/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2020-04-02
 * Description: provide quota function definition
 ******************************************************************************/
#ifndef __PROJECT_QUOTA_H
#define __PROJECT_QUOTA_H

#include <sys/mount.h>
#include <sys/quota.h>
#include <memory.h>
#include <linux/xattr.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/statfs.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <linux/magic.h>
#include <linux/dqblk_xfs.h>
#include <linux/fs.h>
#include <errno.h>
#include <libgen.h>
#include <dirent.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Check whether we have to define FS_IOC_FS[GS]ETXATTR ourselves. These
 * are a copy of the definitions moved to linux/uapi/fs.h in the 4.5 kernel,
 * so this is purely for supporting builds against old kernel headers.
 */
#if !defined FS_IOC_FSGETXATTR
struct fsxattr {
    __u32		fsx_xflags;	/* xflags field value (get/set) */
    __u32		fsx_extsize;	/* extsize field value (get/set)*/
    __u32		fsx_nextents;	/* nextents field value (get)	*/
    __u32		fsx_projid;	/* project identifier (get/set) */
    __u32		fsx_cowextsize;	/* cow extsize field value (get/set) */
    unsigned char	fsx_pad[8];
};
#endif

#ifndef FS_IOC_FSGETXATTR
/*
 * Flags for the fsx_xflags field
 */
#define FS_XFLAG_REALTIME	0x00000001	/* data in realtime volume */
#define FS_XFLAG_PREALLOC	0x00000002	/* preallocated file extents */
#define FS_XFLAG_IMMUTABLE	0x00000008	/* file cannot be modified */
#define FS_XFLAG_APPEND		0x00000010	/* all writes append */
#define FS_XFLAG_SYNC		0x00000020	/* all writes synchronous */
#define FS_XFLAG_NOATIME	0x00000040	/* do not update access time */
#define FS_XFLAG_NODUMP		0x00000080	/* do not include in backups */
#define FS_XFLAG_RTINHERIT	0x00000100	/* create with rt bit set */
#define FS_XFLAG_PROJINHERIT	0x00000200	/* create with parents projid */
#define FS_XFLAG_NOSYMLINKS	0x00000400	/* disallow symlink creation */
#define FS_XFLAG_EXTSIZE	0x00000800	/* extent size allocator hint */
#define FS_XFLAG_EXTSZINHERIT	0x00001000	/* inherit inode extent size */
#define FS_XFLAG_NODEFRAG	0x00002000	/* do not defragment */
#define FS_XFLAG_FILESTREAM	0x00004000	/* use filestream allocator */
#define FS_XFLAG_DAX		0x00008000	/* use DAX for IO */
#define FS_XFLAG_HASATTR	0x80000000	/* no DIFLAG for this	*/

#define FS_IOC_FSGETXATTR     _IOR ('X', 31, struct fsxattr)
#define FS_IOC_FSSETXATTR     _IOW ('X', 32, struct fsxattr)

#endif

struct pquota_control {
    char *backing_fs_type;
    char *backing_fs_device;
    uint32_t next_project_id;
    pthread_rwlock_t rwlock;
    // ops
    int (*set_quota)(const char *target, struct pquota_control *ctrl, uint64_t size);
};

struct pquota_control *project_quota_control_init(const char *home_dir, const char *fs);

#ifdef __cplusplus
}
#endif

#endif
