/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-04-02
 * Description: provide quota function definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_GRAPHDRIVER_QUOTA_PROJECT_QUOTA_H
#define DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_GRAPHDRIVER_QUOTA_PROJECT_QUOTA_H

#include <sys/mount.h>
#include <sys/quota.h>
#include <memory.h>
#include <pthread.h>
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

#if !defined FS_IOC_FSGETXATTR
// if did not define the fsxattr, define by ourself
struct fsxattr {
    __u32 fsx_xflags, fsx_extsize, fsx_nextents, fsx_projid, fsx_cowextsize;
    unsigned char fsx_pad[8];
};
#endif

#ifndef FS_IOC_FSGETXATTR
// if did not define the FSGETXATTR, define by ourself
#define FS_XFLAG_REALTIME 0x00000001
#define FS_XFLAG_PREALLOC 0x00000002
#define FS_XFLAG_IMMUTABLE 0x00000008
#define FS_XFLAG_APPEND 0x00000010
#define FS_XFLAG_SYNC 0x00000020
#define FS_XFLAG_NOATIME 0x00000040
#define FS_XFLAG_NODUMP 0x00000080
#define FS_XFLAG_RTINHERIT 0x00000100
#define FS_XFLAG_PROJINHERIT 0x00000200
#define FS_XFLAG_NOSYMLINKS 0x00000400
#define FS_XFLAG_EXTSIZE 0x00000800
#define FS_XFLAG_EXTSZINHERIT 0x00001000
#define FS_XFLAG_NODEFRAG 0x00002000
#define FS_XFLAG_FILESTREAM 0x00004000
#define FS_XFLAG_DAX 0x00008000
#define FS_XFLAG_HASATTR 0x80000000
#define FS_IOC_FSGETXATTR _IOR('X', 31, struct fsxattr)
#define FS_IOC_FSSETXATTR _IOW('X', 32, struct fsxattr)
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

void free_pquota_control(struct pquota_control *ctrl);

#ifdef __cplusplus
}
#endif

#endif
