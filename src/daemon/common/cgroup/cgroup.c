/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2023-03-29
 * Description: provide cgroup functions
 ******************************************************************************/
#include "cgroup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/stat.h>

#include <isula_libutils/auto_cleanup.h>

#include "err_msg.h"
#include "utils.h"
#include "utils_array.h"
#include "sysinfo.h"
#include "cgroup_v1.h"
#include "cgroup_v2.h"
#include "path.h"

#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC 0x27e0eb
#endif

static cgroup_ops g_cgroup_ops;

static int get_cgroup_version_for_init(void)
{
    struct statfs fs = { 0 };

    if (statfs(CGROUP_MOUNTPOINT, &fs) != 0) {
        SYSERROR("failed to statfs %s", CGROUP_MOUNTPOINT);
        return -1;
    }

    if (fs.f_type == CGROUP2_SUPER_MAGIC) {
        return CGROUP_VERSION_2;
    }

    return CGROUP_VERSION_1;
}

/* connect client ops init */
int cgroup_ops_init(void)
{
    (void)memset(&g_cgroup_ops, 0, sizeof(g_cgroup_ops));
    int cgroupVersion = get_cgroup_version_for_init();
    if (cgroupVersion < 0) {
        ERROR("Invalid cgroup version");
        return -1;
    }

    if (cgroupVersion == CGROUP_VERSION_1) {
        return cgroup_v1_ops_init(&g_cgroup_ops);
    } else {
        return cgroup_v2_ops_init(&g_cgroup_ops);
    }
}

int common_get_cgroup_version(void)
{
    if (g_cgroup_ops.get_cgroup_version == NULL) {
        ERROR("Unimplemented get_cgroup_version ops");
        return -1;
    }

    return g_cgroup_ops.get_cgroup_version();
}

int common_get_cgroup_info(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                            cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                            cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                            cgroup_files_info_t *filesinfo, bool quiet)
{
    if (g_cgroup_ops.get_cgroup_info == NULL) {
        ERROR("Unimplemented get_cgroup_info ops");
        return -1;
    }

    return g_cgroup_ops.get_cgroup_info(meminfo, cpuinfo, hugetlbinfo, blkioinfo, cpusetinfo, pidsinfo, filesinfo, quiet);
}

int common_get_cgroup_metrics(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics)
{
    if (g_cgroup_ops.get_cgroup_metrics == NULL) {
        ERROR("Unimplemented get_cgroup_metrics ops");
        return -1;
    }

    return g_cgroup_ops.get_cgroup_metrics(cgroup_path, cgroup_metrics);
}

int common_get_cgroup_mnt_and_root_path(const char *subsystem, char **mountpoint, char **root)
{
    if (g_cgroup_ops.get_cgroup_mnt_and_root_path == NULL) {
        ERROR("Unimplemented get_cgroup_mnt_and_root_path ops");
        return -1;
    }

    return g_cgroup_ops.get_cgroup_mnt_and_root_path(subsystem, mountpoint, root);
}

// only for cgroup v1
char *common_get_init_cgroup_path(const char *subsystem)
{
    if (g_cgroup_ops.get_init_cgroup_path == NULL) {
        ERROR("Unimplemented get_init_cgroup_path ops");
        return NULL;
    }

    return g_cgroup_ops.get_init_cgroup_path(subsystem);
}

char *common_get_own_cgroup_path(const char *subsystem)
{
    if (g_cgroup_ops.get_own_cgroup_path == NULL) {
        ERROR("Unimplemented get_own_cgroup_path ops");
        return NULL;
    }

    return g_cgroup_ops.get_own_cgroup_path(subsystem);
}