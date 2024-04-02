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

char *common_convert_cgroup_path(const char *cgroup_path)
{
    char *token = NULL;
    char result[PATH_MAX + 1] = {0};
    __isula_auto_array_t char **arr = NULL;

    if (cgroup_path == NULL) {
        ERROR("Invalid NULL cgroup path");
        return NULL;
    }

    // for systemd cgroup, cgroup_path should have the form slice:prefix:id,
    // convert it to a true path, such as from test-a.slice:isulad:id
    // to test.slice/test-a.slice/isulad-id.scope
    arr = util_string_split_n(cgroup_path, ':', 3);
    if (arr == NULL || util_array_len((const char **)arr) != 3) {
        // not a systemd cgroup, return cgroup path directly
        return util_strdup_s(cgroup_path);
    }

    // for cgroup fs cgroup path, return directly
    if (!util_has_suffix(arr[0], ".slice")) {
        ERROR("Invalid systemd cgroup path: %s", cgroup_path);
        return NULL;
    }

    token = strchr(arr[0], '-');
    while (token != NULL) {
        *token = '\0';
        if (strlen(arr[0]) > PATH_MAX || strlen(result) + 1 + strlen(".slice") >
            PATH_MAX - strlen(arr[0])) {
            ERROR("Invalid systemd cgroup parent: exceeds max length of path");
            *token = '-';
            return NULL;
        }
        if (result[0] != '\0') {
            strcat(result, "/");
        }
        strcat(result, arr[0]);
        strcat(result, ".slice");
        *token = '-';
        token = strchr(token + 1, '-');
    }

    // Add /arr[0]/arr[1]-arr[2].scope, 3 include two slashes and one dash
    if (strlen(cgroup_path) > PATH_MAX || strlen(result) + 3 + strlen(".scope") >
        PATH_MAX - strlen(arr[0] - strlen(arr[1]) - strlen(arr[2]))) {
        ERROR("Invalid systemd cgroup parent: exceeds max length of path");
        return NULL;
    }

    (void)strcat(result, "/");
    (void)strcat(result, arr[0]);
    (void)strcat(result, "/");
    (void)strcat(result, arr[1]);
    (void)strcat(result, "-");
    (void)strcat(result, arr[2]);
    (void)strcat(result, ".scope");

    return util_strdup_s(result);
}

cgroup_oom_handler_info_t *common_get_cgroup_oom_handler(int fd, const char *name, const char *cgroup_path, const char *exit_fifo)
{
    if (g_cgroup_ops.get_cgroup_oom_handler == NULL) {
        ERROR("Unimplmented get_cgroup_oom_handler op");
        return NULL;
    }

    return g_cgroup_ops.get_cgroup_oom_handler(fd, name, cgroup_path, exit_fifo);
}

void common_free_cgroup_oom_handler_info(cgroup_oom_handler_info_t *info)
{
    if (info == NULL) {
        return;
    }

    if (info->oom_event_fd >= 0) {
        close(info->oom_event_fd);
    }
    if (info->cgroup_file_fd >= 0) {
        close(info->cgroup_file_fd);
    }

    free(info->name);
    free(info->cgroup_memory_event_path);
    free(info);
}
