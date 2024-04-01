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
 * Description: provide cgroup definition
 ******************************************************************************/
#ifndef DAEMON_COMMON_CGROUP_H
#define DAEMON_COMMON_CGROUP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <isula_libutils/log.h>

#include "cgroup_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int cgroup_ops_init(void);

int common_get_cgroup_version(void);
int common_get_cgroup_info(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                            cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                            cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                            cgroup_files_info_t *filesinfo, bool quiet);
int common_get_cgroup_metrics(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics);
int common_get_cgroup_mnt_and_root_path(const char *subsystem, char **mountpoint, char **root);

// only for cgroup v1
char *common_get_init_cgroup_path(const char *subsystem);
char *common_get_own_cgroup_path(const char *subsystem);

char *common_convert_cgroup_path(const char *cgroup_path);

cgroup_oom_handler_info_t *common_get_cgroup_oom_handler(int fd, const char *name, const char *cgroup_path, const char *exit_fifo);
void common_free_cgroup_oom_handler_info(cgroup_oom_handler_info_t *info);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_COMMON_CGROUP_H
