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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#define CGROUP_VERSION_1 1
#define CGROUP_VERSION_2 2

#define CGROUP_MOUNTPOINT "/sys/fs/cgroup"
#define CGROUP_ISULAD_PATH CGROUP_MOUNTPOINT"/isulad"

typedef struct {
    bool limit;
    bool swap;
    bool reservation;
    bool oomkilldisable;
    bool swappiness;
    bool kernel;
} cgroup_mem_info_t;

typedef struct {
    bool cpu_rt_period;
    bool cpu_rt_runtime;
    bool cpu_shares;
    bool cpu_cfs_period;
    bool cpu_cfs_quota;
} cgroup_cpu_info_t;

typedef struct {
    bool hugetlblimit;
} cgroup_hugetlb_info_t;

typedef struct {
    bool blkio_weight;
    bool blkio_weight_device;
    bool blkio_read_bps_device;
    bool blkio_write_bps_device;
    bool blkio_read_iops_device;
    bool blkio_write_iops_device;
} cgroup_blkio_info_t;

typedef struct {
    bool cpuset;
    char *cpus;
    char *mems;
} cgroup_cpuset_info_t;

typedef struct {
    bool pidslimit;
} cgroup_pids_info_t;

typedef struct {
    bool fileslimit;
} cgroup_files_info_t;

int get_cgroup_version(void);

int find_cgroup_mountpoint_and_root(const char *subsystem, char **mountpoint, char **root);

int get_cgroup_info_v1(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo, cgroup_hugetlb_info_t *hugetlbinfo,
                       cgroup_blkio_info_t *blkioinfo, cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                       cgroup_files_info_t *filesinfo, bool quiet);

int get_cgroup_info_v2(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo, cgroup_hugetlb_info_t *hugetlbinfo,
                       cgroup_blkio_info_t *blkioinfo, cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                       cgroup_files_info_t *filesinfo, bool quiet);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_COMMON_CGROUP_H
