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

#ifdef __cplusplus
extern "C" {
#endif

#define CGROUP_VERSION_1 1
#define CGROUP_VERSION_2 2

#define CGROUP_MOUNTPOINT "/sys/fs/cgroup"
#define CGROUP_ISULAD_PATH CGROUP_MOUNTPOINT"/isulad"

struct cgfile_t {
    char *name;
    char *file;
    char *match;
    int (*get_value)(const char *content, const char *match, void *result);
};

int get_match_value_ull(const char *content, const char *match, void *result);

int common_get_cgroup_version(void);

int common_find_cgroup_mnt_and_root(const char *subsystem, char **mountpoint, char **root);

static inline void common_cgroup_do_log(bool quiet, bool do_log, const char *msg)
{
    if (!quiet && do_log) {
        WARN("%s", msg);
    }
}

typedef struct {
    char **controllers;
    char *mountpoint;
} cgroup_layers_item;

typedef struct {
    cgroup_layers_item **items;
    size_t len;
    size_t cap;
} cgroup_layer_t;

char *common_find_cgroup_subsystem_mountpoint(const cgroup_layer_t *layers, const char *subsystem);

cgroup_layer_t *common_cgroup_layers_find(void);

void common_free_cgroup_layer(cgroup_layer_t *layers);


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

int common_get_cgroup_info_v1(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                              cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                              cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                              cgroup_files_info_t *filesinfo, bool quiet);

int common_get_cgroup_info_v2(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                              cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                              cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                              cgroup_files_info_t *filesinfo, bool quiet);


typedef struct {
    uint64_t cpu_use_nanos;
} cgroup_cpu_metrics_t;

typedef struct {
    uint64_t mem_limit;
    uint64_t mem_used;
    uint64_t total_rss;
    uint64_t total_pgfault;
    uint64_t total_pgmajfault;
    uint64_t total_inactive_file;
} cgroup_mem_metrics_t;

typedef struct {
    uint64_t pid_current;
} cgroup_pids_metrics_t;

typedef struct {
    cgroup_cpu_metrics_t cgcpu_metrics;
    cgroup_mem_metrics_t cgmem_metrics;
    cgroup_pids_metrics_t cgpids_metrics;
} cgroup_metrics_t;

int common_get_cgroup_v1_metrics(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics);
int common_get_cgroup_v2_metrics(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics);

char *common_get_init_cgroup(const char *subsystem);

char *common_get_own_cgroup(const char *subsystem);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_COMMON_CGROUP_H
