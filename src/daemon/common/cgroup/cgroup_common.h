/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-03-22
 * Description: provide cgroup common func definition
 ******************************************************************************/
#ifndef DAEMON_COMMON_CGROUP_COMMON_H
#define DAEMON_COMMON_CGROUP_COMMON_H

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

static inline void common_cgroup_do_log(bool quiet, bool do_log, const char *msg)
{
    if (!quiet && do_log) {
        WARN("%s", msg);
    }
}

int get_cgroup_value_helper(const char *path, struct cgfile_t *cgfile, void *result);

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

#define CGROUP_OOM_HANDLE_CONTINUE false
#define CGROUP_OOM_HANDLE_CLOSE true

typedef struct _cgroup_oom_handler_info_t {
    int oom_event_fd;
    int cgroup_file_fd;
    char *name;
    char *cgroup_memory_event_path;
    bool (*oom_event_handler)(int, void *);
} cgroup_oom_handler_info_t;

typedef struct {
    int (*get_cgroup_version)(void);
    int (*get_cgroup_info)(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                            cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                            cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                            cgroup_files_info_t *filesinfo, bool quiet);
    int (*get_cgroup_metrics)(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics);

    int (*get_cgroup_mnt_and_root_path)(const char *subsystem, char **mountpoint, char **root);

    char *(*get_init_cgroup_path)(const char *subsystem);
    char *(*get_own_cgroup_path)(const char *subsystem);

    cgroup_oom_handler_info_t *(*get_cgroup_oom_handler)(int fd, const char *name, const char *cgroup_path, const char *exit_fifo);
} cgroup_ops;

#ifdef __cplusplus
}
#endif

#endif // DAEMON_COMMON_CGROUP_COMMON_H
