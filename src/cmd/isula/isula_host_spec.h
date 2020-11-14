/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-09-28
 * Description: provide generate host spec in client
 ******************************************************************************/
#ifndef CMD_ISULA_GENERATE_HOST_SPEC_H
#define CMD_ISULA_GENERATE_HOST_SPEC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "isula_libutils/json_common.h"
#include "isula_libutils/mount_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct container_cgroup_resources {
    uint16_t blkio_weight;
    int64_t cpu_shares;
    int64_t cpu_period;
    int64_t cpu_quota;
    int64_t cpu_realtime_period;
    int64_t cpu_realtime_runtime;
    char *cpuset_cpus;
    char *cpuset_mems;
    int64_t memory;
    int64_t memory_swap;
    int64_t memory_reservation;
    int64_t kernel_memory;
    int64_t pids_limit;
    int64_t files_limit;
    int64_t oom_score_adj;
    int64_t swappiness;
    int64_t nano_cpus;
} container_cgroup_resources_t;

typedef struct isula_host_config {
    char **devices;
    size_t devices_len;

    char **hugetlbs;
    size_t hugetlbs_len;

    char **group_add;
    size_t group_add_len;

    char *network_mode;

    char *ipc_mode;

    char *pid_mode;

    char *uts_mode;

    char *userns_mode;

    char *user_remap;

    char **ulimits;
    size_t ulimits_len;

    char *restart_policy;

    char *host_channel;

    char **cap_add;
    size_t cap_add_len;

    char **cap_drop;
    size_t cap_drop_len;

    json_map_string_string *storage_opts;

    json_map_string_string *sysctls;

    char **dns;
    size_t dns_len;

    char **dns_options;
    size_t dns_options_len;

    char **dns_search;
    size_t dns_search_len;

    char **extra_hosts;
    size_t extra_hosts_len;

    char *hook_spec;

    char **volumes_from;
    size_t volumes_from_len;

    char **binds;
    size_t binds_len;

    mount_spec **mounts;
    size_t mounts_len;

    char **blkio_weight_device;
    size_t blkio_weight_device_len;

    char **blkio_throttle_read_bps_device;
    size_t blkio_throttle_read_bps_device_len;

    char **blkio_throttle_write_bps_device;
    size_t blkio_throttle_write_bps_device_len;

    char **blkio_throttle_read_iops_device;
    size_t blkio_throttle_read_iops_device_len;

    char **blkio_throttle_write_iops_device;
    size_t blkio_throttle_write_iops_device_len;

    char **device_cgroup_rules;
    size_t device_cgroup_rules_len;

    bool privileged;
    bool system_container;
    char **ns_change_files;
    size_t ns_change_files_len;
    bool auto_remove;

    bool oom_kill_disable;

    int64_t shm_size;

    bool readonly_rootfs;

    char *env_target_file;

    char *cgroup_parent;

    container_cgroup_resources_t *cr;

    char **security;
    size_t security_len;
} isula_host_config_t;

int generate_hostconfig(const isula_host_config_t *srcconfig, char **hostconfigstr);
void isula_host_config_free(isula_host_config_t *hostconfig);

void isula_ns_change_files_free(isula_host_config_t *hostconfig);

void isula_host_config_storage_opts_free(isula_host_config_t *hostconfig);

void isula_host_config_sysctl_free(isula_host_config_t *hostconfig);

#ifdef __cplusplus
}
#endif

#endif
