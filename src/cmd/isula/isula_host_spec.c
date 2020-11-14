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
#include "isula_host_spec.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/docker_seccomp.h>
#include <isula_libutils/json_common.h>
#include <limits.h>
#include <stdint.h>
#include <strings.h>

#include "isula_libutils/log.h"
#include "isula_libutils/host_config.h"
#include "utils.h"
#include "isula_libutils/parse_common.h"
#include "path.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"
#include "opt_ulimit.h"

static bool parse_restart_policy(const char *policy, host_config_restart_policy **rp)
{
    bool ret = false;
    char *dup = NULL;
    char *dotpos = NULL;

    if (rp == NULL || policy == NULL) {
        return true;
    }

    dup = util_strdup_s(policy);

    *rp = util_common_calloc_s(sizeof(host_config_restart_policy));
    if (*rp == NULL) {
        ERROR("Restart policy: Out of memory");
        goto cleanup;
    }

    dotpos = strchr(dup, ':');
    if (dotpos != NULL) {
        int nret;
        *dotpos++ = '\0';
        if (strchr(dotpos, ':') != NULL) {
            COMMAND_ERROR("Invalid restart policy format");
            goto cleanup;
        }
        nret = util_safe_int(dotpos, &(*rp)->maximum_retry_count);
        if (nret != 0) {
            COMMAND_ERROR("Maximum retry count must be an integer: %s", strerror(-nret));
            goto cleanup;
        }
    }

    (*rp)->name = util_strdup_s(dup);
    ret = true;
cleanup:
    free(dup);
    return ret;
}

static int pack_host_config_ns_change_files(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    if (util_dup_array_of_strings((const char **)srcconfig->ns_change_files, srcconfig->ns_change_files_len,
                                  &dstconfig->ns_change_files, &dstconfig->ns_change_files_len) != 0) {
        COMMAND_ERROR("Failed to dup ns change files");
        return -1;
    }

    return 0;
}

static int pack_host_config_cap_add(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    /* cap-add */
    if (util_dup_array_of_strings((const char **)srcconfig->cap_add, srcconfig->cap_add_len, &dstconfig->cap_add,
                                  &dstconfig->cap_add_len) != 0) {
        COMMAND_ERROR("Failed to dup cap add");
        return -1;
    }

    for (i = 0; i < dstconfig->cap_add_len; i++) {
        // skip `all`
        if (strcasecmp(dstconfig->cap_add[i], "all") == 0) {
            continue;
        }

        if (!util_valid_cap(dstconfig->cap_add[i])) {
            COMMAND_ERROR("Unknown capability to add: '%s'", dstconfig->cap_add[i]);
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int pack_host_config_cap_drop(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    /* cap-drops */
    if (util_dup_array_of_strings((const char **)srcconfig->cap_drop, srcconfig->cap_drop_len, &dstconfig->cap_drop,
                                  &dstconfig->cap_drop_len) != 0) {
        COMMAND_ERROR("Failed to dup cap drop");
        return -1;
    }

    for (i = 0; i < dstconfig->cap_drop_len; i++) {
        // skip `all`
        if (strcasecmp(dstconfig->cap_drop[i], "all") == 0) {
            continue;
        }

        if (!util_valid_cap(dstconfig->cap_drop[i])) {
            COMMAND_ERROR("Unknown capability to drop: '%s'", dstconfig->cap_drop[i]);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int pack_host_config_caps(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    ret = pack_host_config_cap_add(dstconfig, srcconfig);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = pack_host_config_cap_drop(dstconfig, srcconfig);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int pack_host_network_extra_hosts(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    /* extra hosts */
    if (util_dup_array_of_strings((const char **)srcconfig->extra_hosts, srcconfig->extra_hosts_len,
                                  &dstconfig->extra_hosts, &dstconfig->extra_hosts_len) != 0) {
        COMMAND_ERROR("Failed to dup extra hosts");
        return -1;
    }

    return 0;
}

static int pack_host_network_dns(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    if (util_dup_array_of_strings((const char **)srcconfig->dns, srcconfig->dns_len, &dstconfig->dns,
                                  &dstconfig->dns_len) != 0) {
        COMMAND_ERROR("Failed to dup dns");
        return -1;
    }

    if (util_dup_array_of_strings((const char **)srcconfig->dns_options, srcconfig->dns_options_len,
                                  &dstconfig->dns_options, &dstconfig->dns_options_len) != 0) {
        COMMAND_ERROR("Failed to dup dns options");
        return -1;
    }

    if (util_dup_array_of_strings((const char **)srcconfig->dns_search, srcconfig->dns_search_len,
                                  &dstconfig->dns_search, &dstconfig->dns_search_len) != 0) {
        COMMAND_ERROR("Failed to dup dns search");
        return -1;
    }

    return 0;
}

static int pack_host_config_network(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    ret = pack_host_network_extra_hosts(dstconfig, srcconfig);
    if (ret != 0) {
        goto out;
    }

    ret = pack_host_network_dns(dstconfig, srcconfig);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

static int check_parsed_device(const host_config_devices_element *device_map)
{
    int ret = 0;

    if (device_map->path_on_host == NULL || device_map->path_in_container == NULL ||
        device_map->cgroup_permissions == NULL) {
        ret = -1;
        goto out;
    }

    if (!util_file_exists(device_map->path_on_host)) {
        COMMAND_ERROR("Error gathering device information while adding device \"%s\",stat %s:no such file or directory",
                      device_map->path_on_host, device_map->path_on_host);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static host_config_devices_element *parse_device(const char *devices)
{
    char **tmp_str = NULL;
    size_t tmp_str_len = 0;
    host_config_devices_element *device_map = NULL;

    if (devices == NULL || !strcmp(devices, "")) {
        ERROR("devices can't be empty");
        return NULL;
    }

    device_map = util_common_calloc_s(sizeof(host_config_devices_element));
    if (device_map == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    tmp_str = util_string_split(devices, ':');
    tmp_str_len = util_array_len((const char **)tmp_str);

    switch (tmp_str_len) {
        case 3:
            device_map->path_on_host = util_strdup_s(tmp_str[0]);
            device_map->path_in_container = util_strdup_s(tmp_str[1]);
            if (util_valid_device_mode(tmp_str[2])) {
                device_map->cgroup_permissions = util_strdup_s(tmp_str[2]);
            }
            break;
        case 2:
            device_map->path_on_host = util_strdup_s(tmp_str[0]);
            if (util_valid_device_mode(tmp_str[1])) {
                device_map->path_in_container = util_strdup_s(tmp_str[0]);
                device_map->cgroup_permissions = util_strdup_s(tmp_str[1]);
            } else {
                device_map->path_in_container = util_strdup_s(tmp_str[1]);
                device_map->cgroup_permissions = util_strdup_s("rwm");
            }
            break;
        case 1:
            device_map->path_on_host = util_strdup_s(tmp_str[0]);
            device_map->path_in_container = util_strdup_s(tmp_str[0]);
            device_map->cgroup_permissions = util_strdup_s("rwm");
            break;
        default:
            ERROR("Invalid parament %s", devices);
            break;
    }

    util_free_array(tmp_str);

    if (check_parsed_device(device_map) != 0) {
        goto erro_out;
    }

    return device_map;

erro_out:
    free_host_config_devices_element(device_map);
    return NULL;
}

static void pack_cgroup_resources_cpu(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    /* cgroup blkio weight */
    if (srcconfig->cr->blkio_weight) {
        dstconfig->blkio_weight = srcconfig->cr->blkio_weight;
    }

    /* cpus */
    if (srcconfig->cr->nano_cpus != 0) {
        dstconfig->nano_cpus = srcconfig->cr->nano_cpus;
    }

    /* cpu shares */
    if (srcconfig->cr->cpu_shares) {
        dstconfig->cpu_shares = srcconfig->cr->cpu_shares;
    }

    /* cpu period */
    if (srcconfig->cr->cpu_period) {
        dstconfig->cpu_period = srcconfig->cr->cpu_period;
    }

    /* cpu quota */
    if (srcconfig->cr->cpu_quota) {
        dstconfig->cpu_quota = srcconfig->cr->cpu_quota;
    }

    /* cpuset-cpus */
    if (util_valid_str(srcconfig->cr->cpuset_cpus)) {
        dstconfig->cpuset_cpus = util_strdup_s(srcconfig->cr->cpuset_cpus);
    }

    /* cpuset mems */
    if (util_valid_str(srcconfig->cr->cpuset_mems)) {
        dstconfig->cpuset_mems = util_strdup_s(srcconfig->cr->cpuset_mems);
    }

    if (srcconfig->cr->cpu_realtime_period) {
        dstconfig->cpu_realtime_period = srcconfig->cr->cpu_realtime_period;
    }

    if (srcconfig->cr->cpu_realtime_runtime) {
        dstconfig->cpu_realtime_runtime = srcconfig->cr->cpu_realtime_runtime;
    }
}

static void pack_cgroup_resources_mem(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    /* memory limit */
    if (srcconfig->cr->memory) {
        dstconfig->memory = srcconfig->cr->memory;
    }

    /* memory swap */
    if (srcconfig->cr->memory_swap) {
        dstconfig->memory_swap = srcconfig->cr->memory_swap;
    }

    /* memory reservation */
    if (srcconfig->cr->memory_reservation) {
        dstconfig->memory_reservation = srcconfig->cr->memory_reservation;
    }

    /* kernel memory limit */
    if (srcconfig->cr->kernel_memory) {
        dstconfig->kernel_memory = srcconfig->cr->kernel_memory;
    }

    // swappiness
    if (srcconfig->cr->swappiness != -1) {
        dstconfig->memory_swappiness = util_common_calloc_s(sizeof(uint64_t));
        if (dstconfig->memory_swappiness != NULL) {
            *(dstconfig->memory_swappiness) = (uint64_t)(srcconfig->cr->swappiness);
        }
    }
}

static void pack_cgroup_resources(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    pack_cgroup_resources_cpu(dstconfig, srcconfig);

    pack_cgroup_resources_mem(dstconfig, srcconfig);

    /* cgroup limit */
    dstconfig->pids_limit = srcconfig->cr->pids_limit;
    dstconfig->files_limit = srcconfig->cr->files_limit;

    /* oom score adj */
    dstconfig->oom_score_adj = (int)srcconfig->cr->oom_score_adj;
}

static int pack_hostconfig_ulimits(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i;

    if (srcconfig->ulimits == NULL || srcconfig->ulimits_len == 0) {
        goto out;
    }

    if (srcconfig->ulimits_len > SIZE_MAX / sizeof(host_config_ulimits_element *)) {
        COMMAND_ERROR("Too many ulimit elements in host config");
        ret = -1;
        goto out;
    }
    dstconfig->ulimits = util_common_calloc_s(srcconfig->ulimits_len * sizeof(host_config_ulimits_element *));
    if (dstconfig->ulimits == NULL) {
        COMMAND_ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->ulimits_len; i++) {
        size_t j;
        bool exists = false;
        host_config_ulimits_element *tmp = NULL;

        tmp = parse_opt_ulimit(srcconfig->ulimits[i]);
        if (tmp == NULL) {
            ret = -1;
            goto out;
        }
        for (j = 0; j < dstconfig->ulimits_len; j++) {
            if (strcmp(dstconfig->ulimits[j]->name, tmp->name) == 0) {
                exists = true;
                break;
            }
        }
        if (exists) {
            free_host_config_ulimits_element(dstconfig->ulimits[j]);
            dstconfig->ulimits[j] = tmp;
        } else {
            dstconfig->ulimits[dstconfig->ulimits_len] = tmp;
            dstconfig->ulimits_len++;
        }
    }
out:
    return ret;
}

static int pack_hostconfig_cgroup(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    if (srcconfig->cr != NULL) {
        pack_cgroup_resources(dstconfig, srcconfig);
    }

    ret = pack_hostconfig_ulimits(dstconfig, srcconfig);

    return ret;
}

static defs_blkio_weight_device *pack_blkio_weight_devices(const char *devices)
{
    char **tmp_str = NULL;
    unsigned int weight = 0;
    size_t tmp_str_len = 0;
    defs_blkio_weight_device *weight_dev = NULL;

    if (devices == NULL || !strcmp(devices, "")) {
        COMMAND_ERROR("Weight devices can't be empty");
        return NULL;
    }

    weight_dev = util_common_calloc_s(sizeof(defs_blkio_weight_device));
    if (weight_dev == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    tmp_str = util_string_split(devices, ':');
    if (tmp_str == NULL) {
        COMMAND_ERROR("String split failed");
        goto erro_out;
    }
    tmp_str_len = util_array_len((const char **)tmp_str);

    if (tmp_str_len != 2) {
        COMMAND_ERROR("Bad blkio weight device format: %s", devices);
        goto erro_out;
    }

    if (strncmp("/dev/", tmp_str[0], strlen("/dev/")) != 0) {
        COMMAND_ERROR("Bad format for device path: %s", devices);
        goto erro_out;
    }

    if (util_safe_uint(tmp_str[1], &weight)) {
        COMMAND_ERROR("Invalid weight for device: %s", devices);
        goto erro_out;
    }

    if (weight > 0 && (weight < 10 || weight > 1000)) {
        COMMAND_ERROR("Invalid weight for device: %s", devices);
        goto erro_out;
    }

    weight_dev->path = util_strdup_s(tmp_str[0]);

    weight_dev->weight = (uint16_t)weight;
    util_free_array(tmp_str);

    return weight_dev;

erro_out:
    util_free_array(tmp_str);
    free_defs_blkio_weight_device(weight_dev);
    return NULL;
}

static int parse_blkio_throttle_bps_device(const char *device, char **path, uint64_t *rate)
{
    int ret = 0;
    char **split = NULL;

    split = util_string_split_multi(device, ':');
    if (split == NULL || util_array_len((const char **)split) != 2) {
        COMMAND_ERROR("bad format: %s", device);
        ret = -1;
        goto out;
    }

    if (strncmp(split[0], "/dev/", strlen("/dev/")) != 0) {
        COMMAND_ERROR("bad format for device path: %s", device);
        ret = -1;
        goto out;
    }

    if (util_parse_byte_size_string(split[1], (int64_t *)rate) != 0) {
        COMMAND_ERROR("invalid rate for device: %s. The correct format is <device-path>:<number>[<unit>]."
                      " Number must be a positive integer. Unit is optional and can be kb, mb, or gb",
                      device);
        ret = -1;
        goto out;
    }
    *path = util_strdup_s(split[0]);

out:
    util_free_array(split);
    return ret;
}

// validate that the specified string has a valid device-rate format.
static defs_blkio_device *pack_throttle_bps_device(const char *device)
{
    char *path = NULL;
    uint64_t rate = 0;
    defs_blkio_device *bps_dev = NULL;

    if (device == NULL || !strcmp(device, "")) {
        COMMAND_ERROR("blkio throttle read bps device can't be empty");
        return NULL;
    }

    bps_dev = util_common_calloc_s(sizeof(defs_blkio_device));
    if (bps_dev == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (parse_blkio_throttle_bps_device(device, &path, &rate) != 0) {
        goto error_out;
    }

    bps_dev->path = path;
    bps_dev->rate = rate;

    return bps_dev;

error_out:
    free(path);
    free_defs_blkio_device(bps_dev);
    return NULL;
}

static int parse_blkio_throttle_iops_device(const char *device, char **path, uint64_t *rate)
{
    int ret = 0;
    char **split = NULL;

    split = util_string_split_multi(device, ':');
    if (split == NULL || util_array_len((const char **)split) != 2) {
        COMMAND_ERROR("bad format: %s", device);
        ret = -1;
        goto out;
    }

    if (strncmp(split[0], "/dev/", strlen("/dev/")) != 0) {
        COMMAND_ERROR("bad format for device path: %s", device);
        ret = -1;
        goto out;
    }

    if (!util_valid_positive_interger(split[1])) {
        COMMAND_ERROR("invalid rate for device: %s. The correct format is <device-path>:<number>."
                      " Number must be unsigned 64 bytes integer.",
                      device);
        ret = -1;
        goto out;
    }

    if (util_safe_uint64(split[1], rate) != 0) {
        COMMAND_ERROR("invalid rate for device: %s. The correct format is <device-path>:<number>."
                      " Number must be unsigned 64 bytes integer.",
                      device);
        ret = -1;
        goto out;
    }

    *path = util_strdup_s(split[0]);

out:
    util_free_array(split);
    return ret;
}

// validate that the specified string has a valid device-rate format.
static defs_blkio_device *pack_throttle_iops_device(const char *device)
{
    char *path = NULL;
    uint64_t rate = 0;
    defs_blkio_device *iops_dev = NULL;

    if (device == NULL || !strcmp(device, "")) {
        COMMAND_ERROR("blkio throttle read bps device can't be empty");
        return NULL;
    }

    iops_dev = util_common_calloc_s(sizeof(defs_blkio_device));
    if (iops_dev == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (parse_blkio_throttle_iops_device(device, &path, &rate) != 0) {
        goto error_out;
    }

    iops_dev->path = path;
    iops_dev->rate = rate;

    return iops_dev;

error_out:
    free(path);
    free_defs_blkio_device(iops_dev);
    return NULL;
}

static int split_hugetlb_limit(char *temp, char **pagesize, char **limit_value)
{
    int ret = 0;
    char *saveptr = NULL;

    if (strchr(temp, ':') == NULL) {
        *limit_value = temp;
        goto out;
    } else if (temp[0] != ':') {
        *pagesize = strtok_r(temp, ":", &saveptr);
        if ((*pagesize) == NULL) {
            ret = -1;
            goto out;
        }
        *limit_value = strtok_r(NULL, ":", &saveptr);
        if ((*limit_value) == NULL) {
            ret = -1;
            goto out;
        }
    } else {
        *limit_value = strtok_r(temp, ":", &saveptr);
        if ((*limit_value) == NULL) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static host_config_hugetlbs_element *pase_hugetlb_limit(const char *input)
{
    int ret;
    char *temp = NULL;
    char *pagesize = NULL;
    char *limit_value = NULL;
    char *trans_page = NULL;
    uint64_t limit = 0;
    uint64_t page = 0;
    host_config_hugetlbs_element *limit_element = NULL;

    temp = util_strdup_s(input);
    if (temp == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    ret = split_hugetlb_limit(temp, &pagesize, &limit_value);
    if (ret != 0) {
        goto free_out;
    }

    ret = util_parse_byte_size_string(limit_value, (int64_t *)(&limit));
    if (ret != 0) {
        COMMAND_ERROR("Parse limit value: %s failed:%s", limit_value, strerror(-ret));
        goto free_out;
    }

    if (pagesize != NULL) {
        ret = util_parse_byte_size_string(pagesize, (int64_t *)(&page));
        if (ret != 0) {
            COMMAND_ERROR("Parse pagesize error.Invalid hugepage size: %s: %s", pagesize, strerror(-ret));
            goto free_out;
        }

        trans_page = util_human_size(page);
        if (trans_page == NULL) {
            COMMAND_ERROR("Failed to translate page size");
            goto free_out;
        }
    }

    limit_element = util_common_calloc_s(sizeof(host_config_hugetlbs_element));
    if (limit_element == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    limit_element->limit = limit;
    limit_element->page_size = trans_page ? util_strdup_s(trans_page) : util_strdup_s("");

free_out:
    free(temp);
    free(trans_page);

    return limit_element;
}

uint64_t get_proc_mem_size(const char *item)
{
    uint64_t sysmem_limit = 0;
    FILE *fp = NULL;
    size_t len = 0;
    char *line = NULL;
    char *p = NULL;

    fp = util_fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        ERROR("Failed to open /proc/meminfo: %s", strerror(errno));
        return sysmem_limit;
    }

    while (getline(&line, &len, fp) != -1) {
        p = strchr(line, ' ');
        if (p == NULL) {
            goto out;
        }
        *p = '\0';
        p++;
        if (strcmp(line, item) == 0) {
            while (*p == ' ' || *p == '\t') {
                p++;
            }
            if (*p == '\0') {
                goto out;
            }
            sysmem_limit = strtoull(p, NULL, 0);
            break;
        }
    }

out:
    fclose(fp);
    free(line);
    return sysmem_limit * SIZE_KB;
}

static bool parse_host_path(const char *input, const char *token, host_config_host_channel *host_channel)
{
    char real_path[PATH_MAX] = { 0 };

    if (strcmp(token, "") == 0) {
        COMMAND_ERROR("Bad host channel format: %s", input);
        return false;
    }
    if (token[0] != '/') {
        COMMAND_ERROR("Host channel host path should be absolute: %s", token);
        return false;
    }
    if (util_clean_path(token, real_path, sizeof(real_path)) == NULL) {
        ERROR("Failed to clean path: '%s'", token);
        return false;
    }
    if (util_dir_exists(real_path)) {
        COMMAND_ERROR("Host path '%s' already exists", real_path);
        return false;
    }
    host_channel->path_on_host = util_strdup_s(real_path);
    return true;
}

static bool parse_container_path(const char *input, const char *token, host_config_host_channel *host_channel)
{
    char real_path[PATH_MAX] = { 0 };

    if (strcmp(token, "") == 0) {
        COMMAND_ERROR("Bad host channel format: %s", input);
        return false;
    }
    if (token[0] != '/') {
        COMMAND_ERROR("Host channel container path should be absolute: %s", token);
        return false;
    }
    if (util_clean_path(token, real_path, sizeof(real_path)) == NULL) {
        ERROR("Failed to clean path: '%s'", token);
        return false;
    }
    host_channel->path_in_container = util_strdup_s(real_path);
    return true;
}

static bool parse_mode(const char *input, const char *token, host_config_host_channel *host_channel)
{
    if (strcmp(token, "") == 0) {
        host_channel->permissions = util_strdup_s("rw");
        return true;
    }
    if (!util_valid_mount_mode(token)) {
        COMMAND_ERROR("Invalid mount mode for host channel: %s", input);
        return false;
    }
    host_channel->permissions = util_strdup_s(token);
    return true;
}

static bool parse_size(const char *input, const char *token, host_config_host_channel *host_channel)
{
    uint64_t size = 0;
    uint64_t mem_total_size = 0;
    uint64_t mem_available_size = 0;

    if (strcmp(token, "") == 0) {
        host_channel->size = 64 * SIZE_MB;
        return true;
    }
    if (util_parse_byte_size_string(token, (int64_t *)(&size))) {
        COMMAND_ERROR("Invalid size limit for host channel: %s", input);
        return false;
    }
    if (size < HOST_CHANNLE_MIN_SIZE) {
        COMMAND_ERROR("Invalid size, larger than 4KB is allowed");
        return false;
    }
    mem_total_size = get_proc_mem_size("MemTotal:");
    if (size > mem_total_size / 2) {
        COMMAND_ERROR("Required host channel size %llu is larger than half of total memory %llu",
                      (unsigned long long)size, (unsigned long long)mem_total_size);
        return false;
    }
    mem_available_size = get_proc_mem_size("MemAvailable:");
    if (size > mem_available_size) {
        COMMAND_ERROR("Required host channel size %llu is larger than available memory %llu", (unsigned long long)size,
                      (unsigned long long)mem_available_size);
        return false;
    }
    host_channel->size = size;
    return true;
}

host_config_host_channel *parse_host_channel(const char *input)
{
    int count = 0;
    char *tmp_str = NULL;
    char *save_ptr = NULL;
    char *token = NULL;
    host_config_host_channel *host_channel = NULL;

    host_channel = util_common_calloc_s(sizeof(host_config_host_channel));
    if (host_channel == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    tmp_str = util_strdup_s(input);
    save_ptr = tmp_str;
    token = util_str_token(&tmp_str, ":");
    while (token != NULL) {
        count++;
        if (count > 4) {
            COMMAND_ERROR("Bad host channel format: %s", input);
            goto erro_out;
        }
        switch (count) {
            case 1:
                if (!parse_host_path(input, token, host_channel)) {
                    goto erro_out;
                }
                break;
            case 2:
                if (!parse_container_path(input, token, host_channel)) {
                    goto erro_out;
                }
                break;
            case 3:
                if (!parse_mode(input, token, host_channel)) {
                    goto erro_out;
                }
                break;
            case 4:
                if (!parse_size(input, token, host_channel)) {
                    goto erro_out;
                }
                break;
            default:
                break;
        }
        free(token);
        token = util_str_token(&tmp_str, ":");
    }
    if (count < 4) {
        COMMAND_ERROR("Bad host channel format: %s", input);
        goto erro_out;
    }
    free(save_ptr);
    return host_channel;

erro_out:
    free(token);
    free(save_ptr);
    free_host_config_host_channel(host_channel);
    return NULL;
}
static int append_no_new_privileges_to_security_opts(host_config *dstconfig)
{
    dstconfig->security_opt[dstconfig->security_opt_len] = util_strdup_s("no-new-privileges");
    dstconfig->security_opt_len++;

    return 0;
}

static int append_seccomp_to_security_opts(const char *full_opt, const char *seccomp_file, host_config *dstconfig)
{
    int ret = 0;
    int nret = 0;
    size_t size = 0;
    char *seccomp_json = NULL;
    char *tmp_str = NULL;
    docker_seccomp *seccomp_spec = NULL;
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };

    if (strcmp(seccomp_file, "unconfined") == 0) {
        dstconfig->security_opt[dstconfig->security_opt_len] = util_strdup_s(full_opt);
        dstconfig->security_opt_len++;
        return 0;
    }

    seccomp_spec = get_seccomp_security_opt_spec(seccomp_file);
    if (seccomp_spec == NULL) {
        ERROR("Failed to parse docker format seccomp specification file \"%s\", error message: %s", seccomp_file, err);
        COMMAND_ERROR("failed to parse seccomp file: %s", seccomp_file);
        ret = -1;
        goto out;
    }

    seccomp_json = docker_seccomp_generate_json(seccomp_spec, &ctx, &err);
    if (seccomp_json == NULL) {
        COMMAND_ERROR("failed to generate seccomp json!");
        ret = -1;
        goto out;
    }

    if (strlen(seccomp_json) > (SIZE_MAX - strlen("seccomp=")) - 1) {
        COMMAND_ERROR("seccomp json is too big!");
        ret = -1;
        goto out;
    }
    size = strlen("seccomp=") + strlen(seccomp_json) + 1;
    tmp_str = util_common_calloc_s(size);
    if (tmp_str == NULL) {
        COMMAND_ERROR("out of memory");
        ret = -1;
        goto out;
    }
    nret = snprintf(tmp_str, size, "seccomp=%s", seccomp_json);
    if (nret < 0 || nret >= size) {
        COMMAND_ERROR("failed to sprintf buffer!");
        ret = -1;
        goto out;
    }
    dstconfig->security_opt[dstconfig->security_opt_len] = util_strdup_s(tmp_str);
    dstconfig->security_opt_len++;

out:
    free(seccomp_json);
    free(tmp_str);
    free_docker_seccomp(seccomp_spec);
    free(err);

    return ret;
}

#ifdef ENABLE_SELINUX
static int append_selinux_label_to_security_opts(const char *selinux_label, host_config *dstconfig)
{
    dstconfig->security_opt[dstconfig->security_opt_len] = util_strdup_s(selinux_label);
    dstconfig->security_opt_len++;

    return 0;
}
#endif

static int parse_security_opts(const isula_host_config_t *srcconfig, host_config *dstconfig)
{
    int ret = 0;
    size_t i;
    char **items = NULL;

    for (i = 0; i < srcconfig->security_len; i++) {
        items = util_string_split_n(srcconfig->security[i], '=', 2);
        if (util_array_len((const char **)items) == 1) {
            if (strcmp(items[0], "no-new-privileges") != 0) {
                ret = -1;
            } else {
                ret = append_no_new_privileges_to_security_opts(dstconfig);
            }
        } else {
            if (strcmp(items[0], "seccomp") == 0) {
                ret = append_seccomp_to_security_opts(srcconfig->security[i], items[1], dstconfig);
#ifdef ENABLE_SELINUX
            } else if (strcmp(items[0], "label") == 0) {
                ret = append_selinux_label_to_security_opts(srcconfig->security[i], dstconfig);
#endif
            } else {
                ret = -1;
            }
        }

        if (ret != 0) {
            COMMAND_ERROR("Invalid --security-opt: %s", srcconfig->security[i]);
            ret = -1;
            goto out;
        }

        util_free_array(items);
        items = NULL;
    }

out:
    util_free_array(items);
    return ret;
}

int generate_storage_opts(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    if (srcconfig->storage_opts == NULL) {
        goto out;
    }

    dstconfig->storage_opt = util_common_calloc_s(sizeof(json_map_string_string));
    if (dstconfig->storage_opt == NULL) {
        ret = -1;
        goto out;
    }

    if (dup_json_map_string_string(srcconfig->storage_opts, dstconfig->storage_opt) != 0) {
        COMMAND_ERROR("Failed to dup storage opts");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int generate_sysctls(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    if (srcconfig->sysctls == NULL) {
        goto out;
    }

    dstconfig->sysctls = util_common_calloc_s(sizeof(json_map_string_string));
    if (dstconfig->sysctls == NULL) {
        ret = -1;
        goto out;
    }

    if (dup_json_map_string_string(srcconfig->sysctls, dstconfig->sysctls) != 0) {
        COMMAND_ERROR("Failed to dup sysctls");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int generate_devices(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->devices == NULL || srcconfig->devices_len == 0) {
        goto out;
    }

    if (srcconfig->devices_len > SIZE_MAX / sizeof(host_config_devices_element *)) {
        ERROR("Too many devices to be populated into container");
        ret = -1;
        goto out;
    }
    dstconfig->devices = util_common_calloc_s(sizeof(host_config_devices_element *) * srcconfig->devices_len);
    if (dstconfig->devices == NULL) {
        ret = -1;
        goto out;
    }
    for (i = 0; i < srcconfig->devices_len; i++) {
        dstconfig->devices[i] = parse_device(srcconfig->devices[i]);
        if (dstconfig->devices[i] == NULL) {
            ERROR("Failed to parse devices:%s", srcconfig->devices[i]);
            ret = -1;
            goto out;
        }

        dstconfig->devices_len++;
    }
out:
    return ret;
}

static int generate_blkio_weight_device(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->blkio_weight_device == NULL || srcconfig->blkio_weight_device_len == 0) {
        goto out;
    }

    dstconfig->blkio_weight_device =
        util_smart_calloc_s(sizeof(defs_blkio_weight_device *), srcconfig->blkio_weight_device_len);
    if (dstconfig->blkio_weight_device == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_weight_device_len; i++) {
        dstconfig->blkio_weight_device[dstconfig->blkio_weight_device_len] =
            pack_blkio_weight_devices(srcconfig->blkio_weight_device[i]);
        if (dstconfig->blkio_weight_device[dstconfig->blkio_weight_device_len] == NULL) {
            ERROR("Failed to get blkio weight devies");
            ret = -1;
            goto out;
        }

        dstconfig->blkio_weight_device_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_read_bps_device(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->blkio_throttle_read_bps_device == NULL || srcconfig->blkio_throttle_read_bps_device_len == 0) {
        goto out;
    }

    dstconfig->blkio_device_read_bps =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_read_bps_device_len);
    if (dstconfig->blkio_device_read_bps == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_read_bps_device_len; i++) {
        dstconfig->blkio_device_read_bps[dstconfig->blkio_device_read_bps_len] =
            pack_throttle_bps_device(srcconfig->blkio_throttle_read_bps_device[i]);
        if (dstconfig->blkio_device_read_bps[dstconfig->blkio_device_read_bps_len] == NULL) {
            ERROR("Failed to get blkio throttle read bps devices");
            ret = -1;
            goto out;
        }

        dstconfig->blkio_device_read_bps_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_write_bps_device(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->blkio_throttle_write_bps_device == NULL || srcconfig->blkio_throttle_write_bps_device_len == 0) {
        goto out;
    }

    dstconfig->blkio_device_write_bps =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_write_bps_device_len);
    if (dstconfig->blkio_device_write_bps == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_write_bps_device_len; i++) {
        dstconfig->blkio_device_write_bps[dstconfig->blkio_device_write_bps_len] =
            pack_throttle_bps_device(srcconfig->blkio_throttle_write_bps_device[i]);
        if (dstconfig->blkio_device_write_bps[dstconfig->blkio_device_write_bps_len] == NULL) {
            ERROR("Failed to get blkio throttle write bps devices");
            ret = -1;
            goto out;
        }

        dstconfig->blkio_device_write_bps_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_read_iops_device(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->blkio_throttle_read_iops_device == NULL || srcconfig->blkio_throttle_read_iops_device_len == 0) {
        goto out;
    }

    dstconfig->blkio_device_read_iops =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_read_iops_device_len);
    if (dstconfig->blkio_device_read_iops == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_read_iops_device_len; i++) {
        dstconfig->blkio_device_read_iops[dstconfig->blkio_device_read_iops_len] =
            pack_throttle_iops_device(srcconfig->blkio_throttle_read_iops_device[i]);
        if (dstconfig->blkio_device_read_iops[dstconfig->blkio_device_read_iops_len] == NULL) {
            ERROR("Failed to get blkio throttle read iops devices");
            ret = -1;
            goto out;
        }

        dstconfig->blkio_device_read_iops_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_write_iops_device(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->blkio_throttle_write_iops_device == NULL || srcconfig->blkio_throttle_write_iops_device_len == 0) {
        goto out;
    }

    dstconfig->blkio_device_write_iops =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_write_iops_device_len);
    if (dstconfig->blkio_device_write_iops == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_write_iops_device_len; i++) {
        dstconfig->blkio_device_write_iops[dstconfig->blkio_device_write_iops_len] =
            pack_throttle_iops_device(srcconfig->blkio_throttle_write_iops_device[i]);
        if (dstconfig->blkio_device_write_iops[dstconfig->blkio_device_write_iops_len] == NULL) {
            ERROR("Failed to get blkio throttle write iops devices");
            ret = -1;
            goto out;
        }

        dstconfig->blkio_device_write_iops_len++;
    }
out:
    return ret;
}

static int generate_blkio(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret;

    /* blkio weight devies */
    ret = generate_blkio_weight_device(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* blkio throttle read bps devies */
    ret = generate_blkio_throttle_read_bps_device(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* blkio throttle write bps devies */
    ret = generate_blkio_throttle_write_bps_device(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* blkio throttle read iops devies */
    ret = generate_blkio_throttle_read_iops_device(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* blkio throttle write iops devies */
    ret = generate_blkio_throttle_write_iops_device(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

out:
    return ret;
}

int generate_hugetlb_limits(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->hugetlbs_len == 0 || srcconfig->hugetlbs == NULL) {
        goto out;
    }

    if (srcconfig->hugetlbs_len > SIZE_MAX / sizeof(host_config_hugetlbs_element *)) {
        ERROR("Too many hugepage limits to get!");
        ret = -1;
        goto out;
    }

    dstconfig->hugetlbs = util_common_calloc_s(srcconfig->hugetlbs_len * sizeof(host_config_hugetlbs_element *));
    if (dstconfig->hugetlbs == NULL) {
        ret = -1;
        goto out;
    }
    for (i = 0; i < srcconfig->hugetlbs_len; i++) {
        dstconfig->hugetlbs[dstconfig->hugetlbs_len] = pase_hugetlb_limit(srcconfig->hugetlbs[i]);
        if (dstconfig->hugetlbs[dstconfig->hugetlbs_len] == NULL) {
            ERROR("Failed to get hugepage limits");
            ret = -1;
            goto out;
        }

        dstconfig->hugetlbs_len++;
    }
out:
    return ret;
}

int generate_volumes_from(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    if (util_dup_array_of_strings((const char **)srcconfig->volumes_from, srcconfig->volumes_from_len,
                                  &dstconfig->volumes_from, &dstconfig->volumes_from_len) != 0) {
        COMMAND_ERROR("Failed to dup volumes-from");
        return -1;
    }

    return 0;
}

int generate_binds(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    if (util_dup_array_of_strings((const char **)srcconfig->binds, srcconfig->binds_len, &dstconfig->binds,
                                  &dstconfig->binds_len) != 0) {
        COMMAND_ERROR("Failed to dup binds");
        return -1;
    }

    return 0;
}

int generate_device_cgroup_rules(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    if (util_dup_array_of_strings((const char **)srcconfig->device_cgroup_rules, srcconfig->device_cgroup_rules_len,
                                  &dstconfig->device_cgroup_rules, &dstconfig->device_cgroup_rules_len) != 0) {
        COMMAND_ERROR("Failed to dup device cgroup rules");
        return -1;
    }

    return 0;
}

static mount_spec *dup_mount_spec(mount_spec *spec)
{
    int ret = 0;
    mount_spec *m = NULL;

    m = util_common_calloc_s(sizeof(mount_spec));
    if (m == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    m->type = util_strdup_s(spec->type);
    m->source = util_strdup_s(spec->source);
    m->target = util_strdup_s(spec->target);
    m->readonly = spec->readonly;
    m->consistency = util_strdup_s(spec->consistency);
    if (spec->bind_options != NULL) {
        m->bind_options = util_common_calloc_s(sizeof(bind_options));
        if (m->bind_options == NULL) {
            ret = -1;
            goto out;
        }
        m->bind_options->propagation = util_strdup_s(spec->bind_options->propagation);
        m->bind_options->selinux_opts = util_strdup_s(spec->bind_options->selinux_opts);
    }
    if (spec->volume_options != NULL) {
        m->volume_options = util_common_calloc_s(sizeof(volume_options));
        if (m->volume_options == NULL) {
            ret = -1;
            goto out;
        }
        m->volume_options->no_copy = spec->volume_options->no_copy;
    }

out:
    if (ret != 0) {
        free_mount_spec(m);
        m = NULL;
    }

    return m;
}

static int generate_mounts(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    int i = 0;

    if (srcconfig->mounts == NULL || srcconfig->mounts_len == 0) {
        goto out;
    }

    if (srcconfig->mounts_len > SIZE_MAX / sizeof(char *)) {
        COMMAND_ERROR("Too many mounts to mount!");
        ret = -1;
        goto out;
    }

    dstconfig->mounts = util_common_calloc_s(srcconfig->mounts_len * sizeof(mount_spec*));
    if (dstconfig->mounts == NULL) {
        ret = -1;
        goto out;
    }
    for (i = 0; i < srcconfig->mounts_len; i++) {
        dstconfig->mounts[dstconfig->mounts_len] = dup_mount_spec(srcconfig->mounts[i]);
        if (dstconfig->mounts[dstconfig->mounts_len] == NULL) {
            ret = -1;
            goto out;
        }
        dstconfig->mounts_len++;
    }

out:

    return ret;
}

int generate_groups(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    if (util_dup_array_of_strings((const char **)srcconfig->group_add, srcconfig->group_add_len, &dstconfig->group_add,
                                  &dstconfig->group_add_len) != 0) {
        COMMAND_ERROR("Failed to dup device group add");
        return -1;
    }

    return 0;
}

int generate_security(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    if (srcconfig->security == NULL || srcconfig->security_len == 0) {
        goto out;
    }

    if (srcconfig->security_len > SIZE_MAX / sizeof(char *)) {
        COMMAND_ERROR("Too many security opts!");
        ret = -1;
        goto out;
    }

    dstconfig->security_opt = util_common_calloc_s(srcconfig->security_len * sizeof(char *));
    if (dstconfig->security_opt == NULL) {
        ret = -1;
        goto out;
    }

    if (parse_security_opts(srcconfig, dstconfig) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static inline void check_and_strdup_s(char **dst_item, const char *src_item)
{
    if (src_item != NULL && dst_item != NULL) {
        (*dst_item) = util_strdup_s((src_item));
    }
}

static int pack_host_config_common(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    ret = pack_host_config_ns_change_files(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    ret = pack_hostconfig_cgroup(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    ret = pack_host_config_caps(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    ret = generate_storage_opts(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    ret = generate_sysctls(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    ret = pack_host_config_network(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* devices which will be populated into container */
    ret = generate_devices(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* blkio device */
    ret = generate_blkio(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* hugepage limits */
    ret = generate_hugetlb_limits(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* --volumes-from parameters */
    ret = generate_volumes_from(dstconfig, srcconfig);
    if (ret != 0) {
        goto out;
    }

    /* -v parameters */
    ret = generate_binds(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* --mount parameters */
    ret = generate_mounts(dstconfig, srcconfig);
    if (ret != 0) {
        goto out;
    }

    /* groups to add */
    ret = generate_groups(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* security opt */
    ret = generate_security(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* device cgroup rules*/
    ret = generate_device_cgroup_rules(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

out:
    return ret;
}

int generate_hostconfig(const isula_host_config_t *srcconfig, char **hostconfigstr)
{
    int ret = 0;
    parser_error err = NULL;
    host_config *dstconfig = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };

    dstconfig = util_common_calloc_s(sizeof(host_config));
    if (dstconfig == NULL) {
        ret = -1;
        goto out;
    }

    dstconfig->privileged = srcconfig->privileged;
    dstconfig->system_container = srcconfig->system_container;
    dstconfig->auto_remove = srcconfig->auto_remove;
    dstconfig->auto_remove_bak = srcconfig->auto_remove;
    dstconfig->readonly_rootfs = srcconfig->readonly_rootfs;
    dstconfig->oom_kill_disable = srcconfig->oom_kill_disable;
    dstconfig->shm_size = srcconfig->shm_size;

    ret = pack_host_config_common(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    check_and_strdup_s(&dstconfig->network_mode, srcconfig->network_mode);
    check_and_strdup_s(&dstconfig->ipc_mode, srcconfig->ipc_mode);
    check_and_strdup_s(&dstconfig->userns_mode, srcconfig->userns_mode);
    check_and_strdup_s(&dstconfig->user_remap, srcconfig->user_remap);
    check_and_strdup_s(&dstconfig->uts_mode, srcconfig->uts_mode);
    check_and_strdup_s(&dstconfig->pid_mode, srcconfig->pid_mode);
    /* hook-spec file */
    check_and_strdup_s(&dstconfig->hook_spec, srcconfig->hook_spec);
    /* env target file */
    check_and_strdup_s(&dstconfig->env_target_file, srcconfig->env_target_file);
    /* cgroup parent */
    check_and_strdup_s(&dstconfig->cgroup_parent, srcconfig->cgroup_parent);

    if (!parse_restart_policy(srcconfig->restart_policy, &dstconfig->restart_policy)) {
        ERROR("Invalid restart policy");
        ret = -1;
        goto out;
    }

    if (srcconfig->host_channel != NULL) {
        dstconfig->host_channel = parse_host_channel(srcconfig->host_channel);
        if (dstconfig->host_channel == NULL) {
            ERROR("Invalid host channel");
            ret = -1;
            goto out;
        }
    }
    *hostconfigstr = host_config_generate_json(dstconfig, &ctx, &err);
    if (*hostconfigstr == NULL) {
        COMMAND_ERROR("Failed to generate hostconfig json:%s", err);
        ret = -1;
        goto out;
    }

out:
    free(err);
    free_host_config(dstconfig);
    return ret;
}

void isula_ns_change_files_free(isula_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    util_free_array_by_len(hostconfig->ns_change_files, hostconfig->ns_change_files_len);
    hostconfig->ns_change_files = NULL;
    hostconfig->ns_change_files_len = 0;
}

void isula_host_config_storage_opts_free(isula_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    free_json_map_string_string(hostconfig->storage_opts);
    hostconfig->storage_opts = NULL;
}

void isula_host_config_sysctl_free(isula_host_config_t *hostconfig)
{
    if (hostconfig == NULL) {
        return;
    }

    free_json_map_string_string(hostconfig->sysctls);
    hostconfig->sysctls = NULL;
}

/* container cgroup resources free */
static void container_cgroup_resources_free(container_cgroup_resources_t *cr)
{
    if (cr == NULL) {
        return;
    }
    free(cr->cpuset_cpus);
    cr->cpuset_cpus = NULL;

    free(cr->cpuset_mems);
    cr->cpuset_mems = NULL;

    free(cr);
}

/* isula host config free */
void isula_host_config_free(isula_host_config_t *hostconfig)
{
    size_t i = 0;

    if (hostconfig == NULL) {
        return;
    }

    util_free_array_by_len(hostconfig->cap_add, hostconfig->cap_add_len);
    hostconfig->cap_add = NULL;
    hostconfig->cap_add_len = 0;

    util_free_array_by_len(hostconfig->cap_drop, hostconfig->cap_drop_len);
    hostconfig->cap_drop = NULL;
    hostconfig->cap_drop_len = 0;

    free_json_map_string_string(hostconfig->storage_opts);
    hostconfig->storage_opts = NULL;

    free_json_map_string_string(hostconfig->sysctls);
    hostconfig->sysctls = NULL;

    util_free_array_by_len(hostconfig->devices, hostconfig->devices_len);
    hostconfig->devices = NULL;
    hostconfig->devices_len = 0;

    util_free_array_by_len(hostconfig->ns_change_files, hostconfig->ns_change_files_len);
    hostconfig->ns_change_files = NULL;
    hostconfig->ns_change_files_len = 0;

    util_free_array_by_len(hostconfig->hugetlbs, hostconfig->hugetlbs_len);
    hostconfig->hugetlbs = NULL;
    hostconfig->hugetlbs_len = 0;

    free(hostconfig->network_mode);
    hostconfig->network_mode = NULL;

    free(hostconfig->ipc_mode);
    hostconfig->ipc_mode = NULL;

    free(hostconfig->pid_mode);
    hostconfig->pid_mode = NULL;

    free(hostconfig->uts_mode);
    hostconfig->uts_mode = NULL;

    free(hostconfig->userns_mode);
    hostconfig->userns_mode = NULL;

    free(hostconfig->user_remap);
    hostconfig->user_remap = NULL;

    util_free_array_by_len(hostconfig->ulimits, hostconfig->ulimits_len);
    hostconfig->ulimits = NULL;
    hostconfig->ulimits_len = 0;

    free(hostconfig->restart_policy);
    hostconfig->restart_policy = NULL;

    free(hostconfig->host_channel);
    hostconfig->host_channel = NULL;

    free(hostconfig->hook_spec);
    hostconfig->hook_spec = NULL;

    free(hostconfig->env_target_file);
    hostconfig->env_target_file = NULL;

    free(hostconfig->cgroup_parent);
    hostconfig->cgroup_parent = NULL;

    util_free_array_by_len(hostconfig->binds, hostconfig->binds_len);
    hostconfig->binds = NULL;
    hostconfig->binds_len = 0;

    for (i = 0; i < hostconfig->mounts_len; i++) {
        free_mount_spec(hostconfig->mounts[i]);
        hostconfig->mounts[i] = NULL;
    }
    free(hostconfig->mounts);
    hostconfig->mounts = NULL;
    hostconfig->mounts_len = 0;

    util_free_array_by_len(hostconfig->blkio_weight_device, hostconfig->blkio_weight_device_len);
    hostconfig->blkio_weight_device = NULL;
    hostconfig->blkio_weight_device_len = 0;

    util_free_array_by_len(hostconfig->blkio_throttle_read_bps_device, hostconfig->blkio_throttle_read_bps_device_len);
    hostconfig->blkio_throttle_read_bps_device = NULL;
    hostconfig->blkio_throttle_read_bps_device_len = 0;

    util_free_array_by_len(hostconfig->blkio_throttle_write_bps_device,
                           hostconfig->blkio_throttle_write_bps_device_len);
    hostconfig->blkio_throttle_write_bps_device = NULL;
    hostconfig->blkio_throttle_write_bps_device_len = 0;

    util_free_array_by_len(hostconfig->blkio_throttle_read_iops_device,
                           hostconfig->blkio_throttle_read_iops_device_len);
    hostconfig->blkio_throttle_read_iops_device = NULL;
    hostconfig->blkio_throttle_read_iops_device_len = 0;

    util_free_array_by_len(hostconfig->blkio_throttle_write_iops_device,
                           hostconfig->blkio_throttle_write_iops_device_len);
    hostconfig->blkio_throttle_write_iops_device = NULL;
    hostconfig->blkio_throttle_write_iops_device_len = 0;

    util_free_array_by_len(hostconfig->device_cgroup_rules, hostconfig->device_cgroup_rules_len);
    hostconfig->device_cgroup_rules = NULL;
    hostconfig->device_cgroup_rules_len = 0;

    container_cgroup_resources_free(hostconfig->cr);
    hostconfig->cr = NULL;

    free(hostconfig);
}
