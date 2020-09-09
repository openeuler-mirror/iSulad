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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container package configure functions
 ******************************************************************************/
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
#include "pack_config.h"
#include "isula_libutils/host_config.h"
#include "utils.h"
#include "isula_libutils/parse_common.h"
#include "path.h"
#include "isula_libutils/container_config.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"

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
    int ret = 0;
    size_t i = 0;

    if (dstconfig == NULL || srcconfig == NULL) {
        return -1;
    }

    if (srcconfig->ns_change_files_len != 0 && srcconfig->ns_change_files != NULL) {
        if (srcconfig->ns_change_files_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many capabilities to add!");
            ret = -1;
            goto out;
        }
        dstconfig->ns_change_files = util_common_calloc_s(srcconfig->ns_change_files_len * sizeof(char *));
        if (dstconfig->ns_change_files == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < srcconfig->ns_change_files_len; i++) {
            dstconfig->ns_change_files[dstconfig->ns_change_files_len] = util_strdup_s(srcconfig->ns_change_files[i]);
            dstconfig->ns_change_files_len++;
        }
    }

out:
    return ret;
}

static int pack_host_config_cap_add(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    /* cap-add */
    if (srcconfig->cap_add_len != 0 && srcconfig->cap_add != NULL) {
        if (srcconfig->cap_add_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many capabilities to add!");
            ret = -1;
            goto out;
        }
        dstconfig->cap_add = util_common_calloc_s(srcconfig->cap_add_len * sizeof(char *));
        if (dstconfig->cap_add == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < srcconfig->cap_add_len; i++) {
            dstconfig->cap_add[dstconfig->cap_add_len] = util_strdup_s(srcconfig->cap_add[i]);
            dstconfig->cap_add_len++;
        }
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
    if (srcconfig->cap_drop_len != 0 && srcconfig->cap_drop != NULL) {
        if (srcconfig->cap_drop_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many capabilities to drop!");
            ret = -1;
            goto out;
        }
        dstconfig->cap_drop = util_common_calloc_s(srcconfig->cap_drop_len * sizeof(char *));
        if (dstconfig->cap_drop == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < srcconfig->cap_drop_len; i++) {
            dstconfig->cap_drop[dstconfig->cap_drop_len] = util_strdup_s(srcconfig->cap_drop[i]);
            dstconfig->cap_drop_len++;
        }
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
    int ret = 0;
    size_t i = 0;

    /* extra hosts */
    if (srcconfig->extra_hosts_len != 0 && srcconfig->extra_hosts != NULL) {
        if (srcconfig->extra_hosts_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many extra hosts to add!");
            ret = -1;
            goto out;
        }
        dstconfig->extra_hosts = util_common_calloc_s(srcconfig->extra_hosts_len * sizeof(char *));
        if (dstconfig->extra_hosts == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < srcconfig->extra_hosts_len; i++) {
            dstconfig->extra_hosts[dstconfig->extra_hosts_len] = util_strdup_s(srcconfig->extra_hosts[i]);
            dstconfig->extra_hosts_len++;
        }
    }
out:
    return ret;
}

static int pack_host_network_dns(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    /* dns */
    if (srcconfig->dns_len != 0 && srcconfig->dns != NULL) {
        if (srcconfig->dns_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many dns to add!");
            ret = -1;
            goto out;
        }
        dstconfig->dns = util_common_calloc_s(srcconfig->dns_len * sizeof(char *));
        if (dstconfig->dns == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < srcconfig->dns_len; i++) {
            dstconfig->dns[dstconfig->dns_len] = util_strdup_s(srcconfig->dns[i]);
            dstconfig->dns_len++;
        }
    }

out:
    return ret;
}

static int pack_host_network_dns_options(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    /* dns options */
    if (srcconfig->dns_options_len != 0 && srcconfig->dns_options != NULL) {
        if (srcconfig->dns_options_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many dns options to add!");
            ret = -1;
            goto out;
        }
        dstconfig->dns_options = util_common_calloc_s(srcconfig->dns_options_len * sizeof(char *));
        if (dstconfig->dns_options == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < srcconfig->dns_options_len; i++) {
            dstconfig->dns_options[dstconfig->dns_options_len] = util_strdup_s(srcconfig->dns_options[i]);
            dstconfig->dns_options_len++;
        }
    }

out:
    return ret;
}

static int pack_host_network_dns_search(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    /* dns search */
    if (srcconfig->dns_search_len != 0 && srcconfig->dns_search != NULL) {
        if (srcconfig->dns_search_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many dns search to add!");
            ret = -1;
            goto out;
        }
        dstconfig->dns_search = util_common_calloc_s(srcconfig->dns_search_len * sizeof(char *));
        if (dstconfig->dns_search == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < srcconfig->dns_search_len; i++) {
            dstconfig->dns_search[dstconfig->dns_search_len] = util_strdup_s(srcconfig->dns_search[i]);
            dstconfig->dns_search_len++;
        }
    }

out:
    return ret;
}

static int pack_host_config_network(host_config *dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;

    if (dstconfig == NULL) {
        return -1;
    }

    ret = pack_host_network_extra_hosts(dstconfig, srcconfig);
    if (ret != 0) {
        goto out;
    }

    ret = pack_host_network_dns(dstconfig, srcconfig);
    if (ret != 0) {
        goto out;
    }

    ret = pack_host_network_dns_options(dstconfig, srcconfig);
    if (ret != 0) {
        goto out;
    }

    ret = pack_host_network_dns_search(dstconfig, srcconfig);
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

static int check_ulimit_input(const char *val)
{
    int ret = 0;
    if (val == NULL || strcmp(val, "") == 0) {
        COMMAND_ERROR("ulimit argument can't be empty");
        ret = -1;
        goto out;
    }

    if (val[0] == '=' || val[strlen(val) - 1] == '=') {
        COMMAND_ERROR("Invalid ulimit argument: \"%s\", delimiter '=' can't"
                      " be the first or the last character",
                      val);
        ret = -1;
    }

out:
    return ret;
}

static void get_ulimit_split_parts(const char *val, char ***parts, size_t *parts_len, char deli)
{
    *parts = util_string_split_multi(val, deli);
    if (*parts == NULL) {
        COMMAND_ERROR("Out of memory");
        return;
    }
    *parts_len = util_array_len((const char **)(*parts));
}

static int parse_soft_hard_ulimit(const char *val, char **limitvals, size_t limitvals_len, int64_t *soft, int64_t *hard)
{
    int ret = 0;
    // parse soft
    ret = util_safe_llong(limitvals[0], (long long *)soft);
    if (ret < 0) {
        COMMAND_ERROR("Invalid ulimit soft value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
        ret = -1;
        goto out;
    }

    // parse hard if exists
    if (limitvals_len > 1) {
        ret = util_safe_llong(limitvals[1], (long long *)hard);
        if (ret < 0) {
            COMMAND_ERROR("Invalid ulimit hard value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
            ret = -1;
            goto out;
        }

        if (*soft > *hard) {
            COMMAND_ERROR("Ulimit soft limit must be less than or equal to hard limit: %lld > %lld",
                          (long long int)(*soft), (long long int)(*hard));
            ret = -1;
            goto out;
        }
    } else {
        *hard = *soft; // default to soft in case no hard was set
    }
out:
    return ret;
}

static int check_ulimit_type(const char *type)
{
    int ret = 0;
    char **tmptype = NULL;
    char *ulimit_valid_type[] = {
        // "as", // Disabled since this doesn't seem usable with the way Docker inits a container.
        "core",   "cpu",   "data", "fsize",  "locks",  "memlock",    "msgqueue", "nice",
        "nofile", "nproc", "rss",  "rtprio", "rttime", "sigpending", "stack",    NULL
    };

    for (tmptype = ulimit_valid_type; *tmptype != NULL; tmptype++) {
        if (strcmp(type, *tmptype) == 0) {
            break;
        }
    }

    if (*tmptype == NULL) {
        COMMAND_ERROR("Invalid ulimit type: %s", type);
        ret = -1;
    }
    return ret;
}

static host_config_ulimits_element *parse_ulimit(const char *val)
{
    int ret = 0;
    int64_t soft = 0;
    int64_t hard = 0;
    size_t parts_len = 0;
    size_t limitvals_len = 0;
    char **parts = NULL;
    char **limitvals = NULL;
    host_config_ulimits_element *ulimit = NULL;

    ret = check_ulimit_input(val);
    if (ret != 0) {
        return NULL;
    }

    get_ulimit_split_parts(val, &parts, &parts_len, '=');
    if (parts == NULL) {
        ERROR("Out of memory");
        return NULL;
    } else if (parts_len != 2) {
        COMMAND_ERROR("Invalid ulimit argument: %s", val);
        ret = -1;
        goto out;
    }

    ret = check_ulimit_type(parts[0]);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    if (parts[1][0] == ':' || parts[1][strlen(parts[1]) - 1] == ':') {
        COMMAND_ERROR("Invalid ulimit value: \"%s\", delimiter ':' can't be the first"
                      " or the last character",
                      val);
        ret = -1;
        goto out;
    }

    // parse value
    get_ulimit_split_parts(parts[1], &limitvals, &limitvals_len, ':');
    if (limitvals == NULL) {
        ret = -1;
        goto out;
    }

    if (limitvals_len > 2) {
        COMMAND_ERROR("Too many limit value arguments - %s, can only have up to two, `soft[:hard]`", parts[1]);
        ret = -1;
        goto out;
    }

    ret = parse_soft_hard_ulimit(val, limitvals, limitvals_len, &soft, &hard);
    if (ret < 0) {
        goto out;
    }

    ulimit = util_common_calloc_s(sizeof(host_config_ulimits_element));
    if (ulimit == NULL) {
        ret = -1;
        goto out;
    }
    ulimit->name = util_strdup_s(parts[0]);
    ulimit->hard = hard;
    ulimit->soft = soft;

out:
    util_free_array(parts);
    util_free_array(limitvals);
    if (ret != 0) {
        free_host_config_ulimits_element(ulimit);
        ulimit = NULL;
    }

    return ulimit;
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

        tmp = parse_ulimit(srcconfig->ulimits[i]);
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
    if (cleanpath(token, real_path, sizeof(real_path)) == NULL) {
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
    if (cleanpath(token, real_path, sizeof(real_path)) == NULL) {
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
    int ret = 0;
    size_t new_size, old_size;
    char **tmp_security_opt = NULL;

    if (dstconfig->security_opt_len > (SIZE_MAX / sizeof(char *)) - 1) {
        COMMAND_ERROR("Out of memory");
        return -1;
    }
    new_size = (dstconfig->security_opt_len + 1) * sizeof(char *);
    old_size = dstconfig->security_opt_len * sizeof(char *);
    ret = mem_realloc((void **)(&tmp_security_opt), new_size, (void *)dstconfig->security_opt, old_size);
    if (ret != 0) {
        COMMAND_ERROR("Out of memory");
        return ret;
    }
    dstconfig->security_opt = tmp_security_opt;
    dstconfig->security_opt[dstconfig->security_opt_len++] = util_strdup_s("no-new-privileges");

    return ret;
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

static int append_selinux_label_to_security_opts(const char *selinux_label, host_config *dstconfig)
{
    int ret = 0;
    size_t new_size;
    size_t old_size;
    char **tmp_security_opt = NULL;

    if (dstconfig->security_opt_len > (SIZE_MAX / sizeof(char *)) - 1) {
        COMMAND_ERROR("Too large security options");
        return -1;
    }
    new_size = (dstconfig->security_opt_len + 1) * sizeof(char *);
    old_size = dstconfig->security_opt_len * sizeof(char *);
    ret = mem_realloc((void **)(&tmp_security_opt), new_size, (void *)dstconfig->security_opt, old_size);
    if (ret != 0) {
        COMMAND_ERROR("Out of memory");
        return ret;
    }
    dstconfig->security_opt = tmp_security_opt;
    dstconfig->security_opt[dstconfig->security_opt_len++] = util_strdup_s(selinux_label);

    return ret;
}

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
            } else if (strcmp(items[0], "label") == 0) {
                ret = append_selinux_label_to_security_opts(srcconfig->security[i], dstconfig);
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

int generate_storage_opts(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t j;

    if (srcconfig->storage_opts == NULL || dstconfig == NULL) {
        goto out;
    }

    (*dstconfig)->storage_opt = util_common_calloc_s(sizeof(json_map_string_string));
    if ((*dstconfig)->storage_opt == NULL) {
        ret = -1;
        goto out;
    }
    for (j = 0; j < srcconfig->storage_opts->len; j++) {
        ret = append_json_map_string_string((*dstconfig)->storage_opt, srcconfig->storage_opts->keys[j],
                                            srcconfig->storage_opts->values[j]);
        if (ret != 0) {
            ERROR("Append map failed");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int generate_sysctls(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t j;

    if (srcconfig->sysctls == NULL || dstconfig == NULL) {
        goto out;
    }

    (*dstconfig)->sysctls = util_common_calloc_s(sizeof(json_map_string_string));
    if ((*dstconfig)->sysctls == NULL) {
        ret = -1;
        goto out;
    }
    for (j = 0; j < srcconfig->sysctls->len; j++) {
        ret = append_json_map_string_string((*dstconfig)->sysctls, srcconfig->sysctls->keys[j],
                                            srcconfig->sysctls->values[j]);
        if (ret < 0) {
            goto out;
        }
    }
out:
    return ret;
}

int generate_devices(host_config **dstconfig, const isula_host_config_t *srcconfig)
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
    (*dstconfig)->devices = util_common_calloc_s(sizeof(host_config_devices_element *) * srcconfig->devices_len);
    if ((*dstconfig)->devices == NULL) {
        ret = -1;
        goto out;
    }
    for (i = 0; i < srcconfig->devices_len; i++) {
        (*dstconfig)->devices[i] = parse_device(srcconfig->devices[i]);
        if ((*dstconfig)->devices[i] == NULL) {
            ERROR("Failed to parse devices:%s", srcconfig->devices[i]);
            ret = -1;
            goto out;
        }

        (*dstconfig)->devices_len++;
    }
out:
    return ret;
}

static int generate_blkio_weight_device(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->blkio_weight_device == NULL || srcconfig->blkio_weight_device_len == 0) {
        goto out;
    }

    (*dstconfig)->blkio_weight_device =
        util_smart_calloc_s(sizeof(defs_blkio_weight_device *), srcconfig->blkio_weight_device_len);
    if ((*dstconfig)->blkio_weight_device == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_weight_device_len; i++) {
        (*dstconfig)->blkio_weight_device[(*dstconfig)->blkio_weight_device_len] =
            pack_blkio_weight_devices(srcconfig->blkio_weight_device[i]);
        if ((*dstconfig)->blkio_weight_device[(*dstconfig)->blkio_weight_device_len] == NULL) {
            ERROR("Failed to get blkio weight devies");
            ret = -1;
            goto out;
        }

        (*dstconfig)->blkio_weight_device_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_read_bps_device(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (dstconfig == NULL || *dstconfig == NULL) {
        goto out;
    }

    if (srcconfig->blkio_throttle_read_bps_device == NULL || srcconfig->blkio_throttle_read_bps_device_len == 0) {
        goto out;
    }

    (*dstconfig)->blkio_device_read_bps =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_read_bps_device_len);
    if ((*dstconfig)->blkio_device_read_bps == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_read_bps_device_len; i++) {
        (*dstconfig)->blkio_device_read_bps[(*dstconfig)->blkio_device_read_bps_len] =
            pack_throttle_bps_device(srcconfig->blkio_throttle_read_bps_device[i]);
        if ((*dstconfig)->blkio_device_read_bps[(*dstconfig)->blkio_device_read_bps_len] == NULL) {
            ERROR("Failed to get blkio throttle read bps devices");
            ret = -1;
            goto out;
        }

        (*dstconfig)->blkio_device_read_bps_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_write_bps_device(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (dstconfig == NULL || *dstconfig == NULL) {
        goto out;
    }

    if (srcconfig->blkio_throttle_write_bps_device == NULL || srcconfig->blkio_throttle_write_bps_device_len == 0) {
        goto out;
    }

    (*dstconfig)->blkio_device_write_bps =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_write_bps_device_len);
    if ((*dstconfig)->blkio_device_write_bps == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_write_bps_device_len; i++) {
        (*dstconfig)->blkio_device_write_bps[(*dstconfig)->blkio_device_write_bps_len] =
            pack_throttle_bps_device(srcconfig->blkio_throttle_write_bps_device[i]);
        if ((*dstconfig)->blkio_device_write_bps[(*dstconfig)->blkio_device_write_bps_len] == NULL) {
            ERROR("Failed to get blkio throttle write bps devices");
            ret = -1;
            goto out;
        }

        (*dstconfig)->blkio_device_write_bps_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_read_iops_device(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (dstconfig == NULL || *dstconfig == NULL) {
        goto out;
    }

    if (srcconfig->blkio_throttle_read_iops_device == NULL || srcconfig->blkio_throttle_read_iops_device_len == 0) {
        goto out;
    }

    (*dstconfig)->blkio_device_read_iops =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_read_iops_device_len);
    if ((*dstconfig)->blkio_device_read_iops == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_read_iops_device_len; i++) {
        (*dstconfig)->blkio_device_read_iops[(*dstconfig)->blkio_device_read_iops_len] =
            pack_throttle_iops_device(srcconfig->blkio_throttle_read_iops_device[i]);
        if ((*dstconfig)->blkio_device_read_iops[(*dstconfig)->blkio_device_read_iops_len] == NULL) {
            ERROR("Failed to get blkio throttle read iops devices");
            ret = -1;
            goto out;
        }

        (*dstconfig)->blkio_device_read_iops_len++;
    }
out:
    return ret;
}

static int generate_blkio_throttle_write_iops_device(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (dstconfig == NULL || *dstconfig == NULL) {
        goto out;
    }

    if (srcconfig->blkio_throttle_write_iops_device == NULL || srcconfig->blkio_throttle_write_iops_device_len == 0) {
        goto out;
    }

    (*dstconfig)->blkio_device_write_iops =
        util_smart_calloc_s(sizeof(defs_blkio_device *), srcconfig->blkio_throttle_write_iops_device_len);
    if ((*dstconfig)->blkio_device_write_iops == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < srcconfig->blkio_throttle_write_iops_device_len; i++) {
        (*dstconfig)->blkio_device_write_iops[(*dstconfig)->blkio_device_write_iops_len] =
            pack_throttle_iops_device(srcconfig->blkio_throttle_write_iops_device[i]);
        if ((*dstconfig)->blkio_device_write_iops[(*dstconfig)->blkio_device_write_iops_len] == NULL) {
            ERROR("Failed to get blkio throttle write iops devices");
            ret = -1;
            goto out;
        }

        (*dstconfig)->blkio_device_write_iops_len++;
    }
out:
    return ret;
}

static int generate_blkio(host_config **dstconfig, const isula_host_config_t *srcconfig)
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

int generate_hugetlb_limits(host_config **dstconfig, const isula_host_config_t *srcconfig)
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

    (*dstconfig)->hugetlbs = util_common_calloc_s(srcconfig->hugetlbs_len * sizeof(host_config_hugetlbs_element *));
    if ((*dstconfig)->hugetlbs == NULL) {
        ret = -1;
        goto out;
    }
    for (i = 0; i < srcconfig->hugetlbs_len; i++) {
        (*dstconfig)->hugetlbs[(*dstconfig)->hugetlbs_len] = pase_hugetlb_limit(srcconfig->hugetlbs[i]);
        if ((*dstconfig)->hugetlbs[(*dstconfig)->hugetlbs_len] == NULL) {
            ERROR("Failed to get hugepage limits");
            ret = -1;
            goto out;
        }

        (*dstconfig)->hugetlbs_len++;
    }
out:
    return ret;
}

int generate_binds(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->binds == NULL || srcconfig->binds_len == 0) {
        goto out;
    }

    if (srcconfig->binds_len > SIZE_MAX / sizeof(char *)) {
        COMMAND_ERROR("Too many binds to mount!");
        ret = -1;
        goto out;
    }

    (*dstconfig)->binds = util_common_calloc_s(srcconfig->binds_len * sizeof(char *));
    if ((*dstconfig)->binds == NULL) {
        ret = -1;
        goto out;
    }
    for (i = 0; i < srcconfig->binds_len; i++) {
        (*dstconfig)->binds[(*dstconfig)->binds_len] = util_strdup_s(srcconfig->binds[i]);
        (*dstconfig)->binds_len++;
    }

out:
    return ret;
}

int generate_groups(host_config **dstconfig, const isula_host_config_t *srcconfig)
{
    int ret = 0;
    size_t i = 0;

    if (srcconfig->group_add == NULL || srcconfig->group_add_len == 0 || dstconfig == NULL) {
        goto out;
    }

    if (srcconfig->group_add_len > SIZE_MAX / sizeof(char *)) {
        COMMAND_ERROR("Too many groups to add!");
        ret = -1;
        goto out;
    }

    (*dstconfig)->group_add = util_common_calloc_s(srcconfig->group_add_len * sizeof(char *));
    if ((*dstconfig)->group_add == NULL) {
        ret = -1;
        goto out;
    }
    for (i = 0; i < srcconfig->group_add_len; i++) {
        (*dstconfig)->group_add[(*dstconfig)->group_add_len] = util_strdup_s(srcconfig->group_add[i]);
        (*dstconfig)->group_add_len++;
    }
out:
    return ret;
}

int generate_security(host_config **dstconfig, const isula_host_config_t *srcconfig)
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

    (*dstconfig)->security_opt = util_common_calloc_s(srcconfig->security_len * sizeof(char *));
    if ((*dstconfig)->security_opt == NULL) {
        ret = -1;
        goto out;
    }

    if (parse_security_opts(srcconfig, (*dstconfig)) != 0) {
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

    ret = generate_storage_opts(&dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    ret = generate_sysctls(&dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    ret = pack_host_config_network(dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* devices which will be populated into container */
    ret = generate_devices(&dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* blkio device */
    ret = generate_blkio(&dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* hugepage limits */
    ret = generate_hugetlb_limits(&dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* binds to mount */
    ret = generate_binds(&dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* groups to add */
    ret = generate_groups(&dstconfig, srcconfig);
    if (ret < 0) {
        goto out;
    }

    /* security opt */
    ret = generate_security(&dstconfig, srcconfig);
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

    dstconfig = util_common_calloc_s(sizeof(*dstconfig));
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

static int pack_container_custom_config_args(container_config *container_spec,
                                             const isula_container_config_t *custom_conf)
{
    int ret = 0;
    int i;

    /* entrypoint */
    if (util_valid_str(custom_conf->entrypoint)) {
        container_spec->entrypoint = util_common_calloc_s(sizeof(char *));
        if (container_spec->entrypoint == NULL) {
            ret = -1;
            goto out;
        }
        container_spec->entrypoint[0] = util_strdup_s(custom_conf->entrypoint);
        container_spec->entrypoint_len++;
    }

    /* commands */
    if ((custom_conf->cmd_len != 0 && custom_conf->cmd)) {
        if (custom_conf->cmd_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("The length of cmd is too long!");
            ret = -1;
            goto out;
        }
        container_spec->cmd = util_common_calloc_s(custom_conf->cmd_len * sizeof(char *));
        if (container_spec->cmd == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < (int)custom_conf->cmd_len; i++) {
            container_spec->cmd[container_spec->cmd_len] = util_strdup_s(custom_conf->cmd[i]);
            container_spec->cmd_len++;
        }
    }

out:
    return ret;
}

static int pack_container_custom_config_mounts(container_config *container_spec,
                                               const isula_container_config_t *custom_conf)
{
    int ret = 0;
    int i = 0;

    /* mounts to mount filesystem */
    if (custom_conf->mounts != NULL && custom_conf->mounts_len > 0) {
        if (custom_conf->mounts_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many mounts to mount filesystem!");
            ret = -1;
            goto out;
        }
        container_spec->mounts = util_common_calloc_s(custom_conf->mounts_len * sizeof(char *));
        if (container_spec->mounts == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < (int)custom_conf->mounts_len; i++) {
            container_spec->mounts[container_spec->mounts_len] = util_strdup_s(custom_conf->mounts[i]);
            container_spec->mounts_len++;
        }
    }
out:
    return ret;
}

static int pack_container_custom_config_array(container_config *container_spec,
                                              const isula_container_config_t *custom_conf)
{
    int ret = 0;
    int i = 0;

    /* environment variables */
    if (custom_conf->env_len != 0 && custom_conf->env) {
        if (custom_conf->env_len > SIZE_MAX / sizeof(char *)) {
            COMMAND_ERROR("Too many environment variables");
            return -1;
        }
        container_spec->env = util_common_calloc_s(custom_conf->env_len * sizeof(char *));
        if (container_spec->env == NULL) {
            ret = -1;
            goto out;
        }
        for (i = 0; i < (int)custom_conf->env_len; i++) {
            container_spec->env[container_spec->env_len] = util_strdup_s(custom_conf->env[i]);
            container_spec->env_len++;
        }
    }

out:
    return ret;
}

static int get_label_key_value(const char *label, char **key, char **value)
{
    int ret = 0;
    char **arr = util_string_split_n(label, '=', 2);
    if (arr == NULL) {
        ERROR("Failed to split input label");
        ret = -1;
        goto out;
    }

    *key = util_strdup_s(arr[0]);
    if (util_array_len((const char **)arr) == 1) {
        *value = util_strdup_s("");
    } else {
        *value = util_strdup_s(arr[1]);
    }

out:
    util_free_array(arr);
    return ret;
}

static int pack_container_custom_config_labels(container_config *container_spec,
                                               const isula_container_config_t *custom_conf)
{
    int ret = 0;
    int i;
    char *key = NULL;
    char *value = NULL;

    if (custom_conf->label_len == 0 || custom_conf->label == NULL) {
        return 0;
    }

    /* labels */
    container_spec->labels = util_common_calloc_s(sizeof(json_map_string_string));
    if (container_spec->labels == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < custom_conf->label_len; i++) {
        if (get_label_key_value(custom_conf->label[i], &key, &value) != 0) {
            ERROR("Failed to get key and value of label");
            ret = -1;
            goto out;
        }

        if (append_json_map_string_string(container_spec->labels, key, value)) {
            ERROR("Append map failed");
            ret = -1;
            goto out;
        }
        free(key);
        key = NULL;
        free(value);
        value = NULL;
    }

out:
    free(key);
    free(value);
    return ret;
}

static bool have_health_check(const isula_container_config_t *custom_conf)
{
    bool have_health_settings = false;

    if ((custom_conf->health_cmd != NULL && strlen(custom_conf->health_cmd) != 0) ||
        custom_conf->health_interval != 0 || custom_conf->health_timeout != 0 ||
        custom_conf->health_start_period != 0 || custom_conf->health_retries != 0) {
        have_health_settings = true;
    }

    return have_health_settings;
}

static int pack_custom_no_health_check(container_config *container_spec, bool have_health_settings,
                                       defs_health_check *health_config)
{
    int ret = 0;

    if (have_health_settings) {
        COMMAND_ERROR("--no-healthcheck conflicts with --health-* options");
        ret = -1;
        goto out;
    }
    health_config->test = util_common_calloc_s(sizeof(char *));
    if (health_config->test == NULL) {
        ret = -1;
        goto out;
    }
    health_config->test[health_config->test_len++] = util_strdup_s("NONE");
    container_spec->healthcheck = health_config;

out:
    return ret;
}

static int pack_custom_with_health_check(container_config *container_spec, const isula_container_config_t *custom_conf,
                                         bool have_health_settings, defs_health_check *health_config)
{
    int ret = 0;

    if (custom_conf->health_cmd != NULL && strlen(custom_conf->health_cmd) != 0) {
        health_config->test = util_common_calloc_s(2 * sizeof(char *));
        if (health_config->test == NULL) {
            ret = -1;
            goto out;
        }
        health_config->test[health_config->test_len++] = util_strdup_s("CMD-SHELL");
        health_config->test[health_config->test_len++] = util_strdup_s(custom_conf->health_cmd);
    } else {
        COMMAND_ERROR("--health-cmd required!");
        ret = -1;
        goto out;
    }
    health_config->interval = custom_conf->health_interval;
    health_config->timeout = custom_conf->health_timeout;
    health_config->start_period = custom_conf->health_start_period;
    health_config->retries = custom_conf->health_retries;
    health_config->exit_on_unhealthy = custom_conf->exit_on_unhealthy;
    if (container_spec->healthcheck != NULL) {
        free_defs_health_check(container_spec->healthcheck);
    }
    container_spec->healthcheck = health_config;

out:
    return ret;
}

static int pack_container_custom_config_health(container_config *container_spec,
                                               const isula_container_config_t *custom_conf)
{
    int ret = 0;
    bool have_health_settings = false;
    defs_health_check *health_config = NULL;

    if (container_spec == NULL || custom_conf == NULL) {
        return 0;
    }

    have_health_settings = have_health_check(custom_conf);

    health_config = util_common_calloc_s(sizeof(defs_health_check));
    if (health_config == NULL) {
        ret = -1;
        goto out;
    }

    if (custom_conf->no_healthcheck) {
        ret = pack_custom_no_health_check(container_spec, have_health_settings, health_config);
        if (ret != 0) {
            goto out;
        }
    } else if (have_health_settings) {
        ret = pack_custom_with_health_check(container_spec, custom_conf, have_health_settings, health_config);
        if (ret != 0) {
            goto out;
        }
    } else {
        goto out;
    }

    return ret;

out:
    free_defs_health_check(health_config);
    return ret;
}

static int pack_container_custom_config_annotation(container_config *container_spec,
                                                   const isula_container_config_t *custom_conf)
{
    int ret = 0;
    size_t j;

    container_spec->annotations = util_common_calloc_s(sizeof(json_map_string_string));
    if (container_spec->annotations == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (custom_conf->annotations != NULL) {
        for (j = 0; j < custom_conf->annotations->len; j++) {
            if (append_json_map_string_string(container_spec->annotations, custom_conf->annotations->keys[j],
                                              custom_conf->annotations->values[j])) {
                ERROR("Append map failed");
                ret = -1;
                goto out;
            }
        }
    }
out:
    return ret;
}

static int pack_container_custom_config_pre(container_config *container_spec,
                                            const isula_container_config_t *custom_conf)
{
    int ret = 0;

    ret = pack_container_custom_config_args(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_custom_config_mounts(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_custom_config_array(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_custom_config_labels(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    ret = pack_container_custom_config_health(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }
out:
    return ret;
}

/* translate create_custom_config to container_config */
static int pack_container_custom_config(container_config *container_spec, const isula_container_config_t *custom_conf)
{
    int ret = -1;

    if (container_spec == NULL || custom_conf == NULL) {
        return ret;
    }

    ret = pack_container_custom_config_pre(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    if (custom_conf->hostname != NULL) {
        container_spec->hostname = util_strdup_s(custom_conf->hostname);
    }
    container_spec->log_driver = util_strdup_s(custom_conf->log_driver);

    /* console config */
    container_spec->tty = custom_conf->tty;
    container_spec->open_stdin = custom_conf->open_stdin;
    container_spec->attach_stdin = custom_conf->attach_stdin;
    container_spec->attach_stdout = custom_conf->attach_stdout;
    container_spec->attach_stderr = custom_conf->attach_stderr;

    /* user and group */
    if (custom_conf->user != NULL) {
        container_spec->user = util_strdup_s(custom_conf->user);
    }

    /* settings for system container */
    if (custom_conf->system_container) {
        container_spec->system_container = custom_conf->system_container;
    }

    if (custom_conf->ns_change_opt != NULL) {
        container_spec->ns_change_opt = util_strdup_s(custom_conf->ns_change_opt);
    }

    ret = pack_container_custom_config_annotation(container_spec, custom_conf);
    if (ret != 0) {
        goto out;
    }

    if (custom_conf->workdir != NULL) {
        container_spec->working_dir = util_strdup_s(custom_conf->workdir);
    }

out:
    return ret;
}

int generate_container_config(const isula_container_config_t *custom_conf, char **container_config_str)
{
    int ret = 0;
    container_config *container_spec = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;

    /* step 1: malloc the container config */
    container_spec = util_common_calloc_s(sizeof(container_config));
    if (container_spec == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    /* step 2: pack the container custom config */
    ret = pack_container_custom_config(container_spec, custom_conf);
    if (ret != 0) {
        ERROR("Failed to pack the container custom config");
        ret = -1;
        goto out;
    }

    /* step 3: generate the config string */
    *container_config_str = container_config_generate_json(container_spec, &ctx, &err);
    if (*container_config_str == NULL) {
        ERROR("Failed to generate OCI specification json string");
        ret = -1;
        goto out;
    }

out:
    free_container_config(container_spec);
    free(err);

    return ret;
}
