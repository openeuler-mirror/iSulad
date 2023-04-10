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
 * Description: provide cgroup v1 functions
 ******************************************************************************/
#include "cgroup.h"

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "path.h"
#include "sysinfo.h"

#define CGROUP_HUGETLB_LIMIT "hugetlb.%s.limit_in_bytes"

typedef struct {
    char *match;
} cgfile_callback_args_t;

struct cgfile_t {
    char *name;
    char *file;
    int (*get_value)(const char *content, const cgfile_callback_args_t *args, void *result);
};

static int get_value_ll(const char *content, const cgfile_callback_args_t *args, void *result);
static int get_value_ull(const char *content, const cgfile_callback_args_t *args, void *result);
static int get_match_value_ull(const char *content, const cgfile_callback_args_t *args, void *result);
static int get_value_string(const char *content, const cgfile_callback_args_t *args, void *result);

typedef enum {
    // CPU subsystem
    CPU_RT_PERIOD, CPU_RT_RUNTIME, CPU_SHARES, CPU_CFS_PERIOD, CPU_CFS_QUOTA,
    // CPUSET subsystem
    CPUSET_CPUS, CPUSET_MEMS,
    // CPUACCT subsystem
    CPUACCT_USE_NANOS, CPUACCT_USE_USER, CPUACCT_USE_SYS,
    // MEMORY subsystem
    MEMORY_LIMIT, MEMORY_USAGE, MEMORY_SOFT_LIMIT,
    MEMORY_KMEM_LIMIT, MEMORY_KMEM_USAGE,
    MEMORY_SWAPPINESS, MEMORY_SW_LIMIT, MEMORY_SW_USAGE,
    MEMORY_CACHE, MEMORY_CACHE_TOTAL,
    MEMORY_INACTIVE_FILE_TOTAL, MEMORY_OOM_CONTROL,
    // BLKIO subsystem
    BLKIO_WEIGTH, BLKIO_WEIGTH_DEVICE, BLKIO_READ_BPS, BLKIO_WRITE_BPS, BLKIO_READ_IOPS, BLKIO_WRITE_IOPS,
    // PIDS subsystem
    PIDS_CURRENT,
    // MAX
    CGROUP_V1_FILES_INDEX_MAXS
} cgroup_v1_files_index;

static struct cgfile_t g_cgroup_v1_files[] = {
    // CPU subsystem
    [CPU_RT_PERIOD]                 = {"cpu_rt_period",         "cpu.rt_period_us",                 get_value_ull},
    [CPU_RT_RUNTIME]                = {"cpu_rt_runtime",        "cpu.rt_runtime_us",                get_value_ull},
    [CPU_SHARES]                    = {"cpu_shares",            "cpu.shares",                       get_value_ull},
    [CPU_CFS_PERIOD]                = {"cpu_cfs_period",        "cpu.cfs_period_us",                get_value_ull},
    [CPU_CFS_QUOTA]                 = {"cpu_cfs_quota",         "cpu.cfs_quota_us",                 get_value_ll},
    // CPUSET subsystem
    [CPUSET_CPUS]                   = {"cpuset_cpus",           "cpuset.cpus",                      get_value_string},
    [CPUSET_MEMS]                   = {"cpuset_mems",           "cpuset.mems",                      get_value_string},
    // CPUACCT subsystem
    [CPUACCT_USE_NANOS]             = {"cpu_use_nanos",         "cpuacct.usage",                    get_value_ull},
    [CPUACCT_USE_USER]              = {"cpu_use_user",          "cpuacct.stat",                     get_match_value_ull},
    [CPUACCT_USE_SYS]               = {"cpu_use_sys",           "cpuacct.stat",                     get_match_value_ull},
    // MEMORY subsystem
    [MEMORY_LIMIT]                  = {"mem_limit",             "memory.limit_in_bytes",            get_value_ull},
    [MEMORY_USAGE]                  = {"mem_usage",             "memory.usage_in_bytes",            get_value_ull},
    [MEMORY_SOFT_LIMIT]             = {"mem_soft_limit",        "memory.soft_limit_in_bytes",       get_value_ull},
    [MEMORY_KMEM_LIMIT]             = {"kmem_limit",            "memory.kmem.limit_in_bytes",       get_value_ull},
    [MEMORY_KMEM_USAGE]             = {"kmem_usage",            "memory.kmem.usage_in_bytes",       get_value_ull},
    [MEMORY_SWAPPINESS]             = {"swappiness",            "memory.swappiness",                NULL},
    [MEMORY_SW_LIMIT]               = {"memsw_limit",           "memory.memsw.limit_in_bytes",      get_value_ull},
    [MEMORY_SW_USAGE]               = {"memsw_usage",           "memory.memsw.usage_in_bytes",      get_value_ull},
    [MEMORY_CACHE]                  = {"cache",                 "memory.stat",                      get_match_value_ull},
    [MEMORY_CACHE_TOTAL]            = {"cache_total",           "memory.stat",                      get_match_value_ull},
    [MEMORY_INACTIVE_FILE_TOTAL]    = {"inactive_file_total",   "memory.stat",                      get_match_value_ull},
    [MEMORY_OOM_CONTROL]            = {"oom_control",           "memory.oom_control",               NULL},
    // BLKIO subsystem
    [BLKIO_WEIGTH]                  = {"blkio_weigth",          "blkio.weight",                     NULL},
    [BLKIO_WEIGTH_DEVICE]           = {"blkio_weigth_device",   "blkio.weight_device",              NULL},
    [BLKIO_READ_BPS]                = {"blkio_read_bps",        "blkio.throttle.read_bps_device",   NULL},
    [BLKIO_WRITE_BPS]               = {"blkio_write_bps",       "blkio.throttle.write_bps_device",  NULL},
    [BLKIO_READ_IOPS]               = {"blkio_read_iops",       "blkio.throttle.read_iops_device",  NULL},
    [BLKIO_WRITE_IOPS]              = {"blkio_write_iops",      "blkio.throttle.write_iops_device", NULL},
    // PIDS subsystem
    [PIDS_CURRENT]                  = {"pids_current",          "pids.current",                     get_value_ull},
};

static int get_value_ll(const char *content, const cgfile_callback_args_t *args, void *result)
{
    long long ll_result = 0;

    if (util_safe_llong(content, &ll_result) != 0) {
        ERROR("Failed to convert %s to long long", content);
        return -1;
    }

    *(int64_t *)result = (int64_t)ll_result;
    return 0;
}

static int get_value_ull(const char *content, const cgfile_callback_args_t *args, void *result)
{
    uint64_t ull_result = 0;

    if (util_safe_uint64(content, &ull_result) != 0) {
        ERROR("Failed to convert %s to uint64", content);
        return -1;
    }

    *(uint64_t *)result = ull_result;
    return 0;
}

static int get_match_value_ull(const char *content, const cgfile_callback_args_t *args, void *result)
{
    int ret = 0;
    uint64_t llu_result = 0;
    char *llu_string = NULL;
    char *match_with_space = NULL;
    char **lines = NULL;
    char **worker = NULL;

    if (args == NULL || args->match == NULL || strlen(args->match) == 0) {
        ERROR("Invalid arguments");
        return -1;
    }

    // match full string
    match_with_space = util_string_append(" ", args->match);
    if (match_with_space == NULL) {
        ERROR("Failed to append string");
        return -1;
    }

    lines = util_string_split(content, '\n');
    if (lines == NULL) {
        ERROR("Failed to split content %s", content);
        ret = -1;
        goto out;
    }

    for (worker = lines; worker && *worker; worker++) {
        if (util_has_prefix(*worker, match_with_space)) {
            break;
        }
    }
    if (*worker == NULL) {
        ERROR("Cannot find match string %s", args->match);
        ret = -1;
        goto out;
    }

    llu_string = util_sub_string(*worker, strlen(match_with_space), strlen(*worker) - strlen(match_with_space));
    if (llu_string == NULL) {
        ERROR("Failed to sub string");
        ret = -1;
        goto out;
    }
    llu_string = util_trim_space(llu_string);

    ret = util_safe_uint64(llu_string, &llu_result);
    if (ret != 0) {
        ERROR("Failed to convert %s to uint64", llu_string);
    } else {
        *(uint64_t *)result = llu_result;
    }

out:
    free(match_with_space);
    free(llu_string);
    util_free_array(lines);
    return ret;
}

static int get_value_string(const char *content, const cgfile_callback_args_t *args, void *result)
{
    *(char **)result = util_strdup_s(content);
    return 0;
}

static bool check_cgroup_v1_helper(const char *mountpoint, const cgroup_v1_files_index index, const bool quiet)
{
    int nret = 0;
    char path[PATH_MAX] = { 0 };

    if (index >= CGROUP_V1_FILES_INDEX_MAXS) {
        ERROR("Index out of range");
        return false;
    }

    if (mountpoint == NULL) {
        ERROR("%s: invalid arguments", g_cgroup_v1_files[index].name);
        return false;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, g_cgroup_v1_files[index].file);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("%s: failed to snprintf", g_cgroup_v1_files[index].name);
        return false;
    }

    if (util_file_exists(path)) {
        return true;
    }

    if (!quiet) {
        WARN("Your kernel does not support cgroup %s", g_cgroup_v1_files[index].name);
    }

    return false;
}

static int get_cgroup_v1_value_helper(const char *path, const cgroup_v1_files_index index,
                                      const cgfile_callback_args_t *args, void *result)
{
    int nret = 0;
    char file_path[PATH_MAX] = { 0 };
    char real_path[PATH_MAX] = { 0 };
    char *content = NULL;

    if (index >= CGROUP_V1_FILES_INDEX_MAXS) {
        ERROR("Index out of range");
        return false;
    }

    if (path == NULL || strlen(path) == 0 || result == NULL) {
        ERROR("%s: Invalid arguments", g_cgroup_v1_files[index].name);
        return -1;
    }

    nret = snprintf(file_path, sizeof(file_path), "%s/%s", path, g_cgroup_v1_files[index].file);
    if (nret < 0 || (size_t)nret >= sizeof(file_path)) {
        ERROR("%s: failed to snprintf", g_cgroup_v1_files[index].name);
        return -1;
    }

    if (util_clean_path(file_path, real_path, sizeof(real_path)) == NULL) {
        ERROR("%s: failed to clean path %s", g_cgroup_v1_files[index].name, file_path);
        return -1;
    }

    content = util_read_content_from_file(real_path);
    if (content == NULL) {
        ERROR("%s: failed to read file %s", g_cgroup_v1_files[index].name, real_path);
        return -1;
    }

    nret = g_cgroup_v1_files[index].get_value(content, args, result);
    if (nret != 0) {
        ERROR("%s: failed to get value", g_cgroup_v1_files[index].name);
    }

    free(content);
    return nret;
}

static void check_cgroup_v1_cpu(const cgroup_layer_t *layers, const bool quiet, cgroup_cpu_info_t *cpuinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "cpu");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find cpu cgroup in mounts");
        return;
    }

    cpuinfo->cpu_rt_period = check_cgroup_v1_helper(mountpoint, CPU_RT_PERIOD, quiet);
    cpuinfo->cpu_rt_runtime = check_cgroup_v1_helper(mountpoint, CPU_RT_RUNTIME, quiet);
    cpuinfo->cpu_shares = check_cgroup_v1_helper(mountpoint, CPU_SHARES, quiet);
    cpuinfo->cpu_cfs_period = check_cgroup_v1_helper(mountpoint, CPU_CFS_PERIOD, quiet);
    cpuinfo->cpu_cfs_quota = check_cgroup_v1_helper(mountpoint, CPU_CFS_QUOTA, quiet);
}

static void check_cgroup_v1_cpuset(const cgroup_layer_t *layers, const bool quiet, cgroup_cpuset_info_t *cpusetinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "cpuset");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, ("Unable to find cpuset cgroup in mounts"));
        return;
    }

    if (!check_cgroup_v1_helper(mountpoint, CPUSET_CPUS, quiet)) {
        return;
    }
    if (!check_cgroup_v1_helper(mountpoint, CPUSET_MEMS, quiet)) {
        return;
    }

    if (get_cgroup_v1_value_helper(mountpoint, CPUSET_CPUS, NULL, (void *)&cpusetinfo->cpus) != 0) {
        ERROR("Failed to get cgroup cpuset.cpus data");
        return;
    }
    if (get_cgroup_v1_value_helper(mountpoint, CPUSET_MEMS, NULL, (void *)&cpusetinfo->mems) != 0) {
        free(cpusetinfo->cpus);
        cpusetinfo->cpus = NULL;
        ERROR("Failed to get cgroup cpuset.cpus data");
        return;
    }

    cpusetinfo->cpus = util_trim_space(cpusetinfo->cpus);
    cpusetinfo->mems = util_trim_space(cpusetinfo->mems);
    cpusetinfo->cpuset = true;
}

static void check_cgroup_v1_mem(const cgroup_layer_t *layers, const bool quiet, cgroup_mem_info_t *meminfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "memory");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find memory cgroup in mounts");
        return;
    }

    meminfo->limit = check_cgroup_v1_helper(mountpoint, MEMORY_LIMIT, quiet);
    meminfo->swap = check_cgroup_v1_helper(mountpoint, MEMORY_SW_LIMIT, quiet);
    meminfo->reservation = check_cgroup_v1_helper(mountpoint, MEMORY_SOFT_LIMIT, quiet);
    meminfo->oomkilldisable = check_cgroup_v1_helper(mountpoint, MEMORY_OOM_CONTROL, quiet);
    meminfo->swappiness = check_cgroup_v1_helper(mountpoint, MEMORY_SWAPPINESS, quiet);
    meminfo->kernel = check_cgroup_v1_helper(mountpoint, MEMORY_KMEM_LIMIT, quiet);
}

static void check_cgroup_v1_blkio(const cgroup_layer_t *layers, const bool quiet, cgroup_blkio_info_t *blkioinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "blkio");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find blkio cgroup in mounts");
        return;
    }

    blkioinfo->blkio_weight = check_cgroup_v1_helper(mountpoint, BLKIO_WEIGTH, quiet);
    blkioinfo->blkio_weight_device = check_cgroup_v1_helper(mountpoint, BLKIO_WEIGTH_DEVICE, quiet);
    blkioinfo->blkio_read_bps_device = check_cgroup_v1_helper(mountpoint, BLKIO_READ_BPS, quiet);
    blkioinfo->blkio_write_bps_device = check_cgroup_v1_helper(mountpoint, BLKIO_WRITE_BPS, quiet);
    blkioinfo->blkio_read_iops_device = check_cgroup_v1_helper(mountpoint, BLKIO_READ_IOPS, quiet);
    blkioinfo->blkio_write_iops_device = check_cgroup_v1_helper(mountpoint, BLKIO_WRITE_IOPS, quiet);
}

static void check_cgroup_v1_hugetlb(const cgroup_layer_t *layers, const bool quiet, cgroup_hugetlb_info_t *hugetlbinfo)
{
    int nret;
    char *mountpoint = NULL;
    char *defaultpagesize = NULL;
    char hugetlbpath[PATH_MAX] = { 0x00 };

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "hugetlb");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Your kernel does not support cgroup hugetlb limit");
        return;
    }

    defaultpagesize = get_default_huge_page_size();
    if (defaultpagesize == NULL) {
        common_cgroup_do_log(quiet, true, "Your kernel does not support cgroup hugetlb limit");
        return;
    }

    nret = snprintf(hugetlbpath, sizeof(hugetlbpath), "%s/"CGROUP_HUGETLB_LIMIT, mountpoint, defaultpagesize);
    if (nret < 0 || (size_t)nret >= sizeof(hugetlbpath)) {
        ERROR("Failed to snprintf hugetlb path");
        goto free_out;
    }

    hugetlbinfo->hugetlblimit = util_file_exists(hugetlbpath);
    common_cgroup_do_log(quiet, !hugetlbinfo->hugetlblimit, ("Your kernel does not support hugetlb limit"));

free_out:
    free(defaultpagesize);
}

static void check_cgroup_v1_pids(const cgroup_layer_t *layers, const bool quiet, cgroup_pids_info_t *pidsinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "pids");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find pids cgroup in mounts");
        return;
    }

    pidsinfo->pidslimit = true;
}

static void check_cgroup_v1_files(const cgroup_layer_t *layers, const bool quiet, cgroup_files_info_t *filesinfo)
{
    char *mountpoint = NULL;

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "files");
    if (mountpoint == NULL) {
        common_cgroup_do_log(quiet, true, "Unable to find files cgroup in mounts");
        return;
    }

    filesinfo->fileslimit = true;
}

int common_get_cgroup_info_v1(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                              cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                              cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                              cgroup_files_info_t *filesinfo, bool quiet)
{
    cgroup_layer_t *layers = NULL;

    layers = common_cgroup_layers_find();
    if (layers == NULL) {
        ERROR("Failed to parse cgroup information");
        return -1;
    }

    check_cgroup_v1_cpu(layers, quiet, cpuinfo);
    check_cgroup_v1_cpuset(layers, quiet, cpusetinfo);
    check_cgroup_v1_mem(layers, quiet, meminfo);
    check_cgroup_v1_blkio(layers, quiet, blkioinfo);
    check_cgroup_v1_hugetlb(layers, quiet, hugetlbinfo);
    check_cgroup_v1_pids(layers, quiet, pidsinfo);
    check_cgroup_v1_files(layers, quiet, filesinfo);

    common_free_cgroup_layer(layers);

    return 0;
}

static void get_cgroup_v1_metrics_cpu(const cgroup_layer_t *layers, const char *cgroup_path,
                                      cgroup_cpu_metrics_t *cgroup_cpu_metrics)
{
    int nret = 0;
    char *mountpoint = NULL;
    char path[PATH_MAX] = { 0 };
    const cgfile_callback_args_t use_user_arg = {
        .match = "user",
    };
    const cgfile_callback_args_t use_sys_arg = {
        .match = "system",
    };


    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "cpu");
    if (mountpoint == NULL) {
        ERROR("Unable to find cpu cgroup in mounts");
        return;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v1_value_helper(path, CPUACCT_USE_NANOS, NULL, (void *)&cgroup_cpu_metrics->cpu_use_nanos);
    get_cgroup_v1_value_helper(path, CPUACCT_USE_USER, &use_user_arg, (void *)&cgroup_cpu_metrics->cpu_use_user);
    get_cgroup_v1_value_helper(path, CPUACCT_USE_SYS, &use_sys_arg, (void *)&cgroup_cpu_metrics->cpu_use_sys);
}

static void get_cgroup_v1_metrics_memory(const cgroup_layer_t *layers, const char *cgroup_path,
                                         cgroup_mem_metrics_t *cgroup_mem_metrics)
{
    int nret = 0;
    char *mountpoint = NULL;
    char path[PATH_MAX] = { 0 };
    const cgfile_callback_args_t cache_arg = {
        .match = "cache",
    };
    const cgfile_callback_args_t total_cache_arg = {
        .match = "total_cache",
    };

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "memory");
    if (mountpoint == NULL) {
        ERROR("Unable to find cpu cgroup in mounts");
        return;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v1_value_helper(path, MEMORY_LIMIT, NULL, (void *)&cgroup_mem_metrics->mem_limit);
    get_cgroup_v1_value_helper(path, MEMORY_USAGE, NULL, (void *)&cgroup_mem_metrics->mem_used);
    get_cgroup_v1_value_helper(path, MEMORY_KMEM_LIMIT, NULL, (void *)&cgroup_mem_metrics->kmem_limit);
    get_cgroup_v1_value_helper(path, MEMORY_KMEM_USAGE, NULL, (void *)&cgroup_mem_metrics->kmem_used);
    get_cgroup_v1_value_helper(path, MEMORY_SW_LIMIT, NULL, (void *)&cgroup_mem_metrics->memsw_limit);
    get_cgroup_v1_value_helper(path, MEMORY_SW_USAGE, NULL, (void *)&cgroup_mem_metrics->memsw_used);
    get_cgroup_v1_value_helper(path, MEMORY_CACHE, &cache_arg, (void *)&cgroup_mem_metrics->cache);
    get_cgroup_v1_value_helper(path, MEMORY_CACHE_TOTAL, &total_cache_arg, (void *)&cgroup_mem_metrics->cache_total);
}

static void get_cgroup_v1_metrics_pid(const cgroup_layer_t *layers, const char *cgroup_path,
                                      cgroup_pids_metrics_t *cgroup_pids_metrics)
{
    int nret = 0;
    char *mountpoint = NULL;
    char path[PATH_MAX] = { 0 };

    mountpoint = common_find_cgroup_subsystem_mountpoint(layers, "pids");
    if (mountpoint == NULL) {
        ERROR("Unable to find cpu cgroup in mounts");
        return;
    }

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v1_value_helper(path, PIDS_CURRENT, NULL, (void *)&cgroup_pids_metrics->pid_current);
}

int common_get_cgroup_v1_metrics(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics)
{
    cgroup_layer_t *layers = NULL;

    if (cgroup_path == NULL || strlen(cgroup_path) == 0 || cgroup_metrics == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    layers = common_cgroup_layers_find();
    if (layers == NULL) {
        ERROR("Failed to parse cgroup information");
        return -1;
    }

    get_cgroup_v1_metrics_cpu(layers, cgroup_path, &cgroup_metrics->cgcpu_metrics);
    get_cgroup_v1_metrics_memory(layers, cgroup_path, &cgroup_metrics->cgmem_metrics);
    get_cgroup_v1_metrics_pid(layers, cgroup_path, &cgroup_metrics->cgpids_metrics);

    common_free_cgroup_layer(layers);

    return 0;
}

