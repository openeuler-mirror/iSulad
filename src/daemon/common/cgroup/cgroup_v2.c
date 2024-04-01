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
 * Create: 2024-01-16
 * Description: provide cgroup v2 functions
 ******************************************************************************/
#include "cgroup.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/inotify.h>

#include <isula_libutils/auto_cleanup.h>

#include "utils.h"
#include "path.h"
#include "sysinfo.h"
#include "events_sender_api.h"

// Cgroup V2 Item Definition
#define CGROUP2_CPU_WEIGHT "cpu.weight"
#define CGROUP2_CPU_MAX "cpu.max"
#define CGROUP2_CPUSET_CPUS_EFFECTIVE "cpuset.cpus.effective"
#define CGROUP2_CPUSET_MEMS_EFFECTIVE "cpuset.mems.effective"
#define CGROUP2_CPUSET_CPUS "cpuset.cpus"
#define CGROUP2_CPUSET_MEMS "cpuset.mems"
#define CGROUP2_IO_WEIGHT "io.weight"
#define CGROUP2_IO_BFQ_WEIGHT "io.bfq.weight"
#define CGROUP2_IO_MAX "io.max"
#define CGROUP2_MEMORY_MAX "memory.max"
#define CGROUP2_MEMORY_LOW "memory.low"
#define CGROUP2_MEMORY_SWAP_MAX "memory.swap.max"
#define CGROUP2_HUGETLB_MAX "hugetlb.%s.max"
#define CGROUP2_PIDS_MAX "pids.max"
#define CGROUP2_FILES_LIMIT "files.limit"

#define CGROUP2_CONTROLLERS_PATH CGROUP_MOUNTPOINT"/cgroup.controllers"
#define CGROUP2_SUBTREE_CONTROLLER_PATH CGROUP_MOUNTPOINT"/cgroup.subtree_control"
#define CGROUP2_CPUSET_CPUS_EFFECTIVE_PATH CGROUP_MOUNTPOINT"/cpuset.cpus.effective"
#define CGROUP2_CPUSET_MEMS_EFFECTIVE_PATH CGROUP_MOUNTPOINT"/cpuset.mems.effective"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

static int get_value_ull_v2(const char *content, const char *match, void *result)
{
    uint64_t ull_result = 0;
    __isula_auto_free char *tmp_str = util_strdup_s(content);

    tmp_str = util_trim_space(tmp_str);
    if (strcmp(tmp_str, "max") == 0) {
        *(uint64_t *)result = UINT64_MAX;
        return 0;
    }

    if (util_safe_uint64(content, &ull_result) != 0) {
        ERROR("Failed to convert %s to uint64", content);
        return -1;
    }

    *(uint64_t *)result = ull_result;
    return 0;
}

typedef enum {
    // cpu
    CPUACCT_USE_USER, CPUACCT_USE_SYS, CPUACCT_USE_NANOS,
    // MEMORY subsystem
    MEMORY_USAGE, MEMORY_LIMIT, MEMORY_ANON,
    MEMORY_TOTAL_PGFAULT, MEMORY_TOTAL_INACTIVE_FILE, MEMORY_TOTAL_PGMAJFAULT,
    MEMORY_CACHE, MEMORY_CACHE_TOTAL,
    // BLKIO subsystem
    BLKIO_READ_BPS, BLKIO_WRITE_BPS, BLKIO_READ_IOPS, BLKIO_WRITE_IOPS,
    // PIDS subsystem
    PIDS_CURRENT,
    // MAX
    CGROUP_V2_FILES_INDEX_MAXS
} cgroup_v2_files_index;

static struct cgfile_t g_cgroup_v2_files[] = {
    // cpu
    [CPUACCT_USE_USER]              = {"cpu_use_user",          "cpu.stat",        "user_usec",         get_match_value_ull},
    [CPUACCT_USE_SYS]               = {"cpu_use_sys",           "cpu.stat",        "system_usec",       get_match_value_ull},
    [CPUACCT_USE_NANOS]             = {"cpu_use_nanos",         "cpu.stat",        "usage_usec",        get_match_value_ull},
    // memory
    [MEMORY_USAGE]                  = {"mem_usage",             "memory.current",  NULL,                get_value_ull_v2},
    [MEMORY_LIMIT]                  = {"mem_limit",             "memory.max",      NULL,                get_value_ull_v2},
    [MEMORY_ANON]                   = {"mem_anon",              "memory.stat",     "anon",              get_match_value_ull},
    [MEMORY_TOTAL_PGFAULT]          = {"total_page_fault",      "memory.stat",     "pgfault",           get_match_value_ull},
    [MEMORY_TOTAL_PGMAJFAULT]       = {"total_page_majfault",   "memory.stat",     "pgmajfault",        get_match_value_ull},
    [MEMORY_TOTAL_INACTIVE_FILE]    = {"total_inactive_file",   "memory.stat",     "inactive_file",     get_match_value_ull},
    [MEMORY_CACHE]                  = {"cache",                 "memory.stat",     "file",              get_match_value_ull},
    [MEMORY_CACHE_TOTAL]            = {"cache_total",           "memory.stat",     "file",              get_match_value_ull},
    // pids
    [PIDS_CURRENT]                  = {"pids_current",          "pids.current",    NULL,                get_value_ull_v2},
};

static int get_cgroup_v2_value_helper(const char *path, const cgroup_v2_files_index index, void *result)
{
    if (index >= CGROUP_V2_FILES_INDEX_MAXS) {
        ERROR("Index out of range");
        return false;
    }

    return get_cgroup_value_helper(path, &g_cgroup_v2_files[index], result);
}

static void get_cgroup_v2_metrics_cpu(const char *cgroup_path, cgroup_cpu_metrics_t *cgroup_cpu_metrics)
{
    int nret = 0;
    char path[PATH_MAX] = { 0 };

    nret = snprintf(path, sizeof(path), "%s/%s", CGROUP_MOUNTPOINT, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v2_value_helper(path, CPUACCT_USE_NANOS, (void *)&cgroup_cpu_metrics->cpu_use_nanos);
}

static void get_cgroup_v2_metrics_memory(const char *cgroup_path, cgroup_mem_metrics_t *cgroup_mem_metrics)
{
    int nret = 0;
    char path[PATH_MAX] = { 0 };

    nret = snprintf(path, sizeof(path), "%s/%s", CGROUP_MOUNTPOINT, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v2_value_helper(path, MEMORY_LIMIT, (void *)&cgroup_mem_metrics->mem_limit);
    get_cgroup_v2_value_helper(path, MEMORY_USAGE, (void *)&cgroup_mem_metrics->mem_used);
    // Use Anon memory for RSS as cAdvisor on cgroupv2
    // see https://github.com/google/cadvisor/blob/a9858972e75642c2b1914c8d5428e33e6392c08a/container/libcontainer/handler.go#L799
    get_cgroup_v2_value_helper(path, MEMORY_ANON, (void *)&cgroup_mem_metrics->total_rss);
    get_cgroup_v2_value_helper(path, MEMORY_TOTAL_PGFAULT,
                               (void *)&cgroup_mem_metrics->total_pgfault);
    get_cgroup_v2_value_helper(path, MEMORY_TOTAL_PGMAJFAULT,
                               (void *)&cgroup_mem_metrics->total_pgmajfault);
    get_cgroup_v2_value_helper(path, MEMORY_TOTAL_INACTIVE_FILE,
                               (void *)&cgroup_mem_metrics->total_inactive_file);
}

static void get_cgroup_v2_metrics_pid(const char *cgroup_path, cgroup_pids_metrics_t *cgroup_pids_metrics)
{
    int nret = 0;
    char path[PATH_MAX] = { 0 };

    nret = snprintf(path, sizeof(path), "%s/%s", CGROUP_MOUNTPOINT, cgroup_path);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Failed to snprintf");
        return;
    }

    get_cgroup_v2_value_helper(path, PIDS_CURRENT, (void *)&cgroup_pids_metrics->pid_current);
}

static int cgroup2_enable_all()
{
    int ret = 0;
    int nret = 0;
    int n = 0;
    size_t i = 0;
    const char *space = "";
    __isula_auto_free char *controllers_str = NULL;
    __isula_auto_free char *subtree_controller_str = NULL;
    __isula_auto_array_t char **controllers = NULL;
    char enable_controllers[PATH_MAX] = { 0 };

    controllers_str = util_read_content_from_file(CGROUP2_CONTROLLERS_PATH);
    if (controllers_str == NULL || strlen(controllers_str) == 0 || strcmp(controllers_str, "\n") == 0) {
        WARN("no cgroup controller found");
        return ret;
    }

    subtree_controller_str = util_read_content_from_file(CGROUP2_SUBTREE_CONTROLLER_PATH);
    if (subtree_controller_str != NULL && strcmp(controllers_str, subtree_controller_str) == 0) {
        return ret;
    }

    controllers = util_string_split(controllers_str, ' ');
    if (controllers == NULL) {
        ERROR("split %s failed", controllers_str);
        return -1;
    }

    for (i = 0; i < util_array_len((const char **)controllers); i++) {
        nret = snprintf(enable_controllers + n, PATH_MAX - n, "%s+%s", space, controllers[i]);
        if (nret < 0 || (size_t)nret >= PATH_MAX - n) {
            ERROR("Path is too long");
            return -1;
        }
        n += nret;
        space = " ";
    }
    ret = util_write_file(CGROUP2_SUBTREE_CONTROLLER_PATH, enable_controllers, strlen(enable_controllers),
                          DEFAULT_CGROUP_FILE_MODE);
    if (ret != 0) {
        SYSERROR("write %s to %s failed", enable_controllers, CGROUP2_SUBTREE_CONTROLLER_PATH);
        return ret;
    }

    return ret;
}

#if defined (__ANDROID__) || defined(__MUSL__)
static bool cgroup2_no_controller()
{
    char *controllers_str = NULL;

    controllers_str = util_read_content_from_file(CGROUP2_CONTROLLERS_PATH);
    if (controllers_str == NULL || strlen(controllers_str) == 0 || strcmp(controllers_str, "\n") == 0) {
        free(controllers_str);
        return true;
    }

    free(controllers_str);
    return false;
}
#endif

static int make_sure_cgroup2_isulad_path_exist()
{
    int ret = 0;

    if (util_dir_exists(CGROUP_ISULAD_PATH)) {
        return 0;
    }

    if (cgroup2_enable_all() != 0) {
        return -1;
    }

#if defined (__ANDROID__) || defined(__MUSL__)
    if (cgroup2_no_controller()) {
        DEBUG("no cgroup controller found");
        return 0;
    }
#endif

    ret = mkdir(CGROUP_ISULAD_PATH, DEFAULT_CGROUP_DIR_MODE);
    if (ret != 0 && (errno != EEXIST || !util_dir_exists(CGROUP_ISULAD_PATH))) {
        return -1;
    }

    return ret;
}

/* cgroup enabled */
static bool cgroup_v2_enabled(const char *mountpoint, const char *name)
{
    char path[PATH_MAX] = { 0 };
    int nret;

    nret = snprintf(path, sizeof(path), "%s/%s", mountpoint, name);
    if (nret < 0 || (size_t)nret >= sizeof(path)) {
        ERROR("Path is too long");
        return false;
    }
    return util_file_exists(path);
}

static void get_cgroup_v2_cpu_info(const bool quiet, cgroup_cpu_info_t *cpuinfo)
{
    cpuinfo->cpu_shares = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPU_WEIGHT);
    common_cgroup_do_log(quiet, !(cpuinfo->cpu_shares), "Your kernel does not support cgroup2 cpu weight");

    cpuinfo->cpu_cfs_period = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPU_MAX);
    cpuinfo->cpu_cfs_quota = cpuinfo->cpu_cfs_period;
    common_cgroup_do_log(quiet, !(cpuinfo->cpu_cfs_period), "Your kernel does not support cgroup2 cpu max");
}

static int get_cgroup_v2_cpuset_info(const bool quiet, cgroup_cpuset_info_t *cpusetinfo)
{
    cpusetinfo->cpuset = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_CPUS_EFFECTIVE) &&
                         cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_CPUS) &&
                         cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_MEMS_EFFECTIVE) &&
                         cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_CPUSET_MEMS);
    common_cgroup_do_log(quiet, !(cpusetinfo->cpuset), "Your kernel does not support cpuset");
    if (cpusetinfo->cpuset) {
        cpusetinfo->cpus = util_read_content_from_file(CGROUP2_CPUSET_CPUS_EFFECTIVE_PATH);
        cpusetinfo->mems = util_read_content_from_file(CGROUP2_CPUSET_MEMS_EFFECTIVE_PATH);
        if (cpusetinfo->cpus == NULL || cpusetinfo->mems == NULL) {
            ERROR("read cpus or mems failed");
            return -1;
        }
        cpusetinfo->cpus = util_trim_space(cpusetinfo->cpus);
        cpusetinfo->mems = util_trim_space(cpusetinfo->mems);
    }
    return 0;
}

static void get_cgroup_v2_mem_info(const bool quiet, cgroup_mem_info_t *meminfo)
{
    meminfo->limit = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_MAX);
    common_cgroup_do_log(quiet, !(meminfo->limit), "Your kernel does not support cgroup2 memory max");

    meminfo->reservation = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_LOW);
    common_cgroup_do_log(quiet, !(meminfo->reservation), "Your kernel does not support cgroup2 memory low");

    meminfo->swap = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_MEMORY_SWAP_MAX);
    common_cgroup_do_log(quiet, !(meminfo->swap), "Your kernel does not support cgroup2 memory swap max");
}

static void get_cgroup_v2_blkio_info(const bool quiet, cgroup_blkio_info_t *blkioinfo)
{
    blkioinfo->blkio_weight = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_IO_BFQ_WEIGHT) ||
                              cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_IO_WEIGHT);
    blkioinfo->blkio_weight_device = blkioinfo->blkio_weight;
    common_cgroup_do_log(quiet, !(blkioinfo->blkio_weight), "Your kernel does not support cgroup2 io weight");

    blkioinfo->blkio_read_bps_device = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_IO_MAX);
    blkioinfo->blkio_write_bps_device = blkioinfo->blkio_read_bps_device;
    blkioinfo->blkio_read_iops_device = blkioinfo->blkio_read_bps_device;
    blkioinfo->blkio_write_iops_device = blkioinfo->blkio_read_bps_device;
    common_cgroup_do_log(quiet, !(blkioinfo->blkio_read_bps_device), "Your kernel does not support cgroup2 io max");
}

static int get_cgroup_v2_hugetlb_info(const bool quiet, cgroup_hugetlb_info_t *hugetlbinfo)
{
    __isula_auto_free char *size = NULL;
    int nret = 0;
    char path[PATH_MAX] = { 0 };

    size = get_default_huge_page_size();
    if (size != NULL) {
        nret = snprintf(path, sizeof(path), CGROUP2_HUGETLB_MAX, size);
        if (nret < 0 || (size_t)nret >= sizeof(path)) {
            WARN("Failed to print hugetlb path");
            return -1;
        }
        hugetlbinfo->hugetlblimit = cgroup_v2_enabled(CGROUP_ISULAD_PATH, path);
        common_cgroup_do_log(quiet, !hugetlbinfo->hugetlblimit, "Your kernel does not support cgroup2 hugetlb limit");
    } else {
        WARN("Your kernel does not support cgroup2 hugetlb limit");
    }
    return 0;
}

static void get_cgroup_v2_pids_info(const bool quiet, cgroup_pids_info_t *pidsinfo)
{
    pidsinfo->pidslimit = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_PIDS_MAX);
    common_cgroup_do_log(quiet, !(pidsinfo->pidslimit), "Your kernel does not support cgroup2 pids max");

}

static void get_cgroup_v2_files_info(const bool quiet, cgroup_files_info_t *filesinfo)
{
    filesinfo->fileslimit = cgroup_v2_enabled(CGROUP_ISULAD_PATH, CGROUP2_FILES_LIMIT);
    common_cgroup_do_log(quiet, !(filesinfo->fileslimit), "Your kernel does not support cgroup2 files limit");

}

static int get_cgroup_info_v2(cgroup_mem_info_t *meminfo, cgroup_cpu_info_t *cpuinfo,
                              cgroup_hugetlb_info_t *hugetlbinfo, cgroup_blkio_info_t *blkioinfo,
                              cgroup_cpuset_info_t *cpusetinfo, cgroup_pids_info_t *pidsinfo,
                              cgroup_files_info_t *filesinfo, bool quiet)
{
    int ret = 0;
    if (make_sure_cgroup2_isulad_path_exist() != 0) {
        return -1;
    }

    get_cgroup_v2_cpu_info(quiet, cpuinfo);

    ret = get_cgroup_v2_cpuset_info(quiet, cpusetinfo);
    if (ret != 0) {
        return ret;
    }

    get_cgroup_v2_mem_info(quiet, meminfo);
    get_cgroup_v2_blkio_info(quiet, blkioinfo);

    ret = get_cgroup_v2_hugetlb_info(quiet, hugetlbinfo);
    if (ret != 0) {
        return ret;
    }
    
    get_cgroup_v2_pids_info(quiet, pidsinfo);
    get_cgroup_v2_files_info(quiet, filesinfo);

    return 0;
}

static int get_cgroup_metrics_v2(const char *cgroup_path, cgroup_metrics_t *cgroup_metrics)
{
    if (cgroup_path == NULL || strlen(cgroup_path) == 0 || cgroup_metrics == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    get_cgroup_v2_metrics_cpu(cgroup_path, &cgroup_metrics->cgcpu_metrics);
    get_cgroup_v2_metrics_memory(cgroup_path, &cgroup_metrics->cgmem_metrics);
    get_cgroup_v2_metrics_pid(cgroup_path, &cgroup_metrics->cgpids_metrics);

    return 0;
}

static int get_cgroup_mnt_and_root_v2(const char *subsystem, char **mountpoint, char **root)
{
    if (mountpoint != NULL) {
        *mountpoint = util_strdup_s(CGROUP_ISULAD_PATH);
    }
    return 0;
}

static bool oom_cb_cgroup_v2(int fd, void *cbdata)
{
    const size_t events_size = sizeof(struct inotify_event) + NAME_MAX + 1;
    char events[events_size];
    cgroup_oom_handler_info_t *info = (cgroup_oom_handler_info_t *)cbdata;

    if (info == NULL) {
        ERROR("Invalid callback data");
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    ssize_t num_read = util_read_nointr(fd, &events, events_size);
    if (num_read < 0) {
        ERROR("Failed to read oom event from eventfd in v2");
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    if (((struct inotify_event *)events)->mask & ( IN_DELETE | IN_DELETE_SELF)) {
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    __isula_auto_file FILE *fp = fopen(info->cgroup_memory_event_path, "re");
    if (fp == NULL) {
        ERROR("Failed to open cgroups file: %s", info->cgroup_memory_event_path);
        return CGROUP_OOM_HANDLE_CLOSE;
    }

    __isula_auto_free char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, fp)) != -1) {
        int count;
        const char *oom_str = "oom ";
        const char *oom_kill_str = "oom_kill ";
        const int oom_len = strlen(oom_str), oom_kill_len = strlen(oom_kill_str);

        if (read >= oom_kill_len + 2 && memcmp(line, oom_kill_str, oom_kill_len) == 0) {
            len = oom_kill_len;
        } else if (read >= oom_len + 2 && memcmp(line, oom_str, oom_len) == 0) {
            len = oom_len;
        } else {
            continue;
        }

        // to make use of util_safe_int, it requires it ends with '\0'
        line[strcspn(line, "\n")] = '\0';
        if (util_safe_int(&line[len], &count) < 0) {
            ERROR("Failed to parse: %s", &line[len]);
            continue;
        }

        if (count == 0) {
            continue;
        }

        INFO("OOM event detected in cgroup v2");
        (void)isulad_monitor_send_container_event(info->name, OOM, -1, 0, NULL, NULL);

        return CGROUP_OOM_HANDLE_CLOSE;
    }

    return CGROUP_OOM_HANDLE_CONTINUE;
}

static char *get_real_cgroup_path_v2(const char *cgroup_path)
{
    __isula_auto_free char *converted_cgroup_path = NULL;
    converted_cgroup_path = common_convert_cgroup_path(cgroup_path);
    if (converted_cgroup_path == NULL) {
        ERROR("Failed to convert cgroup path");
        return NULL;
    }

    return util_path_join(CGROUP_MOUNTPOINT, converted_cgroup_path);
}

cgroup_oom_handler_info_t *get_cgroup_oom_handler_v2(int fd, const char *name, const char *cgroup_path, const char *exit_fifo)
{
    __isula_auto_free char *real_cgroup_path = NULL;
    if (name == NULL || cgroup_path == NULL || exit_fifo == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    cgroup_oom_handler_info_t *info = util_common_calloc_s(sizeof(cgroup_oom_handler_info_t));
    if (info == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    info->name = util_strdup_s(name);
    info->oom_event_fd = -1;
    info->cgroup_file_fd = -1;
    info->oom_event_handler = oom_cb_cgroup_v2;

    real_cgroup_path = get_real_cgroup_path_v2(cgroup_path);
    if (real_cgroup_path == NULL) {
        ERROR("Failed to transfer cgroup path: %s", cgroup_path);
        goto cleanup;
    }

    info->cgroup_memory_event_path = util_path_join(real_cgroup_path, "memory.events");
    if (info->cgroup_memory_event_path == NULL) {
        ERROR("Failed to join path");
        goto cleanup;
    }

    if ((info->oom_event_fd = inotify_init()) < 0) {
        ERROR("Failed to init inotify fd");
        goto cleanup;
    }

    if (inotify_add_watch(info->oom_event_fd, info->cgroup_memory_event_path, IN_MODIFY) < 0) {
        ERROR("Failed to watch inotify fd for %s", info->cgroup_memory_event_path);
        goto cleanup;
    }

    // watch exit fifo for container exit, so we can close the inotify fd
    // because inotify cannot watch cgroup file delete event
    if (inotify_add_watch(info->oom_event_fd, exit_fifo, IN_DELETE | IN_DELETE_SELF) < 0) {
        ERROR("Failed to watch inotify fd for %s", exit_fifo);
        goto cleanup;
    }

    return info;

cleanup:
    common_free_cgroup_oom_handler_info(info);
    return NULL;
}

int get_cgroup_version_v2()
{
    return CGROUP_VERSION_2;
}

int cgroup_v2_ops_init(cgroup_ops *ops)
{
    if (ops == NULL) {
        return -1;
    }
    ops->get_cgroup_version = get_cgroup_version_v2;
    ops->get_cgroup_info = get_cgroup_info_v2;
    ops->get_cgroup_metrics = get_cgroup_metrics_v2;
    ops->get_cgroup_mnt_and_root_path = get_cgroup_mnt_and_root_v2;
    ops->get_cgroup_oom_handler = get_cgroup_oom_handler_v2;
    return 0;
}