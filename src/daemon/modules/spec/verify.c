/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container verify functions
 ******************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "verify.h"
#include <sys/utsname.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <errno.h>
#include <fcntl.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_runtime_config_linux.h>
#include <isula_libutils/oci_runtime_spec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/oom.h>
#include <inttypes.h>

#include "constants.h"
#include "err_msg.h"
#include "isula_libutils/log.h"
#include "sysinfo.h"
#include "selinux_label.h"
#include "image_api.h"
#include "utils.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils_verify.h"

/* verify hook timeout */
static int verify_hook_timeout(int t)
{
    if (t < 0) {
        ERROR("Hook spec timeout invalid");
        isulad_set_error_message("Invalid timeout: %d", t);
        return -1;
    }

    return 0;
}

/* verify hook path */

static int verify_hook_root_and_no_other(const struct stat *st, const char *path)
{
    /* validate file owner */
    if (st->st_uid != 0) {
        ERROR("Hook file %s isn't right,file owner should be root", path);
        isulad_set_error_message("Hook file %s isn't right,file owner should be root", path);
        return -1;
    }

    /* validate file if can be written by other user */
    if (st->st_mode & S_IWOTH) {
        ERROR("Hook path %s isn't right,file should not be written by non-root", path);
        isulad_set_error_message("%s should not be written by non-root", path);
        return -1;
    }
    return 0;
}

static int verify_hook_path(const char *path)
{
    int ret = 0;
    struct stat st;

    /* validate absolute path */
    ret = util_validate_absolute_path(path);
    if (ret != 0) {
        ERROR("Hook path %s must be an absolute path", path);
        isulad_set_error_message("%s is not an absolute path", path);
        goto out;
    }

    ret = stat(path, &st);
    /* validate file exits */
    if (ret < 0) {
        ERROR("Hook path %s isn't exist", path);
        isulad_set_error_message("Cann't find path: %s", path);
        ret = -1;
        goto out;
    }

    if (verify_hook_root_and_no_other(&st, path) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int verify_hook_conf(const defs_hook *p)
{
    int ret = 0;
    /* validate hookpath */
    ret = verify_hook_path(p->path);
    if (ret != 0) {
        goto out;
    }
    /* validate timeout */
    ret = verify_hook_timeout(p->timeout);
out:
    return ret;
}

static inline bool is_mem_limit_minimum(int64_t limit)
{
    /* It's not kernel limit, we want this 4M limit to supply a reasonable functional container */
#define LINUX_MIN_MEMORY 4194304

    return limit != 0 && limit < LINUX_MIN_MEMORY;
}

/* check memroy limit and memory swap */
static int verify_mem_limit_swap(const sysinfo_t *sysinfo, int64_t limit, int64_t swap, bool update)
{
    int ret = 0;

    /* check the minimum memory limit */
    if (is_mem_limit_minimum(limit)) {
        ERROR("Minimum memory limit allowed is 4MB");
        isulad_set_error_message("Minimum memory limit allowed is 4MB");
        ret = -1;
        goto out;
    }

    if (limit > 0 && !(sysinfo->cgmeminfo.limit)) {
        ERROR("Your kernel does not support memory limit capabilities. Limitation discarded.");
        isulad_set_error_message("Your kernel does not support memory limit capabilities. Limitation discarded.");
        ret = -1;
        goto out;
    }

    if (limit > 0 && swap != 0 && !(sysinfo->cgmeminfo.swap)) {
        ERROR("Your kernel does not support swap limit capabilities, memory limited without swap.");
        isulad_set_error_message("Your kernel does not support swap limit capabilities, memory limited without swap.");
        ret = -1;
        goto out;
    }

    if (limit > 0 && swap > 0 && swap < limit) {
        ERROR("Minimum memoryswap limit should be larger than memory limit, see usage.");
        isulad_set_error_message("Minimum memoryswap limit should be larger than memory limit");
        ret = -1;
        goto out;
    }

    if (limit == 0 && swap > 0 && !update) {
        ERROR("You should always set the Memory limit when using Memoryswap limit, see usage.");
        isulad_set_error_message("You should set the memory limit when using memoryswap limit");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static inline bool is_swappiness_invalid(uint64_t swapiness)
{
    return (int64_t)swapiness < -1 || (int64_t)swapiness > 100;
}

/* verify memory swappiness */
static int verify_memory_swappiness(const sysinfo_t *sysinfo, uint64_t swapiness)
{
    int ret = 0;

    if ((int64_t)swapiness != -1 && !(sysinfo->cgmeminfo.swappiness)) {
        ERROR("Your kernel does not support memory swappiness capabilities, memory swappiness discarded.");
        isulad_set_error_message(
            "Your kernel does not support memory swappiness capabilities, memory swappiness discarded.");
        ret = -1;
        goto out;
    }

    if (is_swappiness_invalid(swapiness)) {
        ERROR("Invalid value: %lld, valid memory swappiness range is 0-100", (long long)swapiness);
        isulad_set_error_message("Invalid value: %lld, valid memory swappiness range is 0-100", (long long)swapiness);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* verify memory reservation */
static int verify_memory_reservation(const sysinfo_t *sysinfo, int64_t limit, int64_t reservation)
{
    int ret = 0;

    if (reservation > 0 && !(sysinfo->cgmeminfo.reservation)) {
        ERROR("Your kernel does not support memory soft limit capabilities. Limitation discarded");
        isulad_set_error_message("Your kernel does not support memory soft limit capabilities. Limitation discarded");
        ret = -1;
        goto out;
    }

    /* check the minimum memory limit */
    if (is_mem_limit_minimum(reservation)) {
        ERROR("Minimum memory reservation allowed is 4MB");
        isulad_set_error_message("Minimum memory reservation allowed is 4MB");
        ret = -1;
        goto out;
    }

    if (limit > 0 && reservation > 0 && limit < reservation) {
        ERROR("Minimum memory limit should be larger than memory reservation limit, see usage.");
        isulad_set_error_message("Minimum memory limit should be larger than memory reservation limit, see usage.");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* check kernel version */
static bool check_kernel_version(const char *version)
{
    struct utsname uts;
    int ret;

    ret = uname(&uts);
    if (ret < 0) {
        WARN("Can not get kernel version: %s", strerror(errno));
    } else {
        if (strverscmp(uts.release, version) < 0) {
            return false;
        }
    }
    return true;
}

/* verify memory kernel */
static int verify_memory_kernel(const sysinfo_t *sysinfo, int64_t kernel)
{
    int ret = 0;

    if (kernel > 0 && !(sysinfo->cgmeminfo.kernel)) {
        ERROR("Your kernel does not support kernel memory limit capabilities. Limitation discarded.");
        isulad_set_error_message(
            "Your kernel does not support kernel memory limit capabilities. Limitation discarded.");
        ret = -1;
        goto out;
    }

    if (is_mem_limit_minimum(kernel)) {
        ERROR("Minimum kernel memory limit allowed is 4MB");
        isulad_set_error_message("Minimum kernel memory limit allowed is 4MB");
        ret = -1;
        goto out;
    }

    if (kernel > 0 && !check_kernel_version("4.0.0")) {
        WARN("You specified a kernel memory limit on a kernel older than 4.0. "
             "Kernel memory limits are experimental on older kernels, "
             "it won't work as expected and can cause your system to be unstable.");
    }

out:
    return ret;
}

/* verify pids limit */
static int verify_pids_limit(const sysinfo_t *sysinfo, int64_t pids_limit)
{
    int ret = 0;

    if (pids_limit != 0 && !(sysinfo->pidsinfo.pidslimit)) {
        ERROR("Your kernel does not support pids limit capabilities, pids limit discarded.");
        isulad_set_error_message("Your kernel does not support pids limit capabilities, pids limit discarded.");
        ret = -1;
    }
    return ret;
}

/* verify files limit */
static int verify_files_limit(const sysinfo_t *sysinfo, int64_t files_limit)
{
    int ret = 0;

    if (files_limit != 0 && !(sysinfo->filesinfo.fileslimit)) {
        ERROR("Your kernel does not support files limit capabilities, files limit discarded.");
        isulad_set_error_message("Your kernel does not support files limit capabilities, files limit discarded.");
        ret = -1;
    }
    return ret;
}

/* verify oom control */
static int verify_oom_control(const sysinfo_t *sysinfo, bool oomdisable)
{
    int ret = 0;

    if (oomdisable && !(sysinfo->cgmeminfo.oomkilldisable)) {
        ERROR("Your kernel does not support OomKillDisable, OomKillDisable discarded");
        isulad_set_error_message("Your kernel does not support OomKillDisable, OomKillDisable discarded");
        ret = -1;
    }

    return ret;
}

/* verify resources memory */
static int verify_resources_memory(const sysinfo_t *sysinfo, const defs_resources_memory *memory)
{
    int ret = 0;

    ret = verify_mem_limit_swap(sysinfo, memory->limit, memory->swap, false);
    if (ret != 0) {
        goto out;
    }

    ret = verify_memory_swappiness(sysinfo, memory->swappiness);
    if (ret != 0) {
        goto out;
    }

    ret = verify_memory_reservation(sysinfo, memory->limit, memory->reservation);
    if (ret != 0) {
        goto out;
    }

    ret = verify_memory_kernel(sysinfo, memory->kernel);
    if (ret != 0) {
        goto out;
    }

    ret = verify_oom_control(sysinfo, memory->disable_oom_killer);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

/* verify resources pids */
static int verify_resources_pids(const sysinfo_t *sysinfo, const defs_resources_pids *pids)
{
    int ret = 0;

    ret = verify_pids_limit(sysinfo, pids->limit);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

// ValidateResources performs platform specific validation of the resource settings
// cpu-rt-runtime and cpu-rt-period can not be greater than their parent, cpu-rt-runtime requires sys_nice
static int verify_cpu_realtime(const sysinfo_t *sysinfo, int64_t realtime_period, int64_t realtime_runtime)
{
    int ret = 0;

    if (realtime_period > 0 && !(sysinfo->cgcpuinfo.cpu_rt_period)) {
        ERROR("Invalid --cpu-rt-period: Your kernel does not support cgroup rt period");
        isulad_set_error_message("Invalid --cpu-rt-period: Your kernel does not support cgroup rt period");
        ret = -1;
        goto out;
    }

    if (realtime_runtime > 0 && !(sysinfo->cgcpuinfo.cpu_rt_runtime)) {
        ERROR("Invalid --cpu-rt-runtime: Your kernel does not support cgroup rt runtime");
        isulad_set_error_message("Invalid --cpu-rt-period: Your kernel does not support cgroup rt runtime");
        ret = -1;
        goto out;
    }

    if (realtime_period != 0 && realtime_runtime != 0 && realtime_runtime > realtime_period) {
        ERROR("Invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period");
        isulad_set_error_message("Invalid --cpu-rt-runtime: rt runtime cannot be higher than rt period");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* verify cpu shares */
static int verify_cpu_shares(const sysinfo_t *sysinfo, int64_t cpu_shares)
{
    int ret = 0;

    if (cpu_shares > 0 && !(sysinfo->cgcpuinfo.cpu_shares)) {
        ERROR("Your kernel does not support cgroup cpu shares. Shares discarded.");
        isulad_set_error_message("Your kernel does not support cgroup cpu shares. Shares discarded.");
        ret = -1;
    }

    return ret;
}

static int verify_cpu_cfs_period(const sysinfo_t *sysinfo, int64_t cpu_cfs_period)
{
    int ret = 0;

    if (cpu_cfs_period > 0 && !(sysinfo->cgcpuinfo.cpu_cfs_period)) {
        ERROR("Your kernel does not support CPU cfs period. Period discarded.");
        isulad_set_error_message("Your kernel does not support CPU cfs period. Period discarded.");
        ret = -1;
        goto out;
    }

    if (cpu_cfs_period > 0 && cpu_cfs_period < 1000) {
        ERROR("CPU cfs period can not be less than 1ms (i.e. 1000)");
        isulad_set_error_message("CPU cfs period can not be less than 1ms (i.e. 1000)");
        ret = -1;
        goto out;
    }

    if (cpu_cfs_period > 1000000) {
        ERROR("CPU cfs period can not be more than 1s (i.e. 1000000)");
        isulad_set_error_message("CPU cfs period can not be more than 1s (i.e. 1000000)");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static inline bool is_cpu_cfs_quota_invalid(int64_t cpu_cfs_quota)
{
    return cpu_cfs_quota > 0 && cpu_cfs_quota < 1000;
}

static int verify_cpu_cfs_quota(const sysinfo_t *sysinfo, int64_t cpu_cfs_quota)
{
    int ret = 0;

    if (cpu_cfs_quota > 0 && !(sysinfo->cgcpuinfo.cpu_cfs_quota)) {
        ERROR("Your kernel does not support CPU cfs quato. Quota discarded.");
        isulad_set_error_message("Your kernel does not support CPU cfs quato. Quota discarded.");
        ret = -1;
        goto out;
    }

    if (is_cpu_cfs_quota_invalid(cpu_cfs_quota)) {
        ERROR("CPU cfs quota can not be less than 1ms (i.e. 1000)");
        isulad_set_error_message("CPU cfs quota can not be less than 1ms (i.e. 1000)");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* verify cpu cfs scheduler */
static int verify_cpu_cfs_scheduler(const sysinfo_t *sysinfo, int64_t cpu_cfs_period, int64_t cpu_cfs_quota)
{
    int ret = 0;

    ret = verify_cpu_cfs_period(sysinfo, cpu_cfs_period);
    if (ret != 0) {
        goto out;
    }

    ret = verify_cpu_cfs_quota(sysinfo, cpu_cfs_quota);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

/* max cpu */
int max_cpu(const char *cores)
{
    int max = -1;
    char *str = NULL;
    char *tmp = NULL;
    char *chr = NULL;

    str = util_strdup_s(cores);
    if (str == NULL) {
        goto out;
    }
    tmp = str;
    chr = strchr(tmp, ',');
    for (; chr != NULL || *tmp != '\0'; chr = strchr(tmp, ',')) {
        char *subchr = NULL;
        int value = 0;
        if (chr != NULL) {
            *chr++ = '\0';
        }
        subchr = strchr(tmp, '-');
        if (subchr != NULL) {
            *subchr++ = '\0';
        } else {
            subchr = tmp;
        }
        if (util_safe_int(subchr, &value) || value < 0) {
            max = -1;
            goto out;
        }

        if (value > max) {
            max = value;
        }
        if (chr != NULL) {
            tmp = chr;
        } else {
            break;
        }
    }
out:
    free(str);
    return max;
}

/* check cpu */
static bool check_cpu(const char *provided, const char *available)
{
    int max_available = 0;
    int max_request = 0;
    if (provided == NULL) {
        return true;
    }
    max_available = max_cpu(available);
    max_request = max_cpu(provided);
    if (max_available == -1 || max_request == -1) {
        ERROR("failed to get the number of cpus");
        return false;
    }
    if (max_request > max_available) {
        ERROR("invalid maxRequest is %d, max available: %d", max_request, max_available);
        isulad_set_error_message("invalid maxRequest is %d, max available: %d", max_request, max_available);
        return false;
    }
    return true;
}

/* parse unit list */
int parse_unit_list(const char *val, bool *available_list, int cpu_num)
{
    int ret = -1;
    char *str = NULL;
    char *tmp = NULL;
    char *chr = NULL;
    if (val == NULL) {
        return 0;
    }
    str = util_strdup_s(val);
    tmp = str;
    chr = strchr(tmp, ',');
    for (; chr != NULL || *tmp != '\0'; chr = strchr(tmp, ',')) {
        char *subchr = NULL;
        if (chr != NULL) {
            *chr++ = '\0';
        }
        subchr = strchr(tmp, '-');
        if (subchr == NULL) {
            int value = 0;
            if (util_safe_int(tmp, &value) || value < 0 || value >= cpu_num) {
                goto out;
            }
            available_list[value] = true;
        } else {
            int min = 0;
            int max = 0;
            int i = 0;
            *subchr++ = '\0';
            if (util_safe_int(tmp, &min) || min < 0) {
                goto out;
            }
            if (util_safe_int(subchr, &max) || max < 0 || max >= cpu_num) {
                goto out;
            }
            for (i = min; i <= max; i++) {
                available_list[i] = true;
            }
        }
        if (chr != NULL) {
            tmp = chr;
        } else {
            break;
        }
    }
    ret = 0;
out:
    free(str);
    return ret;
}

/* is cpuset list available */
static bool is_cpuset_list_available(const char *provided, const char *available)
{
    int cpu_num = 0;
    int i = 0;
    bool ret = false;
    bool *parsed_provided = NULL;
    bool *parsed_available = NULL;
    sysinfo_t *sysinfo = NULL;

    sysinfo = get_sys_info(true);
    if (sysinfo == NULL) {
        ERROR("get sysinfo failed");
        return false;
    }

    cpu_num = sysinfo->ncpus;
    if ((size_t)cpu_num > SIZE_MAX / sizeof(bool)) {
        ERROR("invalid cpu num");
        goto out;
    }
    parsed_provided = util_common_calloc_s(sizeof(bool) * (unsigned int)cpu_num);
    if (parsed_provided == NULL) {
        ERROR("memory alloc failed!");
        goto out;
    }
    parsed_available = util_common_calloc_s(sizeof(bool) * (unsigned int)cpu_num);
    if (parsed_available == NULL) {
        ERROR("memory alloc failed!");
        goto out;
    }

    if (!check_cpu(provided, available)) {
        goto out;
    }

    if (parse_unit_list(provided, parsed_provided, cpu_num) < 0 ||
        parse_unit_list(available, parsed_available, cpu_num) < 0) {
        goto out;
    }
    for (i = 0; i < cpu_num; i++) {
        if (!parsed_provided[i] || parsed_available[i]) {
            continue;
        }
        goto out;
    }
    ret = true;
out:
    free(parsed_provided);
    free(parsed_available);
    return ret;
}

/* is cpuset cpus available */
bool is_cpuset_cpus_available(const sysinfo_t *sysinfo, const char *cpus)
{
    bool ret = false;
    ret = is_cpuset_list_available(cpus, sysinfo->cpusetinfo.cpus);
    if (!ret) {
        ERROR("Checking cpuset.cpus got invalid format: %s.", cpus);
        isulad_set_error_message("Checking cpuset.cpus got invalid format: %s.", cpus);
    }
    return ret;
}

/* is cpuset mems available */
bool is_cpuset_mems_available(const sysinfo_t *sysinfo, const char *mems)
{
    bool ret = false;
    ret = is_cpuset_list_available(mems, sysinfo->cpusetinfo.mems);
    if (!ret) {
        ERROR("Checking cpuset.mems got invalid format: %s.", mems);
        isulad_set_error_message("Checking cpuset.mems got invalid format: %s.", mems);
    }
    return ret;
}

// cpuset subsystem checks and adjustments
static int verify_resources_cpuset(const sysinfo_t *sysinfo, const char *cpus, const char *mems)
{
    int ret = 0;
    bool cpus_available = false;
    bool mems_available = false;

    if (cpus != NULL && !(sysinfo->cpusetinfo.cpuset)) {
        ERROR("Your kernel does not support cpuset. Cpuset discarded.");
        isulad_set_error_message("Your kernel does not support cpuset. Cpuset discarded.");
        ret = -1;
        goto out;
    }

    if (mems != NULL && !(sysinfo->cpusetinfo.cpuset)) {
        ERROR("Your kernel does not support cpuset. Cpuset discarded.");
        isulad_set_error_message("Your kernel does not support cpuset. Cpuset discarded.");
        ret = -1;
        goto out;
    }

    cpus_available = is_cpuset_cpus_available(sysinfo, cpus);
    if (!cpus_available) {
        ERROR("Requested CPUs are not available - requested %s, available: %s.", cpus, sysinfo->cpusetinfo.cpus);
        isulad_set_error_message("Requested CPUs are not available - requested %s, available: %s.", cpus,
                                 sysinfo->cpusetinfo.cpus);
        ret = -1;
        goto out;
    }

    mems_available = is_cpuset_mems_available(sysinfo, mems);
    if (!mems_available) {
        ERROR("Requested memory nodes are not available - requested %s, available: %s.", mems,
              sysinfo->cpusetinfo.mems);
        isulad_set_error_message("Requested memory nodes are not available - requested %s, available: %s.", mems,
                                 sysinfo->cpusetinfo.mems);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* verify resources cpu */
static int verify_resources_cpu(const sysinfo_t *sysinfo, const defs_resources_cpu *cpu)
{
    int ret = 0;

    ret = verify_cpu_realtime(sysinfo, (int64_t)(cpu->realtime_period), cpu->realtime_runtime);
    if (ret != 0) {
        goto out;
    }

    ret = verify_cpu_shares(sysinfo, (int64_t)(cpu->shares));
    if (ret != 0) {
        goto out;
    }

    ret = verify_cpu_cfs_scheduler(sysinfo, (int64_t)(cpu->period), cpu->quota);
    if (ret != 0) {
        goto out;
    }

    ret = verify_resources_cpuset(sysinfo, cpu->cpus, cpu->mems);
    if (ret != 0) {
        goto out;
    }
out:
    return ret;
}

static inline bool is_blkio_weight_invalid(int weight)
{
    return weight > 0 && (weight < 10 || weight > 1000);
}

/* verify blkio weight */
static int verify_blkio_weight(const sysinfo_t *sysinfo, int weight)
{
    int ret = 0;

    if (weight > 0 && !(sysinfo->blkioinfo.blkio_weight)) {
        ERROR("Your kernel does not support Block I/O weight. Weight discarded.");
        isulad_set_error_message("Your kernel does not support Block I/O weight. Weight discarded.");
        ret = -1;
        goto out;
    }
    if (is_blkio_weight_invalid(weight)) {
        ERROR("Range of blkio weight is from 10 to 1000.");
        isulad_set_error_message("Range of blkio weight is from 10 to 1000.");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* verify blkio device */
static int verify_blkio_device(const sysinfo_t *sysinfo, const defs_block_io_device_weight **weight_device,
                               size_t weight_device_len)
{
    int ret = 0;
    size_t i = 0;

    if (weight_device_len > 0 && !(sysinfo->blkioinfo.blkio_weight_device)) {
        ERROR("Your kernel does not support Block I/O weight_device.");
        isulad_set_error_message("Your kernel does not support Block I/O weight_device.");
        ret = -1;
    }

    for (i = 0; i < weight_device_len; i++) {
        if (is_blkio_weight_invalid(weight_device[i]->weight)) {
            ERROR("Range of blkio weight is from 10 to 1000.");
            isulad_set_error_message("Range of blkio weight is from 10 to 1000.");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

/* verify oom score adj */
static int verify_oom_score_adj(int oom_score_adj)
{
    int ret = 0;
    if (oom_score_adj < OOM_SCORE_ADJ_MIN || oom_score_adj > OOM_SCORE_ADJ_MAX) {
        ERROR("Invalid value %d, range for oom score adj is [-1000, 1000].", oom_score_adj);
        isulad_set_error_message("Invalid value %d, range for oom score adj is [-1000, 1000].", oom_score_adj);
        ret = -1;
    }
    return ret;
}

#ifdef ENABLE_OCI_IMAGE
static bool is_storage_opts_valid(const json_map_string_string *storage_opts)
{
    size_t i;

    for (i = 0; i < storage_opts->len; i++) {
        if (strcmp(storage_opts->keys[i], "size") != 0) {
            // Only check key here, check value by image driver
            ERROR("Unknown storage option: %s", storage_opts->keys[i]);
            isulad_set_error_message("Unknown storage option: %s", storage_opts->keys[i]);
            return false;
        }
    }
    return true;
}

/* verify storage options */
static int verify_storage_opts(const host_config *hc)
{
    int ret = 0;
    json_map_string_string *storage_opts = NULL;
    struct graphdriver_status *driver_status = NULL;

    if (hc != NULL) {
        storage_opts = hc->storage_opt;
    }

    driver_status = im_graphdriver_get_status();
    if (driver_status == NULL) {
        ERROR("Failed to get graph driver status info!");
        ret = -1;
        goto cleanup;
    }

    if (storage_opts == NULL || storage_opts->len == 0 || strcmp(driver_status->driver_name, "overlay2") != 0) {
        goto cleanup;
    }

    if (storage_opts->len > 0) {
        if (strcmp(driver_status->backing_fs, "xfs") == 0) {
            WARN("Filesystem quota for overlay2 over xfs is not totally support");
        }
    }

    if (!is_storage_opts_valid(storage_opts)) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    im_free_graphdriver_status(driver_status);
    return ret;
}
#endif

/* verify blkio rw bps device */
static int verify_blkio_rw_bps_device(const sysinfo_t *sysinfo, size_t throttle_read_bps_device_len,
                                      size_t throttle_write_bps_device_len)
{
    int ret = 0;

    if (throttle_read_bps_device_len > 0 && !(sysinfo->blkioinfo.blkio_read_bps_device)) {
        ERROR("Your kernel does not support Block read limit in bytes per second");
        isulad_set_error_message("Your kernel does not support Block read limit in bytes per second");
        ret = -1;
        goto out;
    }

    if (throttle_write_bps_device_len > 0 && !(sysinfo->blkioinfo.blkio_write_bps_device)) {
        ERROR("Your kernel does not support Block write limit in bytes per second");
        isulad_set_error_message("Your kernel does not support Block write limit in bytes per second");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* verify blkio rw iops device */
static int verify_blkio_rw_iops_device(const sysinfo_t *sysinfo, size_t throttle_read_iops_device_len,
                                       size_t throttle_write_iops_device_len)
{
    int ret = 0;

    if (throttle_read_iops_device_len > 0 && !(sysinfo->blkioinfo.blkio_read_iops_device)) {
        ERROR("Your kernel does not support Block read limit in IO per second");
        isulad_set_error_message("Your kernel does not support Block read limit in IO per second");
        ret = -1;
        goto out;
    }

    if (throttle_write_iops_device_len > 0 && !(sysinfo->blkioinfo.blkio_write_iops_device)) {
        ERROR("Your kernel does not support Block write limit in IO per second");
        isulad_set_error_message("Your kernel does not support Block write limit in IO per second");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* verify resources blkio */
static int verify_resources_blkio(const sysinfo_t *sysinfo, const defs_resources_block_io *blkio)
{
    int ret = 0;

    ret = verify_blkio_weight(sysinfo, blkio->weight);
    if (ret != 0) {
        goto out;
    }

    ret = verify_blkio_device(sysinfo, (const defs_block_io_device_weight **)blkio->weight_device,
                              blkio->weight_device_len);
    if (ret != 0) {
        goto out;
    }

    ret = verify_blkio_rw_bps_device(sysinfo, blkio->throttle_read_bps_device_len,
                                     blkio->throttle_write_bps_device_len);
    if (ret != 0) {
        goto out;
    }

    ret = verify_blkio_rw_iops_device(sysinfo, blkio->throttle_read_iops_device_len,
                                      blkio->throttle_write_iops_device_len);
    if (ret != 0) {
        goto out;
    }
out:
    return ret;
}

static bool check_hugetlbs_repeated(size_t newlen, const char *pagesize,
                                    const defs_resources_hugepage_limits_element *hugetlb,
                                    defs_resources_hugepage_limits_element **newtlb)
{
    bool repeated = false;
    size_t j;

    for (j = 0; j < newlen; j++) {
        if (newtlb[j] != NULL && newtlb[j]->page_size != NULL && !strcmp(newtlb[j]->page_size, pagesize)) {
            WARN("hugetlb-limit setting of %s is repeated, former setting %" PRIu64 " will be replaced with %" PRIu64,
                 pagesize, newtlb[j]->limit, hugetlb->limit);
            newtlb[j]->limit = hugetlb->limit;
            repeated = true;
            goto out;
        }
    }

out:
    return repeated;
}

static void free_hugetlbs_array(defs_resources_hugepage_limits_element **hugetlb, size_t hugetlb_len)
{
    size_t i;

    if (hugetlb == NULL) {
        return;
    }

    for (i = 0; i < hugetlb_len; i++) {
        if (hugetlb[i] != NULL) {
            free_defs_resources_hugepage_limits_element(hugetlb[i]);
            hugetlb[i] = NULL;
        }
    }
    free(hugetlb);
}

/* verify resources hugetlbs */
static int verify_resources_hugetlbs(const sysinfo_t *sysinfo, defs_resources_hugepage_limits_element ***hugetlb,
                                     size_t *hugetlb_len)
{
    int ret = 0;
    defs_resources_hugepage_limits_element **newhugetlb = NULL;
    size_t newlen = 0;
    size_t i;

    if (!sysinfo->hugetlbinfo.hugetlblimit) {
        ERROR("Your kernel does not support hugetlb limit. --hugetlb-limit discarded.");
        isulad_set_error_message("Your kernel does not support hugetlb limit. --hugetlb-limit discarded.");
        ret = -1;
        goto out;
    }

    for (i = 0; i < *hugetlb_len; i++) {
        char *pagesize = NULL;
        size_t newsize, oldsize;
        defs_resources_hugepage_limits_element **tmphugetlb;

        pagesize = validate_hugetlb((*hugetlb)[i]->page_size, (*hugetlb)[i]->limit);
        if (pagesize == NULL) {
            ret = -1;
            goto out;
        }

        if (check_hugetlbs_repeated(newlen, pagesize, (*hugetlb)[i], newhugetlb)) {
            free(pagesize);
            continue;
        }

        // append new hugetlb
        if (newlen > SIZE_MAX / sizeof(defs_resources_hugepage_limits_element *) - 1) {
            free(pagesize);
            ERROR("Too many new hugetlb to append!");
            ret = -1;
            goto out;
        }
        newsize = sizeof(defs_resources_hugepage_limits_element *) * (newlen + 1);
        oldsize = newsize - sizeof(defs_resources_hugepage_limits_element *);
        ret = util_mem_realloc((void **)&tmphugetlb, newsize, newhugetlb, oldsize);
        if (ret < 0) {
            free(pagesize);
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        newhugetlb = tmphugetlb;
        newhugetlb[newlen] = util_common_calloc_s(sizeof(defs_resources_hugepage_limits_element));
        if (newhugetlb[newlen] == NULL) {
            free(pagesize);
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        newhugetlb[newlen]->limit = (*hugetlb)[i]->limit;
        newhugetlb[newlen]->page_size = pagesize;
        newlen++;
    }
out:
    if (ret != 0 && newhugetlb != NULL) {
        free_hugetlbs_array(newhugetlb, newlen);
    } else if (ret == 0) {
        free_hugetlbs_array(*hugetlb, *hugetlb_len);
        *hugetlb = newhugetlb;
        *hugetlb_len = newlen;
    }
    return ret;
}

/* adapt memory swap */
static int adapt_memory_swap(const sysinfo_t *sysinfo, const int64_t *limit, int64_t *swap)
{
    if (*limit > 0 && *swap == 0 && sysinfo->cgmeminfo.swap) {
        if (*limit > (INT64_MAX / 2)) {
            ERROR("Memory swap out of range!");
            isulad_set_error_message("Memory swap out of range!");
            return -1;
        }
        *swap = (*limit) * 2;
    }
    return 0;
}

/* adapt resources memory */
static int adapt_resources_memory(const sysinfo_t *sysinfo, defs_resources_memory *memory)
{
    return adapt_memory_swap(sysinfo, &(memory->limit), &(memory->swap));
}

/* verify resources device */
static int verify_resources_device(defs_resources *resources)
{
    int ret = 0;
    size_t i = 0;

    for (i = 0; i < resources->devices_len; i++) {
        if (!util_valid_device_mode(resources->devices[i]->access)) {
            ERROR("Invalid device mode \"%s\" for device \"%" PRId64" %" PRId64 "\"", resources->devices[i]->access,
                  resources->devices[i]->major, resources->devices[i]->minor);
            isulad_set_error_message("Invalid device mode \"%s\" for device \"%ld %ld\"", resources->devices[i]->access,
                                     resources->devices[i]->major, resources->devices[i]->minor);
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

/* verify linux resources */
static int verify_linux_resources(const sysinfo_t *sysinfo, defs_resources *resources)
{
    int ret = 0;

    // memory
    if (resources->memory != NULL) {
        ret = verify_resources_memory(sysinfo, resources->memory);
        if (ret != 0) {
            goto out;
        }
    }
    // pids
    if (resources->pids != NULL) {
        ret = verify_resources_pids(sysinfo, resources->pids);
        if (ret != 0) {
            goto out;
        }
    }
    // cpu
    if (resources->cpu != NULL) {
        ret = verify_resources_cpu(sysinfo, resources->cpu);
        if (ret != 0) {
            goto out;
        }
    }
    // hugetlb
    if (resources->hugepage_limits_len && resources->hugepage_limits != NULL) {
        ret = verify_resources_hugetlbs(sysinfo, &(resources->hugepage_limits), &(resources->hugepage_limits_len));
        if (ret != 0) {
            goto out;
        }
    }
    // blkio
    if (resources->block_io != NULL) {
        ret = verify_resources_blkio(sysinfo, resources->block_io);
        if (ret != 0) {
            goto out;
        }
    }
    // device
    if (resources->devices != NULL) {
        ret = verify_resources_device(resources);
        if (ret != 0) {
            goto out;
        }
    }
out:
    return ret;
}

/* adapt linux resources */
static int adapt_linux_resources(const sysinfo_t *sysinfo, defs_resources *resources)
{
    int ret = 0;

    // memory
    if (resources->memory != NULL) {
        ret = adapt_resources_memory(sysinfo, resources->memory);
        if (ret != 0) {
            goto out;
        }
    }
out:
    return ret;
}

static bool verify_oci_linux_sysctl(const oci_runtime_config_linux *l)
{
    size_t i = 0;

    if (l->sysctl == NULL) {
        return true;
    }
    for (i = 0; i < l->sysctl->len; i++) {
        if (strcmp("kernel.pid_max", l->sysctl->keys[i]) == 0) {
            if (!util_check_pid_max_kernel_namespaced()) {
                isulad_set_error_message("Sysctl '%s' is not kernel namespaced, it cannot be changed",
                                         l->sysctl->keys[i]);
                return false;
            } else {
                return true;
            }
        }
        if (!util_valid_sysctl(l->sysctl->keys[i])) {
            isulad_set_error_message("Sysctl %s=%s is not whitelist", l->sysctl->keys[i], l->sysctl->values[i]);
            return false;
        }
    }
    return true;
}

/* verify oci linux */
static int verify_oci_linux(const sysinfo_t *sysinfo, const oci_runtime_config_linux *l)
{
    int ret = 0;

    // Resources
    if (l->resources != NULL) {
        ret = verify_linux_resources(sysinfo, l->resources);
        if (ret != 0) {
            goto out;
        }
    }
    if (!verify_oci_linux_sysctl(l)) {
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int verify_oci_hook_prestart(const oci_runtime_spec_hooks *h)
{
    size_t i;
    for (i = 0; i < h->prestart_len; i++) {
        int ret = 0;
        ret = verify_hook_conf(h->prestart[i]);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

static int verify_oci_hook_poststart(const oci_runtime_spec_hooks *h)
{
    size_t i;
    for (i = 0; i < h->poststart_len; i++) {
        int ret = 0;
        ret = verify_hook_conf(h->poststart[i]);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

static int verify_oci_hook_poststop(const oci_runtime_spec_hooks *h)
{
    size_t i;
    for (i = 0; i < h->poststop_len; i++) {
        int ret = 0;
        ret = verify_hook_conf(h->poststop[i]);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

/* verify oci hook */
int verify_oci_hook(const oci_runtime_spec_hooks *h)
{
    int ret = 0;

    // Prestart
    ret = verify_oci_hook_prestart(h);
    if (ret != 0) {
        goto out;
    }

    // Poststart
    ret = verify_oci_hook_poststart(h);
    if (ret != 0) {
        goto out;
    }

    // Poststop
    ret = verify_oci_hook_poststop(h);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

/* adapt oci linux */
static int adapt_oci_linux(const sysinfo_t *sysinfo, oci_runtime_config_linux *l)
{
    int ret = 0;

    // Resources
    if (l->resources != NULL) {
        ret = adapt_linux_resources(sysinfo, l->resources);
        if (ret != 0) {
            goto out;
        }
    }
out:
    return ret;
}

/* get source mount */
static int get_source_mount(const char *src, char **srcpath, char **optional)
{
    mountinfo_t **minfos = NULL;
    mountinfo_t *info = NULL;
    int ret = 0;
    char real_path[PATH_MAX + 1] = { 0 };
    char *dirc = NULL;
    char *dname = NULL;

    if (realpath(src, real_path) == NULL) {
        ERROR("Failed to get real path for %s : %s", src, strerror(errno));
        return -1;
    }

    minfos = getmountsinfo();
    if (minfos == NULL) {
        ERROR("Failed to get mounts info");
        ret = -1;
        goto out;
    }

    info = find_mount_info(minfos, real_path);
    if (info != NULL) {
        *srcpath = util_strdup_s(real_path);
        *optional = info->optional ? util_strdup_s(info->optional) : NULL;
        goto out;
    }

    dirc = util_strdup_s(real_path);
    dname = dirc;
    while (strcmp(dirc, "/")) {
        dname = dirname(dname);
        info = find_mount_info(minfos, dname);
        if (info != NULL) {
            *srcpath = util_strdup_s(dname);
            *optional = info->optional ? util_strdup_s(info->optional) : NULL;
            goto out;
        }
    }
    ERROR("Could not find source mount of %s", src);
    ret = -1;
out:
    free(dirc);
    free_mounts_info(minfos);
    return ret;
}

static inline bool is_optional_shared(const char *optional)
{
    return optional != NULL && strncmp(optional, "shared:", strlen("shared:")) == 0;
}

/* ensure shared */
static int ensure_shared(const char *src)
{
    int ret = 0;
    char *srcpath = NULL;
    char *optional = NULL;

    ret = get_source_mount(src, &srcpath, &optional);
    if (ret != 0) {
        goto out;
    }
    if (is_optional_shared(optional)) {
        goto out;
    }
    ERROR("Path %s is mounted on %s but it is not a shared mount", src, srcpath);
    ret = -1;
out:
    free(srcpath);
    free(optional);
    return ret;
}

static inline bool is_optional_slave(const char *optional)
{
    return optional != NULL && strncmp(optional, "master:", strlen("master:")) == 0;
}

/* ensure shared or slave */
static int ensure_shared_or_slave(const char *src)
{
    int ret = 0;
    char *srcpath = NULL;
    char *optional = NULL;

    ret = get_source_mount(src, &srcpath, &optional);
    if (ret != 0) {
        goto out;
    }
    if (is_optional_shared(optional) || is_optional_slave(optional)) {
        goto out;
    }
    ERROR("Path %s is mounted on %s but it is not a shared or slave mount", src, srcpath);
    ret = -1;
out:

    free(srcpath);
    free(optional);
    return ret;
}

static inline bool is_propagation_shared(const char *propagation)
{
    return strcmp(propagation, "shared") == 0 || strcmp(propagation, "rshared") == 0;
}

static void set_mount_propagation_shared(const oci_runtime_spec *container)
{
    if (container->linux->rootfs_propagation == NULL) {
        container->linux->rootfs_propagation = util_strdup_s("shared");
        return;
    }

    if (!is_propagation_shared(container->linux->rootfs_propagation)) {
        free(container->linux->rootfs_propagation);
        container->linux->rootfs_propagation = util_strdup_s("shared");
    }
}

static inline bool is_propagation_slave(const char *propagation)
{
    return strcmp(propagation, "slave") == 0 || strcmp(propagation, "rslave") == 0;
}

static void set_mount_propagation_slave(const oci_runtime_spec *container)
{
    if (container->linux->rootfs_propagation == NULL) {
        container->linux->rootfs_propagation = util_strdup_s("rslave");
        return;
    }

    if (!is_propagation_shared(container->linux->rootfs_propagation) &&
        !is_propagation_slave(container->linux->rootfs_propagation)) {
        free(container->linux->rootfs_propagation);
        container->linux->rootfs_propagation = util_strdup_s("rslave");
    }
}

static int make_mount_propagation(const oci_runtime_spec *container, const char *source, const char *option)
{
    int ret;

    if (is_propagation_shared(option)) {
        ret = ensure_shared(source);
        if (ret != 0) {
            return ret;
        }
        set_mount_propagation_shared(container);
    } else if (is_propagation_slave(option)) {
        ret = ensure_shared_or_slave(source);
        if (ret != 0) {
            return ret;
        }
        set_mount_propagation_slave(container);
    }

    return 0;
}

/* set mounts */
static int set_mounts(const oci_runtime_spec *container)
{
    int ret = 0;
    size_t i, k;
    defs_mount **m = NULL;

    if (container == NULL) {
        return -1;
    }

    m = container->mounts;
    for (i = 0; i < container->mounts_len; i++) {
        for (k = 0; k < m[i]->options_len; k++) {
            ret = make_mount_propagation(container, m[i]->source, m[i]->options[k]);
            if (ret != 0) {
                goto out;
            }
        }
    }

out:
    return ret;
}

/* verify custom mount */
static int verify_custom_mount(defs_mount **mounts, size_t len)
{
    int ret = 0;
    size_t i;
    defs_mount *iter = NULL;

    for (i = 0; i < len; ++i) {
        iter = *(mounts + i);
        if (iter == NULL || strcmp(iter->type, MOUNT_TYPE_BIND)) {
            continue;
        }

        if (!util_file_exists(iter->source) && util_mkdir_p(iter->source, CONFIG_DIRECTORY_MODE)) {
            ERROR("Failed to create directory '%s': %s", iter->source, strerror(errno));
            isulad_try_set_error_message("Failed to create directory '%s': %s", iter->source, strerror(errno));
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

/* verify oci linux */
static int verify_process_env(const defs_process *process)
{
    int ret = 0;
    size_t i = 0;
    char *new_env = NULL;

    for (i = 0; i < process->env_len; i++) {
        if (util_valid_env(process->env[i], &new_env) != 0) {
            ERROR("Invalid environment %s", process->env[i]);
            isulad_set_error_message("Invalid environment %s", process->env[i]);
            ret = -1;
            goto out;
        }
        free(new_env);
        new_env = NULL;
    }

out:
    free(new_env);
    return ret;
}

static int verify_container_linux(const oci_runtime_spec *container, const sysinfo_t *sysinfo)
{
    int ret = 0;

    /* verify and adapt container settings */
    if (container->linux != NULL) {
        ret = verify_oci_linux(sysinfo, container->linux);
        if (ret != 0) {
            goto out;
        }
        ret = adapt_oci_linux(sysinfo, container->linux);
        if (ret != 0) {
            goto out;
        }
    }

    /* verify oci spec process settings */
    if (container->process != NULL) {
        ret = verify_process_env(container->process);
        if (ret != 0) {
            goto out;
        }
    }

out:
    return ret;
}

static int verify_container_mounts(const oci_runtime_spec *container)
{
    int ret = 0;

    /* verify custom mount info, ensure source path exist */
    if (container->mounts != NULL && container->mounts_len > 0) {
        ret = verify_custom_mount(container->mounts, container->mounts_len);
        if (ret != 0) {
            goto out;
        }
        ret = set_mounts(container);
        if (ret != 0) {
            goto out;
        }
    }

out:
    return ret;
}

/* verify container settings */
int verify_container_settings(const oci_runtime_spec *container)
{
    int ret = 0;
    sysinfo_t *sysinfo = NULL;

    sysinfo = get_sys_info(true);
    if (sysinfo == NULL) {
        ERROR("Can not get system info");
        ret = -1;
        goto out;
    }

    if (!util_valid_host_name(container->hostname)) {
        ERROR("Invalid container hostname %s", container->hostname);
        isulad_set_error_message("Invalid container hostname (%s), only %s and less than 64 bytes are allowed.",
                                 container->hostname, HOST_NAME_REGEXP);
        ret = -1;
        goto out;
    }

    /* verify and adapt container settings */
    ret = verify_container_linux(container, sysinfo);
    if (ret != 0) {
        goto out;
    }

    ret = verify_container_mounts(container);
    if (ret != 0) {
        goto out;
    }

    /* verify hook settings */
    if (container->hooks != NULL && verify_oci_hook(container->hooks)) {
        ERROR("Verify hook file failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static void free_hugetlb_array(host_config_hugetlbs_element **hugetlb, size_t len)
{
    size_t i;

    if (hugetlb == NULL) {
        return;
    }

    for (i = 0; i < len; i++) {
        free_host_config_hugetlbs_element(hugetlb[i]);
        hugetlb[i] = NULL;
    }
    free(hugetlb);
}

static int append_hugetlb_array(host_config_hugetlbs_element ***hugetlb, size_t len)
{
    size_t newsize;
    size_t oldsize;
    host_config_hugetlbs_element **tmphugetlb;
    int ret;

    if (len > SIZE_MAX / sizeof(host_config_hugetlbs_element *) - 1) {
        return -1;
    }

    newsize = sizeof(host_config_hugetlbs_element *) * (len + 1);
    oldsize = newsize - sizeof(host_config_hugetlbs_element *);
    ret = util_mem_realloc((void **)&tmphugetlb, newsize, *hugetlb, oldsize);
    if (ret < 0) {
        return -1;
    }

    *hugetlb = tmphugetlb;
    (*hugetlb)[len] = util_common_calloc_s(sizeof(host_config_hugetlbs_element));
    if ((*hugetlb)[len] == NULL) {
        return -1;
    }

    return 0;
}

static int add_hugetbl_element(host_config_hugetlbs_element ***hugetlb, size_t *len,
                               const host_config_hugetlbs_element *element)
{
    char *pagesize = NULL;
    size_t j;
    int ret = 0;

    pagesize = validate_hugetlb(element->page_size, element->limit);
    if (pagesize == NULL) {
        return -1;
    }

    for (j = 0; j < *len; j++) {
        if (strcmp((*hugetlb)[j]->page_size, pagesize) == 0) {
            WARN("Hostconfig: hugetlb-limit setting of %s is repeated, "
                 "former setting %" PRIu64 " will be replaced with %" PRIu64,
                 pagesize, (*hugetlb)[j]->limit, element->limit);
            (*hugetlb)[j]->limit = element->limit;
            goto out;
        }
    }

    // append new hugetlb
    ret = append_hugetlb_array(hugetlb, *len);
    if (ret < 0) {
        ERROR("Out of memory");
        goto out;
    }
    (*hugetlb)[*len]->page_size = pagesize;
    (*hugetlb)[*len]->limit = element->limit;
    (*len)++;
    return 0;

out:
    free(pagesize);
    return ret;
}

/* verify host config hugetlbs */
static int verify_host_config_hugetlbs(const sysinfo_t *sysinfo, host_config_hugetlbs_element ***hugetlb,
                                       size_t *hugetlb_len)
{
    int ret;
    host_config_hugetlbs_element **newhugetlb = NULL;
    size_t newlen = 0;
    size_t i = 0;

    if (*hugetlb == NULL || *hugetlb_len == 0) {
        return 0;
    }

    if (!sysinfo->hugetlbinfo.hugetlblimit) {
        ERROR("Your kernel does not support hugetlb limit. --hugetlb-limit discarded.");
        isulad_set_error_message("Your kernel does not support hugetlb limit. --hugetlb-limit discarded.");
        ret = -1;
        goto out;
    }

    for (i = 0; i < *hugetlb_len; i++) {
        ret = add_hugetbl_element(&newhugetlb, &newlen, (*hugetlb)[i]);
        if (ret != 0) {
            goto out;
        }
    }

    free_hugetlb_array(*hugetlb, *hugetlb_len);
    *hugetlb = newhugetlb;
    *hugetlb_len = newlen;
    return 0;

out:
    free_hugetlb_array(newhugetlb, newlen);
    return ret;
}

static int host_config_settings_memory(const sysinfo_t *sysinfo, const host_config *hostconfig, bool update)
{
    int ret = 0;

    ret = verify_mem_limit_swap(sysinfo, hostconfig->memory, hostconfig->memory_swap, update);
    if (ret != 0) {
        goto out;
    }

    ret = verify_memory_reservation(sysinfo, hostconfig->memory, hostconfig->memory_reservation);
    if (ret != 0) {
        goto out;
    }

    ret = verify_memory_kernel(sysinfo, hostconfig->kernel_memory);
    if (ret != 0) {
        goto out;
    }

    if (hostconfig->memory_swappiness != NULL) {
        ret = verify_memory_swappiness(sysinfo, *(hostconfig->memory_swappiness));
        if (ret != 0) {
            goto out;
        }
    }

out:
    return ret;
}

static int verify_nano_cpus(const sysinfo_t *sysinfo, const host_config *hostconfig)
{
    int ret = 0;

    if (hostconfig->nano_cpus == 0) {
        return 0;
    }

    if (hostconfig->nano_cpus > 0 && hostconfig->cpu_period > 0) {
        ERROR("Conflicting options: Nano CPUs and CPU Period cannot both be set.");
        isulad_set_error_message("Conflicting options: Nano CPUs and CPU Period cannot both be set.");
        ret = -1;
        goto out;
    }

    if (hostconfig->nano_cpus > 0 && hostconfig->cpu_quota > 0) {
        ERROR("Conflicting options: Nano CPUs and CPU Quota cannot both be set.");
        isulad_set_error_message("Conflicting options: Nano CPUs and CPU Quota cannot both be set.");
        ret = -1;
        goto out;
    }

    if (hostconfig->nano_cpus > 0 && (!(sysinfo->cgcpuinfo.cpu_cfs_quota) || !(sysinfo->cgcpuinfo.cpu_cfs_period))) {
        ERROR("NanoCPUs can not be set, as your kernel does not support CPU cfs period/quota or the cgroup is not mounted.");
        isulad_set_error_message(
            "NanoCPUs can not be set, as your kernel does not support CPU cfs period/quota or the cgroup is not mounted.");
        ret = -1;
        goto out;
    }

    if (hostconfig->nano_cpus < 0 || (hostconfig->nano_cpus > (sysinfo->ncpus * 1e9))) {
        ERROR("Range of CPUs is from 0.01 to %d.00, as there are only %d CPUs available", sysinfo->ncpus,
              sysinfo->ncpus);
        isulad_set_error_message("Range of CPUs is from 0.01 to %d.00, as there are only %d CPUs available",
                                 sysinfo->ncpus, sysinfo->ncpus);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int host_config_settings_cpu(const sysinfo_t *sysinfo, const host_config *hostconfig)
{
    int ret = 0;

    ret = verify_nano_cpus(sysinfo, hostconfig);
    if (ret != 0) {
        goto out;
    }

    ret = verify_cpu_realtime(sysinfo, hostconfig->cpu_realtime_period, hostconfig->cpu_realtime_runtime);
    if (ret != 0) {
        goto out;
    }

    ret = verify_cpu_shares(sysinfo, hostconfig->cpu_shares);
    if (ret != 0) {
        goto out;
    }

    ret = verify_cpu_cfs_scheduler(sysinfo, hostconfig->cpu_period, hostconfig->cpu_quota);
    if (ret != 0) {
        goto out;
    }

    // cpuset
    ret = verify_resources_cpuset(sysinfo, hostconfig->cpuset_cpus, hostconfig->cpuset_mems);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

static int host_config_settings_blkio(const sysinfo_t *sysinfo, const host_config *hostconfig)
{
    int ret = 0;

    ret = verify_blkio_weight(sysinfo, hostconfig->blkio_weight);
    if (ret != 0) {
        goto out;
    }

    ret = verify_blkio_device(sysinfo, (const defs_block_io_device_weight **)hostconfig->blkio_weight_device,
                              hostconfig->blkio_weight_device_len);
    if (ret != 0) {
        goto out;
    }

    ret = verify_blkio_rw_bps_device(sysinfo, hostconfig->blkio_device_read_bps_len,
                                     hostconfig->blkio_device_write_bps_len);
    if (ret != 0) {
        goto out;
    }

    ret = verify_blkio_rw_iops_device(sysinfo, hostconfig->blkio_device_read_iops_len,
                                      hostconfig->blkio_device_write_iops_len);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

static inline bool is_restart_policy_always(const char *policy)
{
    return strcmp(policy, "always") == 0;
}

static inline bool is_restart_policy_unless_stopped(const char *policy)
{
    return strcmp(policy, "unless-stopped") == 0;
}

static inline bool is_restart_policy_on_reboot(const char *policy)
{
    return strcmp(policy, "on-reboot") == 0;
}

static inline bool is_restart_policy_no(const char *policy)
{
    return strcmp(policy, "no") == 0;
}

static inline bool is_restart_policy_on_failure(const char *policy)
{
    return strcmp(policy, "on-failure") == 0;
}

static int verify_restart_policy_name(const host_config_restart_policy *rp, const host_config *hostconfig)
{
    if (is_restart_policy_always(rp->name) || is_restart_policy_no(rp->name) || is_restart_policy_on_reboot(rp->name) ||
        is_restart_policy_unless_stopped(rp->name)) {
        if (rp->maximum_retry_count != 0) {
            ERROR("Maximum retry count cannot be used with restart policy '%s'", rp->name);
            isulad_set_error_message("Maximum retry count cannot be used with restart policy '%s'", rp->name);
            return -1;
        }
    } else if (is_restart_policy_on_failure(rp->name)) {
        if (rp->maximum_retry_count < 0) {
            ERROR("Maximum retry count cannot be negative");
            isulad_set_error_message("Maximum retry count cannot be negative");
            return -1;
        }
    } else {
        ERROR("Invalid restart policy '%s'", rp->name);
        isulad_set_error_message("Invalid restart policy '%s'", rp->name);
        return -1;
    }

    if (hostconfig->auto_remove && !is_restart_policy_no(rp->name)) {
        ERROR("Can't create 'AutoRemove' container with restart policy");
        isulad_set_error_message("Can't create 'AutoRemove' container with restart policy");
        return -1;
    }

    return 0;
}

static int host_config_settings_restart_policy(const host_config *hostconfig)
{
    host_config_restart_policy *rp = NULL;

    if (hostconfig == NULL || hostconfig->restart_policy == NULL) {
        return 0;
    }

    rp = hostconfig->restart_policy;
    if (rp->name == NULL || rp->name[0] == '\0') {
        if (rp->maximum_retry_count != 0) {
            ERROR("Maximum retry count cannot be used with empty restart policy");
            isulad_set_error_message("Maximum retry count cannot be used with empty restart policy");
            return -1;
        }
        return 0;
    }

    return verify_restart_policy_name(rp, hostconfig);
}

static int host_config_settings_with_sysinfo(host_config *hostconfig, bool update)
{
    int ret = 0;
    sysinfo_t *sysinfo = NULL;

    sysinfo = get_sys_info(true);
    if (sysinfo == NULL) {
        ERROR("Can not get system info");
        return -1;
    }

    ret = verify_host_config_hugetlbs(sysinfo, &(hostconfig->hugetlbs), &(hostconfig->hugetlbs_len));
    if (ret != 0) {
        goto out;
    }

    // memory
    ret = host_config_settings_memory(sysinfo, hostconfig, update);
    if (ret != 0) {
        goto out;
    }

    ret = verify_pids_limit(sysinfo, hostconfig->pids_limit);
    if (ret != 0) {
        goto out;
    }

    ret = verify_files_limit(sysinfo, hostconfig->files_limit);
    if (ret != 0) {
        goto out;
    }

    // cpu & cpuset
    ret = host_config_settings_cpu(sysinfo, hostconfig);
    if (ret != 0) {
        goto out;
    }

    // blkio
    ret = host_config_settings_blkio(sysinfo, hostconfig);
    if (ret != 0) {
        goto out;
    }

out:
    return ret;
}

/* verify device cgroup rule */
static int verify_host_config_device_cgroup_rules(const host_config *hostconfig)
{
    int ret = 0;
    size_t i = 0;

    for (i = 0; i < hostconfig->device_cgroup_rules_len; i++) {
        if (!util_valid_device_cgroup_rule(hostconfig->device_cgroup_rules[i])) {
            ERROR("Invalid device cgroup rule %s", hostconfig->device_cgroup_rules[i]);
            isulad_set_error_message("Invalid device cgroup rule %s", hostconfig->device_cgroup_rules[i]);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

/* verify host config settings */
int verify_host_config_settings(host_config *hostconfig, bool update)
{
    int ret = 0;

    if (hostconfig == NULL) {
        return 0;
    }

    // restart policy
    ret = host_config_settings_restart_policy(hostconfig);
    if (ret != 0) {
        goto out;
    }

    ret = host_config_settings_with_sysinfo(hostconfig, update);
    if (ret != 0) {
        goto out;
    }

    // oom score adj
    ret = verify_oom_score_adj(hostconfig->oom_score_adj);
    if (ret != 0) {
        goto out;
    }

    ret = verify_host_config_device_cgroup_rules(hostconfig);
    if (ret != 0) {
        goto out;
    }

#ifdef ENABLE_OCI_IMAGE
    // storage options
    ret = verify_storage_opts(hostconfig);
    if (ret != 0) {
        goto out;
    }
#endif

out:
    return ret;
}

#ifdef ENABLE_SELINUX
static int relabel_mounts_if_needed(defs_mount **mounts, size_t len, const char *mount_label)
{
    int ret = 0;
    size_t i, j;
    defs_mount *iter = NULL;

    for (i = 0; i < len; ++i) {
        bool need_relabel = false;
        bool is_shared = false;
        iter = *(mounts + i);
        if (iter == NULL) {
            continue;
        }

        for (j = 0; j < iter->options_len; j++) {
            if (strcmp(iter->options[j], "Z") == 0) {
                need_relabel = true;
                is_shared = false;
            } else if (strcmp(iter->options[j], "z") == 0) {
                need_relabel = true;
                is_shared = true;
            }
        }

        if (need_relabel && relabel(iter->source, mount_label, is_shared) != 0) {
            ERROR("Error setting label on mount source '%s'", iter->source);
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}
#endif

/* verify container settings start */
int verify_container_settings_start(const oci_runtime_spec *oci_spec)
{
    int ret = 0;

    /* verify custom mount info, ensure source path exist */
    if (oci_spec->mounts != NULL && oci_spec->mounts_len > 0) {
        if (verify_custom_mount(oci_spec->mounts, oci_spec->mounts_len) != 0) {
            ERROR("Failed to verify custom mount");
            ret = -1;
            goto out;
        }
#ifdef ENABLE_SELINUX
        if (relabel_mounts_if_needed(oci_spec->mounts, oci_spec->mounts_len, oci_spec->linux->mount_label) != 0) {
            ERROR("Failed to relabel mount");
            ret = -1;
            goto out;
        }
#endif
    }

out:
    return ret;
}

static inline bool is_less_than_one_second(int64_t timeout)
{
    return timeout != 0 && timeout < Time_Second;
}

static int verify_health_check_parameter(const container_config *container_spec)
{
    int ret = 0;

    if (container_spec == NULL || container_spec->healthcheck == NULL) {
        return ret;
    }

    if (is_less_than_one_second(container_spec->healthcheck->interval)) {
        ERROR("Interval in Healthcheck cannot be less than one second");
        isulad_set_error_message("Interval in Healthcheck cannot be less than one second");
        ret = -1;
        goto out;
    }
    if (is_less_than_one_second(container_spec->healthcheck->timeout)) {
        ERROR("Timeout in Healthcheck cannot be less than one second");
        isulad_set_error_message("Timeout in Healthcheck cannot be less than one second");
        ret = -1;
        goto out;
    }
    if (is_less_than_one_second(container_spec->healthcheck->start_period)) {
        ERROR("StartPeriod in Healthcheck cannot be less than one second");
        isulad_set_error_message("StartPeriod in Healthcheck cannot be less than one second");
        ret = -1;
        goto out;
    }
    if (container_spec->healthcheck->retries < 0) {
        ERROR("--health-retries cannot be negative");
        isulad_set_error_message("--health-retries cannot be negative");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int verify_stop_signal(const container_config *container_spec)
{
    int ret = 0;
    int signal = -1;

    if (container_spec->stop_signal == NULL) {
        return 0;
    }

    signal = util_sig_parse(container_spec->stop_signal);

    if (!util_valid_signal(signal)) {
        ERROR("Invalid signal: %s", container_spec->stop_signal);
        isulad_set_error_message("Invalid signal: %s", container_spec->stop_signal);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int verify_container_config(const container_config *container_spec)
{
    int ret = 0;

    if (verify_health_check_parameter(container_spec) != 0) {
        ret = -1;
        goto out;
    }

    if (verify_stop_signal(container_spec) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}
