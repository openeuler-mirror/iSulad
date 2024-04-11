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
 * Description: provide container specs functions
 ******************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/container_config_v2.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_runtime_config_linux.h>
#include <isula_libutils/oci_runtime_spec.h>
#include <isula_libutils/oci_runtime_hooks.h>
#include <isula_libutils/host_config.h>
#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/utils_array.h>

#include "specs_api.h"
#include "utils.h"
#include "isulad_config.h"
#include "namespace.h"
#include "specs_security.h"
#include "specs_mount.h"
#include "specs_extend.h"
#include "specs_namespace.h"
#include "cgroup.h"
#include "path.h"
#include "constants.h"
#ifdef ENABLE_SELINUX
#include "selinux_label.h"
#endif
#include "err_msg.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"
#include "utils_cap.h"

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

struct readonly_default_oci_spec {
    oci_runtime_spec *cont;
    oci_runtime_spec *system_cont;
};

static struct readonly_default_oci_spec g_rdspec;

static int make_sure_oci_spec_annotations(oci_runtime_spec *oci_spec)
{
    if (oci_spec->annotations == NULL) {
        oci_spec->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (oci_spec->annotations == NULL) {
            return -1;
        }
    }
    return 0;
}

static int merge_annotations(oci_runtime_spec *oci_spec, const container_config *container_spec)
{
    int ret = 0;
    size_t i;

    ret = make_sure_oci_spec_annotations(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (container_spec->annotations != NULL && container_spec->annotations->len) {
        if (oci_spec->annotations->len > LIST_SIZE_MAX - container_spec->annotations->len) {
            ERROR("Too many annotations to add, the limit is %lld", LIST_SIZE_MAX);
            isulad_set_error_message("Too many annotations to add, the limit is %d", LIST_SIZE_MAX);
            ret = -1;
            goto out;
        }
        for (i = 0; i < container_spec->annotations->len; i++) {
            ret = append_json_map_string_string(oci_spec->annotations, container_spec->annotations->keys[i],
                                                container_spec->annotations->values[i]);
            if (ret != 0) {
                ERROR("Failed to append annotation:%s, value:%s", container_spec->annotations->keys[i],
                      container_spec->annotations->values[i]);
                goto out;
            }
        }
    }
out:
    return ret;
}

static int make_annotations_log_console(const container_config *container_spec)
{
    if (container_spec->log_driver == NULL) {
        return 0;
    }

    if (append_json_map_string_string(container_spec->annotations, CONTAINER_LOG_CONFIG_KEY_DRIVER,
                                      container_spec->log_driver) != 0) {
        ERROR("append log console driver failed");
        return -1;
    }

    return 0;
}

static int make_annotations_network_mode(const container_config *container_spec, const host_config *host_spec)
{
    int ret = 0;

    if (host_spec->network_mode != NULL) {
        if (append_json_map_string_string(container_spec->annotations, "host.network.mode", host_spec->network_mode)) {
            ERROR("append network mode failed");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int make_annotations_system_container(const container_config *container_spec, const host_config *host_spec)
{
    int ret = 0;

    if (host_spec->system_container) {
        if (append_json_map_string_string(container_spec->annotations, "system.container", "true")) {
            ERROR("Realloc annotations failed");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static char *do_get_container_cgroup_path(const host_config *host_spec)
{
    char *path = NULL;

    if (host_spec->cgroup_parent != NULL) {
        // first, use user setting
        path = util_strdup_s(host_spec->cgroup_parent);
    } else {
        // second, if user donot set, use setting from daemon config
        path = conf_get_isulad_cgroup_parent();
    }

    if (path == NULL) {
        // third, all faild, just use default '/isulad' for cgroupfs or "system.slice" for systemd
        if (conf_get_systemd_cgroup()) {
            return util_strdup_s("system.slice");
        }
        path = util_strdup_s("/isulad");
    }

    return path;
}

static int make_annotations_cgroup_dir(const container_config *container_spec, const host_config *host_spec)
{
    char cleaned[PATH_MAX] = { 0 };
    __isula_auto_free char *path = NULL;

    path = do_get_container_cgroup_path(host_spec);
    if (util_clean_path(path, cleaned, sizeof(cleaned)) == NULL) {
        ERROR("Failed to clean path: %s", path);
        return -1;
    }

    if (append_json_map_string_string(container_spec->annotations, "cgroup.dir", cleaned)) {
        ERROR("Realloc annotations failed");
        return -1;
    }

    return 0;
}

static int make_annotations_oom_score_adj(const container_config *container_spec, const host_config *host_spec)
{
    int ret = 0;
    char tmp_str[ISULAD_NUMSTRLEN64 + 1] = { 0 };

    // oom_score_adj default value is 0, So there is no need to explicitly set this value
    if (host_spec->oom_score_adj != 0) {
        int nret = snprintf(tmp_str, sizeof(tmp_str), "%d", host_spec->oom_score_adj);
        if (nret < 0 || (size_t)nret >= sizeof(tmp_str)) {
            ERROR("create oom score adj string failed");
            ret = -1;
            goto out;
        }
        if (append_json_map_string_string(container_spec->annotations, "proc.oom_score_adj", tmp_str)) {
            ERROR("append oom score adj which configure proc filesystem for the container failed ");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int make_annotations_files_limit(const container_config *container_spec, const host_config *host_spec)
{
    int ret = 0;
    char tmp_str[ISULAD_NUMSTRLEN64 + 1] = { 0 };

    // Not supported in oci runtime-spec, add 'files.limit' to annotations
    if (host_spec->files_limit != 0) {
        // need create new file limit item in annotations
        int64_t filelimit = host_spec->files_limit;
        int nret = snprintf(tmp_str, sizeof(tmp_str), "%lld", (long long)filelimit);
        if (nret < 0 || (size_t)nret >= sizeof(tmp_str)) {
            ERROR("create files limit string failed");
            ret = -1;
            goto out;
        }

        if (append_json_map_string_string(container_spec->annotations, "files.limit", tmp_str)) {
            ERROR("append files limit failed");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int make_sure_container_spec_annotations(container_config *container_spec)
{
    if (container_spec->annotations == NULL) {
        container_spec->annotations = util_common_calloc_s(sizeof(json_map_string_string));
        if (container_spec->annotations == NULL) {
            return -1;
        }
    }
    return 0;
}

static inline bool is_valid_umask_value(const char *value)
{
    return (strcmp(value, UMASK_NORMAL) == 0 || strcmp(value, UMASK_SECURE) == 0);
}

static int add_native_umask(const container_config *container_spec)
{
    int ret = 0;
    size_t i = 0;
    char *umask = NULL;

    for (i = 0; i < container_spec->annotations->len; i++) {
        if (strcmp(container_spec->annotations->keys[i], ANNOTATION_UMAKE_KEY) == 0) {
            if (!is_valid_umask_value(container_spec->annotations->values[i])) {
                ERROR("native.umask option %s not supported", container_spec->annotations->values[i]);
                isulad_set_error_message("native.umask option %s not supported",
                                         container_spec->annotations->values[i]);
                ret = -1;
            }
            goto out;
        }
    }

    umask = conf_get_isulad_native_umask();
    if (umask == NULL) {
        ERROR("Failed to get default native umask");
        ret = -1;
        goto out;
    }

    if (append_json_map_string_string(container_spec->annotations, ANNOTATION_UMAKE_KEY, umask)) {
        ERROR("Failed to append annotations: native.umask=%s", umask);
        ret = -1;
        goto out;
    }

out:
    free(umask);
    return ret;
}

static int make_annotations(oci_runtime_spec *oci_spec, container_config *container_spec, host_config *host_spec)
{
    int ret = 0;

    ret = make_sure_container_spec_annotations(container_spec);
    if (ret < 0) {
        goto out;
    }

    ret = make_annotations_network_mode(container_spec, host_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = make_annotations_system_container(container_spec, host_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = make_annotations_cgroup_dir(container_spec, host_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = make_annotations_oom_score_adj(container_spec, host_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = make_annotations_files_limit(container_spec, host_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    ret = make_annotations_log_console(container_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    /* add rootfs.mount */
    ret = add_rootfs_mount(container_spec);
    if (ret != 0) {
        ERROR("Failed to add rootfs mount");
        goto out;
    }

    /* add native.umask */
    ret = add_native_umask(container_spec);
    if (ret != 0) {
        ERROR("Failed to add native umask");
        goto out;
    }

    if (merge_annotations(oci_spec, container_spec)) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int update_spec_annotations(oci_runtime_spec *oci_spec, container_config *container_spec, host_config *host_spec)
{
    int ret = 0;
    if (oci_spec == NULL || container_spec == NULL || host_spec == NULL) {
        return -1;
    }

    ret = make_sure_container_spec_annotations(container_spec);
    if (ret < 0) {
        return -1;
    }

    ret = make_annotations_cgroup_dir(container_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    // other annotations will either not be updated after containers created
    // or for rootfs mnt and umask, we do not support the update operation

    if (merge_annotations(oci_spec, container_spec)) {
        return -1;
    }

    return 0;
}

static int make_sure_oci_spec_root(oci_runtime_spec *oci_spec)
{
    if (oci_spec->root == NULL) {
        oci_spec->root = util_common_calloc_s(sizeof(oci_runtime_spec_root));
        if (oci_spec->root == NULL) {
            return -1;
        }
    }
    return 0;
}

static int merge_root(oci_runtime_spec *oci_spec, const char *rootfs, const host_config *host_spec)
{
    int ret = 0;

    ret = make_sure_oci_spec_root(oci_spec);
    if (ret < 0) {
        goto out;
    }

    // fill root path properties
    if (rootfs != NULL) {
        free(oci_spec->root->path);
        oci_spec->root->path = util_strdup_s(rootfs);
    }
    if (host_spec->readonly_rootfs) {
        oci_spec->root->readonly = host_spec->readonly_rootfs;
    }

out:
    return ret;
}

static int merge_blkio_weight(oci_runtime_spec *oci_spec, uint16_t blkio_weight)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_blkio(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->block_io->weight = blkio_weight;

out:
    return ret;
}

static int make_sure_oci_spec_linux_resources_cpu(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->resources->cpu == NULL) {
        oci_spec->linux->resources->cpu = util_common_calloc_s(sizeof(defs_resources_cpu));
        if (oci_spec->linux->resources->cpu == NULL) {
            return -1;
        }
    }
    return 0;
}

static int merge_cpu_shares(oci_runtime_spec *oci_spec, int64_t cpu_shares)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->cpu->shares = (uint64_t)cpu_shares;

out:
    return ret;
}

static int merge_cpu_period(oci_runtime_spec *oci_spec, int64_t cpu_period)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->cpu->period = (uint64_t)cpu_period;

out:
    return ret;
}

static int merge_cpu_realtime_period(oci_runtime_spec *oci_spec, int64_t cpu_rt_period)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->cpu->realtime_period = (uint64_t)cpu_rt_period;

out:
    return ret;
}

static int merge_cpu_realtime_runtime(oci_runtime_spec *oci_spec, int64_t cpu_rt_runtime)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->cpu->realtime_runtime = cpu_rt_runtime;

out:
    return ret;
}

static int merge_cpu_quota(oci_runtime_spec *oci_spec, int64_t cpu_quota)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->cpu->quota = cpu_quota;

out:
    return ret;
}

static int merge_cpuset_cpus(oci_runtime_spec *oci_spec, const char *cpuset_cpus)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    free(oci_spec->linux->resources->cpu->cpus);
    oci_spec->linux->resources->cpu->cpus = util_strdup_s(cpuset_cpus);

out:
    return ret;
}

static int merge_cpuset_mems(oci_runtime_spec *oci_spec, const char *cpuset_mems)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    free(oci_spec->linux->resources->cpu->mems);
    oci_spec->linux->resources->cpu->mems = util_strdup_s(cpuset_mems);

out:
    return ret;
}

static int make_sure_oci_spec_linux_resources_mem(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->resources->memory == NULL) {
        oci_spec->linux->resources->memory = util_common_calloc_s(sizeof(defs_resources_memory));
        if (oci_spec->linux->resources->memory == NULL) {
            return -1;
        }
    }
    return 0;
}

static int merge_memory_limit(oci_runtime_spec *oci_spec, int64_t memory)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_mem(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->memory->limit = memory;

out:
    return ret;
}

static int merge_memory_oom_kill_disable(oci_runtime_spec *oci_spec, bool oom_kill_disable)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_mem(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->memory->disable_oom_killer = oom_kill_disable;

out:
    return ret;
}

static int merge_memory_swap(oci_runtime_spec *oci_spec, int64_t memory_swap)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_mem(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->memory->swap = memory_swap;

out:
    return ret;
}

static int merge_memory_reservation(oci_runtime_spec *oci_spec, int64_t memory_reservation)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_mem(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->memory->reservation = memory_reservation;

out:
    return ret;
}

static int merge_kernel_memory(oci_runtime_spec *oci_spec, int64_t kernel_memory)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_mem(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->memory->kernel = kernel_memory;

out:
    return ret;
}

static int merge_hugetlbs(oci_runtime_spec *oci_spec, host_config_hugetlbs_element **hugetlbs, size_t hugetlbs_len)
{
    int ret = 0;
    size_t i = 0;
    size_t new_size, old_size;
    defs_resources_hugepage_limits_element **hugepage_limits_temp = NULL;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (hugetlbs_len >
        SIZE_MAX / sizeof(defs_resources_hugepage_limits_element *) - oci_spec->linux->resources->hugepage_limits_len) {
        ERROR("Too many hugetlbs to merge!");
        ret = -1;
        goto out;
    }
    old_size = oci_spec->linux->resources->hugepage_limits_len * sizeof(defs_resources_hugepage_limits_element *);
    new_size = (oci_spec->linux->resources->hugepage_limits_len + hugetlbs_len) *
               sizeof(defs_resources_hugepage_limits_element *);
    ret = util_mem_realloc((void **)&hugepage_limits_temp, new_size, oci_spec->linux->resources->hugepage_limits,
                           old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for hugepage limits");
        ret = -1;
        goto out;
    }

    oci_spec->linux->resources->hugepage_limits = hugepage_limits_temp;

    for (i = 0; i < hugetlbs_len; i++) {
        oci_spec->linux->resources->hugepage_limits[oci_spec->linux->resources->hugepage_limits_len] =
            util_common_calloc_s(sizeof(defs_resources_hugepage_limits_element));
        if (oci_spec->linux->resources->hugepage_limits[oci_spec->linux->resources->hugepage_limits_len] == NULL) {
            ERROR("Failed to malloc memory for hugepage limits");
            ret = -1;
            goto out;
        }
        oci_spec->linux->resources->hugepage_limits[oci_spec->linux->resources->hugepage_limits_len]->limit =
            hugetlbs[i]->limit;
        oci_spec->linux->resources->hugepage_limits[oci_spec->linux->resources->hugepage_limits_len]->page_size =
            util_strdup_s(hugetlbs[i]->page_size);
        oci_spec->linux->resources->hugepage_limits_len++;
    }
out:
    return ret;
}

static int make_sure_oci_spec_hooks(oci_runtime_spec *oci_spec)
{
    if (oci_spec->hooks == NULL) {
        oci_spec->hooks = util_common_calloc_s(sizeof(oci_runtime_spec_hooks));
        if (oci_spec->hooks == NULL) {
            return -1;
        }
    }
    return 0;
}

static int merge_hook_spec(oci_runtime_spec *oci_spec, const char *hook_spec)
{
    int ret = 0;
    parser_error err = NULL;
    oci_runtime_spec_hooks *hooks = NULL;

    if (hook_spec == NULL) {
        return 0;
    }

    ret = make_sure_oci_spec_hooks(oci_spec);
    if (ret < 0) {
        goto out;
    }

    hooks = oci_runtime_spec_hooks_parse_file(hook_spec, NULL, &err);
    if (hooks == NULL) {
        ERROR("Failed to parse hook-spec file: %s", err);
        ret = -1;
        goto out;
    }
    ret = merge_hooks(oci_spec->hooks, hooks);
    free_oci_runtime_spec_hooks(hooks);
    if (ret < 0) {
        goto out;
    }

out:
    free(err);
    return ret;
}

static void clean_correlated_selinux(defs_process *process)
{
    if (process == NULL) {
        return;
    }

    free(process->selinux_label);
    process->selinux_label = NULL;
}

static void clean_correlated_read_only_path(oci_runtime_config_linux *linux)
{
    if (linux == NULL) {
        return;
    }

    if (linux->readonly_paths != NULL && linux->readonly_paths_len) {
        size_t i;
        for (i = 0; i < linux->readonly_paths_len; i++) {
            free(linux->readonly_paths[i]);
            linux->readonly_paths[i] = NULL;
        }
        free(linux->readonly_paths);
        linux->readonly_paths = NULL;
        linux->readonly_paths_len = 0;
    }
}

static void clean_correlated_masked_path(oci_runtime_config_linux *linux)
{
    if (linux == NULL) {
        return;
    }

    if (linux->masked_paths != NULL && linux->masked_paths_len) {
        size_t i;
        for (i = 0; i < linux->masked_paths_len; i++) {
            free(linux->masked_paths[i]);
            linux->masked_paths[i] = NULL;
        }
        free(linux->masked_paths);
        linux->masked_paths = NULL;
        linux->masked_paths_len = 0;
    }
}

static void clean_correlated_seccomp(oci_runtime_config_linux *linux)
{
    if (linux == NULL) {
        return;
    }

    free_oci_runtime_config_linux_seccomp(linux->seccomp);
    linux->seccomp = NULL;
}

static void clean_correlated_items(const oci_runtime_spec *oci_spec)
{
    if (oci_spec == NULL) {
        return;
    }

    clean_correlated_selinux(oci_spec->process);
    clean_correlated_masked_path(oci_spec->linux);
    clean_correlated_read_only_path(oci_spec->linux);
    clean_correlated_seccomp(oci_spec->linux);
}

static int adapt_settings_for_privileged(oci_runtime_spec *oci_spec, bool privileged)
{
    int ret = 0;
    size_t all_caps_len = 0;
    const char **all_caps = NULL;

    if (!privileged) {
        return 0;
    }

    all_caps = util_get_all_caps(&all_caps_len);
    if (all_caps == NULL) {
        ERROR("Failed to get all capabilities");
        return -1;
    }

    clean_correlated_items(oci_spec);

    ret = set_mounts_readwrite_option(oci_spec);
    if (ret != 0) {
        goto out;
    }

    /* add all capabilities */
    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    ret = refill_oci_process_capabilities(&oci_spec->process->capabilities, all_caps, all_caps_len);
    if (ret != 0) {
        ERROR("Failed to copy all capabilities");
        ret = -1;
        goto out;
    }

    ret = merge_all_devices_and_all_permission(oci_spec);
    if (ret != 0) {
        ERROR("Failed to merge all devices on host and all devices's cgroup permission");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int make_sure_oci_spec_linux_resources_pids(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->resources->pids == NULL) {
        oci_spec->linux->resources->pids = util_common_calloc_s(sizeof(defs_resources_pids));
        if (oci_spec->linux->resources->pids == NULL) {
            return -1;
        }
    }
    return 0;
}

static int make_sure_oci_spec_linux_resources_files(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->resources->files != NULL) {
        return 0;
    }

    oci_spec->linux->resources->files = util_common_calloc_s(sizeof(defs_resources_files));
    if (oci_spec->linux->resources->files == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    return 0;
}

static int merge_pids_limit(oci_runtime_spec *oci_spec, int64_t pids_limit)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_pids(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->linux->resources->pids->limit = pids_limit;

out:
    return ret;
}

static int merge_files_limit(oci_runtime_spec *oci_spec, int64_t files_limit)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_files(oci_spec);
    if (ret < 0) {
        ERROR("Failed to merge files limit");
        return ret;
    }

    oci_spec->linux->resources->files->limit = files_limit;
    return ret;
}

static int merge_hostname(oci_runtime_spec *oci_spec, const host_config *host_spec, container_config *container_spec)
{
    free(oci_spec->hostname);
    oci_spec->hostname = util_strdup_s(container_spec->hostname);

    return 0;
}

static int merge_nanocpus(oci_runtime_spec *oci_spec, int64_t nanocpus)
{
    int ret = 0;
    uint64_t period = 0;
    int64_t quota = 0;

    ret = make_sure_oci_spec_linux_resources_cpu(oci_spec);
    if (ret < 0) {
        goto out;
    }

    period = (uint64_t)(100 * Time_Milli / Time_Micro);
    quota = nanocpus * (int64_t)period / 1e9;

    oci_spec->linux->resources->cpu->quota = quota;
    oci_spec->linux->resources->cpu->period = period;

out:
    return ret;
}

static int merge_conf_cgroup_cpu_int64(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    if (host_spec->nano_cpus > 0) {
        ret = merge_nanocpus(oci_spec, host_spec->nano_cpus);
        if (ret != 0) {
            ERROR("Failed to merge cgroup nano cpus");
            goto out;
        }
    }

    /* cpu shares */
    if (host_spec->cpu_shares != 0) {
        ret = merge_cpu_shares(oci_spec, host_spec->cpu_shares);
        if (ret != 0) {
            ERROR("Failed to merge cgroup cpu shares");
            goto out;
        }
    }

    /* cpu period */
    if (host_spec->cpu_period != 0) {
        ret = merge_cpu_period(oci_spec, host_spec->cpu_period);
        if (ret != 0) {
            ERROR("Failed to merge cgroup cpu period");
            goto out;
        }
    }

    /* cpu realtime period */
    if (host_spec->cpu_realtime_period != 0) {
        ret = merge_cpu_realtime_period(oci_spec, host_spec->cpu_realtime_period);
        if (ret != 0) {
            ERROR("Failed to merge cgroup cpu realtime period");
            goto out;
        }
    }

    /* cpu realtime runtime */
    if (host_spec->cpu_realtime_runtime != 0) {
        ret = merge_cpu_realtime_runtime(oci_spec, host_spec->cpu_realtime_runtime);
        if (ret != 0) {
            ERROR("Failed to merge cgroup cpu realtime runtime");
            goto out;
        }
    }

    /* cpu quota */
    if (host_spec->cpu_quota != 0) {
        ret = merge_cpu_quota(oci_spec, host_spec->cpu_quota);
        if (ret != 0) {
            ERROR("Failed to merge cgroup cpu quota");
            goto out;
        }
    }

out:
    return ret;
}

static int merge_conf_cgroup_cpu(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    ret = merge_conf_cgroup_cpu_int64(oci_spec, host_spec);
    if (ret != 0) {
        goto out;
    }

    /* cpuset-cpus */
    if (util_valid_str(host_spec->cpuset_cpus)) {
        ret = merge_cpuset_cpus(oci_spec, host_spec->cpuset_cpus);
        if (ret != 0) {
            ERROR("Failed to merge cgroup cpuset cpus");
            goto out;
        }
    }

    /* cpuset mems */
    if (util_valid_str(host_spec->cpuset_mems)) {
        ret = merge_cpuset_mems(oci_spec, host_spec->cpuset_mems);
        if (ret != 0) {
            ERROR("Failed to merge cgroup cpuset mems");
            goto out;
        }
    }

out:
    return ret;
}

static int merge_memory_swappiness(oci_runtime_spec *oci_spec, uint64_t *memory_swappiness)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux_resources_mem(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (memory_swappiness == NULL) {
#ifndef ENABLE_GVISOR
        oci_spec->linux->resources->memory->swappiness = (uint64_t)(-1);
#else
        oci_spec->linux->resources->memory->swappiness = 0;
#endif
    } else {
        oci_spec->linux->resources->memory->swappiness = *memory_swappiness;
    }

out:
    return ret;
}

static int merge_conf_cgroup_memory(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    /* memory limit */
    if (host_spec->memory != 0) {
        ret = merge_memory_limit(oci_spec, host_spec->memory);
        if (ret != 0) {
            ERROR("Failed to merge cgroup memory limit");
            goto out;
        }
    }

    if (host_spec->oom_kill_disable) {
        if (host_spec->memory == 0) {
            WARN("Disabling the OOM killer on containers without setting memory limit may be dangerous.");
        }

        ret = merge_memory_oom_kill_disable(oci_spec, host_spec->oom_kill_disable);
        if (ret != 0) {
            ERROR("Failed to merge cgroup memory oom kill disable");
            goto out;
        }
    }

    /* memory swap */
    if (host_spec->memory_swap != 0) {
        ret = merge_memory_swap(oci_spec, host_spec->memory_swap);
        if (ret != 0) {
            ERROR("Failed to merge cgroup memory swap");
            goto out;
        }
    }

    /* memory reservation */
    if (host_spec->memory_reservation != 0) {
        ret = merge_memory_reservation(oci_spec, host_spec->memory_reservation);
        if (ret != 0) {
            ERROR("Failed to merge cgroup memory reservation");
            goto out;
        }
    }

    /* kernel_memory */
    if (host_spec->kernel_memory != 0) {
        ret = merge_kernel_memory(oci_spec, host_spec->kernel_memory);
        if (ret != 0) {
            ERROR("Failed to merge cgroup kernel_memory");
            goto out;
        }
    }

    ret = merge_memory_swappiness(oci_spec, host_spec->memory_swappiness);
    if (ret != 0) {
        ERROR("Failed to merge cgroup memory_swappiness");
        goto out;
    }

out:
    return ret;
}

static int merge_conf_blkio_weight(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    /* blkio weight */
    if (host_spec->blkio_weight != 0) {
        ret = merge_blkio_weight(oci_spec, host_spec->blkio_weight);
        if (ret != 0) {
            ERROR("Failed to merge cgroup blkio weight");
            goto out;
        }
    }
out:
    return ret;
}

static int do_merge_one_ulimit_override(const oci_runtime_spec *oci_spec, defs_process_rlimits_element *rlimit)
{
    size_t j;
    bool exists = false;

    for (j = 0; j < oci_spec->process->rlimits_len; j++) {
        if (oci_spec->process->rlimits[j]->type == NULL) {
            ERROR("rlimit type is empty");
            free(rlimit->type);
            free(rlimit);
            return -1;
        }
        if (strcmp(oci_spec->process->rlimits[j]->type, rlimit->type) == 0) {
            exists = true;
            break;
        }
    }
    if (exists) {
        /* override ulimit */
        free_defs_process_rlimits_element(oci_spec->process->rlimits[j]);
        oci_spec->process->rlimits[j] = rlimit;
    } else {
        oci_spec->process->rlimits[oci_spec->process->rlimits_len] = rlimit;
        oci_spec->process->rlimits_len++;
    }

    return 0;
}

static int merge_one_ulimit_override(const oci_runtime_spec *oci_spec, const host_config_ulimits_element *ulimit)
{
    defs_process_rlimits_element *rlimit = NULL;

    if (trans_ulimit_to_rlimit(&rlimit, ulimit) != 0) {
        return -1;
    }

    return do_merge_one_ulimit_override(oci_spec, rlimit);
}

static int merge_ulimits_override(oci_runtime_spec *oci_spec, host_config_ulimits_element **ulimits, size_t ulimits_len)
{
    int ret = 0;
    size_t i = 0;

    if (oci_spec == NULL || ulimits == NULL || ulimits_len == 0) {
        return -1;
    }

    ret = merge_ulimits_pre(oci_spec, ulimits_len);
    if (ret < 0) {
        goto out;
    }

    for (i = 0; i < ulimits_len; i++) {
        ret = merge_one_ulimit_override(oci_spec, ulimits[i]);
        if (ret != 0) {
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int merge_conf_ulimits(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    /* rlimits */
    if (host_spec->ulimits != NULL && host_spec->ulimits_len != 0) {
        if (host_spec->ulimits_len > LIST_SIZE_MAX) {
            ERROR("Too many ulimits to add, the limit is %lld", LIST_SIZE_MAX);
            isulad_set_error_message("Too many ulimits to add, the limit is %d", LIST_SIZE_MAX);
            ret = -1;
            goto out;
        }
        ret = merge_ulimits_override(oci_spec, host_spec->ulimits, host_spec->ulimits_len);
        if (ret != 0) {
            ERROR("Failed to merge rlimits");
            goto out;
        }
    }

out:
    return ret;
}

static int merge_conf_hugetlbs(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    /* hugepage limits */
    if (host_spec->hugetlbs_len != 0 && host_spec->hugetlbs != NULL) {
        if (host_spec->hugetlbs_len > LIST_SIZE_MAX) {
            ERROR("Too many hugetlbs to add, the limit is %lld", LIST_SIZE_MAX);
            isulad_set_error_message("Too many hugetlbs to add, the limit is %d", LIST_SIZE_MAX);
            ret = -1;
            goto out;
        }
        ret = merge_hugetlbs(oci_spec, host_spec->hugetlbs, host_spec->hugetlbs_len);
        if (ret != 0) {
            ERROR("Failed to merge cgroup hugepage limits");
            goto out;
        }
    }

out:
    return ret;
}

static int merge_conf_pids_limit(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    /* pids limit */
    if (host_spec->pids_limit != 0) {
        ret = merge_pids_limit(oci_spec, host_spec->pids_limit);
        if (ret != 0) {
            ERROR("Failed to merge pids limit");
            goto out;
        }
    }

out:
    return ret;
}

static int merge_conf_files_limit(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    if (host_spec->files_limit == 0) {
        return 0;
    }

    return merge_files_limit(oci_spec, host_spec->files_limit);
}

static int merge_conf_unified(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int i, cgroup_version;

    if (host_spec->unified == NULL || host_spec->unified->len == 0) {
        return 0;
    }

    cgroup_version = common_get_cgroup_version();
    if (cgroup_version != CGROUP_VERSION_2) {
        WARN("Cannot setting unified config without cgroup v2");
        return 0;
    }

    if (make_sure_oci_spec_linux_resources(oci_spec) != 0) {
        ERROR("Failed to make sure oci spec linux resource");
        return -1;
    }

    if (oci_spec->linux->resources->unified == NULL) {
        oci_spec->linux->resources->unified = (json_map_string_string *)util_common_calloc_s(
                                                  sizeof(json_map_string_string));
        if (oci_spec->linux->resources->unified == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    for (i = 0; i < host_spec->unified->len; i++) {
        if (append_json_map_string_string(oci_spec->linux->resources->unified, host_spec->unified->keys[i],
                                          host_spec->unified->values[i]) != 0) {
            ERROR("Failed to append unified map");
            return -1;
        }
    }

    return 0;
}

int merge_conf_cgroup(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;

    if (oci_spec == NULL || host_spec == NULL) {
        return -1;
    }

    ret = merge_conf_cgroup_cpu(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_cgroup_memory(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_blkio_weight(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_ulimits(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_hugetlbs(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_pids_limit(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_files_limit(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_unified(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    return 0;
}

static int prepare_process_args(oci_runtime_spec *oci_spec, size_t args_len)
{
    int ret = 0;

    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->process->args_len != 0 && oci_spec->process->args != NULL) {
        size_t i;
        for (i = 0; i < oci_spec->process->args_len; i++) {
            free(oci_spec->process->args[i]);
            oci_spec->process->args[i] = NULL;
        }
        free(oci_spec->process->args);
        oci_spec->process->args = NULL;
        oci_spec->process->args_len = 0;
    }

    oci_spec->process->args = util_smart_calloc_s(sizeof(char *), args_len);
    if (oci_spec->process->args == NULL) {
        return -1;
    }
    return 0;
}

static int replace_entrypoint_cmds_from_spec(const oci_runtime_spec *oci_spec, container_config *container_spec)
{
    if (oci_spec->process->args_len == 0) {
        ERROR("No command specified");
        isulad_set_error_message("No command specified");
        return -1;
    }
    return util_dup_array_of_strings((const char **)(oci_spec->process->args), oci_spec->process->args_len,
                                     &(container_spec->cmd), &(container_spec->cmd_len));
}

static int merge_conf_args(oci_runtime_spec *oci_spec, container_config *container_spec)
{
    int ret = 0;
    size_t argslen = 0;
    size_t i = 0;

    // Reset entrypoint if we do not want to use entrypoint from image
    if (container_spec->entrypoint_len == 1 && container_spec->entrypoint[0][0] == '\0') {
        free(container_spec->entrypoint[0]);
        container_spec->entrypoint[0] = NULL;
        free(container_spec->entrypoint);
        container_spec->entrypoint = NULL;
        container_spec->entrypoint_len = 0;
    }

    argslen = container_spec->cmd_len;
    if (container_spec->entrypoint_len != 0) {
        argslen += container_spec->entrypoint_len;
    }

    if (argslen > LIST_SIZE_MAX) {
        ERROR("Too many commands to add, the limit is %lld", LIST_SIZE_MAX);
        isulad_set_error_message("Too many commands to add, the limit is %d", LIST_SIZE_MAX);
        return -1;
    }

    if (argslen == 0) {
        return replace_entrypoint_cmds_from_spec(oci_spec, container_spec);
    }

    if (prepare_process_args(oci_spec, argslen) < 0) {
        ret = -1;
        goto out;
    }

    // append commands... to entrypoint
    for (i = 0; container_spec->entrypoint != NULL && i < container_spec->entrypoint_len; i++) {
        oci_spec->process->args[oci_spec->process->args_len] = util_strdup_s(container_spec->entrypoint[i]);
        oci_spec->process->args_len++;
    }

    for (i = 0; container_spec->cmd != NULL && i < container_spec->cmd_len; i++) {
        oci_spec->process->args[oci_spec->process->args_len] = util_strdup_s(container_spec->cmd[i]);
        oci_spec->process->args_len++;
    }

out:
    return ret;
}

static int merge_share_namespace_helper(const oci_runtime_spec *oci_spec, const char *ns_path, const char *type)
{
    int ret = -1;
    size_t len = 0;
    size_t org_len = 0;
    size_t i = 0;
    defs_namespace_reference **work_ns = NULL;

    org_len = oci_spec->linux->namespaces_len;
    len = oci_spec->linux->namespaces_len;
    work_ns = oci_spec->linux->namespaces;

    for (i = 0; i < org_len; i++) {
        if (strcmp(type, work_ns[i]->type) == 0) {
            free(work_ns[i]->path);
            work_ns[i]->path = NULL;
            if (ns_path != NULL) {
                work_ns[i]->path = util_strdup_s(ns_path);
            }
            break;
        }
    }

    if (i >= org_len) {
        if (len > (SIZE_MAX / sizeof(defs_namespace_reference *)) - 1) {
            ret = -1;
            ERROR("Out of memory");
            goto out;
        }

        ret = util_mem_realloc((void **)&work_ns, (len + 1) * sizeof(defs_namespace_reference *), (void *)work_ns,
                               len * sizeof(defs_namespace_reference *));
        if (ret != 0) {
            ERROR("Out of memory");
            goto out;
        }
        work_ns[len] = util_common_calloc_s(sizeof(defs_namespace_reference));
        if (work_ns[len] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        work_ns[len]->type = util_strdup_s(type);
        if (ns_path != NULL) {
            work_ns[len]->path = util_strdup_s(ns_path);
        }
        len++;
    }
    ret = 0;
out:
    if (work_ns != NULL) {
        oci_spec->linux->namespaces = work_ns;
        oci_spec->linux->namespaces_len = len;
    }
    return ret;
}

static int merge_share_single_namespace(const oci_runtime_spec *oci_spec, const char *path,
                                        const char *type, const container_sandbox_info *sandbox_info)
{
    int ret = 0;
    char *ns_path = NULL;

    if (path == NULL) {
        return 0;
    }

#ifdef ENABLE_CRI_API_V1
    if (namespace_is_sandbox(path, sandbox_info)) {
        ns_path = format_share_namespace_path(sandbox_info->pid, type);
        if (ns_path == NULL) {
            ERROR("Failed to get sandbox namespace path");
            return -1;
        }
    } else {
        ret = get_share_namespace_path(type, path, &ns_path);
        if (ret != 0) {
            ERROR("Failed to get share ns type:%s path:%s", type, path);
            return -1;
        }
    }
#else
    (void)sandbox_info;
    ret = get_share_namespace_path(type, path, &ns_path);
    if (ret != 0) {
        ERROR("Failed to get share ns type:%s path:%s", type, path);
        return -1;
    }
#endif


    ret = merge_share_namespace_helper(oci_spec, ns_path, type);
    if (ret != 0) {
        ERROR("Failed to merge share namespace namespace helper");
    }

    free(ns_path);
    return ret;
}

static int merge_share_network_namespace(const oci_runtime_spec *oci_spec, const host_config *host_spec,
                                         const container_network_settings *network_settings, const char *type,
                                         const container_sandbox_info *sandbox_info)
{
    int ret = 0;
    char *ns_path = NULL;

    if (host_spec->network_mode == NULL) {
        return 0;
    }

#ifdef ENABLE_CRI_API_V1
    if (namespace_is_sandbox(host_spec->network_mode, sandbox_info)) {
        ns_path = format_share_namespace_path(sandbox_info->pid, type);
        if (ns_path == NULL) {
            ERROR("Failed to get sandbox namespace path");
            return -1;
        }
    } else {
        ret = get_network_namespace_path(host_spec, network_settings, type, &ns_path);
        if (ret != 0) {
            ERROR("Failed to get network namespace path");
            return -1;
        }
    }
#else
    (void)sandbox_info;
    ret = get_network_namespace_path(host_spec, network_settings, type, &ns_path);
    if (ret != 0) {
        ERROR("Failed to get network namespace path");
        return -1;
    }
#endif
    ret = merge_share_namespace_helper(oci_spec, ns_path, type);
    if (ret != 0) {
        ERROR("Failed to merge share namespace namespace helper");
    }

    free(ns_path);
    return ret;
}

#ifdef ENABLE_USERNS_REMAP
static bool userns_remap_is_enabled(const oci_runtime_spec *oci_spec)
{
    if (oci_spec->linux->uid_mappings != NULL && oci_spec->linux->gid_mappings != NULL) {
        return true;
    }
    return false;
}
#endif

int merge_share_namespace(oci_runtime_spec *oci_spec, const host_config *host_spec,
                          const container_config_v2_common_config *v2_spec,
                          const container_network_settings *network_settings)
{
    int ret = -1;
    const container_sandbox_info *sandbox_info = NULL;

    if (oci_spec == NULL || host_spec == NULL || v2_spec == NULL) {
        goto out;
    }

    if (make_sure_oci_spec_linux(oci_spec) < 0) {
        goto out;
    }

    sandbox_info = v2_spec->sandbox_info;

#ifdef ENABLE_USERNS_REMAP
    // user
    if (userns_remap_is_enabled(oci_spec) &&
        merge_share_single_namespace(oci_spec, "user", TYPE_NAMESPACE_USER, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }
#else
    if (merge_share_single_namespace(oci_spec, host_spec->userns_mode, TYPE_NAMESPACE_USER, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }

    // user remap
    if (host_spec->user_remap != NULL &&
        merge_share_single_namespace(oci_spec, "user", TYPE_NAMESPACE_USER, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }
#endif

    // network
    if (merge_share_network_namespace(oci_spec, host_spec, network_settings, TYPE_NAMESPACE_NETWORK, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }

    // ipc
    if (merge_share_single_namespace(oci_spec, host_spec->ipc_mode, TYPE_NAMESPACE_IPC, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }

    // pid
    if (merge_share_single_namespace(oci_spec, host_spec->pid_mode, TYPE_NAMESPACE_PID, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }

    // uts
    if (merge_share_single_namespace(oci_spec, host_spec->uts_mode, TYPE_NAMESPACE_UTS, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }

    // cgroup
    if (merge_share_single_namespace(oci_spec, host_spec->cgroupns_mode, TYPE_NAMESPACE_CGROUP, sandbox_info) != 0) {
        ret = -1;
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int merge_working_dir(oci_runtime_spec *oci_spec, const char *working_dir)
{
    int ret = 0;

    if (!util_valid_str(working_dir)) {
        return 0;
    }

    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    free(oci_spec->process->cwd);
    oci_spec->process->cwd = util_strdup_s(working_dir);

out:
    return ret;
}

static int change_tmpfs_mount_size(const oci_runtime_spec *oci_spec, int64_t memory_limit)
{
    int ret = 0;
    size_t i = 0;
    char size_opt[MOUNT_PROPERTIES_SIZE] = { 0 };

    if (oci_spec->mounts == NULL) {
        goto out;
    }
    if (memory_limit <= 0) {
        goto out;
    }
    /* set tmpfs mount size to half of container memory limit */
    int nret = snprintf(size_opt, sizeof(size_opt), "size=%lldk", (long long int)(memory_limit / 2048));
    if (nret < 0 || (size_t)nret >= sizeof(size_opt)) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    for (i = 0; i < oci_spec->mounts_len; i++) {
        if (strcmp("tmpfs", oci_spec->mounts[i]->type) != 0) {
            continue;
        }
        if (strcmp("/run", oci_spec->mounts[i]->destination) == 0 ||
            strcmp("/run/lock", oci_spec->mounts[i]->destination) == 0 ||
            strcmp("/tmp", oci_spec->mounts[i]->destination) == 0) {
            ret = util_array_append(&oci_spec->mounts[i]->options, size_opt);
            if (ret != 0) {
                ERROR("append mount size option failed");
                goto out;
            }
            oci_spec->mounts[i]->options_len++;
        }
    }

out:
    return ret;
}

static int merge_settings_for_system_container(oci_runtime_spec *oci_spec, host_config *host_spec,
                                               container_config *container_spec)
{
    int ret = -1;

    if (oci_spec == NULL || host_spec == NULL) {
        return -1;
    }

    if (!host_spec->system_container) {
        return 0;
    }

    ret = adapt_settings_for_system_container(oci_spec, host_spec);
    if (ret != 0) {
        ERROR("Failed to adapt settings for system container");
        goto out;
    }
    if (change_tmpfs_mount_size(oci_spec, host_spec->memory) != 0) {
        ret = -1;
        ERROR("Failed to change tmpfs mount size for system container");
        goto out;
    }

    // append mounts of oci_spec
    if (container_spec->ns_change_opt != NULL) {
        ret = adapt_settings_for_mounts(oci_spec, container_spec);
        if (ret != 0) {
            ERROR("Failed to adapt settings for ns_change_opt");
            goto out;
        }
    }

out:
    return ret;
}

static int merge_resources_conf(oci_runtime_spec *oci_spec, host_config *host_spec,
                                container_config_v2_common_config *v2_spec)
{
    int ret = 0;

    ret = merge_conf_cgroup(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_blkio_device(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    ret = merge_conf_devices(oci_spec, host_spec);
    if (ret != 0) {
        return -1;
    }

    return merge_conf_mounts(oci_spec, host_spec, v2_spec);
}

static int merge_terminal(oci_runtime_spec *oci_spec, bool terminal)
{
    int ret = 0;

    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->process->terminal = terminal;

out:
    return ret;
}

static int merge_process_conf(oci_runtime_spec *oci_spec, const host_config *host_spec,
                              container_config *container_spec)
{
    int ret = 0;

    ret = merge_conf_args(oci_spec, container_spec);
    if (ret != 0) {
        goto out;
    }

    /* environment variables */
    ret = merge_env(oci_spec, (const char **)container_spec->env, container_spec->env_len);
    if (ret != 0) {
        ERROR("Failed to merge environment variables");
        goto out;
    }

    /* env target file */
    ret = merge_env_target_file(oci_spec, host_spec->env_target_file);
    if (ret != 0) {
        ERROR("Failed to merge env target file");
        goto out;
    }

    /* working dir */
    ret = merge_working_dir(oci_spec, container_spec->working_dir);
    if (ret != 0) {
        ERROR("Failed to merge working dir");
        goto out;
    }

    /* hook-spec file */
    ret = merge_hook_spec(oci_spec, host_spec->hook_spec);
    if (ret != 0) {
        ERROR("Failed to merge hook spec");
        goto out;
    }

    /* merge whether allocate a pseudo-TTY */
    ret = merge_terminal(oci_spec, container_spec->tty);
    if (ret != 0) {
        ERROR("Failed to merge process terminal");
        goto out;
    }

out:
    return ret;
}

static int split_security_opt(const char *security_opt, char ***items, size_t *items_size)
{
    int ret = 0;

    if (util_strings_contains_any(security_opt, "=")) {
        *items = util_string_split_n(security_opt, '=', 2);
        if (*items == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        *items_size = util_array_len((const char **)*items);
    } else if (util_strings_contains_any(security_opt, ":")) {
        *items = util_string_split_n(security_opt, ':', 2);
        if (*items == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        *items_size = util_array_len((const char **)*items);
        WARN("Security options with `:` as a separator are deprecated and will be completely unsupported"
             " in new version, use `=` instead.");
    }

out:
    return ret;
}

int parse_security_opt(const host_config *host_spec, bool *no_new_privileges, char ***label_opts,
                       size_t *label_opts_len, char **seccomp_profile)
{
    int ret = 0;
    size_t i;
    char **items = NULL;
    size_t items_size = 0;

    if (host_spec->security_opt == NULL || host_spec->security_opt_len == 0) {
        return 0;
    }
    if (host_spec->security_opt_len > LIST_SIZE_MAX) {
        ERROR("Too many security option to add, the limit is %lld", LIST_SIZE_MAX);
        isulad_set_error_message("Too many security option to add, the limit is %d", LIST_SIZE_MAX);
        ret = -1;
        goto out;
    }

    for (i = 0; i < host_spec->security_opt_len; i++) {
        if (strcmp(host_spec->security_opt[i], "no-new-privileges") == 0) {
            *no_new_privileges = true;
            continue;
        } else if (strcmp(host_spec->security_opt[i], "disable") == 0) {
            ret = util_array_append(label_opts, "disable");
            if (ret != 0) {
                ERROR("Failed to append disable label");
                ret = -1;
                goto out;
            }
            (*label_opts_len)++;
            continue;
        }

        if (split_security_opt(host_spec->security_opt[i], &items, &items_size) != 0) {
            ret = -1;
            goto out;
        }

        if (items == NULL || items_size != 2) {
            ERROR("invalid --security-opt: %s", host_spec->security_opt[i]);
            ret = -1;
            goto out;
        }

        if (strcmp(items[0], "label") == 0) {
            ret = util_array_append(label_opts, items[1]);
            if (ret != 0) {
                ERROR("Failed to append label");
                ret = -1;
                goto out;
            }
            (*label_opts_len)++;
        } else if (strcmp(items[0], "seccomp") == 0) {
            free(*seccomp_profile);
            *seccomp_profile = util_strdup_s(items[1]);
        } else {
            ERROR("invalid --security-opt: %s", host_spec->security_opt[i]);
            ret = -1;
            goto out;
        }
        util_free_array(items);
        items = NULL;
        items_size = 0;
    }

out:
    util_free_array(items);
    return ret;
}

#ifdef ENABLE_SELINUX
static int to_host_config_selinux_labels(const char **labels, size_t len, char ***dst, size_t *dst_len)
{
    int ret = 0;
    size_t i;
    char *item = NULL;

    for (i = 0; i < len; i++) {
        item = util_string_append(labels[i], "label=");
        if (item == NULL) {
            ERROR("Failed to append string");
            ret = -1;
            goto out;
        }
        if (util_array_append(dst, item) != 0) {
            ERROR("Failed to append label");
            ret = -1;
            goto out;
        }
    }
    *dst_len = util_array_len((const char **)*dst);

out:
    free(item);
    return ret;
}

static int handle_host_or_privileged_mode(host_config *hc)
{
    int ret = 0;
    char **labels = NULL;
    size_t labels_len = 0;

    if (get_disable_security_opt(&labels, &labels_len) != 0) {
        ret = -1;
        goto out;
    }

    if (to_host_config_selinux_labels((const char **)labels, labels_len, &hc->security_opt, &hc->security_opt_len) !=
        0) {
        ret = -1;
        goto out;
    }

out:
    util_free_array(labels);
    return ret;
}

static int handle_ipc_pid_label(host_config *hc, const char **ipc_label, size_t ipc_label_len, const char **pid_label,
                                size_t pid_label_len)
{
    int ret = 0;
    size_t i;

    if (pid_label != NULL && ipc_label != NULL) {
        if (pid_label_len != ipc_label_len) {
            ERROR("--ipc and --pid containers SELinux labels aren't the same");
            ret = -1;
            goto out;
        }
        for (i = 0; i < pid_label_len; i++) {
            if (strcmp(pid_label[i], ipc_label[i]) != 0) {
                ERROR("--ipc and --pid containers SELinux labels aren't the same");
                ret = -1;
                goto out;
            }
        }
        if (to_host_config_selinux_labels((const char **)pid_label, pid_label_len, &hc->security_opt,
                                          &hc->security_opt_len) != 0) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int handle_connected_container_mode(host_config *hc)
{
    int ret = 0;
    char **ipc_label = NULL;
    size_t ipc_label_len = 0;
    char **pid_label = NULL;
    size_t pid_label_len = 0;

    char *ipc_container = namespace_get_connected_container(hc->ipc_mode);
    char *pid_container = namespace_get_connected_container(hc->pid_mode);
    if (ipc_container != NULL) {
        char *ipc_process_label = get_container_process_label(ipc_container);
        if (dup_security_opt(ipc_process_label, &ipc_label, &ipc_label_len) != 0) {
            free(ipc_process_label);
            ret = -1;
            goto out;
        }
        if (pid_container == NULL) {
            if (to_host_config_selinux_labels((const char **)ipc_label, ipc_label_len, &hc->security_opt,
                                              &hc->security_opt_len) != 0) {
                free(ipc_process_label);
                ret = -1;
                goto out;
            }
        }
        free(ipc_process_label);
    }

    if (pid_container != NULL) {
        char *pid_process_label = get_container_process_label(pid_container);

        if (dup_security_opt(pid_process_label, &pid_label, &pid_label_len) != 0) {
            free(pid_process_label);
            ret = -1;
            goto out;
        }
        if (ipc_container == NULL) {
            if (to_host_config_selinux_labels((const char **)pid_label, pid_label_len, &hc->security_opt,
                                              &hc->security_opt_len) != 0) {
                free(pid_process_label);
                ret = -1;
                goto out;
            }
        }
        free(pid_process_label);
    }

    if (handle_ipc_pid_label(hc, (const char **)ipc_label, ipc_label_len, (const char **)pid_label, pid_label_len) !=
        0) {
        ret = -1;
        goto out;
    }

out:
    util_free_array(ipc_label);
    util_free_array(pid_label);
    free(ipc_container);
    free(pid_container);
    return ret;
}

static int generate_security_opt(host_config *hc)
{
    size_t i;

    for (i = 0; i < hc->security_opt_len; i++) {
        char **items = util_string_split(hc->security_opt[i], '=');
        if (items == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        size_t len = util_array_len((const char **)(items));
        if (len != 0 && strcmp(items[0], "label") == 0) {
            util_free_array(items);
            return 0;
        }
        util_free_array(items);
    }

    if (namespace_is_host(hc->ipc_mode) || namespace_is_host(hc->pid_mode) || hc->privileged) {
        return handle_host_or_privileged_mode(hc);
    }

    return handle_connected_container_mode(hc);
}
#endif

static int merge_paths(char ***dest_paths, size_t *dest_paths_len, char **src_paths, size_t src_paths_len)
{
    if (dest_paths == NULL || dest_paths_len == NULL) {
        ERROR("Invalid args");
        return -1;
    }

    if (src_paths_len > SIZE_MAX / sizeof(char *) ||
        *dest_paths_len > ((SIZE_MAX / sizeof(char *)) - src_paths_len)) {
        ERROR("Out of memory");
        return -1;
    }

    size_t i;
    char **tmp_paths = NULL;
    size_t old_size = *dest_paths_len * sizeof(char *);
    size_t new_size = old_size + src_paths_len * sizeof(char *);
    int ret = util_mem_realloc((void **)&tmp_paths, new_size,
                               (void *)*dest_paths, old_size);
    if (ret != 0) {
        ERROR("Out of memory");
        return -1;
    }

    *dest_paths = tmp_paths;
    for (i = 0; i < src_paths_len; i++) {
        (*dest_paths)[(*dest_paths_len)++] = util_strdup_s(src_paths[i]);
    }

    return 0;
}

static int merge_masked_paths(oci_runtime_spec *oci_spec, char **masked_paths, size_t masked_paths_len)
{
    if (masked_paths == NULL || masked_paths_len == 0) {
        return 0;
    }

    return merge_paths(&oci_spec->linux->masked_paths, &oci_spec->linux->masked_paths_len,
                       masked_paths, masked_paths_len);
}

static int merge_readonly_paths(oci_runtime_spec *oci_spec, char **readonly_paths, size_t readonly_paths_len)
{
    if (readonly_paths == NULL || readonly_paths_len == 0) {
        return 0;
    }

    return merge_paths(&oci_spec->linux->readonly_paths, &oci_spec->linux->readonly_paths_len,
                       readonly_paths, readonly_paths_len);
}

static int merge_security_conf(oci_runtime_spec *oci_spec, host_config *host_spec,
                               container_config_v2_common_config *v2_spec)
{
    int ret = 0;

#ifdef ENABLE_SELINUX
    ret = generate_security_opt(host_spec);
    if (ret != 0) {
        ERROR("Failed to generate security opt");
        goto out;
    }
#endif

    ret = merge_caps(oci_spec, (const char **)host_spec->cap_add, host_spec->cap_add_len,
                     (const char **)host_spec->cap_drop, host_spec->cap_drop_len);
    if (ret) {
        ERROR("Failed to merge caps");
        goto out;
    }

    ret = merge_default_seccomp_spec(oci_spec, oci_spec->process->capabilities);
    if (ret != 0) {
        ERROR("Failed to merge default seccomp file");
        goto out;
    }

    // merge external parameter
    ret = merge_seccomp(oci_spec, v2_spec->seccomp_profile);
    if (ret != 0) {
        ERROR("Failed to merge user seccomp file");
        goto out;
    }

    ret = merge_no_new_privileges(oci_spec, v2_spec->no_new_privileges);
    if (ret != 0) {
        ERROR("Failed to merge no new privileges");
        goto out;
    }

#ifdef ENABLE_SELINUX
    ret = merge_selinux(oci_spec, v2_spec);
    if (ret != 0) {
        ERROR("Failed to merge selinux config");
        goto out;
    }
#endif

    ret = merge_masked_paths(oci_spec, host_spec->masked_paths, host_spec->masked_paths_len);
    if (ret != 0) {
        ERROR("Failed to merge masked paths");
        goto out;
    }

    ret = merge_readonly_paths(oci_spec, host_spec->readonly_paths, host_spec->readonly_paths_len);
    if (ret != 0) {
        ERROR("Failed to merge readonly paths");
        goto out;
    }

out:
    return ret;
}

char *merge_container_cgroups_path(const char *id, const host_config *host_spec)
{
    __isula_auto_free char *path = NULL;

    if (id == NULL || host_spec == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    path = do_get_container_cgroup_path(host_spec);

    if (conf_get_systemd_cgroup()) {
        // systemd cgroup path has the form of [slice]:[prefix]:[name]
#define SYSTEMD_CGROUP_PATH_LEN 3
        if (!util_has_suffix(path, ".slice")) {
            ERROR("Invalid cgroup path %s for systemd", path);
            isulad_set_error_message("Invalid cgroup path %s for systemd", path);
            return NULL;
        }

        // slice must not contain slashes
        // convert test.slice/test-a.slice/test-a-b.slice to become test-a-b.slice
        __isula_auto_free char *base = util_path_base(path);
        const char *isulad_prefix = "isulad";
        const char *parts[SYSTEMD_CGROUP_PATH_LEN] = {base, isulad_prefix, id};
        return util_string_join(":", parts, SYSTEMD_CGROUP_PATH_LEN);
    }

    return util_path_join(path, id);
}

int update_oci_container_cgroups_path(const char *id, oci_runtime_spec *oci_spec, const host_config *hostconfig)
{
    if (oci_spec == NULL || oci_spec->linux == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    __isula_auto_free char *cgroup_parent = merge_container_cgroups_path(id, hostconfig);
    if (cgroup_parent == NULL) {
        return -1;
    }

    if (oci_spec->linux->cgroups_path != NULL && strcmp(oci_spec->linux->cgroups_path, cgroup_parent) != 0) {
        free(oci_spec->linux->cgroups_path);
        oci_spec->linux->cgroups_path = cgroup_parent;
        cgroup_parent = NULL;
    }

    return 0;
}

static int merge_oci_cgroups_path(const char *id, oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    if (id == NULL || oci_spec == NULL || host_spec == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    free(oci_spec->linux->cgroups_path);
    oci_spec->linux->cgroups_path = merge_container_cgroups_path(id, host_spec);

    if (oci_spec->linux->cgroups_path == NULL) {
        WARN("OCI spec cgroups path is NULL");
    }

    return 0;
}

int merge_all_specs(host_config *host_spec, const char *real_rootfs, container_config_v2_common_config *v2_spec,
                    oci_runtime_spec *oci_spec)
{
    int ret = 0;
#ifdef ENABLE_USERNS_REMAP
    char *userns_remap = conf_get_isulad_userns_remap();
#endif

    if (make_sure_oci_spec_linux(oci_spec) != 0) {
        ERROR("Failed to make oci spec linux");
        return -1;
    }

    ret = merge_root(oci_spec, real_rootfs, host_spec);
    if (ret != 0) {
        ERROR("Failed to merge root");
        goto out;
    }
    v2_spec->base_fs = util_strdup_s(real_rootfs);

    ret = merge_security_conf(oci_spec, host_spec, v2_spec);
    if (ret != 0) {
        ERROR("Failed to merge user security config");
        goto out;
    }

    ret = merge_resources_conf(oci_spec, host_spec, v2_spec);
    if (ret != 0) {
        goto out;
    }

    // should before merge process env
    ret = merge_hostname(oci_spec, host_spec, v2_spec->config);
    if (ret != 0) {
        ERROR("Failed to merge hostname");
        goto out;
    }

    ret = merge_process_conf(oci_spec, host_spec, v2_spec->config);
    if (ret != 0) {
        goto out;
    }

    // merge sysctl
    ret = merge_sysctls(oci_spec, host_spec->sysctls);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    /* settings for system container */
    ret = merge_settings_for_system_container(oci_spec, host_spec, v2_spec->config);
    if (ret != 0) {
        ERROR("Failed to merge system container conf");
        goto out;
    }

    /* settings for privileged */
    ret = adapt_settings_for_privileged(oci_spec, host_spec->privileged);
    if (ret != 0) {
        ERROR("Failed to adapt settings for privileged container");
        goto out;
    }

    ret = make_annotations(oci_spec, v2_spec->config, host_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

#ifdef ENABLE_USERNS_REMAP
    if (!host_spec->system_container && !namespace_is_host(host_spec->userns_mode)) {
        ret = make_userns_remap(oci_spec, userns_remap);
        if (ret != 0) {
            ERROR("Failed to make user remap for container");
            goto out;
        }
    } else {
        ret = make_userns_remap(oci_spec, host_spec->user_remap);
        if (ret != 0) {
            ERROR("Failed to make user remap for container");
            goto out;
        }
    }
#else
    ret = make_userns_remap(oci_spec, host_spec->user_remap);
    if (ret != 0) {
        ERROR("Failed to make user remap for container");
        goto out;
    }
#endif

    ret = merge_oci_cgroups_path(v2_spec->id, oci_spec, host_spec);
    if (ret != 0) {
        ERROR("Failed to make cgroup parent");
        goto out;
    }

out:
#ifdef ENABLE_USERNS_REMAP
    free(userns_remap);
#endif
    return ret;
}

/* merge the default config with host config and custom config */
int merge_global_config(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = merge_global_hook(oci_spec);
    if (ret != 0) {
        ERROR("Failed to merge global hooks");
        goto out;
    }

    ret = merge_global_ulimit(oci_spec);
    if (ret != 0) {
        ERROR("Failed to merge global ulimit");
        goto out;
    }

out:
    return ret;
}

int update_oci_ulimit(oci_runtime_spec *oci_spec, const host_config *hostconfig) {
    if (oci_spec == NULL || hostconfig == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    size_t i = 0;
    if (oci_spec->process != NULL) {
        for (i = 0; i < oci_spec->process->rlimits_len; i++) {
            free_defs_process_rlimits_element(oci_spec->process->rlimits[i]);
            oci_spec->process->rlimits[i] = NULL;
        }
        free(oci_spec->process->rlimits);
        oci_spec->process->rlimits = NULL;
        oci_spec->process->rlimits_len = 0;
    }

    if (merge_conf_ulimits(oci_spec, hostconfig) != 0 || merge_global_ulimit(oci_spec) != 0) {
        return -1;
    }

    return 0;
}

/* read oci config */
oci_runtime_spec *load_oci_config(const char *rootpath, const char *name)
{
    int nret;
    char filename[PATH_MAX] = { 0x00 };
    __isula_auto_free parser_error err = NULL;
    oci_runtime_spec *ociconfig = NULL;

    nret = snprintf(filename, sizeof(filename), "%s/%s/%s", rootpath, name, OCI_CONFIG_JSON);
    if (nret < 0 || (size_t)nret >= sizeof(filename)) {
        ERROR("Failed to print string");
        return NULL;
    }

    ociconfig = oci_runtime_spec_parse_file(filename, NULL, &err);
    if (ociconfig == NULL) {
        ERROR("Failed to parse oci config file:%s", err);
        isulad_set_error_message("Parse oci config file failed:%s", err);
        return NULL;
    }

    return ociconfig;
}

int save_oci_config(const char *id, const char *rootpath, const oci_runtime_spec *oci_spec)
{
    int nret = 0;
    char file_path[PATH_MAX] = { 0x0 };
    struct parser_context ctx = { OPT_PARSE_STRICT, stderr };
    __isula_auto_free char *json_container = NULL;
    __isula_auto_free parser_error err = NULL;

    nret = snprintf(file_path, PATH_MAX, "%s/%s/%s", rootpath, id, OCI_CONFIG_JSON);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to print string");
        return -1;
    }

    json_container = oci_runtime_spec_generate_json(oci_spec, &ctx, &err);
    if (json_container == NULL) {
        ERROR("Failed to generate json: %s", err);
        return -1;
    }

    nret = util_atomic_write_file(file_path, json_container, strlen(json_container), DEFAULT_SECURE_FILE_MODE, false);
    if (nret != 0) {
        SYSERROR("write json container failed");
        return -1;
    }

    return 0;
}

/* default_spec returns default oci spec used by isulad. */
oci_runtime_spec *default_spec(bool system_container)
{
    const char *oci_file = OCICONFIG_PATH;
    if (system_container) {
        oci_file = OCI_SYSTEM_CONTAINER_CONFIG_PATH;
    }
    oci_runtime_spec *oci_spec = NULL;
    __isula_auto_free parser_error err = NULL;

    /* parse the input oci file */
    oci_spec = oci_runtime_spec_parse_file(oci_file, NULL, &err);
    if (oci_spec == NULL) {
        ERROR("Failed to parse OCI specification file \"%s\", error message: %s", oci_file, err);
        isulad_set_error_message("Can not read the default %s file: %s", oci_file, err);
        return NULL;
    }

    return oci_spec;
}

const oci_runtime_spec *get_readonly_default_oci_spec(bool system_container)
{
    if (system_container) {
        return g_rdspec.system_cont;
    }

    return g_rdspec.cont;
}

int spec_module_init(void)
{
    g_rdspec.cont = default_spec(false);
    if (g_rdspec.cont == NULL) {
        return -1;
    }
    g_rdspec.system_cont = default_spec(true);
    if (g_rdspec.system_cont == NULL) {
        return -1;
    }
    return 0;
}

#ifdef ENABLE_CDI
static int add_env(defs_process *dp, const char *env, const char *key)
{
    size_t i;
    char *oci_key = NULL;
    char *oci_value = NULL;
    char *saveptr = NULL;
    __isula_auto_free char *tmp_env = NULL;
 
    for (i = 0; i < dp->env_len; i++) {
        tmp_env = util_strdup_s(dp->env[i]);
        oci_key = strtok_r(tmp_env, "=", &saveptr);
        oci_value = strtok_r(NULL, "=", &saveptr);
        if (oci_key == NULL || oci_value == NULL) {
            ERROR("Bad env format");
            return -1;
        }
        if (strcmp(key, oci_key) == 0) {
            free(dp->env[i]);
            dp->env[i] = util_strdup_s(env);
            return 0;
        }
        free(tmp_env);
        tmp_env = NULL;
    }
    if (util_mem_realloc((void **)&dp->env, (dp->env_len + 1) * sizeof(char *),
                         (void *)dp->env, dp->env_len * sizeof(char *)) != 0) {
        ERROR("Out of memory");
        return -1;
    }
    dp->env[dp->env_len] = util_strdup_s(env);
    dp->env_len++;
    return 0;
}

int defs_process_add_multiple_env(defs_process *dp, const char **envs, size_t env_len)
{
    size_t i;
    char *key = NULL;
    char *value = NULL;
    char *saveptr = NULL;
    __isula_auto_free char *tmp_env = NULL;

    if (envs == NULL || env_len == 0) {
        DEBUG("empty envs");
        return 0;
    }
    if (dp == NULL) {
        ERROR("Invalid params");
        return -1;
    }

    for (i = 0; i < env_len; i++) {
        tmp_env = util_strdup_s(envs[i]);
        key = strtok_r(tmp_env, "=", &saveptr);
        value = strtok_r(NULL, "=", &saveptr);
        if (key == NULL || value == NULL) {
            ERROR("Bad env format: %s", tmp_env);
            return -1;
        }
        if (add_env(dp, envs[i], key) != 0) {
            return -1;
        }
        free(tmp_env);
        tmp_env = NULL;
    }

    return 0;
}

int spec_add_multiple_process_env(oci_runtime_spec *oci_spec, const char **envs, size_t env_len)
{
    int ret = 0;
    
    if (envs == NULL || env_len == 0) {
        DEBUG("empty envs");
        return 0;
    }
    if (oci_spec == NULL) {
        ERROR("Invalid params");
        return -1;
    }
 
    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        ERROR("Out of memory");
        return -1;
    }
 
    ret = defs_process_add_multiple_env(oci_spec->process, envs, env_len);
    if (ret < 0) {
        ERROR("Failed to add envs");
    }
 
    return ret;
}
 
int spec_add_device(oci_runtime_spec *oci_spec, defs_device *device)
{
    int ret = 0;
    size_t i;
 
    if (device == NULL) {
        return -1;
    }
    ret = make_sure_oci_spec_linux(oci_spec);
    if (ret < 0) {
        return -1;
    }
    
    for (i = 0; i < oci_spec->linux->devices_len; i++) {
        if (strcmp(oci_spec->linux->devices[i]->path, device->path) == 0) {
            free_defs_device(oci_spec->linux->devices[i]);
            oci_spec->linux->devices[i] = device;
            return 0;
        }
    }

    if (util_mem_realloc((void **)&oci_spec->linux->devices, (oci_spec->linux->devices_len + 1) * sizeof(char *),
                         (void *)oci_spec->linux->devices, oci_spec->linux->devices_len * sizeof(char *)) != 0) {
        ERROR("Out of memory");
        return -1;
    }
    oci_spec->linux->devices[oci_spec->linux->devices_len] = device;
    oci_spec->linux->devices_len++;
 
    return 0;
}
 
int spec_add_linux_resources_device(oci_runtime_spec *oci_spec, bool allow, const char *dev_type,
                                    int64_t major, int64_t minor, const char *access)
{
    int ret = 0;
    defs_device_cgroup *device = NULL;
 
    ret = make_sure_oci_spec_linux_resources(oci_spec);
    if (ret < 0) {
        return -1;
    }
 
    device = util_common_calloc_s(sizeof(*device));
    if (device == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    device->allow = allow;
    device->type = util_strdup_s(dev_type);
    device->access = util_strdup_s(access);
    device->major = major;
    device->minor = minor;

    if (util_mem_realloc((void **)&oci_spec->linux->resources->devices, (oci_spec->linux->resources->devices_len + 1) * sizeof(char *),
                         (void *)oci_spec->linux->resources->devices, oci_spec->linux->resources->devices_len * sizeof(char *)) != 0) {
        ERROR("Out of memory");
        free_defs_device_cgroup(device);
        return -1;
    }
    oci_spec->linux->resources->devices[oci_spec->linux->resources->devices_len] = device;
    oci_spec->linux->resources->devices_len++;
 
    return 0;
}
 
void spec_remove_mount(oci_runtime_spec *oci_spec, const char *dest)
{
    size_t i;
 
    if (oci_spec == NULL || oci_spec->mounts == NULL || dest == NULL) {
        return;
    }
 
    for (i = 0; i < oci_spec->mounts_len; i++) {
        if (strcmp(oci_spec->mounts[i]->destination, dest) == 0) {
            free_defs_mount(oci_spec->mounts[i]);
            (void)memcpy((void **)&oci_spec->mounts[i], (void **)&oci_spec->mounts[i + 1],
                (oci_spec->mounts_len - i - 1) * sizeof(void *));        
            oci_spec->mounts_len--;
            return;
        }
    }
}
 
int spec_add_mount(oci_runtime_spec *oci_spec, defs_mount *mnt)
{
    if (oci_spec == NULL || mnt == NULL) {
        return -1;
    }
    
    if (util_mem_realloc((void **)&oci_spec->mounts, (oci_spec->mounts_len + 1) * sizeof(char *),
                         (void *)oci_spec->mounts, oci_spec->mounts_len * sizeof(char *)) != 0) {
        ERROR("Out of memory");
        return -1;
    }
    oci_spec->mounts[oci_spec->mounts_len] = mnt;
    oci_spec->mounts_len++;
 
    return 0;
}
 
#define SPEC_ADD_HOOKS_ITEM_DEF(hooktype)                                                                                   \
    int spec_add_##hooktype##_hook(oci_runtime_spec *oci_spec, defs_hook *hooktype##_hook)                                  \
    {                                                                                                                       \
        int ret = 0;                                                                                                        \
        if (oci_spec == NULL || hooktype##_hook == NULL) {                                                                  \
            return -1;                                                                                                      \
        }                                                                                                                   \
        ret = make_sure_oci_spec_hooks(oci_spec);                                                                           \
        if (ret < 0) {                                                                                                      \
            return -1;                                                                                                      \
        }                                                                                                                   \
        if (util_mem_realloc((void **)&oci_spec->hooks->hooktype, (oci_spec->hooks->hooktype##_len + 1) * sizeof(char *),   \
                             (void *)oci_spec->hooks->hooktype, oci_spec->hooks->hooktype##_len * sizeof(char *)) != 0) {   \
            ERROR("Out of memory");                                                                                         \
            return -1;                                                                                                      \
        }                                                                                                                   \
        oci_spec->hooks->hooktype[oci_spec->hooks->hooktype##_len] = hooktype##_hook;                                       \
        oci_spec->hooks->hooktype##_len++;                                                                                  \
        return 0;                                                                                                           \
    }
 
/* 
* The OCI being used by the iSulad not supportes 
* createRuntime/createContainer/startContainer currently.
*/
SPEC_ADD_HOOKS_ITEM_DEF(prestart)
SPEC_ADD_HOOKS_ITEM_DEF(poststart)
SPEC_ADD_HOOKS_ITEM_DEF(poststop)

#endif /* ENABLE_CDI */