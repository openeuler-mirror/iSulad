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
 * Create: 2024-07-17
 * Description: provide nri utils functions
 *********************************************************************************/

#include "nri_utils.h"

#include <isula_libutils/log.h>

#include "utils.h"

static bool copy_nri_hugepage_limit(const nri_hugepage_limit* src, nri_hugepage_limit** dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    *dest = (nri_hugepage_limit *)util_common_calloc_s(sizeof(nri_hugepage_limit));
    if (*dest == NULL) {
        ERROR("Out of memory");
        return false;
    }

    (*dest)->limit = src->limit;
    (*dest)->page_size = util_strdup_s(src->page_size);
    return true;
}

static bool copy_nri_hook(const nri_hook *src, nri_hook **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    *dest = (nri_hook *)util_common_calloc_s(sizeof(nri_hook));
    if (dest == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->args = util_copy_array_by_len(src->args, src->args_len);
    (*dest)->args_len = src->args_len;
    (*dest)->env = util_copy_array_by_len(src->env, src->env_len);
    (*dest)->env_len = src->env_len;
    (*dest)->path = util_strdup_s(src->path);
    return true;
}

static bool copy_nri_linux_device_cgroup(const nri_linux_device_cgroup *src, nri_linux_device_cgroup **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    *dest = (nri_linux_device_cgroup *)util_common_calloc_s(sizeof(nri_linux_device_cgroup));
    if (dest == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->allow = src->allow;
    (*dest)->type = util_strdup_s(src->type);
    (*dest)->major = (int64_t *)util_common_calloc_s(sizeof(int64_t));
    if ((*dest)->major == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->minor = (int64_t *)util_common_calloc_s(sizeof(int64_t));
    if ((*dest)->minor == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->access = util_strdup_s(src->access);
    return true;
}

static bool copy_nri_linux_cpu(const nri_linux_cpu *src, nri_linux_cpu **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    (*dest) = (nri_linux_cpu *)util_common_calloc_s(sizeof(nri_linux_cpu));
    if ((*dest) == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->cpus = util_strdup_s(src->cpus);
    (*dest)->mems = util_strdup_s(src->mems);
    if (src->period != NULL) {
        (*dest)->period = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if ((*dest)->period == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->period = *src->period;
    }

    if (src->quota != NULL) {
        (*dest)->quota = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if ((*dest)->quota == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->quota = *src->quota;
    }

    if (src->realtime_period != NULL) {
        (*dest)->realtime_period = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if ((*dest)->realtime_period == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->realtime_period = *src->realtime_period;
    }

    if (src->realtime_runtime != NULL) {
        (*dest)->realtime_runtime = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if ((*dest)->realtime_runtime == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->realtime_runtime = *src->realtime_runtime;
    }

    if (src->shares != NULL) {
        (*dest)->shares = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if ((*dest)->shares == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->shares = *src->shares;
    }

    return true;
}

static bool copy_nri_linux_memory(const nri_linux_memory *src, nri_linux_memory **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }
    *dest = (nri_linux_memory *)util_common_calloc_s(sizeof(nri_linux_memory));
    if (dest == NULL) {
        ERROR("Out of memory");
        return false;
    }
    if (src->limit != NULL) {
        (*dest)->limit = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if ((*dest)->limit == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->limit = *src->limit;
    }

    if (src->reservation != NULL) {
        (*dest)->reservation = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if ((*dest)->reservation == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->reservation = *src->reservation;
    }

    if (src->swap != NULL) {
        (*dest)->swap = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if ((*dest)->swap == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->swap = *src->swap;
    }

    if (src->kernel != NULL) {
        (*dest)->kernel = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if ((*dest)->kernel == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->kernel = *src->kernel;
    }


    if (src->kernel_tcp != NULL) {
        (*dest)->kernel_tcp = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if ((*dest)->kernel_tcp == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->kernel_tcp = *src->kernel_tcp;
    }

    if (src->swappiness != NULL) {
        (*dest)->swappiness = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if ((*dest)->swappiness == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->swappiness = *src->swappiness;
    }

    if (src->disable_oom_killer != NULL) {
        (*dest)->disable_oom_killer = (uint8_t *)util_common_calloc_s(sizeof(uint8_t));
        if ((*dest)->disable_oom_killer == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->disable_oom_killer = *src->disable_oom_killer;
    }

    if (src->use_hierarchy != NULL) {
        (*dest)->use_hierarchy = (uint8_t *)util_common_calloc_s(sizeof(uint8_t));
        if ((*dest)->use_hierarchy == NULL) {
            ERROR("Out of memory");
            return false;
        }
        *(*dest)->use_hierarchy = *src->use_hierarchy;
    }
    return true;
}

bool is_marked_for_removal(const char* key, char **out)
{
    if (key == NULL || out == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    if (!util_has_prefix(key, "-")) {
        *out = (char*)key;
        return false;
    }

    *out = util_sub_string(key, 1, strlen(key) - 1);
    if (*out == NULL) {
        ERROR("Failed to sub string");
        return false;
    }

    return true;
}

bool copy_nri_mount(const nri_mount *src, nri_mount **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }
    *dest = (nri_mount *)util_common_calloc_s(sizeof(nri_mount));
    if (dest == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->destination = util_strdup_s(src->destination);
    (*dest)->options = util_copy_array_by_len(src->options, src->options_len);
    (*dest)->options_len = src->options_len;
    (*dest)->source = util_strdup_s(src->source);
    (*dest)->type = util_strdup_s(src->type);
    return true;
}

bool copy_nri_key_value(const nri_key_value *src, nri_key_value **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }
    *dest = (nri_key_value *)util_common_calloc_s(sizeof(nri_key_value));
    if (dest == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->key = util_strdup_s(src->key);
    (*dest)->value = util_strdup_s(src->value);
    return true;
}

bool copy_nri_posix_rlimit(const nri_posix_rlimit *src, nri_posix_rlimit **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }
    *dest = (nri_posix_rlimit *)util_common_calloc_s(sizeof(nri_posix_rlimit));
    if (dest == NULL) {
        ERROR("Out of memory");
        return false;
    }
    (*dest)->hard = src->hard;
    (*dest)->soft = src->soft;
    (*dest)->type = util_strdup_s(src->type);
    return true;
}

bool copy_nri_linux_resources(const nri_linux_resources *src, nri_linux_resources **dest)
{
    if (src == NULL || dest == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    *dest = (nri_linux_resources *)util_common_calloc_s(sizeof(nri_linux_resources));
    if (*dest == NULL) {
        ERROR("Out of memory");
        return false;
    }

    if (!init_nri_linux_resources(dest)) {
        ERROR("Failed to init dest nri linux resources");
        goto free_out;
    }

    if (!copy_nri_linux_cpu(src->cpu, &(*dest)->cpu)) {
        ERROR("Failed to copy nri_linux_cpu");
        goto free_out;
    }

    if (!copy_nri_linux_memory(src->memory, &(*dest)->memory)) {
        ERROR("Failed to copy nri_linux_memory");
        goto free_out;
    }

    (*dest)->blockio_class = util_strdup_s(src->blockio_class);
    (*dest)->rdt_class = util_strdup_s(src->rdt_class);

    if (src->hugepage_limits_len > 0) {
        (*dest)->hugepage_limits = (nri_hugepage_limit**)util_smart_calloc_s(sizeof(nri_hugepage_limit*),
                                                                             src->hugepage_limits_len);
        for (size_t i = 0; i < src->hugepage_limits_len; ++i) {
            if (!copy_nri_hugepage_limit(src->hugepage_limits[i], &((*dest)->hugepage_limits[i]))) {
                ERROR("Failed to copy nri_hugepage_limit");
                goto free_out;
            }
        }
    }

    if (src->devices_len > 0) {
        (*dest)->devices = (nri_linux_device_cgroup**)util_smart_calloc_s(sizeof(nri_linux_device_cgroup*), src->devices_len);
        for (size_t i = 0; i < src->devices_len; ++i) {
            if (!copy_nri_linux_device_cgroup(src->devices[i], &((*dest)->devices[i]))) {
                ERROR("Failed to copy nri_linux_device_cgroup");
                goto free_out;
            }
        }
    }

    if (dup_json_map_string_string(src->unified, (*dest)->unified)) {
        ERROR("Failed to copy json_map_string_string");
        goto free_out;
    }

    return true;

free_out:
    free_nri_linux_resources(*dest);
    return false;
}

bool merge_nri_hooks(nri_hook **targetHooks, size_t targetSize, const nri_hook **sourceHooks,
                     size_t sourceLen)
{
    size_t oldSize = targetSize * sizeof(nri_hook *);
    size_t newSize = oldSize + sourceLen * sizeof(nri_hook *);

    if (sourceHooks == NULL || targetHooks == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    if (util_mem_realloc((void**)&targetHooks, newSize, (void**)&targetHooks, oldSize) != 0) {
        ERROR("Failed to realloc and assign hook array");
        return false;
    }

    for (size_t i = 0; i < sourceLen; i++) {
        if (!copy_nri_hook(sourceHooks[i], &targetHooks[targetSize++])) {
            ERROR("Failed to copy hook");
            return false;
        }
    }

    return true;
}

bool init_nri_container_adjust(nri_container_adjustment **adjust)
{
    if (adjust == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    *adjust = (nri_container_adjustment *)util_common_calloc_s(sizeof(nri_container_adjustment));
    if (*adjust == NULL) {
        ERROR("Out of memory");
        return false;
    }

    (*adjust)->annotations = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if ((*adjust)->annotations == NULL) {
        goto free_out;
    }

    (*adjust)->env = (nri_key_value **)util_common_calloc_s(sizeof(nri_key_value *));
    if ((*adjust)->env == NULL) {
        goto free_out;
    }
    (*adjust)->env_len = 0;

    (*adjust)->hooks = (nri_hooks *)util_common_calloc_s(sizeof(nri_hooks));
    if ((*adjust)->hooks == NULL) {
        goto free_out;
    }

    (*adjust)->linux = (nri_linux_container_adjustment *)util_common_calloc_s(sizeof(nri_linux_container_adjustment));
    if ((*adjust)->linux == NULL) {
        goto free_out;
    }

    (*adjust)->linux->resources = (nri_linux_resources *)util_common_calloc_s(sizeof(nri_linux_resources));
    if ((*adjust)->linux->resources == NULL) {
        ERROR("Out of memory");
        return false;
    }

    (*adjust)->mounts = (nri_mount **)util_common_calloc_s(sizeof(nri_mount *));
    if ((*adjust)->mounts == NULL) {
        goto free_out;
    }
    (*adjust)->mounts_len = 0;

    (*adjust)->rlimits = (nri_posix_rlimit **)util_common_calloc_s(sizeof(nri_posix_rlimit *));
    if ((*adjust)->rlimits == NULL) {
        goto free_out;
    }
    (*adjust)->rlimits_len = 0;

    return true;

free_out:
    ERROR("Out of memory");
    free_nri_container_adjustment(*adjust);
    return false;
}

bool init_nri_container_update(nri_container_update **update, const char *id, uint8_t ignore_failure)
{
    if (update == NULL || id == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    *update = (nri_container_update *)util_common_calloc_s(sizeof(nri_container_update));
    if (*update == NULL) {
        ERROR("Out of memory");
        return false;
    }

    (*update)->container_id = util_strdup_s(id);
    (*update)->linux = (nri_linux_container_update *)util_common_calloc_s(sizeof(nri_linux_container_update));
    if ((*update)->linux == NULL) {
        goto free_out;
    }

    (*update)->ignore_failure = ignore_failure;
    return true;

free_out:
    ERROR("Out of memory");
    free_nri_container_update(*update);
    return false;
}

bool init_nri_linux_resources(nri_linux_resources **resources)
{
    if (resources == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    *resources = (nri_linux_resources *)util_common_calloc_s(sizeof(nri_linux_resources));
    if (*resources == NULL) {
        ERROR("Out of memory");
        return false;
    }

    (*resources)->cpu = (nri_linux_cpu *)util_common_calloc_s(sizeof(nri_linux_cpu));
    if ((*resources)->cpu == NULL) {
        goto free_out;
    }

    (*resources)->memory = (nri_linux_memory *)util_common_calloc_s(sizeof(nri_linux_memory));
    if ((*resources)->memory == NULL) {
        goto free_out;
    }

    (*resources)->unified = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if ((*resources)->unified == NULL) {
        goto free_out;
    }
    return true;

free_out:
    ERROR("Out of memory");
    free_nri_linux_resources(*resources);
    return false;
}