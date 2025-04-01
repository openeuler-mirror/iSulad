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

static nri_hugepage_limit *copy_nri_hugepage_limit(const nri_hugepage_limit *src)
{
    nri_hugepage_limit *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    dest = (nri_hugepage_limit *)util_common_calloc_s(sizeof(nri_hugepage_limit));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    dest->limit = src->limit;
    dest->page_size = util_strdup_s(src->page_size);
    return dest;
}

static nri_hook *copy_nri_hook(const nri_hook *src)
{
    nri_hook *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    dest = (nri_hook *)util_common_calloc_s(sizeof(nri_hook));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    dest->args = util_copy_array_by_len(src->args, src->args_len);
    dest->args_len = src->args_len;
    dest->env = util_copy_array_by_len(src->env, src->env_len);
    dest->env_len = src->env_len;
    dest->path = util_strdup_s(src->path);
    return dest;
}

static nri_linux_device_cgroup *copy_nri_linux_device_cgroup(const nri_linux_device_cgroup *src)
{
    nri_linux_device_cgroup *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    dest = (nri_linux_device_cgroup *)util_common_calloc_s(sizeof(nri_linux_device_cgroup));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    dest->allow = src->allow;
    dest->type = util_strdup_s(src->type);
    dest->major = (int64_t *)util_common_calloc_s(sizeof(int64_t));
    if (dest->major == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    dest->minor = (int64_t *)util_common_calloc_s(sizeof(int64_t));
    if (dest->minor == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    dest->access = util_strdup_s(src->access);
    return dest;
free_out:
    free_nri_linux_device_cgroup(dest);
    return NULL;
}

static nri_linux_cpu *copy_nri_linux_cpu(const nri_linux_cpu *src)
{
    nri_linux_cpu *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    dest = (nri_linux_cpu *)util_common_calloc_s(sizeof(nri_linux_cpu));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    dest->cpus = util_strdup_s(src->cpus);
    dest->mems = util_strdup_s(src->mems);
    if (src->period != NULL) {
        dest->period = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if (dest->period == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->period = *src->period;
    }

    if (src->quota != NULL) {
        dest->quota = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if (dest->quota == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->quota = *src->quota;
    }

    if (src->realtime_period != NULL) {
        dest->realtime_period = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if (dest->realtime_period == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->realtime_period = *src->realtime_period;
    }

    if (src->realtime_runtime != NULL) {
        dest->realtime_runtime = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if (dest->realtime_runtime == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->realtime_runtime = *src->realtime_runtime;
    }

    if (src->shares != NULL) {
        dest->shares = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if (dest->shares == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->shares = *src->shares;
    }

    return dest;

free_out:
    free_nri_linux_cpu(dest);
    return NULL;
}

static nri_linux_memory *copy_nri_linux_memory(const nri_linux_memory *src)
{
    nri_linux_memory *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }
    
    dest = (nri_linux_memory *)util_common_calloc_s(sizeof(nri_linux_memory));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    if (src->limit != NULL) {
        dest->limit = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if (dest->limit == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->limit = *src->limit;
    }

    if (src->reservation != NULL) {
        dest->reservation = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if (dest->reservation == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->reservation = *src->reservation;
    }

    if (src->swap != NULL) {
        dest->swap = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if (dest->swap == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->swap = *src->swap;
    }

    if (src->kernel != NULL) {
        dest->kernel = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if (dest->kernel == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->kernel = *src->kernel;
    }


    if (src->kernel_tcp != NULL) {
        dest->kernel_tcp = (int64_t *)util_common_calloc_s(sizeof(int64_t));
        if (dest->kernel_tcp == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->kernel_tcp = *src->kernel_tcp;
    }

    if (src->swappiness != NULL) {
        dest->swappiness = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
        if (dest->swappiness == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->swappiness = *src->swappiness;
    }

    if (src->disable_oom_killer != NULL) {
        dest->disable_oom_killer = (uint8_t *)util_common_calloc_s(sizeof(uint8_t));
        if (dest->disable_oom_killer == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->disable_oom_killer = *src->disable_oom_killer;
    }

    if (src->use_hierarchy != NULL) {
        dest->use_hierarchy = (uint8_t *)util_common_calloc_s(sizeof(uint8_t));
        if (dest->use_hierarchy == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->use_hierarchy = *src->use_hierarchy;
    }
    return dest;

free_out:
    free_nri_linux_memory(dest);
    return NULL;
}

bool is_marked_for_removal(const char* key, char **out)
{
    if (key == NULL || out == NULL) {
        ERROR("Invalid input arguments");
        return false;
    }

    if (!util_has_prefix(key, "-")) {
        *out = util_strdup_s(key);
        return false;
    }

    *out = util_sub_string(key, 1, strlen(key) - 1);
    if (*out == NULL) {
        ERROR("Failed to sub string");
        return false;
    }

    return true;
}

nri_mount *copy_nri_mount(const nri_mount *src)
{
    nri_mount *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    dest = (nri_mount *)util_common_calloc_s(sizeof(nri_mount));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    dest->destination = util_strdup_s(src->destination);
    dest->options = util_copy_array_by_len(src->options, src->options_len);
    dest->options_len = src->options_len;
    dest->source = util_strdup_s(src->source);
    dest->type = util_strdup_s(src->type);
    return dest;
}

nri_linux_device *copy_nri_device(const nri_linux_device *src)
{
    nri_linux_device *dest = NULL;

    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }
    
    dest = (nri_linux_device *)util_common_calloc_s(sizeof(nri_linux_device));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    if (src->file_mode != NULL) {
        dest->file_mode = (uint32_t *)util_common_calloc_s(sizeof(uint32_t));
        if (dest->file_mode == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->file_mode = *src->file_mode;
    }

    if (src->uid != NULL) {
        dest->uid = (uint32_t *)util_common_calloc_s(sizeof(uint32_t));
        if (dest->uid == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->uid = *src->uid;
    }

    if (src->gid != NULL) {
        dest->gid = (uint32_t *)util_common_calloc_s(sizeof(uint32_t));
        if (dest->gid == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        *dest->gid = *src->gid;
    }

    dest->major = src->major;
    dest->minor = src->minor;
    dest->path = util_strdup_s(src->path);
    dest->type = util_strdup_s(src->type);

    return dest;
free_out:
    free_nri_linux_device(dest);
    return NULL;
}

nri_key_value *copy_nri_key_value(const nri_key_value *src)
{
    nri_key_value *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }
    dest = (nri_key_value *)util_common_calloc_s(sizeof(nri_key_value));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    dest->key = util_strdup_s(src->key);
    dest->value = util_strdup_s(src->value);
    return dest;
}

nri_posix_rlimit *copy_nri_posix_rlimit(const nri_posix_rlimit *src)
{
    nri_posix_rlimit *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }
    dest = (nri_posix_rlimit *)util_common_calloc_s(sizeof(nri_posix_rlimit));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    dest->hard = src->hard;
    dest->soft = src->soft;
    dest->type = util_strdup_s(src->type);
    return dest;
}

nri_linux_resources *copy_nri_linux_resources(const nri_linux_resources *src)
{
    nri_linux_resources *dest = NULL;
    if (src == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    dest = (nri_linux_resources *)util_common_calloc_s(sizeof(nri_linux_resources));
    if (dest == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (src->cpu != NULL) {
        dest->cpu = copy_nri_linux_cpu(src->cpu);
        if (dest->cpu == NULL) {
            ERROR("Failed to copy nri_linux_cpu");
            goto free_out;
        }
    }

    if (src->memory != NULL) {
        dest->memory = copy_nri_linux_memory(src->memory);
        if (dest->memory == NULL) {
            ERROR("Failed to copy nri_linux_memory");
            goto free_out;
        }
    }

    dest->blockio_class = util_strdup_s(src->blockio_class);
    dest->rdt_class = util_strdup_s(src->rdt_class);

    if (src->hugepage_limits_len > 0) {
        dest->hugepage_limits = (nri_hugepage_limit**)util_smart_calloc_s(sizeof(nri_hugepage_limit*),
                                                                             src->hugepage_limits_len);
        for (size_t i = 0; i < src->hugepage_limits_len; i++) {
            dest->hugepage_limits[i] = copy_nri_hugepage_limit(src->hugepage_limits[i]);
            if (dest->hugepage_limits[i] == NULL) {
                ERROR("Failed to copy nri_hugepage_limit");
                goto free_out;
            }
        }
    }

    if (src->devices_len > 0) {
        dest->devices = (nri_linux_device_cgroup**)util_smart_calloc_s(sizeof(nri_linux_device_cgroup*), src->devices_len);
        for (size_t i = 0; i < src->devices_len; i++) {
            dest->devices[i] = copy_nri_linux_device_cgroup(src->devices[i]);
            if (dest->devices[i] == NULL) {
                ERROR("Failed to copy nri_linux_device_cgroup");
                goto free_out;
            }
        }
    }

    if (dup_json_map_string_string(src->unified, dest->unified)) {
        ERROR("Failed to copy json_map_string_string");
        goto free_out;
    }

    return dest;

free_out:
    free_nri_linux_resources(dest);
    return NULL;
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

    if (util_mem_realloc((void**)&targetHooks, newSize, targetHooks, oldSize) != 0) {
        ERROR("Failed to realloc and assign hook array");
        return false;
    }

    for (size_t i = 0; i < sourceLen; i++) {
        targetHooks[targetSize] = copy_nri_hook(sourceHooks[i]);
        if (targetHooks[targetSize] == NULL) {
            ERROR("Failed to copy hook");
            return false;
        }
        targetSize++;
    }

    return true;
}

nri_container_update *init_nri_container_update(const char *id, const uint8_t ignore_failure)
{
    nri_container_update *update = NULL;
    if (id == NULL) {
        ERROR("Invalid input arguments");
        return NULL;
    }

    update = (nri_container_update *)util_common_calloc_s(sizeof(nri_container_update));
    if (update == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    update->container_id = util_strdup_s(id);

    update->ignore_failure = ignore_failure;
    return update;
}

nri_linux_resources *init_nri_linux_resources()
{
    nri_linux_resources *resources = NULL;

    resources = (nri_linux_resources *)util_common_calloc_s(sizeof(nri_linux_resources));
    if (resources == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    resources->cpu = (nri_linux_cpu *)util_common_calloc_s(sizeof(nri_linux_cpu));
    if (resources->cpu == NULL) {
        goto free_out;
    }

    resources->memory = (nri_linux_memory *)util_common_calloc_s(sizeof(nri_linux_memory));
    if (resources->memory == NULL) {
        goto free_out;
    }

    return resources;

free_out:
    ERROR("Out of memory");
    free_nri_linux_resources(resources);
    return NULL;
}