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
 * Description: provide nri oci functions
 *********************************************************************************/

#include "nri_spec.h"

#include <isula_libutils/log.h>

#include "map.h"
#include "utils.h"
#include "utils_string.h"
#include "nri_utils.h"
#include "specs_api.h"
#include "sysinfo.h"
#include "verify.h"
#include "specs_extend.h"

static defs_hook *nri_hook_to_oci(const nri_hook *h)
{
    defs_hook *oci_hook = NULL;

    if (h == NULL) {
        return NULL;
    }

    oci_hook = util_common_calloc_s(sizeof(*oci_hook));
    if (oci_hook == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    oci_hook->path = util_strdup_s(h->path);
    if (h->args_len != 0) {
        oci_hook->args = util_copy_array_by_len(h->args, h->args_len);
        if (oci_hook->args == NULL) {
            ERROR("Failed to copy args");
            goto error_out;
        }
        oci_hook->args_len = h->args_len;
    }
    if (h->env_len != 0) {
        oci_hook->env = util_copy_array_by_len(h->env, h->env_len);
        if (oci_hook->env == NULL) {
            ERROR("Failed to copy env");
            goto error_out;
        }
        oci_hook->env_len = h->env_len;
    }
    if (h->timeout != NULL) {
        oci_hook->timeout = *(h->timeout);
    }
    return oci_hook;

error_out:
    free_defs_hook(oci_hook);
    return NULL;
}

static defs_device *nri_device_to_oci(nri_linux_device *dev)
{
    if (dev == NULL) {
        return NULL;
    }

    defs_device *oci_dev = util_common_calloc_s(sizeof(defs_device));
    if (oci_dev == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    oci_dev->path = util_strdup_s(dev->path);
    oci_dev->type = util_strdup_s(dev->type);
    oci_dev->major = dev->major;
    oci_dev->minor = dev->minor;
    if (dev->file_mode != NULL) {
        oci_dev->file_mode = *dev->file_mode;
    }
    if (dev->uid != NULL) {
        oci_dev->uid = *dev->uid;
    }
    if (dev->gid != NULL) {
        oci_dev->gid = *dev->gid;
    }

    return oci_dev;
}

static defs_mount *nri_mount_to_oci(nri_mount *mount)
{
    if (mount == NULL) {
        return NULL;
    }

    defs_mount *oci_mount = util_common_calloc_s(sizeof(defs_mount));
    if (oci_mount == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    oci_mount->destination = util_strdup_s(mount->destination);
    oci_mount->type = util_strdup_s(mount->type);
    oci_mount->source = util_strdup_s(mount->source);
    if (mount->options_len != 0) {
        oci_mount->options = util_copy_array_by_len(mount->options, mount->options_len);
        if (oci_mount->options == NULL) {
            ERROR("Failed to copy options");
            free_defs_mount(oci_mount);
            return NULL;
        }
        oci_mount->options_len = mount->options_len;
    }

    return oci_mount;
}

static int nri_adjust_annotation(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    int ret = -1;
    size_t i;

    if (adjust == NULL || adjust->annotations == NULL || adjust->annotations->len == 0) {
        return 0;
    }

    if (make_sure_oci_spec_annotations(oci_spec) != 0) {
        ERROR("Failed to make sure oci spec annotations");
        return -1;
    }

    json_map_string_string *cleard = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (cleard == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    map_t *del = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (del == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    for (i = 0; i < adjust->annotations->len; i++) {
        __isula_auto_free char *out = NULL;
        if (is_marked_for_removal(adjust->annotations->keys[i], &out)) {
            if (!map_insert(del, out, "")) {
                ERROR("Failed to insert del map");
                goto free_out;
            }
            continue;
        }
        if (append_json_map_string_string(cleard, adjust->annotations->keys[i],
                                          adjust->annotations->values[i]) != 0) {
            ERROR("Failed to append annotation");
            goto free_out;
        }
    }

    for (i = 0; i < oci_spec->annotations->len; i++) {
        if (map_search(del, oci_spec->annotations->keys[i]) != NULL) {
            continue;
        }
        append_json_map_string_string(cleard, oci_spec->annotations->keys[i],
                                      oci_spec->annotations->values[i]);
    }

    free_json_map_string_string(oci_spec->annotations);
    oci_spec->annotations = cleard;
    ret = 0;

free_out:
    free_json_map_string_string(cleard);
    map_free(del);
    return ret;
}

static void nri_key_value_map_kvfree(void *key, void *value)
{
    free(key);

    // no need to free nri_key_value
    // nri_key_value *value will be free in nri_container_adjustment *adjust
}


static int nri_adjust_env(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    int ret = -1;
    size_t i;
    char **old_env = NULL;
    size_t old_env_len = 0;
    __isula_auto_array_t char **adjust_env = NULL;
    size_t adjust_env_len = 0;

    if (adjust->env == NULL || adjust->env_len == 0) {
        return 0;
    }

    map_t *mod = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, nri_key_value_map_kvfree);
    if (mod == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    for (i = 0; i < adjust->env_len; i++) {
        nri_key_value *e = adjust->env[i];
        char *out = NULL;
        (void)is_marked_for_removal(e->key, &out);

        if (!map_insert(mod, out, e) == false) {
            ERROR("Failed to insert mod map");
            goto free_out;
        }
    }

    if (map_size(mod) <= 0 || oci_spec == NULL || oci_spec->process == NULL) {
        ret = 0;
        goto free_out;
    }

    // modify existing environment
    old_env = oci_spec->process->env;
    old_env_len = oci_spec->process->env_len;
    oci_spec->process->env = NULL;
    oci_spec->process->env_len = 0;

    for (i = 0; i < old_env_len; i++) {
        __isula_auto_array_t char **envArr = util_string_split_n(old_env[i], '=', 2);
        if (envArr == NULL) {
            continue;
        }

        nri_key_value *target = map_search(mod, envArr[0]);
        if (target != NULL) {
            __isula_auto_free char *out = NULL;
            if (!is_marked_for_removal(envArr[0], &out)) {
                // If not marked for removal, append modified value
                __isula_auto_free char *tmp_str = util_string_append(target->key, "=");
                __isula_auto_free char *final_str = util_string_append(tmp_str, target->value);

                if (util_array_append(&adjust_env, final_str) != 0) {
                    ERROR("Failed to append env");
                    goto free_out;
                }
                adjust_env_len++;
                continue;
            }
        }
        // If not found in mod map, append original value
        if (util_array_append(&adjust_env, old_env[i]) != 0) {
            ERROR("Failed to append env");
            goto free_out;
        }
        adjust_env_len++;
    }

    ret = 0;
free_out:
    if (merge_env(oci_spec, (const char **)adjust_env, adjust_env_len) != 0) {
        ERROR("Failed to merge env");
        goto free_out;
    }
    for (i = 0; i < old_env_len; i++) {
        free(old_env[i]);
    }
    free(old_env);
    map_free(mod);
    return ret;
}

static int nri_adjust_hooks(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (adjust->hooks == NULL) {
        return 0;
    }

    size_t i;
    int ret = 0;

    if (make_sure_oci_spec_hooks(oci_spec) != 0) {
        ERROR("Failed to make sure oci spec hooks");
        return -1;
    }

    // todo: change to macro definition function call
    for (i = 0; i < adjust->hooks->prestart_len; i++) {
        defs_hook *oci_hook = nri_hook_to_oci(adjust->hooks->prestart[i]);
        ret = spec_add_prestart_hook(oci_spec, oci_hook);
        if (ret != 0) {
            ERROR("Failed add hook %s", adjust->hooks->prestart[i]->path);
            free_defs_hook(oci_hook);
            return -1;
        }
    }

    for (i = 0; i < adjust->hooks->poststart_len; i++) {
        defs_hook *oci_hook = nri_hook_to_oci(adjust->hooks->poststart[i]);
        ret = spec_add_poststart_hook(oci_spec, oci_hook);
        if (ret != 0) {
            ERROR("Failed add hook %s", adjust->hooks->poststart[i]->path);
            free_defs_hook(oci_hook);
            return -1;
        }
    }

    for (i = 0; i < adjust->hooks->poststop_len; i++) {
        defs_hook *oci_hook = nri_hook_to_oci(adjust->hooks->poststop[i]);
        ret = spec_add_poststop_hook(oci_spec, oci_hook);
        if (ret != 0) {
            ERROR("Failed add hook %s", adjust->hooks->poststop[i]->path);
            free_defs_hook(oci_hook);
            return -1;
        }
    }
    /*
    * The OCI being used by the iSulad not supportes
    * createRuntime/createContainer/startContainer currently.
    */

    return ret;
}

static int nri_adjust_devices(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (adjust->linux == NULL || adjust->linux->devices == NULL || adjust->linux->devices_len == 0) {
        return 0;
    }

    size_t i;

    for (i = 0; i < adjust->linux->devices_len; i++) {
        nri_linux_device *dev = adjust->linux->devices[i];
        if (spec_add_device(oci_spec, nri_device_to_oci(dev)) != 0) {
            ERROR("Failed to add device %s", dev->path);
            return -1;
        }
    }

    return 0;
}

static int nri_adjust_cgroup_path(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (adjust->linux == NULL || adjust->linux->cgroups_path == NULL) {
        return 0;
    }

    free(oci_spec->linux->cgroups_path);
    oci_spec->linux->cgroups_path = util_strdup_s(adjust->linux->cgroups_path);

    return 0;
}

static void nri_adjust_cpu_memory(nri_linux_resources *resource, oci_runtime_spec *oci_spec)
{
    if (resource->cpu == NULL) {
        return;
    }
    if (make_sure_oci_spec_linux_resources_cpu(oci_spec) != 0) {
        ERROR("Failed to make sure oci spec linux resources cpu");
        return;
    }
    if (resource->cpu->shares != NULL) {
        oci_spec->linux->resources->cpu->shares = *resource->cpu->shares;
    }
    if (resource->cpu->quota != NULL) {
        oci_spec->linux->resources->cpu->quota = *resource->cpu->quota;
    }
    if (resource->cpu->period != NULL) {
        oci_spec->linux->resources->cpu->period = *resource->cpu->period;
    }
    if (resource->cpu->realtime_runtime != NULL) {
        oci_spec->linux->resources->cpu->realtime_runtime = *resource->cpu->realtime_runtime;
    }
    if (resource->cpu->realtime_period != NULL) {
        oci_spec->linux->resources->cpu->realtime_period = *resource->cpu->realtime_period;
    }
}

static void nri_adjust_memory_resource(nri_linux_resources *resource, oci_runtime_spec *oci_spec)
{
    if (resource->memory == NULL) {
        return;
    }

    if (make_sure_oci_spec_linux_resources_mem(oci_spec) != 0) {
        ERROR("Failed to make sure oci spec linux resources memory");
        return;
    }
    if (resource->memory->limit != NULL) {
        oci_spec->linux->resources->memory->limit = *resource->memory->limit;
    }
    if (resource->memory->reservation != NULL) {
        oci_spec->linux->resources->memory->reservation = *resource->memory->reservation;
    }
    if (resource->memory->swap != NULL) {
        oci_spec->linux->resources->memory->swap = *resource->memory->swap;
    }
    if (resource->memory->kernel != NULL) {
        oci_spec->linux->resources->memory->kernel = *resource->memory->kernel;
    }
    if (resource->memory->kernel_tcp != NULL) {
        oci_spec->linux->resources->memory->kernel_tcp = *resource->memory->kernel_tcp;
    }
    if (resource->memory->swappiness != NULL) {
        oci_spec->linux->resources->memory->swappiness = *resource->memory->swappiness;
    }
    if (resource->memory->disable_oom_killer != NULL) {
        oci_spec->linux->resources->memory->disable_oom_killer = *resource->memory->disable_oom_killer;
    }
}

static int nri_adjust_hugepage_resource(nri_linux_resources *resource, oci_runtime_spec *oci_spec)
{
    size_t i;
    if (resource->hugepage_limits != NULL) {
        for (i = 0; i < resource->hugepage_limits_len; i++) {
            nri_hugepage_limit *limit = resource->hugepage_limits[i];
            if (limit->page_size != NULL) {
                if (spec_add_linux_resources_hugepage_limit(oci_spec, limit->page_size, limit->limit) != 0) {
                    ERROR("Failed to add hugepage limit");
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int nri_adjust_unified_resource(nri_linux_resources *resource, oci_runtime_spec *oci_spec)
{
    size_t i;
    if (resource->unified != NULL) {
        for (i = 0; i < resource->unified->len; i++) {
            if (append_json_map_string_string(oci_spec->linux->resources->unified, resource->unified->keys[i],
                                              resource->unified->values[i]) != 0) {
                ERROR("Failed to append unified resource");
                return -1;
            }
        }
    }
    return 0;
}

static int nri_adjust_resources(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (adjust->linux == NULL || adjust->linux->resources == NULL) {
        return 0;
    }

    nri_linux_resources *resource = adjust->linux->resources;

    nri_adjust_memory_resource(resource, oci_spec);
    nri_adjust_cpu_memory(resource, oci_spec);

    if (nri_adjust_hugepage_resource(resource, oci_spec) != 0) {
        ERROR("Failed to adjust hugepage resource");
        return -1;
    }

    if (nri_adjust_unified_resource(resource, oci_spec) != 0) {
        ERROR("Failed to adjust unified resource");
        return -1;
    }

    return 0;
}

static int nri_adjust_mounts(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (adjust->mounts == NULL || adjust->mounts_len == 0) {
        return 0;
    }

    size_t i;
    for (i = 0; i < adjust->mounts_len; i++) {
        nri_mount *mount = adjust->mounts[i];
        defs_mount *oci_mount = nri_mount_to_oci(mount);
        if (oci_mount == NULL) {
            ERROR("Failed to convert nri mount to oci mount");
            return -1;
        }
        if (spec_add_mount(oci_spec, oci_mount) != 0) {
            ERROR("Failed to add mount");
            free_defs_mount(oci_mount);
            return -1;
        }
    }

    return 0;
}

static int nri_adjust_rlimit(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (adjust->rlimits == NULL || adjust->rlimits_len == 0) {
        return 0;
    }

    size_t i;
    for (i = 0; i < adjust->rlimits_len; i++) {
        nri_posix_rlimit *rlimit = adjust->rlimits[i];
        if (rlimit->type == NULL) {
            ERROR("Invalid rlimit type");
            return -1;
        }
        if (spec_add_linux_resources_rlimit(oci_spec, rlimit->type, rlimit->soft, rlimit->hard) != 0) {
            ERROR("Failed to add rlimit");
            return -1;
        }
    }

    return 0;
}

// todo: we do not support it blockio_class
static int nri_adjust_blockio_class(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (adjust->linux == NULL || adjust->linux->resources->blockio_class == NULL) {
        return 0;
    }

    return 0;
}

int nri_adjust_oci_spec(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec)
{
    if (oci_spec == NULL || adjust == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (nri_adjust_annotation(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust annotation in oci spec");
        return -1;
    }

    if (nri_adjust_env(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust env in oci spec");
        return -1;
    }

    if (nri_adjust_hooks(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust hooks in oci spec");
        return -1;
    }

    if (nri_adjust_devices(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust devices in oci spec");
        return -1;
    }

    if (nri_adjust_cgroup_path(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust cgroup path in oci spec");
        return -1;
    }

    if (nri_adjust_resources(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust resources in oci spec");
        return -1;
    }

    if (nri_adjust_blockio_class(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust blockio class in oci spec");
        return -1;
    }

    // iSuald is not support IntelRdt
    if (nri_adjust_mounts(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust mount in oci spec");
        return -1;
    }

    if (nri_adjust_rlimit(adjust, oci_spec) != 0) {
        ERROR("Failed to do nri adjust rlimit in oci spec");
        return -1;
    }

    __isula_auto_sysinfo_t sysinfo_t *sysinfo = NULL;

    sysinfo = get_sys_info(true);
    if (sysinfo == NULL) {
        ERROR("Failed to get system info");
        return -1;
    }

    if (verify_container_settings(oci_spec, sysinfo) != 0) {
        ERROR("Failed to verify oci runtime spec settings after adjust by nri");
        return -1;
    }

    return 0;
}