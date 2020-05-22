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
 * Author: maoweiyong
 * Create: 2018-11-07
 * Description: provide embedded image merge config
 ******************************************************************************/
#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/limits.h>

#include "utils.h"
#include "isula_libutils/log.h"
#include "libisulad.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/embedded_manifest.h"
#include "specs_extend.h"
#include "specs_mount.h"
#include "lim.h"
#include "mediatype.h"
#include "embedded_config_merge.h"

static int embedded_merge_entrypoint(embedded_config *config, container_config *container_spec)
{
    if (config->entrypoint && container_spec->entrypoint_len == 0) {
        int ret = dup_array_of_strings((const char **)config->entrypoint, config->entrypoint_len,
                                       &(container_spec->entrypoint), &(container_spec->entrypoint_len));
        if (ret != 0) {
            ERROR("Failed to duplicate entrypoint from manifest");
            return -1;
        }
        container_spec->entrypoint_len = config->entrypoint_len;
    }
    return 0;
}

static int embedded_merge_env(const embedded_config *config, container_config *container_spec)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    size_t j = 0;
    char **temp = NULL;
    char **im_kv = NULL;
    char **custom_kv = NULL;

    if (config->env == NULL || config->env_len == 0) {
        return 0;
    }

    if (config->env_len > LIST_ENV_SIZE_MAX - container_spec->env_len) {
        ERROR("The length of envionment variables is too long, the limit is %lld", LIST_ENV_SIZE_MAX);
        isulad_set_error_message("The length of envionment variables is too long, the limit is %lld", LIST_ENV_SIZE_MAX);
        ret = -1;
        goto out;
    }
    new_size = (container_spec->env_len + config->env_len) * sizeof(char *);
    old_size = container_spec->env_len * sizeof(char *);
    ret = mem_realloc((void **)&temp, new_size, container_spec->env, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for envionment variables");
        ret = -1;
        goto out;
    }

    container_spec->env = temp;
    for (i = 0; i < config->env_len; i++) {
        bool found = false;
        im_kv = util_string_split(config->env[i], '=');
        if (im_kv == NULL) {
            continue;
        }

        for (j = 0; j < container_spec->env_len; j++) {
            custom_kv = util_string_split(container_spec->env[j], '=');
            if (custom_kv == NULL) {
                continue;
            }
            if (strcmp(im_kv[0], custom_kv[0]) == 0) {
                found = true;
            }
            util_free_array(custom_kv);
            custom_kv = NULL;
            if (found) {
                break;
            }
        }

        if (!found) {
            container_spec->env[container_spec->env_len] = util_strdup_s(config->env[i]);
            container_spec->env_len++;
        }
        util_free_array(im_kv);
        im_kv = NULL;
    }
out:
    return ret;
}


static int merge_embedded_config(const embedded_manifest *manifest, container_config *container_spec)
{
    if (manifest->config != NULL) {
        if (container_spec->working_dir == NULL) {
            container_spec->working_dir = util_strdup_s(manifest->config->workdir);
        }

        if (embedded_merge_env(manifest->config, container_spec) != 0) {
            return -1;
        }

        return embedded_merge_entrypoint(manifest->config, container_spec);
    }
    return 0;
}

static int gen_abs_path(const embedded_manifest *manifest, char **abs_path, char *config_path, char *real_path, int i)
{
    /* change source to absolute path */
    if (manifest->layers[i]->path_in_host[0] == '/') {
        (*abs_path) = util_strdup_s(manifest->layers[i]->path_in_host);
    } else {
        (*abs_path) = util_add_path(config_path, manifest->layers[i]->path_in_host);
    }
    if ((*abs_path) == NULL) {
        ERROR("add path %s and %s failed", config_path,
              manifest->layers[i]->path_in_host);
        return -1;
    }

    if (strlen(*abs_path) > PATH_MAX || realpath(*abs_path, real_path) == NULL) {
        ERROR("get real path of %s failed", *abs_path);
        return -1;
    }
    return 0;
}

static int gen_one_mount(const embedded_manifest *manifest, char *mount, char *real_path, int i)
{
    int nret = 0;
    if (manifest->layers[i]->media_type == NULL) {
        ERROR("Unknown media type");
        return -1;
    }
    if (strcmp(manifest->layers[i]->media_type, MediaTypeEmbeddedLayerSquashfs) == 0) {
        nret = snprintf(mount, PATH_MAX * 3,
                        "type=squashfs,ro=true,src=%s,dst=%s",
                        real_path, manifest->layers[i]->path_in_container);
    } else {
        nret = snprintf(mount, PATH_MAX * 3,
                        "type=bind,ro=true,bind-propagation=rprivate,src=%s,dst=%s",
                        real_path, manifest->layers[i]->path_in_container);
    }
    if (nret < 0 || nret >= (PATH_MAX * 3)) {
        ERROR("print string for mounts failed");
        return -1;
    }
    return 0;
}

static int embedded_append_mounts(char **volumes, size_t volumes_len, container_config *container_spec)
{
    int ret = 0;
    size_t i = 0;
    size_t new_size = 0;
    char **temp = NULL;
    size_t temp_len = 0;

    if (volumes == NULL || volumes_len == 0) {
        return 0;
    }
    if (volumes_len > LIST_ENV_SIZE_MAX - container_spec->mounts_len) {
        ERROR("The length of mounts is too long, the limit is %lld", LIST_ENV_SIZE_MAX);
        isulad_set_error_message("The length of mounts is too long, the limit is %lld", LIST_ENV_SIZE_MAX);
        ret = -1;
        goto out;
    }
    new_size = (container_spec->mounts_len + volumes_len) * sizeof(char *);
    temp = util_common_calloc_s(new_size);
    if (temp == NULL) {
        ERROR("Failed to realloc memory for mounts");
        ret = -1;
        goto out;
    }

    for (i = 0; i < volumes_len; i++) {
        temp[temp_len] = util_strdup_s(volumes[i]);
        temp_len++;
    }

    for (i = 0; i < container_spec->mounts_len; i++) {
        temp[temp_len] = util_strdup_s(container_spec->mounts[i]);
        temp_len++;
        free(container_spec->mounts[i]);
        container_spec->mounts[i] = NULL;
    }

    free(container_spec->mounts);
    container_spec->mounts = temp;
    container_spec->mounts_len = temp_len;

out:
    return ret;
}

static int embedded_merge_mounts(const embedded_manifest *manifest, container_config *container_spec)
{
    int ret = 0;
    int i = 0;
    char *config_path = NULL;
    char *abs_path = NULL;
    size_t cap = 0;
    char **mounts = NULL;

    ret = lim_query_image_data(manifest->image_name, IMAGE_DATA_TYPE_CONFIG_PATH, &config_path, NULL);
    if (ret != 0) {
        ERROR("query config path for image %s failed", manifest->image_name);
        ret = -1;
        goto out;
    }

    ret = util_grow_array(&mounts, &cap, manifest->layers_len, manifest->layers_len);
    if (ret != 0) {
        ERROR("grow array failed");
        ret = -1;
        goto out;
    }
    /* First layer is used for rootfs, so begin from 1 */
    for (i = 1; i < (int)manifest->layers_len; i++) {
        char real_path[PATH_MAX] = { 0 }; /* Init to zero every time loop enter here */

        /* PATH_MAX * 3: one for src and one for dst, the left
         * PATH_MAX is enough for other parameters */
        mounts[i - 1] = util_common_calloc_s(PATH_MAX * 3);
        if (mounts[i - 1] == NULL) {
            ret = -1;
            goto out;
        }

        if (gen_abs_path(manifest, &abs_path, config_path, real_path, i) != 0) {
            ret = -1;
            goto out;
        }

        UTIL_FREE_AND_SET_NULL(abs_path);
        if (gen_one_mount(manifest, mounts[i - 1], real_path, i) != 0) {
            ret = -1;
            goto out;
        }
    }

    ret = embedded_append_mounts(mounts, util_array_len((const char **)mounts), container_spec);
    if (ret) {
        ERROR("Failed to merge layer into mounts");
        goto out;
    }

out:
    util_free_array(mounts);
    free(abs_path);
    UTIL_FREE_AND_SET_NULL(config_path);
    return ret;
}

int embedded_image_merge_config(const char *image_config, container_config *container_spec)
{
    int ret = 0;
    char *err = NULL;
    embedded_manifest *manifest = NULL;

    manifest = embedded_manifest_parse_data(image_config, 0, &err);
    if (manifest == NULL) {
        ERROR("parse manifest failed: %s", err);
        ret = -1;
        goto out;
    }

    if (merge_embedded_config(manifest, container_spec) != 0) {
        ret = -1;
        goto out;
    }

    ret = embedded_merge_mounts(manifest, container_spec);
    if (ret != 0) {
        ERROR("query config path for image %s failed", manifest->image_name);
        ret = -1;
        goto out;
    }
out:
    free(err);
    free_embedded_manifest(manifest);
    return ret;
}


