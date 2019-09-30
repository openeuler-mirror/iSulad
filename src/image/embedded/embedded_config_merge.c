/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
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

#include "securec.h"
#include "utils.h"
#include "log.h"
#include "liblcrd.h"
#include "oci_runtime_spec.h"
#include "embedded_manifest.h"
#include "specs_extend.h"
#include "specs_mount.h"
#include "lim.h"
#include "mediatype.h"
#include "embedded_config_merge.h"

int merge_env_config(oci_runtime_spec *oci_spec,
                     embedded_manifest **manifest)
{
    if ((*manifest)->config->env && (*manifest)->config->env_len != 0) {
        int ret = merge_env(oci_spec, (const char **)(*manifest)->config->env, (*manifest)->config->env_len);
        if (ret != 0) {
            ERROR("Failed to merge environment variables");
            return -1;
        }
    }
    return 0;
}

int replace_cmds_config(container_custom_config *custom_spec,
                        embedded_manifest **manifest)
{
    embedded_config *config = (*manifest)->config;

    if (config->entrypoint && custom_spec->entrypoint_len == 0) {
        int ret = dup_array_of_strings((const char **)config->entrypoint, config->entrypoint_len,
                                       &(custom_spec->entrypoint), &(custom_spec->entrypoint_len));
        if (ret != 0) {
            ERROR("Failed to duplicate entrypoint from manifest");
            return -1;
        }
        custom_spec->entrypoint_len = (*manifest)->config->entrypoint_len;
    }
    return 0;
}

int merge_config(oci_runtime_spec *oci_spec,
                 container_custom_config *custom_spec,
                 const char *image_config,
                 embedded_manifest **manifest)
{
    if ((*manifest)->config != NULL) {
        if ((*manifest)->config->workdir != NULL) {
            free(oci_spec->process->cwd);
            oci_spec->process->cwd = util_strdup_s((*manifest)->config->workdir);
        }

        if (merge_env_config(oci_spec, manifest) != 0) {
            return -1;
        }

        return replace_cmds_config(custom_spec, manifest);
    }
    return 0;
}

int pre_deal_config(oci_runtime_spec *oci_spec,
                    container_custom_config *custom_spec,
                    const char *image_config,
                    embedded_manifest **manifest,
                    char **config_path,
                    char **err)
{
    bool param_error = (oci_spec == NULL || image_config == NULL);
    if (param_error) {
        ERROR("invalid NULL param");
        return -1;
    }

    *manifest = embedded_manifest_parse_data(image_config, 0, err);
    if (*manifest == NULL) {
        ERROR("parse manifest failed: %s", *err);
        return -1;
    }

    if (merge_config(oci_spec, custom_spec, image_config, manifest) != 0) {
        return -1;
    }

    int ret = lim_query_image_data((*manifest)->image_name, IMAGE_DATA_TYPE_CONFIG_PATH, config_path, NULL);
    if (ret != 0) {
        ERROR("query config path for image %s failed", (*manifest)->image_name);
        return -1;
    }
    return 0;
}

int gen_abs_path(embedded_manifest **manifest, char **abs_path, char *config_path, char *real_path, int i)
{
    /* change source to absolute path */
    if ((*manifest)->layers[i]->path_in_host[0] == '/') {
        (*abs_path) = util_strdup_s((*manifest)->layers[i]->path_in_host);
    } else {
        (*abs_path) = util_add_path(config_path, (*manifest)->layers[i]->path_in_host);
    }
    if ((*abs_path) == NULL) {
        ERROR("add path %s and %s failed", config_path,
              (*manifest)->layers[i]->path_in_host);
        return -1;
    }

    if (strlen(*abs_path) > PATH_MAX || realpath(*abs_path, real_path) == NULL) {
        ERROR("get real path of %s failed", *abs_path);
        return -1;
    }
    return 0;
}

int gen_one_mount(embedded_manifest *manifest, char *mount, char *real_path, int i)
{
    int nret = 0;
    if (manifest->layers[i]->media_type == NULL) {
        ERROR("Unknown media type");
        return -1;
    }
    if (strcmp(manifest->layers[i]->media_type, MediaTypeEmbeddedLayerSquashfs) == 0) {
        nret = sprintf_s(mount, PATH_MAX * 3,
                         "type=squashfs,ro=true,src=%s,dst=%s",
                         real_path, manifest->layers[i]->path_in_container);
    } else {
        nret = sprintf_s(mount, PATH_MAX * 3,
                         "type=bind,ro=true,bind-propagation=rprivate,src=%s,dst=%s",
                         real_path, manifest->layers[i]->path_in_container);
    }
    if (nret < 0) {
        ERROR("print string for mounts failed");
        return -1;
    }
    return 0;
}

int embedded_image_merge_config(oci_runtime_spec *oci_spec,
                                container_custom_config *custom_spec,
                                const char *image_config)
{
    int ret = 0;
    char *err = NULL;
    embedded_manifest *manifest = NULL;
    int i = 0;
    char **mounts = NULL;
    size_t cap = 0;
    char *config_path = NULL;
    char *abs_path = NULL;

    if (pre_deal_config(oci_spec, custom_spec, image_config, &manifest, &config_path, &err) != 0) {
        ret = -1;
        goto out;
    }

    ret = util_grow_array(&mounts, &cap, manifest->layers_len,
                          manifest->layers_len);
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

        if (gen_abs_path(&manifest, &abs_path, config_path, real_path, i) != 0) {
            ret = -1;
            goto out;
        }

        UTIL_FREE_AND_SET_NULL(abs_path);
        if (gen_one_mount(manifest, mounts[i - 1], real_path, i) != 0) {
            ret = -1;
            goto out;
        }
    }

    ret = merge_volumes(oci_spec, mounts, util_array_len(mounts), NULL, parse_mount);
    if (ret) {
        ERROR("Failed to merge layer into mounts");
        goto out;
    }

out:
    free(err);
    util_free_array(mounts);
    free_embedded_manifest(manifest);
    free(abs_path);
    UTIL_FREE_AND_SET_NULL(config_path);
    return ret;
}


