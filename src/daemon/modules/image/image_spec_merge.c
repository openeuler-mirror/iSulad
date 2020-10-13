/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
* Author: lifeng
* Create: 2020-10-10
* Description: provide oci image operator definition
*******************************************************************************/
#include "image_spec_merge.h"

#include "utils.h"
#include "isula_libutils/log.h"
#include "err_msg.h"

int image_spec_merge_env(const char **env, size_t env_len, container_config *container_spec)
{
    int ret = 0;
    size_t new_size = 0;
    size_t old_size = 0;
    size_t i = 0;
    size_t j = 0;
    char **temp = NULL;
    char **im_kv = NULL;
    char **custom_kv = NULL;

    if (env == NULL || env_len == 0) {
        return 0;
    }

    if (env_len > LIST_ENV_SIZE_MAX - container_spec->env_len) {
        ERROR("The length of envionment variables is too long, the limit is %lld", LIST_ENV_SIZE_MAX);
        isulad_set_error_message("The length of envionment variables is too long, the limit is %lld",
                                 LIST_ENV_SIZE_MAX);
        ret = -1;
        goto out;
    }
    new_size = (container_spec->env_len + env_len) * sizeof(char *);
    old_size = container_spec->env_len * sizeof(char *);
    ret = util_mem_realloc((void **)&temp, new_size, container_spec->env, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for envionment variables");
        ret = -1;
        goto out;
    }

    container_spec->env = temp;
    for (i = 0; i < env_len; i++) {
        bool found = false;
        im_kv = util_string_split(env[i], '=');
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
            container_spec->env[container_spec->env_len] = util_strdup_s(env[i]);
            container_spec->env_len++;
        }
        util_free_array(im_kv);
        im_kv = NULL;
    }
out:
    return ret;
}