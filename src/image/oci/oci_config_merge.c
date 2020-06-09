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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide oci config merge functions
 ******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "oci_config_merge.h"
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "utils.h"
#include "isula_libutils/log.h"
#include "libisulad.h"
#include "specs_mount.h"
#include "specs_extend.h"

static void oci_image_merge_working_dir(const char *working_dir, container_config *container_spec)
{
    if (container_spec->working_dir != NULL || working_dir == NULL) {
        return;
    }

    container_spec->working_dir = util_strdup_s(working_dir);
}

static int oci_image_merge_env(const oci_image_spec_config *config, container_config *container_spec)
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
        isulad_set_error_message("The length of envionment variables is too long, the limit is %d", LIST_ENV_SIZE_MAX);
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

static int do_duplicate_commands(const oci_image_spec_config *config, container_config *container_spec)
{
    size_t i;

    if (container_spec->cmd_len != 0 || config->cmd_len == 0) {
        return 0;
    }

    if (config->cmd_len > SIZE_MAX / sizeof(char *)) {
        ERROR("too many commands!");
        return -1;
    }

    container_spec->cmd = (char **)util_common_calloc_s(sizeof(char *) * config->cmd_len);
    if (container_spec->cmd == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < config->cmd_len; i++) {
        container_spec->cmd[i] = util_strdup_s(config->cmd[i]);
        container_spec->cmd_len++;
    }

    return 0;
}

static int do_duplicate_entrypoints(const oci_image_spec_config *config, container_config *container_spec)
{
    size_t i;

    if (config->entrypoint_len == 0) {
        return 0;
    }

    if (config->entrypoint_len > SIZE_MAX / sizeof(char *)) {
        ERROR("too many entrypoints!");
        return -1;
    }

    container_spec->entrypoint = (char **)util_common_calloc_s(sizeof(char *) * config->entrypoint_len);
    if (container_spec->entrypoint == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < config->entrypoint_len; i++) {
        container_spec->entrypoint[i] = util_strdup_s(config->entrypoint[i]);
        container_spec->entrypoint_len++;
    }

    return 0;
}

static int oci_image_merge_entrypoint(const oci_image_spec_config *config, container_config *container_spec)
{
    if (container_spec->entrypoint_len != 0) {
        return 0;
    }

    if (do_duplicate_commands(config, container_spec) != 0) {
        return -1;
    }

    if (do_duplicate_entrypoints(config, container_spec) != 0) {
        return -1;
    }

    return 0;
}

static int make_sure_container_config_labels(container_config *container_spec)
{
    if (container_spec->labels != NULL) {
        return 0;
    }

    container_spec->labels = util_common_calloc_s(sizeof(json_map_string_string));
    if (container_spec->labels == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    return 0;
}

static int oci_image_merge_labels(const oci_image_spec_config *config, container_config *container_spec)
{
    int ret = 0;
    size_t i;
    json_map_string_string *tmp = NULL;

    if (config->labels == NULL || config->labels->len == 0) {
        return 0;
    }

    tmp = util_common_calloc_s(sizeof(json_map_string_string));
    if (tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (make_sure_container_config_labels(container_spec) != 0) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < config->labels->len; i++) {
        ret = append_json_map_string_string(tmp, config->labels->keys[i], config->labels->values[i]);
        if (ret != 0) {
            ret = -1;
            goto out;
        }
    }

    for (i = 0; i < container_spec->labels->len; i++) {
        ret = append_json_map_string_string(tmp, container_spec->labels->keys[i], container_spec->labels->values[i]);
        if (ret != 0) {
            ret = -1;
            goto out;
        }
    }

    free_json_map_string_string(container_spec->labels);
    container_spec->labels = tmp;
    tmp = NULL;

out:
    free_json_map_string_string(tmp);
    return ret;
}

static void oci_image_merge_user(const char *user, container_config *container_spec)
{
    if (container_spec->user != NULL) {
        return;
    }

    container_spec->user = util_strdup_s(user);
}

static int dup_health_check_from_image(const defs_health_check *image_health_check, container_config *container_spec)
{
    int ret = 0;
    size_t i;

    defs_health_check *health_check = (defs_health_check *)util_common_calloc_s(sizeof(defs_health_check));
    if (health_check == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (image_health_check->test_len > SIZE_MAX / sizeof(char *)) {
        ERROR("invalid health check commands!");
        ret = -1;
        goto out;
    }

    health_check->test = util_common_calloc_s(sizeof(char *) * image_health_check->test_len);
    if (health_check->test == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < image_health_check->test_len; i++) {
        health_check->test[i] = util_strdup_s(image_health_check->test[i]);
        health_check->test_len++;
    }
    health_check->interval = image_health_check->interval;
    health_check->timeout = image_health_check->timeout;
    health_check->start_period = image_health_check->start_period;
    health_check->retries = image_health_check->retries;
    health_check->exit_on_unhealthy = image_health_check->exit_on_unhealthy;

    container_spec->healthcheck = health_check;

    health_check = NULL;

out:
    free_defs_health_check(health_check);
    return ret;
}

static int update_health_check_from_image(const defs_health_check *image_health_check, container_config *container_spec)
{
    if (container_spec->healthcheck->test_len == 0) {
        size_t i;

        if (image_health_check->test_len > SIZE_MAX / sizeof(char *)) {
            ERROR("invalid health check commands!");
            return -1;
        }
        container_spec->healthcheck->test = util_common_calloc_s(sizeof(char *) * image_health_check->test_len);
        if (container_spec->healthcheck->test == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        for (i = 0; i < image_health_check->test_len; i++) {
            container_spec->healthcheck->test[i] = util_strdup_s(image_health_check->test[i]);
            container_spec->healthcheck->test_len++;
        }
    }
    if (container_spec->healthcheck->interval == 0) {
        container_spec->healthcheck->interval = image_health_check->interval;
    }
    if (container_spec->healthcheck->timeout == 0) {
        container_spec->healthcheck->timeout = image_health_check->timeout;
    }
    if (container_spec->healthcheck->start_period == 0) {
        container_spec->healthcheck->start_period = image_health_check->start_period;
    }
    if (container_spec->healthcheck->retries == 0) {
        container_spec->healthcheck->retries = image_health_check->retries;
    }

    return 0;
}

static int oci_image_merge_health_check(const defs_health_check *image_health_check, container_config *container_spec)
{
    int ret = 0;

    if (image_health_check == NULL || image_health_check->test_len == 0) {
        return 0;
    }

    if (container_spec->healthcheck == NULL) {
        if (dup_health_check_from_image(image_health_check, container_spec) != 0) {
            ret = -1;
            goto out;
        }
    } else {
        if (update_health_check_from_image(image_health_check, container_spec) != 0) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

int oci_image_merge_config(imagetool_image *image_conf, container_config *container_spec)
{
    int ret = 0;

    if (image_conf == NULL || container_spec == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (image_conf->spec != NULL && image_conf->spec->config != NULL) {
        oci_image_merge_working_dir(image_conf->spec->config->working_dir, container_spec);

        if (oci_image_merge_env(image_conf->spec->config, container_spec) != 0) {
            ret = -1;
            goto out;
        }

        if (oci_image_merge_entrypoint(image_conf->spec->config, container_spec) != 0) {
            ret = -1;
            goto out;
        }

        oci_image_merge_user(image_conf->spec->config->user, container_spec);

        if (oci_image_merge_labels(image_conf->spec->config, container_spec) != 0) {
            ret = -1;
            goto out;
        }

        // ignore volumes now
    }

    if (oci_image_merge_health_check(image_conf->healthcheck, container_spec) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}
