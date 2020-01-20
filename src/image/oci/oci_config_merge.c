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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide oci config merge functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include "oci_config_merge.h"
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "utils.h"
#include "log.h"
#include "libisulad.h"
#include "specs_mount.h"
#include "specs_extend.h"

static void oci_image_merge_working_dir(const char *working_dir, oci_runtime_spec *oci_spec)
{
    if (working_dir == NULL) {
        return;
    }

    free(oci_spec->process->cwd);
    oci_spec->process->cwd = util_strdup_s(working_dir);
}

static int oci_image_merge_env(const oci_image_spec_config *config, oci_runtime_spec *oci_spec)
{
    if (config->env == NULL || config->env_len == 0) {
        return 0;
    }
    if (merge_env(oci_spec, (const char **)config->env, config->env_len) != 0) {
        ERROR("Failed to merge environment variables");
        return -1;
    }

    return 0;
}

static int do_duplicate_commands(const oci_image_spec_config *config, container_custom_config *custom_spec)
{
    size_t i;

    if (custom_spec->cmd_len != 0 || config->cmd_len == 0) {
        return 0;
    }

    custom_spec->cmd = (char **)util_smart_calloc_s(sizeof(char *), config->cmd_len);
    if (custom_spec->cmd == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < config->cmd_len; i++) {
        custom_spec->cmd[i] = util_strdup_s(config->cmd[i]);
        custom_spec->cmd_len++;
    }

    return 0;
}

static int do_duplicate_entrypoints(const oci_image_spec_config *config, container_custom_config *custom_spec)
{
    size_t i;

    if (config->entrypoint_len == 0) {
        return 0;
    }

    custom_spec->entrypoint = (char **)util_smart_calloc_s(sizeof(char *), config->entrypoint_len);
    if (custom_spec->entrypoint == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    for (i = 0; i < config->entrypoint_len; i++) {
        custom_spec->entrypoint[i] = util_strdup_s(config->entrypoint[i]);
        custom_spec->entrypoint_len++;
    }

    return 0;
}

static int oci_image_merge_entrypoint(const oci_image_spec_config *config, container_custom_config *custom_spec)
{
    if (custom_spec->entrypoint_len != 0) {
        return 0;
    }

    if (do_duplicate_commands(config, custom_spec) != 0) {
        return -1;
    }

    if (do_duplicate_entrypoints(config, custom_spec) != 0) {
        return -1;
    }

    return 0;
}

static void oci_image_merge_user(const char *user, container_custom_config *custom_spec)
{
    if (custom_spec->user != NULL) {
        return;
    }

    custom_spec->user = util_strdup_s(user);
}

static int oci_image_merge_volumes(const oci_image_spec_config *config, oci_runtime_spec *oci_spec)
{
    int ret;

    if (config->volumes == NULL) {
        return 0;
    }
    ret = merge_volumes(oci_spec, config->volumes->keys, config->volumes->len, NULL, parse_volume);
    if (ret != 0) {
        ERROR("Failed to merge volumes");
        return -1;
    }

    return 0;
}

static int dup_health_check_from_image(const defs_health_check *image_health_check,
                                       container_custom_config *custom_spec)
{
    int ret = 0;
    size_t i;
    defs_health_check *health_check = (defs_health_check *)util_common_calloc_s(sizeof(defs_health_check));
    if (health_check == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    health_check->test = util_smart_calloc_s(sizeof(char *), image_health_check->test_len);
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

    custom_spec->health_check = health_check;

    health_check = NULL;

out:
    free_defs_health_check(health_check);
    return ret;
}

static int update_health_check_from_image(const defs_health_check *image_health_check,
                                          container_custom_config *custom_spec)
{
    if (custom_spec->health_check->test_len == 0) {
        size_t i;

        custom_spec->health_check->test = util_smart_calloc_s(sizeof(char *), image_health_check->test_len);
        if (custom_spec->health_check->test == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        for (i = 0; i < image_health_check->test_len; i++) {
            custom_spec->health_check->test[i] = util_strdup_s(image_health_check->test[i]);
            custom_spec->health_check->test_len++;
        }
    }
    if (custom_spec->health_check->interval == 0) {
        custom_spec->health_check->interval = image_health_check->interval;
    }
    if (custom_spec->health_check->timeout == 0) {
        custom_spec->health_check->timeout = image_health_check->timeout;
    }
    if (custom_spec->health_check->start_period == 0) {
        custom_spec->health_check->start_period = image_health_check->start_period;
    }
    if (custom_spec->health_check->retries == 0) {
        custom_spec->health_check->retries = image_health_check->retries;
    }

    return 0;
}

static int oci_image_merge_health_check(const defs_health_check *image_health_check,
                                        container_custom_config *custom_spec)
{
    int ret = 0;

    if (image_health_check == NULL) {
        return 0;
    }

    if (image_health_check->test_len == 0) {
        ERROR("health check commands required");
        return -1;
    }

    if (custom_spec->health_check == NULL) {
        if (dup_health_check_from_image(image_health_check, custom_spec) != 0) {
            ret = -1;
            goto out;
        }
    } else {
        if (update_health_check_from_image(image_health_check, custom_spec) != 0) {
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

int oci_image_merge_config(imagetool_image *image_conf, oci_runtime_spec *oci_spec,
                           container_custom_config *custom_spec)
{
    int ret = 0;

    if (image_conf == NULL || oci_spec == NULL || custom_spec == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (image_conf->spec != NULL && image_conf->spec->config != NULL) {
        oci_image_merge_working_dir(image_conf->spec->config->working_dir, oci_spec);

        if (oci_image_merge_env(image_conf->spec->config, oci_spec) != 0) {
            ret = -1;
            goto out;
        }

        if (oci_image_merge_entrypoint(image_conf->spec->config, custom_spec) != 0) {
            ret = -1;
            goto out;
        }

        oci_image_merge_user(image_conf->spec->config->user, custom_spec);

        if (oci_image_merge_volumes(image_conf->spec->config, oci_spec) != 0) {
            ret = -1;
            goto out;
        }
    }

    if (oci_image_merge_health_check(image_conf->healthcheck, custom_spec) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

