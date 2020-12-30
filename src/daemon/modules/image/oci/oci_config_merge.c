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

#include <stdio.h>
#include <string.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/imagetool_image.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_image_spec.h>
#include <stdbool.h>
#include <stdint.h>

#include "utils.h"
#include "isula_libutils/log.h"
#include "err_msg.h"
#include "utils_array.h"
#include "utils_string.h"
#include "image_spec_merge.h"
#include "map.h"

static void oci_image_merge_working_dir(const char *working_dir, container_config *container_spec)
{
    if (container_spec->working_dir != NULL || working_dir == NULL) {
        return;
    }

    container_spec->working_dir = util_strdup_s(working_dir);
}

static void oci_image_merge_stop_signal(const char *stop_signal, container_config *container_spec)
{
    if (container_spec->stop_signal != NULL || stop_signal == NULL) {
        return;
    }

    container_spec->stop_signal = util_strdup_s(stop_signal);
}

static int oci_image_merge_env(const oci_image_spec_config *config, container_config *container_spec)
{
    int ret = 0;

    if (config->env == NULL || config->env_len == 0) {
        return 0;
    }

    if (image_spec_merge_env((const char **)config->env, config->env_len, container_spec) != 0) {
        ret = -1;
        goto out;
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

static int oci_image_merge_anonymous_volumes(const oci_image_spec_config *config, container_config *container_spec)
{
    if (container_spec == NULL) {
        ERROR("Invalid NULL container spec");
        return -1;
    }

    // no image config found
    if (config == NULL || config->volumes == NULL || config->volumes->len == 0) {
        return 0;
    }

    // container's config contains image's anonymous volumes only right now, so just dump.
    container_spec->volumes = dup_map_string_empty_object(config->volumes);
    if (container_spec->volumes == NULL) {
        ERROR("dup anonymous volumes failed");
        return -1;
    }

    return 0;
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

static void oci_image_merge_image_ref(imagetool_image *image_conf, container_config *container_spec)
{
    if (image_conf->repo_digests_len > 0) {
        container_spec->image_ref = util_strdup_s(image_conf->repo_digests[0]);
    } else {
        container_spec->image_ref = util_strdup_s(image_conf->id);
    }
}

static int oci_image_merge_port_mappings(oci_image_spec_config *img_spec, container_config *container_spec)
{
    defs_map_string_object *work = NULL;
    size_t new_len, i;
    int ret = 0;
    // string -> bool
    map_t *port_table = NULL;
    bool flag = true;

    if (img_spec == NULL || img_spec->exposed_ports == NULL || img_spec->exposed_ports->len == 0) {
        return 0;
    }

    if (container_spec->exposed_ports == NULL) {
        container_spec->exposed_ports = img_spec->exposed_ports;
        img_spec->exposed_ports = NULL;
        return 0;
    }

    port_table = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (port_table == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    new_len = img_spec->exposed_ports->len;
    if (container_spec->exposed_ports->len > SIZE_MAX - new_len) {
        ERROR("Too large portmappings list to set");
        ret = -1;
        goto out;
    }
    new_len += container_spec->exposed_ports->len;

    work = util_common_calloc_s(sizeof(defs_map_string_object));
    if (work == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    work->keys = util_smart_calloc_s(sizeof(char *), new_len);
    if (work->keys == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    work->values = util_smart_calloc_s(sizeof(defs_map_string_object_element *), new_len);
    if (work->values == NULL) {
        free(work->keys);
        work->keys = NULL;
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    // Step 1: merge container spec portmapping into work
    for (i = 0; i < container_spec->exposed_ports->len; i++) {
        if (!map_replace(port_table, (void *)container_spec->exposed_ports->keys[i], (void *)&flag)) {
            ERROR("insert port mapping: %s into table failed", container_spec->exposed_ports->keys[i]);
            ret = -1;
            goto out;
        }
        work->keys[i] = container_spec->exposed_ports->keys[i];
        container_spec->exposed_ports->keys[i] = NULL;
        work->values[i] = container_spec->exposed_ports->values[i];
        container_spec->exposed_ports->values[i] = NULL;
        work->len += 1;
    }

    // Step 2: merge image spec portmapping into work, ignore port which same with container spec
    for (i = 0; i < img_spec->exposed_ports->len; i++) {
        if (map_search(port_table, img_spec->exposed_ports->keys[i]) != NULL) {
            WARN("found same port: %s, just skip.", img_spec->exposed_ports->keys[i]);
            continue;
        }
        if (!map_replace(port_table, (void *)img_spec->exposed_ports->keys[i], (void *)&flag)) {
            ERROR("insert port mapping: %s into table failed", img_spec->exposed_ports->keys[i]);
            ret = -1;
            goto out;
        }
        work->keys[work->len] = img_spec->exposed_ports->keys[i];
        img_spec->exposed_ports->keys[i] = NULL;
        work->values[work->len] = img_spec->exposed_ports->values[i];
        img_spec->exposed_ports->values[i] = NULL;
        work->len += 1;
    }

    free_defs_map_string_object(container_spec->exposed_ports);
    container_spec->exposed_ports = work;
    work = NULL;

out:
    free_defs_map_string_object(work);
    map_free(port_table);
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

        oci_image_merge_stop_signal(image_conf->spec->config->stop_signal, container_spec);

        if (oci_image_merge_port_mappings(image_conf->spec->config, container_spec) != 0) {
            ret = -1;
            goto out;
        }

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

        // Merge image's anonymous volumes to container_spec, here we do not check conflict.
        // We will check conflict after all volumes/binds merged.
        if (oci_image_merge_anonymous_volumes(image_conf->spec->config, container_spec) != 0) {
            ret = -1;
            goto out;
        }
    }

    if (oci_image_merge_health_check(image_conf->healthcheck, container_spec) != 0) {
        ret = -1;
        goto out;
    }

    oci_image_merge_image_ref(image_conf, container_spec);

out:
    return ret;
}
