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
 * Author: WuJing
 * Create: 2020-06-13
 * Description: provide registry common functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "registry_common.h"
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"

void free_items_not_inherit(docker_image_config_v2 *config)
{
    size_t i = 0;

    if (config == NULL) {
        return;
    }
    free(config->id);
    config->id = NULL;
    free(config->parent);
    config->parent = NULL;
    config->size = 0;
    free_docker_image_rootfs(config->rootfs);
    config->rootfs = NULL;

    for (i = 0; i < config->history_len; i++) {
        free_docker_image_history(config->history[i]);
        config->history[i] = NULL;
    }
    config->history = NULL;
    config->history_len = 0;

    return;
}

static char *convert_created_by(image_manifest_v1_compatibility *config)
{
    size_t i = 0;
    char *created_by = NULL;
    size_t size = 0;

    if (config == NULL || config->container_config == NULL || config->container_config->cmd == NULL ||
        config->container_config->cmd_len == 0) {
        return NULL;
    }

    for (i = 0; i < config->container_config->cmd_len; i++) {
        size += strlen(config->container_config->cmd[i]) + 1; // +1 for ' ' or '\0'
    }

    created_by = util_common_calloc_s(size);
    if (created_by == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    for (i = 0; i < config->container_config->cmd_len; i++) {
        if (i != 0) {
            (void)strcat(created_by, " ");
        }
        (void)strcat(created_by, config->container_config->cmd[i]);
    }

    return created_by;
}

int add_rootfs_and_history(const layer_blob *layers, size_t layers_len,
                           const registry_manifest_schema1 *manifest, docker_image_config_v2 *config)
{
    int i = 0;
    int ret = 0;
    size_t history_index = 0;
    parser_error err = NULL;
    image_manifest_v1_compatibility *v1config = NULL;
    docker_image_history *history = NULL;

    if (layers == NULL || layers_len == 0 || config == NULL || manifest == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    config->rootfs = util_common_calloc_s(sizeof(docker_image_rootfs));
    config->history = util_common_calloc_s(sizeof(docker_image_history *) * layers_len);
    if (config->rootfs == NULL || config->history == NULL) {
        ERROR("out of memory");
        return -1;
    }
    config->rootfs->type = util_strdup_s(ROOTFS_TYPE);

    history_index = manifest->history_len - 1;
    for (i = 0; i < layers_len; i++) {
        v1config = image_manifest_v1_compatibility_parse_data(manifest->history[history_index]->v1compatibility, NULL,
                                                              &err);
        if (v1config == NULL) {
            ERROR("parse v1 compatibility config failed, err: %s", err);
            ret = -1;
            goto out;
        }
        free(err);
        err = NULL;

        history = util_common_calloc_s(sizeof(docker_image_history));
        if (history == NULL) {
            ERROR("out of memory");
            ret = -1;
            goto out;
        }

        history->created = v1config->created;
        v1config->created = NULL;
        history->author = v1config->author;
        v1config->author = NULL;
        history->created_by = convert_created_by(v1config);
        history->comment = v1config->comment;
        v1config->comment = NULL;
        history->empty_layer = layers[i].empty_layer;

        config->history[i] = history;
        history = NULL;
        config->history_len++;

        free_image_manifest_v1_compatibility(v1config);
        v1config = NULL;
        history_index--;
        if (layers[i].empty_layer) {
            continue;
        }

        ret = util_array_append(&config->rootfs->diff_ids, layers[i].diff_id);
        if (ret != 0) {
            ERROR("append diff id of layer %u to rootfs failed, diff id is %s", i, layers[i].diff_id);
            ret = -1;
            goto out;
        }
        config->rootfs->diff_ids_len++;
    }

out:
    free(err);
    err = NULL;
    free_docker_image_history(history);
    history = NULL;
    free_image_manifest_v1_compatibility(v1config);
    v1config = NULL;

    return ret;
}

char *without_sha256_prefix(char *digest)
{
    if (digest == NULL) {
        ERROR("Invalid digest NULL when strip sha256 prefix");
        return NULL;
    }

    return digest + strlen(SHA256_PREFIX);
}

types_timestamp_t created_to_timestamp(char *created)
{
    int64_t nanos = 0;
    types_timestamp_t timestamp = { 0 };

    if (to_unix_nanos_from_str(created, &nanos) != 0) {
        ERROR("Failed to get created time from image config");
        goto out;
    }

    timestamp.has_seconds = true;
    timestamp.seconds = nanos / Time_Second;
    timestamp.has_nanos = true;
    timestamp.nanos = nanos % Time_Second;

out:

    return timestamp;
}

