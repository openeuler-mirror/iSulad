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
 * Create: 2020-05-09
 * Description: provide isula image common functions
 *******************************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <isula_libutils/docker_image_config_v2.h>
#include <isula_libutils/docker_image_history.h>
#include <isula_libutils/docker_image_rootfs.h>
#include <isula_libutils/image_manifest_v1_compatibility.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/registry_manifest_schema1.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_images.h"
#include "sha256.h"
#include "utils_array.h"
#include "utils_base64.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"

char *get_last_part(char **parts)
{
    char *last_part = NULL;
    char **p;

    for (p = parts; p != NULL && *p != NULL; p++) {
        last_part = *p;
    }

    return last_part;
}

char *oci_get_host(const char *name)
{
    char **parts = NULL;
    char *host = NULL;

    if (name == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    parts = util_string_split(name, '/');
    if ((parts != NULL && *parts != NULL && !strings_contains_any(*parts, ".:") && strcmp(*parts, "localhost")) ||
        (strstr(name, "/") == NULL)) {
        util_free_array(parts);
        return NULL;
    }

    if (parts != NULL) {
        host = util_strdup_s(parts[0]);
        util_free_array(parts);
    }

    return host;
}

char *oci_default_tag(const char *name)
{
    char temp[PATH_MAX] = { 0 };
    char **parts = NULL;
    char *last_part = NULL;
    char *add_default_tag = "";

    if (name == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    parts = util_string_split(name, '/');
    if (parts == NULL) {
        ERROR("split %s by '/' failed", name);
        return NULL;
    }

    last_part = get_last_part(parts);
    if (last_part != NULL && strrchr(last_part, ':') == NULL) {
        add_default_tag = DEFAULT_TAG;
    }

    util_free_array(parts);

    // Add image's default tag
    int nret = snprintf(temp, sizeof(temp), "%s%s", name, add_default_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
        ERROR("sprint temp image name failed");
        return NULL;
    }

    return util_strdup_s(temp);
}

char *oci_host_from_mirror(const char *mirror)
{
    const char *host = mirror;

    if (mirror == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    if (util_has_prefix(mirror, HTTPS_PREFIX)) {
        host = mirror + strlen(HTTPS_PREFIX);
    } else if (util_has_prefix(mirror, HTTP_PREFIX)) {
        host = mirror + strlen(HTTP_PREFIX);
    }

    return util_strdup_s(host);
}

char *oci_add_host(const char *host, const char *name)
{
    char *with_host = NULL;
    bool need_repo_prefix = false;

    if (host == NULL || name == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    if (strchr(name, '/') == NULL) {
        need_repo_prefix = true;
    }

    with_host = util_common_calloc_s(strlen(host) + strlen("/") + strlen(DEFAULT_REPO_PREFIX) + strlen(name) + 1);
    if (with_host == NULL) {
        ERROR("out of memory");
        return NULL;
    }
    (void)strcat(with_host, host);
    (void)strcat(with_host, "/");
    if (need_repo_prefix) {
        (void)strcat(with_host, DEFAULT_REPO_PREFIX);
    }
    (void)strcat(with_host, name);

    return with_host;
}

// normalize the unqualified image to be domain/repo/image...
char *oci_normalize_image_name(const char *name)
{
    char temp[PATH_MAX] = { 0 };
    char **parts = NULL;
    char *last_part = NULL;
    char *add_dockerio = "";
    char *add_library = "";
    char *add_default_tag = "";

    // Add prefix docker.io if necessary
    parts = util_string_split(name, '/');
    if ((parts != NULL && *parts != NULL && !strings_contains_any(*parts, ".:") && strcmp(*parts, "localhost")) ||
        (strstr(name, "/") == NULL)) {
        add_dockerio = DEFAULT_HOSTNAME;
    }

    // Add library if necessary
    if (strlen(add_dockerio) != 0 && strstr(name, "/") == NULL) {
        add_library = DEFAULT_REPO_PREFIX;
    }

    // Add default tag if necessary
    last_part = get_last_part(parts);
    if (last_part != NULL && strrchr(last_part, ':') == NULL) {
        add_default_tag = DEFAULT_TAG;
    }

    util_free_array(parts);

    // Normalize image name
    int nret = snprintf(temp, sizeof(temp), "%s%s%s%s", add_dockerio, add_library, name, add_default_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
        ERROR("sprint temp image name failed");
        return NULL;
    }

    return util_strdup_s(temp);
}

int oci_split_image_name(const char *image_name, char **host, char **name, char **tag)
{
    char *tag_pos = NULL;
    char *name_pos = NULL;
    char *tmp_image_name = NULL;

    if (!util_valid_image_name(image_name)) {
        ERROR("Invalid full image name %s", image_name);
        return -1;
    }

    tmp_image_name = util_strdup_s(image_name);
    tag_pos = util_tag_pos(tmp_image_name);
    if (tag_pos != NULL) {
        *tag_pos = 0;
        tag_pos++;
        if (tag != NULL) {
            *tag = util_strdup_s(tag_pos);
        }
    }

    name_pos = strchr(tmp_image_name, '/');
    if (name_pos != NULL) {
        *name_pos = 0;
        name_pos++;
        if (name != NULL) {
            *name = util_strdup_s(name_pos);
        }
        if (host != NULL) {
            *host = util_strdup_s(tmp_image_name);
        }
    }

    free(tmp_image_name);
    tmp_image_name = NULL;

    return 0;
}

char *oci_strip_dockerio_prefix(const char *name)
{
    char prefix[PATH_MAX] = { 0 };
    size_t size = 0;

    if (name == NULL) {
        ERROR("NULL image name");
        return NULL;
    }

    int nret = snprintf(prefix, sizeof(prefix), "%s%s", DEFAULT_HOSTNAME, DEFAULT_REPO_PREFIX);
    if (nret < 0 || (size_t)nret >= sizeof(prefix)) {
        ERROR("sprint prefix prefix failed");
        return NULL;
    }

    // Strip docker.io/library
    size = strlen(prefix);
    if (strncmp(name, prefix, size) == 0 && strlen(name) > size) {
        return util_strdup_s(name + size);
    }

    // Strip docker.io
    size = strlen(DEFAULT_HOSTNAME);
    if (strncmp(name, DEFAULT_HOSTNAME, size) == 0 && strlen(name) > size) {
        return util_strdup_s(name + size);
    }

    return util_strdup_s(name);
}

static bool should_use_origin_name(const char *name)
{
    size_t i;

    for (i = 0; i < strlen(name); i++) {
        char ch = name[i];
        if (ch != '.' && !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'z')) {
            return false;
        }
    }

    return true;
}

// Convert a BigData key name into an acceptable file name.
char *make_big_data_base_name(const char *key)
{
    int ret = 0;
    int nret = 0;
    char *b64_encode_name = NULL;
    char *base_name = NULL;
    size_t name_size;

    if (should_use_origin_name(key)) {
        return util_strdup_s(key);
    }

    nret = util_base64_encode((unsigned char *)key, strlen(key), &b64_encode_name);
    if (nret < 0) {
        ret = -1;
        ERROR("Encode auth to base64 failed");
        goto out;
    }
    name_size = 1 + strlen(b64_encode_name) + 1; // '=' + encode string + '\0'

    base_name = (char *)util_common_calloc_s(name_size * sizeof(char));
    if (base_name == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    nret = snprintf(base_name, name_size, "=%s", b64_encode_name);
    if (nret < 0 || (size_t)nret >= name_size) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    DEBUG("big data file name : %s", base_name);

out:
    if (ret != 0) {
        free(base_name);
        base_name = NULL;
    }
    free(b64_encode_name);

    return base_name;
}

char *oci_calc_diffid(const char *file)
{
    int ret = 0;
    char *diff_id = NULL;
    bool gzip = false;

    if (file == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    ret = util_gzip_compressed(file, &gzip);
    if (ret != 0) {
        ERROR("Get layer file %s gzip attribute failed", file);
        goto out;
    }

    if (gzip) {
        diff_id = sha256_full_gzip_digest(file);
    } else {
        diff_id = sha256_full_file_digest(file);
    }
    if (diff_id == NULL) {
        ERROR("calculate digest failed for file %s", file);
        ret = -1;
    }

out:
    if (ret != 0) {
        UTIL_FREE_AND_SET_NULL(diff_id);
    }
    return diff_id;
}

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

