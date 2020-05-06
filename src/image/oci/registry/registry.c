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
 * Author: wangfengtu
 * Create: 2020-02-27
 * Description: provide registry functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "mediatype.h"
#include "log.h"
#include "registry_type.h"
#include "registry.h"
#include "utils.h"
#include "oci_common_operators.h"
#include "registry_apiv2.h"
#include "auths.h"
#include "certs.h"
#include "registry_manifest_schema2.h"
#include "registry_manifest_schema1.h"
#include "docker_image_config_v2.h"
#include "image_manifest_v1_compatibility.h"
#include "sha256.h"
#include "map.h"
#include "linked_list.h"
#include "pthread.h"
#include "isulad_config.h"

#define MAX_LAYER_NUM 125
#define MANIFEST_BIG_DATA_KEY "manifest"
#define ROOTFS_TYPE "layers"
#define MAX_CONCURRENT_DOWNLOAD_NUM 5

typedef struct {
    pull_descriptor *desc;
    size_t index;
    char *blob_digest;
    char *file;
    bool use;
} thread_fetch_info;

typedef struct {
    pthread_mutex_t mutex;
    int result;
    bool complete;
    char *diffid;
    struct linked_list file_list;
    size_t file_list_len;
} cached_layer;

// Share infomation of downloading layers to avoid downloading the same layer.
typedef struct {
    pthread_mutex_t mutex;
    bool mutex_inited;
    pthread_cond_t cond;
    bool cond_inited;
    map_t *cached_layers;
    size_t count;
} registry_global;

static registry_global *g_shared;

static int parse_manifest_schema1(pull_descriptor *desc)
{
    registry_manifest_schema1 *manifest = NULL;
    parser_error err = NULL;
    int ret = 0;
    int i = 0;
    size_t index = 0;
    image_manifest_v1_compatibility *v1config = NULL;

    manifest = registry_manifest_schema1_parse_file(desc->manifest.file, NULL, &err);
    if (manifest == NULL) {
        ERROR("parse manifest schema1 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    if (manifest->fs_layers_len > MAX_LAYER_NUM || manifest->fs_layers_len == 0) {
        ERROR("Invalid layer number %d, maxium is %d and it can't be 0", manifest->fs_layers_len, MAX_LAYER_NUM);
        ret = -1;
        goto out;
    }

    if (manifest->fs_layers_len != manifest->history_len) {
        ERROR("Invalid layer number %d do not match history number %d", manifest->fs_layers_len, manifest->history_len);
        ret = -1;
        goto out;
    }

    desc->layers = util_common_calloc_s(sizeof(layer_blob) * manifest->fs_layers_len);
    if (desc->layers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    for (i = (int)manifest->fs_layers_len - 1, index = 0; i >= 0; i--, index++) {
        free(err);
        err = NULL;
        v1config = image_manifest_v1_compatibility_parse_data(manifest->history[i]->v1compatibility, NULL, &err);
        if (v1config == NULL) {
            ERROR("parse v1 compatibility %d failed, err: %s", i, err);
            ret = -1;
            goto out;
        }

        desc->layers[index].empty_layer = v1config->throwaway;
        // Cann't download an empty layer, skip related infomation.
        if (v1config->throwaway) {
            continue;
        }

        desc->layers[index].media_type = util_strdup_s(DOCKER_IMAGE_LAYER_TAR_GZIP);
        desc->layers[index].digest = util_strdup_s(manifest->fs_layers[i]->blob_sum);
    }
    desc->layers_len = manifest->fs_layers_len;

out:
    free_registry_manifest_schema1(manifest);
    manifest = NULL;
    free(err);
    err = NULL;

    return ret;
}

static int parse_manifest_schema2(pull_descriptor *desc)
{
    registry_manifest_schema2 *manifest = NULL;
    parser_error err = NULL;
    int ret = 0;
    size_t i = 0;

    manifest = registry_manifest_schema2_parse_file(desc->manifest.file, NULL, &err);
    if (manifest == NULL) {
        ERROR("parse manifest schema2 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    desc->config.media_type = util_strdup_s(manifest->config->media_type);
    desc->config.digest = util_strdup_s(manifest->config->digest);
    desc->config.size = manifest->config->size;

    if (manifest->layers_len > MAX_LAYER_NUM) {
        ERROR("Invalid layer number %d, maxium is %d", manifest->layers_len, MAX_LAYER_NUM);
        ret = -1;
        goto out;
    }

    desc->layers = util_common_calloc_s(sizeof(layer_blob) * manifest->layers_len);
    if (desc->layers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < manifest->layers_len; i++) {
        if (strcmp(manifest->layers[i]->media_type, DOCKER_IMAGE_LAYER_TAR_GZIP) &&
            strcmp(manifest->layers[i]->media_type, DOCKER_IMAGE_LAYER_FOREIGN_TAR_GZIP)) {
            ERROR("Unsupported layer's media type %s, layer index %d", manifest->layers[i]->media_type, i);
            ret = -1;
            goto out;
        }
        desc->layers[i].media_type = util_strdup_s(manifest->layers[i]->media_type);
        desc->layers[i].size = manifest->layers[i]->size;
        desc->layers[i].digest = util_strdup_s(manifest->layers[i]->digest);
    }
    desc->layers_len = manifest->layers_len;

out:
    if (manifest != NULL) {
        free_registry_manifest_schema2(manifest);
        manifest = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static int parse_manifest_ociv1(pull_descriptor *desc)
{
    oci_image_manifest *manifest = NULL;
    parser_error err = NULL;
    int ret = 0;
    size_t i = 0;

    manifest = oci_image_manifest_parse_file(desc->manifest.file, NULL, &err);
    if (manifest == NULL) {
        ERROR("parse manifest oci v1 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    desc->config.media_type = util_strdup_s(manifest->config->media_type);
    desc->config.digest = util_strdup_s(manifest->config->digest);
    desc->config.size = manifest->config->size;

    if (manifest->layers_len > MAX_LAYER_NUM) {
        ERROR("Invalid layer number %d, maxium is %d", manifest->layers_len, MAX_LAYER_NUM);
        ret = -1;
        goto out;
    }

    desc->layers = util_common_calloc_s(sizeof(layer_blob) * manifest->layers_len);
    if (desc->layers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < manifest->layers_len; i++) {
        if (strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_TAR_GZIP)) {
            ERROR("Unsupported layer's media type %s, layer index %d", manifest->layers[i]->media_type, i);
            ret = -1;
            goto out;
        }
        desc->layers[i].media_type = util_strdup_s(manifest->layers[i]->media_type);
        desc->layers[i].size = manifest->layers[i]->size;
        desc->layers[i].digest = util_strdup_s(manifest->layers[i]->digest);
    }
    desc->layers_len = manifest->layers_len;

out:
    if (manifest != NULL) {
        free_oci_image_manifest(manifest);
        manifest = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static bool is_manifest_schemav1(char *media_type)
{
    if (media_type == NULL) {
        return false;
    }

    if (!strcmp(media_type, DOCKER_MANIFEST_SCHEMA1_JSON) ||
        !strcmp(media_type, DOCKER_MANIFEST_SCHEMA1_PRETTYJWS) ||
        !strcmp(media_type, MEDIA_TYPE_APPLICATION_JSON)) {
        return true;
    }

    return false;
}

static int parse_manifest(pull_descriptor *desc)
{
    char *media_type = NULL;
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    media_type = desc->manifest.media_type;
    if (!strcmp(media_type, DOCKER_MANIFEST_SCHEMA2_JSON)) {
        ret = parse_manifest_schema2(desc);
    } else if (!strcmp(media_type, OCI_MANIFEST_V1_JSON)) {
        ret = parse_manifest_ociv1(desc);
    } else if (is_manifest_schemav1(media_type)) {
        WARN("found manifest schema1 %s, it has been deprecated", media_type);
        ret = parse_manifest_schema1(desc);
    } else {
        ERROR("Unsupported manifest media type %s", desc->manifest.media_type);
        return -1;
    }
    if (ret != 0) {
        ERROR("parse manifest failed, media type %s", desc->manifest.media_type);
        return ret;
    }

    return ret;
}

static void mutex_lock(pthread_mutex_t *mutex)
{
    if (pthread_mutex_lock(mutex)) {
        ERROR("Failed to lock");
    }
}

static void mutex_unlock(pthread_mutex_t *mutex)
{
    if (pthread_mutex_unlock(mutex)) {
        ERROR("Failed to unlock");
    }
}

static cached_layer *get_cached_layer(char *blob_digest)
{
    return map_search(g_shared->cached_layers, blob_digest);
}

static void del_cached_layer(char *blob_digest, char *file)
{
    cached_layer *cache = NULL;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    cache = (cached_layer *)map_search(g_shared->cached_layers, blob_digest);
    if (cache == NULL) {
        return;
    }
    if (cache->file_list_len != 0) {
        linked_list_for_each_safe(item, &(cache->file_list), next) {
            if (strcmp((char *)item->elem, file)) {
                linked_list_del(item);
                free((char *)item->elem);
                free(item);
                item = NULL;
                cache->file_list_len--;
                break;
            }
        }
    }

    if (cache->file_list_len != 0) {
        return;
    }

    if (!map_remove(g_shared->cached_layers, blob_digest)) {
        ERROR("remove %s from cached layers failed", blob_digest);
        return;
    }

    return;
}

static int add_cached_layer(char *blob_digest, char *file)
{
    int ret = 0;
    cached_layer *cache = NULL;
    struct linked_list *node = NULL;
    char *src_file = NULL;

    cache = (cached_layer *)map_search(g_shared->cached_layers, blob_digest);
    if (cache == NULL) {
        cache = util_common_calloc_s(sizeof(cached_layer));
        if (cache == NULL) {
            ERROR("out of memory");
            return -1;
        }

        linked_list_init(&cache->file_list);
        ret = pthread_mutex_init(&cache->mutex, NULL);
        if (ret != 0) {
            ERROR("Failed to init mutex for layer cache");
            free(cache);
            cache = NULL;
            return -1;
        }

        if (!map_insert(g_shared->cached_layers, blob_digest, cache)) {
            ERROR("Failed to insert cache layer %s", blob_digest);
            pthread_mutex_destroy(&cache->mutex);
            free(cache);
            cache = NULL;
            return -1;
        }
    }

    // Newlay added cached layer need to do a hard link to let
    // the layer exist in the downloader's directory if the layer
    // is already downloaded.
    if (cache->complete && cache->result == 0) {
        src_file = linked_list_first_elem(&cache->file_list);
        if (src_file == NULL) {
            ERROR("Failed to add cache, list's first element is NULL");
            ret = -1;
            goto out;
        }

        if (link(src_file, file) != 0) {
            ERROR("link %s to %s failed: %s", src_file, file, strerror(errno));
            ret = -1;
            goto out;
        }
    }

    node = util_common_calloc_s(sizeof(struct linked_list));
    if (node == NULL) {
        ERROR("Failed to malloc for linked_list");
        ret = -1;
        goto out;
    }
    linked_list_init(node);
    linked_list_add_elem(node, util_strdup_s(file));
    linked_list_add_tail(&cache->file_list, node);
    node = NULL;
    cache->file_list_len++;

out:
    if (ret != 0) {
        del_cached_layer(blob_digest, file);
        if (node != NULL) {
            free(node->elem);
            node->elem = NULL;
        }
        free(node);
        node = NULL;
    }

    return ret;
}

static int set_cached_info_to_desc(thread_fetch_info *infos, size_t infos_len, pull_descriptor *desc)
{
    size_t i = 0;
    cached_layer *cache = NULL;

    for (i = 0; i < infos_len; i++) {
        if (infos[i].use) {
            cache = (cached_layer *)map_search(g_shared->cached_layers, infos[i].blob_digest);
            if (cache == NULL) {
                ERROR("no cached layer found error, this should never happen");
                return -1;
            }

            desc->layers[i].diff_id = util_strdup_s(cache->diffid);
            desc->layers[i].file = util_strdup_s(infos[i].file);
        }
    }

    return 0;
}

static char *calc_diffid(char *file)
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
        // consider it as gziped just like media type indicated if we cann't determined if it's gziped.
        gzip = true;
    }

    if (gzip) {
        diff_id = util_full_gzip_digest(file);
    } else {
        diff_id = util_full_file_digest(file);
    }
    if (diff_id == NULL) {
        ERROR("calculate digest failed for file %s", file);
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free(diff_id);
        diff_id = NULL;
    }

    return diff_id;
}

static char *without_sha256_prefix(char *digest)
{
    return digest + strlen(SHA256_PREFIX);
}

static int register_layers(pull_descriptor *desc)
{
    int ret = 0;
    size_t i = 0;
    struct layer *l = NULL;
    char *id = NULL;
    char *parent = NULL;
    cached_layer *cached = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    if (desc->layers_len == 0) {
        ERROR("No layer found failed");
        return -1;
    }

    for (i = 0; i < desc->layers_len; i++) {
        id = without_sha256_prefix(desc->layers[i].chain_id);
        if (desc->layers[i].already_exist) {
            l = storage_layer_get(id);
            if (l != NULL) {
                free_layer(l);
                l = NULL;
                ret = storage_layer_try_repair_lowers(id, parent);
                if (ret != 0) {
                    ERROR("try to repair lowers for layer %s failed", id);
                }
                parent = id;
                continue;
            }
            ERROR("Pull image failed, because layer %s has be deleted when pulling image", id);
            ret = -1;
            goto out;
        }

        mutex_lock(&g_shared->mutex);
        cached = get_cached_layer(desc->layers[i].digest);
        mutex_unlock(&g_shared->mutex);
        if (cached == NULL) {
            ERROR("get cached layer %s failed, this should never happen");
            ret = -1;
            goto out;
        }

        // Lock this layer when create layer to avoid concurrent create for the same layer.
        mutex_lock(&cached->mutex);
        l = storage_layer_get(id);
        if (l != NULL) {
            free_layer(l);
            l = NULL;
        } else {
            ret = storage_layer_create(id, parent, false, desc->layers[i].file);
        }
        mutex_unlock(&cached->mutex);
        if (ret != 0) {
            ERROR("create layer %s failed, parent %s, file %s", id, parent, desc->layers[i].file);
            goto out;
        }

        parent = id;
    }

out:
    for (i = 0; i < desc->layers_len; i++) {
        mutex_lock(&g_shared->mutex);
        del_cached_layer(desc->layers[i].digest, desc->layers[i].file);
        mutex_unlock(&g_shared->mutex);
    }

    return ret;
}

static int create_image(pull_descriptor *desc, char *image_id)
{
    int ret = 0;
    size_t top_layer_index = 0;
    struct storage_img_create_options opts = {0};
    char *top_layer_id = NULL;
    storage_image *image = NULL;

    if (desc == NULL || image_id == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    top_layer_index = desc->layers_len - 1;
    opts.create_time = &desc->config.create_time;
    opts.digest = desc->manifest.digest;
    top_layer_id = without_sha256_prefix(desc->layers[top_layer_index].chain_id);
    ret = storage_img_create(image_id, top_layer_id, NULL, &opts);
    if (ret != 0) {
        image = (storage_image *)storage_img_get(image_id);
        if (image == NULL || image->layer == NULL) {
            ERROR("create image %s for %s failed", image_id, desc->dest_image_name);
            goto out;
        }

        if (strcmp(image->layer, top_layer_id)) {
            ERROR("error committing image, image id %s exist, but top layer doesn't match. local %s, download %s",
                  image_id, image->layer, top_layer_id);
            ret = -1;
            goto out;
        }

        goto out;
    }

    ret = storage_img_add_name(image_id, desc->dest_image_name);
    if (ret != 0) {
        ERROR("add image name failed");
        goto out;
    }

out:

    free_storage_image(image);
    image = NULL;

    return ret;
}

static int set_manifest(pull_descriptor *desc, char *image_id)
{
    int ret = 0;
    char *manifest_str = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    manifest_str = util_read_text_file(desc->manifest.file);
    if (manifest_str == NULL) {
        ERROR("read file %s content failed", desc->manifest.file);
        ret = -1;
        goto out;
    }

    ret = storage_img_set_big_data(image_id, MANIFEST_BIG_DATA_KEY, manifest_str);
    if (ret != 0) {
        ERROR("set big data failed");
        goto out;
    }

out:

    free(manifest_str);
    manifest_str = NULL;

    return ret;
}

static int set_config(pull_descriptor *desc, char *image_id)
{
    int ret = 0;
    char *config_str = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    config_str = util_read_text_file(desc->config.file);
    if (config_str == NULL) {
        ERROR("read file %s content failed", desc->config.file);
        ret = -1;
        goto out;
    }

    ret = storage_img_set_big_data(image_id, desc->config.digest, config_str);
    if (ret != 0) {
        ERROR("set big data failed");
        goto out;
    }

out:

    free(config_str);
    config_str = NULL;

    return ret;
}

static int set_loaded_time(pull_descriptor *desc, char *image_id)
{
    int ret = 0;
    types_timestamp_t now = {0};

    if (!get_now_time_stamp(&now)) {
        ret = -1;
        ERROR("get now time stamp failed");
        goto out;
    }

    ret = storage_img_set_loaded_time(image_id, &now);
    if (ret != 0) {
        ERROR("set loaded time failed");
        goto out;
    }

out:

    return ret;
}

static int register_image(pull_descriptor *desc)
{
    int ret = 0;
    char *image_id = NULL;
    bool image_created = false;

    if (desc == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    ret = register_layers(desc);
    if (ret != 0) {
        ERROR("registry layers failed");
        goto out;
    }

    image_id = without_sha256_prefix(desc->config.digest);
    ret = create_image(desc, image_id);
    if (ret != 0) {
        ERROR("create image failed");
        goto out;
    }
    image_created = true;

    ret = set_config(desc, image_id);
    if (ret != 0) {
        ERROR("set image config failed");
        goto out;
    }

    ret = set_manifest(desc, image_id);
    if (ret != 0) {
        ERROR("set manifest failed");
        goto out;
    }

    ret = set_loaded_time(desc, image_id);
    if (ret != 0) {
        ERROR("set loaded time failed");
        goto out;
    }

out:

    if (ret != 0 && image_created) {
        if (storage_img_delete(image_id, true)) {
            ERROR("delete image %d failed", image_id);
        }
    }

    return ret;
}

static char *calc_chain_id(char *parent_chain_id, char *diff_id)
{
    int sret = 0;
    char tmp_buffer[256] = {0};
    char *digest = NULL;
    char *full_digest = NULL;

    if (parent_chain_id == NULL || diff_id == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    if (strlen(diff_id) <= strlen(SHA256_PREFIX)) {
        ERROR("Invalid diff id %s found when calc chain id", diff_id);
        return NULL;
    }

    if (strlen(parent_chain_id) == 0) {
        return util_strdup_s(diff_id);
    }

    if (strlen(parent_chain_id) <= strlen(SHA256_PREFIX)) {
        ERROR("Invalid parent chain id %s found when calc chain id", parent_chain_id);
        return NULL;
    }

    sret = snprintf(tmp_buffer, sizeof(tmp_buffer), "%s+%s", parent_chain_id + strlen(SHA256_PREFIX),
                    diff_id + strlen(SHA256_PREFIX));
    if (sret < 0 || (size_t)sret >= sizeof(tmp_buffer)) {
        ERROR("Failed to sprintf chain id original string");
        return NULL;
    }

    digest = sha256_digest_str(tmp_buffer);
    if (digest == NULL) {
        ERROR("Failed to calculate chain id");
        goto out;
    }

    full_digest = util_full_digest(digest);

out:

    free(digest);
    digest = NULL;

    return full_digest;
}

static types_timestamp_t created_to_timestamp(char *created)
{
    int64_t nanos = 0;
    types_timestamp_t timestamp = {0};

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

static int parse_docker_config(pull_descriptor *desc)
{
    int ret = 0;
    parser_error err = NULL;
    size_t i = 0;
    docker_image_config_v2 *config = NULL;
    char *diff_id = NULL;
    char *parent_chain_id = "";

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    config = docker_image_config_v2_parse_file(desc->config.file, NULL, &err);
    if (config == NULL) {
        ERROR("parse image config v2 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    if (config->rootfs == NULL || config->rootfs->diff_ids_len == 0) {
        ERROR("No rootfs found in config");
        ret = -1;
        goto out;
    }

    for (i = 0; i < config->rootfs->diff_ids_len; i++) {
        diff_id = config->rootfs->diff_ids[i];
        desc->layers[i].diff_id = util_strdup_s(diff_id);
        desc->layers[i].chain_id = calc_chain_id(parent_chain_id, diff_id);
        if (desc->layers[i].chain_id == NULL) {
            ERROR("calc chain id failed, diff id %s, parent chain id %s", diff_id, parent_chain_id);
            ret = -1;
            goto out;
        }
        parent_chain_id = desc->layers[i].chain_id;
    }

    desc->config.create_time = created_to_timestamp(config->created);

out:

    if (config != NULL) {
        free_docker_image_config_v2(config);
        config = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static int parse_oci_config(pull_descriptor *desc)
{
    int ret = 0;
    parser_error err = NULL;
    size_t i = 0;
    oci_image_spec *config = NULL;
    char *diff_id = NULL;
    char *parent_chain_id = "";

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    config = oci_image_spec_parse_file(desc->config.file, NULL, &err);
    if (config == NULL) {
        ERROR("parse image config v2 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    if (config->rootfs == NULL || config->rootfs->diff_ids_len == 0) {
        ERROR("No rootfs found in config");
        ret = -1;
        goto out;
    }

    for (i = 0; i < config->rootfs->diff_ids_len; i++) {
        diff_id = config->rootfs->diff_ids[i];
        desc->layers[i].diff_id = util_strdup_s(diff_id);
        desc->layers[i].chain_id = calc_chain_id(parent_chain_id, diff_id);
        if (desc->layers[i].chain_id == NULL) {
            ERROR("calc chain id failed, diff id %s, parent chain id %s", diff_id, parent_chain_id);
            ret = -1;
            goto out;
        }
        parent_chain_id = desc->layers[i].chain_id;
    }

    desc->config.create_time = created_to_timestamp(config->created);

out:
    if (config != NULL) {
        free_oci_image_spec(config);
        config = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static int parse_config(pull_descriptor *desc)
{
    int ret = 0;
    char *media_type = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    media_type = desc->config.media_type;
    if (!strcmp(media_type, DOCKER_IMAGE_V1)) {
        ret = parse_docker_config(desc);
    } else if (!strcmp(media_type, OCI_IMAGE_V1)) {
        ret = parse_oci_config(desc);
    } else {
        ERROR("Unsupported config media type %s", media_type);
        return -1;
    }
    if (ret != 0) {
        ERROR("parse config failed, media type %s", media_type);
        return ret;
    }

    return ret;
}

static int fetch_and_parse_config(pull_descriptor *desc)
{
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = fetch_config(desc);
    if (ret != 0) {
        ERROR("fetch config failed");
        goto out;
    }

    ret = parse_config(desc);
    if (ret != 0) {
        ERROR("parse config failed");
        goto out;
    }

out:

    return ret;
}

static int fetch_and_parse_manifest(pull_descriptor *desc)
{
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = fetch_manifest(desc);
    if (ret != 0) {
        ERROR("fetch manifest failed");
        goto out;
    }

    ret = parse_manifest(desc);
    if (ret != 0) {
        ERROR("parse manifest failed");
        goto out;
    }

out:

    return ret;
}

static void set_cached_layers_info(char *blob_digest, char *diffid, int result, char *src_file)
{
    cached_layer *cache = NULL;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    char *file = NULL;

    cache = (cached_layer *)map_search(g_shared->cached_layers, blob_digest);
    if (cache == NULL) {
        ERROR("can't get cache for %s, this should never happen", blob_digest);
        return;
    }
    free(cache->diffid);
    cache->diffid = util_strdup_s(diffid);
    cache->result = result;
    cache->complete = true;

    if (result != 0) {
        return;
    }

    // Do hard links to let the layer exist in every downloader's directory.
    linked_list_for_each_safe(item, &cache->file_list, next) {
        file = (char *)item->elem;
        if (!strcmp(src_file, file)) {
            continue;
        }
        if (link(src_file, file) != 0) {
            ERROR("link %s to %s failed: %s", src_file, file, strerror(errno));
            cache->result = -1;
            return;
        }
    }

    return;
}

static void *fetch_layer_in_thread(void *arg)
{
    thread_fetch_info *info = (thread_fetch_info *)arg;
    int ret = 0;
    char *diffid = NULL;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        ERROR("Set thread detach fail");
        goto out;
    }

    prctl(PR_SET_NAME, "fetch_layer");

    if (fetch_layer(info->desc, info->index) != 0) {
        ERROR("fetch layer %d failed", info->index);
        ret = -1;
        goto out;
    }

    diffid = calc_diffid(info->file);
    if (diffid == NULL) {
        ERROR("calc diffid for layer %d failed", info->index);
        ret = -1;
        goto out;
    }

out:
    // notify to continue downloading
    mutex_lock(&g_shared->mutex);
    g_shared->count--;
    set_cached_layers_info(info->blob_digest, diffid, ret, info->file);
    if (pthread_cond_broadcast(&g_shared->cond)) {
        ERROR("Failed to broadcast");
    }
    mutex_unlock(&g_shared->mutex);

    free(diffid);
    diffid = NULL;

    return NULL;
}

static int add_fetch_task(thread_fetch_info *info)
{
    int ret = 0;
    int cond_ret = 0;
    pthread_t tid = 0;
    bool cached_layers_added = true;
    cached_layer *cache = NULL;

    mutex_lock(&g_shared->mutex);
    cache = get_cached_layer(info->blob_digest);
    if (cache == NULL) {
        // If there are too many download threads, wait until anyone completed.
        while (g_shared->count >= MAX_CONCURRENT_DOWNLOAD_NUM) {
            cond_ret = pthread_cond_wait(&g_shared->cond, &g_shared->mutex);
            if (cond_ret != 0) {
                ERROR("condition wait failed, ret %d", cond_ret);
                ret = -1;
                goto out;
            }
        }
    }

    ret = add_cached_layer(info->blob_digest, info->file);
    if (ret != 0) {
        ERROR("add fetch info failed, ret %d", cond_ret);
        ret = -1;
        goto out;
    }
    cached_layers_added = true;

    // First request to download this blob.
    if (cache == NULL) {
        ret = pthread_create(&tid, NULL, fetch_layer_in_thread, info);
        if (ret != 0) {
            ERROR("failed to start thread to fetch layer %d", (int)info->index);
            goto out;
        }
        g_shared->count++;
    }

out:
    if (ret != 0 && cached_layers_added) {
        del_cached_layer(info->blob_digest, info->file);
    }

    mutex_unlock(&g_shared->mutex);

    return ret;
}

static void free_thread_fetch_info(thread_fetch_info *info)
{
    if (info == NULL) {
        return;
    }
    free(info->blob_digest);
    info->blob_digest = NULL;
    free(info->file);
    info->file = NULL;
    return;
}

static bool all_fetch_complete(thread_fetch_info *infos, size_t infos_len, int *result)
{
    size_t i = 0;
    cached_layer *cache = NULL;

    *result = 0;
    for (i = 0; i < infos_len; i++) {
        if (!infos[i].use) {
            continue;
        }

        cache = (cached_layer *)map_search(g_shared->cached_layers, infos[i].blob_digest);
        if (cache == NULL) {
            ERROR("no cached layer found for %s error, this should never happen", infos[i].blob_digest);
            return true;
        }

        if (!cache->complete) {
            return false;
        }

        if (cache->result != 0) {
            *result = cache->result;
        }
    }

    return true;
}

static int fetch_layers(pull_descriptor *desc)
{
    size_t i = 0;
    int ret = 0;
    int sret = 0;
    struct layer *l = NULL;
    thread_fetch_info *infos = NULL;
    char file[PATH_MAX] = { 0 };
    int cond_ret = 0;
    int result = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    infos = util_common_calloc_s(sizeof(thread_fetch_info) * desc->layers_len);
    if (infos == NULL) {
        ERROR("out of memory");
        return -1;
    }

    for (i = 0; i < desc->layers_len; i++) {
        // Skip empty layer
        if (desc->layers[i].empty_layer) {
            continue;
        }

        // Skip layer that already exist in local store
        if (desc->layers[i].chain_id) {
            l = storage_layer_get(without_sha256_prefix(desc->layers[i].chain_id));
            if (l != NULL) {
                desc->layers[i].already_exist = true;
                free_layer(l);
                l = NULL;
                continue;
            }
        }

        sret = snprintf(file, sizeof(file), "%s/%d", desc->blobpath, (int)i);
        if (sret < 0 || (size_t)sret >= sizeof(file)) {
            ERROR("Failed to sprintf file for layer %d", (int)i);
            goto out;
        }

        infos[i].desc = desc;
        infos[i].index = i;
        infos[i].use = true;
        infos[i].file = util_strdup_s(file);
        infos[i].blob_digest = util_strdup_s(desc->layers[i].digest);

        ret = add_fetch_task(&infos[i]);
        if (ret != 0) {
            goto out;
        }
    }

    mutex_lock(&g_shared->mutex);
    while (!all_fetch_complete(infos, desc->layers_len, &result)) {
        cond_ret = pthread_cond_wait(&g_shared->cond, &g_shared->mutex);
        if (cond_ret != 0) {
            ERROR("condition wait for all layers to complete failed, ret %d", cond_ret);
            ret = -1;
            break;
        }
    }

    if (ret == 0) {
        ret = result;
    }

    ret = set_cached_info_to_desc(infos, desc->layers_len, desc);
    if (ret != 0) {
        ERROR("set cached infos to desc failed");
    }

    mutex_unlock(&g_shared->mutex);

out:
    for (i = 0; i < desc->layers_len; i++) {
        if (ret != 0 && infos[i].use) {
            mutex_lock(&g_shared->mutex);
            del_cached_layer(infos[i].blob_digest, infos[i].file);
            mutex_unlock(&g_shared->mutex);
        }
        free_thread_fetch_info(&infos[i]);
    }
    free(infos);
    infos = NULL;

    return ret;
}

static void free_items_not_inherit(docker_image_config_v2 *config)
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

    return;
}

static char *convert_created_by(docker_image_config_v2 *config)
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

static int add_rootfs_and_history(pull_descriptor *desc, docker_image_config_v2 *config,
                                  registry_manifest_schema1 *manifest)
{
    int i = 0;
    int ret = 0;
    size_t history_index = 0;
    parser_error err = NULL;
    docker_image_config_v2 *v1config = NULL;
    docker_image_history *history = NULL;

    if (desc == NULL || config == NULL || manifest == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    config->rootfs = util_common_calloc_s(sizeof(docker_image_rootfs));
    config->history = util_common_calloc_s(sizeof(docker_image_history*)*desc->layers_len);
    if (config->rootfs == NULL || config->history) {
        ERROR("out of memory");
        return -1;
    }
    config->rootfs->type = util_strdup_s(ROOTFS_TYPE);

    history_index = manifest->history_len - 1;
    for (i = 0; i < desc->layers_len; i++) {
        v1config = docker_image_config_v2_parse_data(manifest->history[history_index]->v1compatibility, NULL, &err);
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
        history->empty_layer = desc->layers[i].empty_layer;

        config->history[i] = history;
        config->history_len++;

        free_docker_image_config_v2(v1config);
        v1config = NULL;
        history_index--;
        if (desc->layers[i].empty_layer) {
            continue;
        }

        ret = util_array_append(&config->rootfs->diff_ids, desc->layers[i].diff_id);
        if (ret != 0) {
            ERROR("append diff id to rootfs failed");
            ret = -1;
            goto out;
        }
        config->rootfs->diff_ids_len++;
    }

out:
    free(err);
    err = NULL;
    free_docker_image_config_v2(v1config);
    v1config = NULL;

    return ret;
}

static int create_config_from_v1config(pull_descriptor *desc)
{
    int ret = 0;
    parser_error err = NULL;
    docker_image_config_v2 *config = NULL;
    registry_manifest_schema1 *manifest = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    manifest = registry_manifest_schema1_parse_file(desc->manifest.file, NULL, &err);
    if (manifest == NULL) {
        ERROR("parse manifest schema1 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    if (manifest->fs_layers_len != desc->layers_len || manifest->fs_layers_len != manifest->history_len ||
        manifest->history_len == 0) {
        ERROR("Invalid length manifest, fs layers length %d, histroy length %d, layers length %d",
              manifest->fs_layers_len, manifest->history_len, desc->layers_len);
        ret = -1;
        goto out;
    }

    // We need to convert v1 config to v2 config, so preserve v2 config's items only,
    // parse it as v2 config can do this directly.
    free(err);
    err = NULL;
    config = docker_image_config_v2_parse_data(manifest->history[0]->v1compatibility, NULL, &err);
    if (config == NULL) {
        ERROR("parse image config v2 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    // Delete items that do not want to inherit
    free_items_not_inherit(config);

    // Add rootfs and history
    ret = add_rootfs_and_history(desc, config, manifest);
    if (ret != 0) {
        ERROR("Add rootfs and history to config failed");
        goto out;
    }

    desc->config.create_time = created_to_timestamp(config->created);

out:
    free_registry_manifest_schema1(manifest);
    manifest = NULL;
    free_docker_image_config_v2(config);
    config = NULL;
    free(err);
    err = NULL;

    return ret;
}

static int registry_fetch(pull_descriptor *desc)
{
    int ret = 0;
    imagetool_image *image = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = fetch_and_parse_manifest(desc);
    if (ret != 0) {
        ERROR("fetch and parse manifest failed");
        goto out;
    }

    // If the image already exist, do not pull it again.
    image = storage_img_get(desc->dest_image_name);
    if (image != NULL && desc->config.digest != NULL && !strcmp(image->id, desc->config.digest)) {
        DEBUG("image %s with id %s already exist, ignore pulling", desc->dest_image_name, image->id);
        goto out;
    }

    // manifest schema1 cann't pull config, the config is composited by
    // the history[0].v1Compatibility in manifest and rootfs's diffID
    if (!is_manifest_schemav1(desc->manifest.media_type)) {
        ret = fetch_and_parse_config(desc);
        if (ret != 0) {
            ERROR("fetch and parse config failed");
            goto out;
        }
    }

    ret = fetch_layers(desc);
    if (ret != 0) {
        ERROR("fetch layers failed");
        goto out;
    }

    // If it's manifest schema1, create config. The config is composited by
    // the history[0].v1Compatibility in manifest and rootfs's diffID
    // note: manifest schema1 has been deprecated.
    if (is_manifest_schemav1(desc->manifest.media_type)) {
        ret = create_config_from_v1config(desc);
        if (ret != 0) {
            ERROR("create config from v1 config failed");
            goto out;
        }
    }

out:
    free_imagetool_image(image);
    image = NULL;

    return ret;
}

static int prepare_pull_desc(pull_descriptor *desc, registry_pull_options *options)
{
    int ret = 0;
    int sret = 0;
    char blobpath[32] = "/var/tmp/isulad-registry-XXXXXX";
    char scope[PATH_MAX] = {0};

    if (desc == NULL || options == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    if (!util_valid_image_name(options->dest_image_name)) {
        ERROR("Invalid dest image name %s", options->dest_image_name);
        return -1;
    }

    ret = oci_split_image_name(options->image_name, &desc->host,
                               &desc->name, &desc->tag);
    if (ret != 0) {
        ERROR("split image name %s failed", options->image_name);
        ret = -1;
        goto out;
    }

    if (desc->host == NULL || desc->name == NULL || desc->tag == NULL) {
        ERROR("Invalid image %s, host or name or tag not found", options->image_name);
        ret = -1;
        goto out;
    }

    // registry-1.docker.io is the real docker.io's registry. index.docker.io is V1 registry, we do not support
    // V1 registry, try use registry-1.docker.io.
    if (!strcmp(desc->host, DOCKER_HOSTNAME) || !strcmp(desc->host, DOCKER_V1HOSTNAME)) {
        free(desc->host);
        desc->host = util_strdup_s(DOCKER_REGISTRY);
    }

    if (mkdtemp(blobpath) == NULL) {
        ERROR("make temporary direcory failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    sret = snprintf(scope, sizeof(scope), "repository:%s:pull", desc->name);
    if (sret < 0 || (size_t)sret >= sizeof(scope)) {
        ERROR("Failed to sprintf scope");
        ret = -1;
        goto out;
    }

    desc->dest_image_name = util_strdup_s(options->dest_image_name);
    desc->scope = util_strdup_s(scope);
    desc->blobpath = util_strdup_s(blobpath);
    desc->use_decrypted_key = conf_get_use_decrypted_key_flag();
    desc->skip_tls_verify = options->skip_tls_verify;

    if (options->auth.username != NULL && options->auth.password != NULL) {
        desc->username = util_strdup_s(options->auth.username);
        desc->password = util_strdup_s(options->auth.password);
    } else {
        free(desc->username);
        desc->username = NULL;
        free(desc->password);
        desc->password = NULL;
        ret = auths_load(desc->host, &desc->username, &desc->password);
        if (ret != 0) {
            ERROR("Failed to load auths");
            goto out;
        }
    }

out:

    return ret;
}

int registry_pull(registry_pull_options *options)
{
    int ret = 0;
    pull_descriptor *desc = NULL;

    if (options == NULL || options->image_name == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    desc = util_common_calloc_s(sizeof(pull_descriptor));
    if (desc == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ret = prepare_pull_desc(desc, options);
    if (ret != 0) {
        ERROR("registry prepare failed");
        ret = -1;
        goto out;
    }

    ret = registry_fetch(desc);
    if (ret != 0) {
        ERROR("error fetching %s", options->image_name);
        ret = -1;
        goto out;
    }

    ret = register_image(desc);
    if (ret != 0) {
        ERROR("error register image %s to store", options->image_name);
        ret = -1;
        goto out;
    }

    INFO("Pull images %s success", options->image_name);

out:
    if (desc->blobpath != NULL) {
        if (util_recursive_rmdir(desc->blobpath, 0)) {
            WARN("failed to remove directory %s", desc->blobpath);
        }
    }
    free_pull_desc(desc);

    return ret;
}

static void cached_layers_kvfree(void *key, void *value)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    cached_layer *cache = (cached_layer *)value;
    if (cache != NULL) {
        linked_list_for_each_safe(item, &(cache->file_list), next) {
            linked_list_del(item);
            free((char *)item->elem);
            free(item);
            item = NULL;
        }
        cache->file_list_len = 0;

        free(cache->diffid);
        cache->diffid = NULL;
        free(cache);
        cache = NULL;
    }
    free(key);
    return;
}

int registry_init()
{
    int ret = 0;

    g_shared = util_common_calloc_s(sizeof(registry_global));
    if (g_shared == NULL) {
        ERROR("out of memory");
        return -1;
    }

    ret = pthread_mutex_init(&g_shared->mutex, NULL);
    if (ret != 0) {
        ERROR("Failed to init mutex for download info");
        goto out;
    }
    g_shared->mutex_inited = true;

    ret = pthread_cond_init(&g_shared->cond, NULL);
    if (ret != 0) {
        ERROR("Failed to init cond for download info");
        goto out;
    }
    g_shared->cond_inited = true;

    g_shared->cached_layers = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, cached_layers_kvfree);
    if (g_shared->cached_layers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

out:

    if (ret != 0) {
        if (g_shared->cond_inited) {
            pthread_cond_destroy(&g_shared->cond);
        }
        if (g_shared->mutex_inited) {
            pthread_mutex_destroy(&g_shared->mutex);
        }
        map_free(g_shared->cached_layers);
        g_shared->cached_layers = NULL;
        free(g_shared);
        g_shared = NULL;
    }

    return ret;
}

int registry_login(registry_login_options *options)
{
    int ret = 0;
    pull_descriptor *desc = NULL;

    if (options == NULL || options->host == NULL || options->auth.username == NULL ||
        options->auth.password == NULL || strlen(options->auth.username) == 0 ||
        strlen(options->auth.password) == 0) {
        ERROR("Invalid NULL param");
        return -1;
    }

    desc = util_common_calloc_s(sizeof(pull_descriptor));
    if (desc == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    desc->host = util_strdup_s(options->host);
    desc->use_decrypted_key = conf_get_use_decrypted_key_flag();
    desc->skip_tls_verify = options->skip_tls_verify;
    desc->username = util_strdup_s(options->auth.username);
    desc->password = util_strdup_s(options->auth.password);

    ret = login_to_registry(desc);
    if (ret != 0) {
        ERROR("login to registry failed");
        goto out;
    }

out:

    free_pull_desc(desc);
    desc = NULL;

    return ret;
}

int registry_logout(char *host)
{
    return auths_delete(host);
}

static void free_registry_auth(registry_auth *auth)
{
    if (auth == NULL) {
        return;
    }
    free_sensitive_string(auth->username);
    auth->username = NULL;
    free_sensitive_string(auth->password);
    auth->password = NULL;
    return;
}

void free_registry_pull_options(registry_pull_options *options)
{
    if (options == NULL) {
        return;
    }
    free_registry_auth(&options->auth);
    free(options->image_name);
    options->image_name = NULL;
    free(options);
    return;
}

void free_registry_login_options(registry_login_options *options)
{
    if (options == NULL) {
        return;
    }
    free_registry_auth(&options->auth);
    free(options->host);
    options->host = NULL;
    free(options);
    return;
}

void free_challenge(challenge *c)
{
    if (c == NULL) {
        return;
    }

    free(c->schema);
    c->schema = NULL;
    free(c->realm);
    c->realm = NULL;
    free(c->service);
    c->service = NULL;
    free(c->cached_token);
    c->cached_token = NULL;
    c->expires_time = 0;

    return;
}

void free_layer_blob(layer_blob *layer)
{
    if (layer == NULL) {
        return;
    }
    layer->empty_layer = false;
    free(layer->media_type);
    layer->media_type = NULL;
    layer->size = 0;
    free(layer->digest);
    layer->digest = NULL;
    free(layer->diff_id);
    layer->diff_id = NULL;
    free(layer->chain_id);
    layer->chain_id = NULL;
    free(layer->file);
    layer->file = NULL;
    layer->already_exist = false;
    return;
}

void free_pull_desc(pull_descriptor *desc)
{
    int i = 0;

    if (desc == NULL) {
        return;
    }

    free(desc->dest_image_name);
    desc->dest_image_name = NULL;
    free(desc->host);
    desc->host = NULL;
    free(desc->name);
    desc->name = NULL;
    free(desc->tag);
    desc->tag = NULL;

    free_sensitive_string(desc->username);
    desc->username = NULL;
    free_sensitive_string(desc->password);
    desc->password = NULL;

    desc->use_decrypted_key = false;
    desc->cert_loaded = false;
    free(desc->ca_file);
    desc->ca_file = NULL;
    free(desc->cert_file);
    desc->cert_file = NULL;
    free(desc->key_file);
    desc->key_file = NULL;

    free(desc->blobpath);
    desc->blobpath = NULL;
    free(desc->protocol);
    desc->protocol = NULL;
    desc->skip_tls_verify = false;
    desc->already_ping = false;
    free(desc->scope);
    desc->scope = NULL;

    for (i = 0; i < CHALLENGE_MAX; i++) {
        free_challenge(&desc->challenges[i]);
    }
    util_free_array(desc->headers);
    desc->headers = NULL;

    free(desc->manifest.media_type);
    desc->manifest.media_type = NULL;
    desc->manifest.size = 0;
    free(desc->manifest.digest);
    desc->manifest.digest = NULL;
    free(desc->manifest.file);
    desc->manifest.file = NULL;

    free(desc->config.media_type);
    desc->config.media_type = NULL;
    desc->config.size = 0;
    free(desc->config.digest);
    desc->config.digest = NULL;
    free(desc->config.file);
    desc->config.file = NULL;
    desc->config.create_time.has_seconds = 0;
    desc->config.create_time.seconds = 0;
    desc->config.create_time.has_nanos = 0;
    desc->config.create_time.nanos = 0;

    for (i = 0; i < desc->layers_len; i++) {
        free_layer_blob(&desc->layers[i]);
    }
    free(desc->layers);
    desc->layers = NULL;
    desc->layers_len = 0;
    return;
}
