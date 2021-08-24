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

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "registry.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <isula_libutils/docker_image_rootfs.h>
#include <isula_libutils/imagetool_image.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_image_content_descriptor.h>
#include <isula_libutils/oci_image_manifest.h>
#include <isula_libutils/oci_image_spec.h>
#include <pthread.h>
#include <stdlib.h>

#include "mediatype.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "registry_apiv2.h"
#include "certs.h"
#include "auths.h"
#include "isula_libutils/registry_manifest_schema2.h"
#include "isula_libutils/registry_manifest_schema1.h"
#include "isula_libutils/docker_image_config_v2.h"
#include "isula_libutils/image_manifest_v1_compatibility.h"
#include "sha256.h"
#include "map.h"
#include "linked_list.h"
#include "pthread.h"
#include "isulad_config.h"
#include "err_msg.h"
#include "storage.h"
#include "constants.h"
#include "utils_images.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_timestamp.h"
#include "utils_verify.h"
#include "oci_image.h"

#define MANIFEST_BIG_DATA_KEY "manifest"
#define MAX_CONCURRENT_DOWNLOAD_NUM 5
#define DEFAULT_WAIT_TIMEOUT 15

typedef struct {
    pull_descriptor *desc;
    size_t index;
    char *blob_digest;
    char *file;
    bool use;
    bool notified;
    char *diffid;
} thread_fetch_info;

typedef struct {
    char *file;
    thread_fetch_info *info; // file related fetch info
} file_elem;

typedef struct {
    pthread_mutex_t mutex;
    int result;
    bool complete;
    struct linked_list file_list;
    size_t file_list_len;
} cached_layer;

// Share information of downloading layers to avoid downloading the same layer.
typedef struct {
    pthread_mutex_t mutex;
    bool mutex_inited;
    pthread_cond_t cond;
    bool cond_inited;
    map_t *cached_layers;
    pthread_mutex_t image_mutex;
    bool image_mutex_inited;
} registry_global;

static registry_global *g_shared;

static void free_file_elem(file_elem *elem)
{
    if (elem != NULL) {
        free(elem->file);
        elem->file = NULL;
    }
    free(elem);
}

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
        ERROR("Invalid layer number %zu, maxium is %d and it can't be 0", manifest->fs_layers_len, MAX_LAYER_NUM);
        ret = -1;
        goto out;
    }

    if (manifest->fs_layers_len != manifest->history_len) {
        ERROR("Invalid layer number %zu do not match history number %zu", manifest->fs_layers_len,
              manifest->history_len);
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
        free_image_manifest_v1_compatibility(v1config);
        v1config = NULL;
        // Cann't download an empty layer, skip related information.
        if (desc->layers[index].empty_layer) {
            continue;
        }

        desc->layers[index].media_type = util_strdup_s(DOCKER_IMAGE_LAYER_TAR_GZIP);
        desc->layers[index].digest = util_strdup_s(manifest->fs_layers[i]->blob_sum);
    }
    desc->layers_len = manifest->fs_layers_len;

out:
    free_image_manifest_v1_compatibility(v1config);
    v1config = NULL;
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
        ERROR("Invalid layer number %zu, maxium is %d", manifest->layers_len, MAX_LAYER_NUM);
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
            ERROR("Unsupported layer's media type %s, layer index %zu", manifest->layers[i]->media_type, i);
            ret = -1;
            goto out;
        }
        desc->layers[i].media_type = util_strdup_s(manifest->layers[i]->media_type);
        desc->layers[i].size = manifest->layers[i]->size;
        desc->layers[i].digest = util_strdup_s(manifest->layers[i]->digest);
    }
    desc->layers_len = manifest->layers_len;

out:
    free_registry_manifest_schema2(manifest);
    manifest = NULL;
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
        ERROR("Invalid layer number %zu, maxium is %d", manifest->layers_len, MAX_LAYER_NUM);
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
        if (strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_TAR_GZIP) &&
            strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_TAR) &&
            strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_ND_TAR) &&
            strcmp(manifest->layers[i]->media_type, OCI_IMAGE_LAYER_ND_TAR_GZIP)) {
            ERROR("Unsupported layer's media type %s, layer index %zu", manifest->layers[i]->media_type, i);
            ret = -1;
            goto out;
        }
        desc->layers[i].media_type = util_strdup_s(manifest->layers[i]->media_type);
        desc->layers[i].size = manifest->layers[i]->size;
        desc->layers[i].digest = util_strdup_s(manifest->layers[i]->digest);
    }
    desc->layers_len = manifest->layers_len;

out:
    free_oci_image_manifest(manifest);
    manifest = NULL;
    free(err);
    err = NULL;

    return ret;
}

static bool is_manifest_schemav1(char *media_type)
{
    if (media_type == NULL) {
        return false;
    }

    if (!strcmp(media_type, DOCKER_MANIFEST_SCHEMA1_JSON) || !strcmp(media_type, DOCKER_MANIFEST_SCHEMA1_PRETTYJWS) ||
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

    if (file == NULL) {
        return;
    }

    cache = (cached_layer *)map_search(g_shared->cached_layers, blob_digest);
    if (cache == NULL) {
        return;
    }
    if (cache->file_list_len != 0) {
        linked_list_for_each_safe(item, &(cache->file_list), next) {
            if (!strcmp(((file_elem *)item->elem)->file, file)) {
                linked_list_del(item);
                free_file_elem(item->elem);
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

static int add_cached_layer(char *blob_digest, char *file, thread_fetch_info *info)
{
    int ret = 0;
    cached_layer *cache = NULL;
    struct linked_list *node = NULL;
    char *src_file = NULL;
    thread_fetch_info *src_info = NULL;
    file_elem *elem = {NULL};
    pull_descriptor *desc = info->desc;

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
    if (cache->complete) {
        if (cache->result == 0) {
            elem = linked_list_first_elem(&cache->file_list);
            if (elem == NULL) {
                ERROR("Failed to add cache, list's first element is NULL");
                ret = -1;
                goto out;
            }
            src_file = ((file_elem*)elem)->file;
            src_info = ((file_elem*)elem)->info;
            if (src_info == NULL) {
                ERROR("source info is NULL, this should never happen");
                ret = -1;
                goto out;
            }

            if (link(src_file, file) != 0) {
                ERROR("link %s to %s failed: %s", src_file, file, strerror(errno));
                ret = -1;
                goto out;
            }
            // As layer have already downloaded, set this flag to let register thread to do register
            info->notified = true;
            if (info->diffid == NULL) {
                info->diffid = util_strdup_s(src_info->diffid);
            }
        } else {
            ERROR("cached layer have result %d", cache->result);
            ret = -1;
            goto out;
        }
    }

    node = util_common_calloc_s(sizeof(struct linked_list));
    elem = util_common_calloc_s(sizeof(file_elem));
    if (node == NULL || elem == NULL) {
        ERROR("Failed to malloc for linked_list");
        ret = -1;
        goto out;
    }
    elem->file = util_strdup_s(file);
    elem->info = info;
    linked_list_init(node);
    linked_list_add_elem(node, elem);
    elem = NULL;
    linked_list_add_tail(&cache->file_list, node);
    node = NULL;
    cache->file_list_len++;

out:
    if (ret != 0) {
        desc->cancel = true;
        del_cached_layer(blob_digest, file);
        if (node != NULL) {
            free_file_elem(node->elem);
            node->elem = NULL;
        }
        free(node);
        node = NULL;
        free_file_elem(elem);
    }

    return ret;
}

static char *calc_chain_id(char *parent_chain_id, char *diff_id)
{
    int sret = 0;
    char tmp_buffer[MAX_ID_BUF_LEN] = { 0 };
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

static int set_cached_info_to_desc(thread_fetch_info *info)
{
    size_t i = info->index;
    pull_descriptor *desc = info->desc;

    if (info->use) {
        if (desc->layers[i].diff_id == NULL) {
            desc->layers[i].diff_id = util_strdup_s(info->diffid);
        }

        if (desc->layers[i].file == NULL) {
            desc->layers[i].file = util_strdup_s(info->file);
        }
    }

    if (desc->layers[i].empty_layer) {
        return 0;
    }

    if (desc->layers[i].already_exist) {
        desc->parent_chain_id = desc->layers[i].chain_id;
        return 0;
    }

    if (desc->layers[i].diff_id == NULL) {
        ERROR("layer %zu of image %s have invalid NULL diffid, info->use=%d, info->diffid=%s",
              i, desc->image_name, info->use, info->diffid);
        return -1;
    }

    if (desc->layers[i].chain_id == NULL) {
        desc->layers[i].chain_id = calc_chain_id(desc->parent_chain_id, desc->layers[i].diff_id);
        if (desc->layers[i].chain_id == NULL) {
            ERROR("calc chain id failed, diff id %s, parent chain id %s",
                  desc->layers[i].diff_id, desc->parent_chain_id);
            return -1;
        }
    }
    desc->parent_chain_id = desc->layers[i].chain_id;

    return 0;
}

static int register_layer(pull_descriptor *desc, size_t i)
{
    struct layer *l = NULL;
    char *id = NULL;
    cached_layer *cached = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    if (desc->layers[i].empty_layer) {
        return 0;
    }

    id = util_without_sha256_prefix(desc->layers[i].chain_id);
    if (id == NULL) {
        ERROR("layer %zu have NULL digest for image %s", i, desc->image_name);
        return -1;
    }

    if (desc->layers[i].already_exist) {
        l = storage_layer_get(id);
        if (l != NULL) {
            free_layer(l);
            l = NULL;
            if (storage_layer_try_repair_lowers(id, desc->parent_layer_id) != 0) {
                ERROR("try to repair lowers for layer %s failed", id);
            }
            desc->parent_layer_id = id;
            return 0;
        }
        ERROR("Pull image failed, maybe layer %zu %s has be deleted when pulling image", i, id);
        return -1;
    }

    mutex_lock(&g_shared->mutex);
    cached = get_cached_layer(desc->layers[i].digest);
    mutex_unlock(&g_shared->mutex);
    if (cached == NULL) {
        ERROR("get cached layer %s failed, this should never happen", desc->layers[i].digest);
        return -1;
    }

    storage_layer_create_opts_t copts = {
        .parent = desc->parent_layer_id,
        .uncompress_digest = desc->layers[i].diff_id,
        .compressed_digest = desc->layers[i].digest,
        .writable = false,
        .layer_data_path = desc->layers[i].file,
    };
    if (storage_layer_create(id, &copts) != 0) {
        ERROR("create layer %s failed, parent %s, file %s", id, desc->parent_layer_id, desc->layers[i].file);
        return -1;
    }
    desc->layers[i].registered = true;
    free(desc->layer_of_hold_refs);
    desc->layer_of_hold_refs = util_strdup_s(id);
    if (desc->parent_layer_id != NULL && storage_dec_hold_refs(desc->parent_layer_id) != 0) {
        ERROR("clear hold flag failed for layer %s", desc->parent_layer_id);
        return -1;
    }

    desc->parent_layer_id = id;

    return 0;
}

static int get_top_layer_index(pull_descriptor *desc, size_t *top_layer_index)
{
    int i = 0;

    if (desc == NULL || top_layer_index == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    for (i = desc->layers_len - 1; i >= 0; i--) {
        if (desc->layers[i].empty_layer) {
            continue;
        }
        *top_layer_index = i;
        return 0;
    }

    ERROR("No valid layer found for image %s", desc->image_name);
    return -1;
}

static int create_image(pull_descriptor *desc, char *image_id, bool *reuse)
{
    int ret = 0;
    size_t top_layer_index = 0;
    struct storage_img_create_options opts = { 0 };
    char *top_layer_id = NULL;
    char *pre_top_layer = NULL;

    if (desc == NULL || image_id == NULL || reuse == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    ret = get_top_layer_index(desc, &top_layer_index);
    if (ret != 0) {
        ERROR("get top layer index for image %s failed", desc->image_name);
        return -1;
    }

    opts.create_time = &desc->config.create_time;
    opts.digest = desc->manifest.digest;
    top_layer_id = util_without_sha256_prefix(desc->layers[top_layer_index].chain_id);
    if (top_layer_id == NULL) {
        ERROR("NULL top layer id found for image %s", desc->image_name);
        ret = -1;
        goto out;
    }

    ret = storage_img_create(image_id, top_layer_id, NULL, &opts);
    if (ret != 0) {
        pre_top_layer = storage_get_img_top_layer(image_id);
        if (pre_top_layer == NULL) {
            ERROR("create image %s for %s failed", image_id, desc->image_name);
            ret = -1;
            goto out;
        }

        if (strcmp(pre_top_layer, top_layer_id) != 0) {
            ERROR("error committing image, image id %s exist, but top layer doesn't match. local %s, download %s",
                  image_id, pre_top_layer, top_layer_id);
            ret = -1;
            goto out;
        }

        ret = 0;
        *reuse = true;
    } else {
        *reuse = false;
    }

    ret = storage_img_add_name(image_id, desc->dest_image_name);
    if (ret != 0) {
        ERROR("add image name failed");
        if (!(*reuse)) {
            if (storage_img_delete(image_id, true)) {
                ERROR("delete image %s failed", image_id);
            }
        }
        goto out;
    }

out:
    free(pre_top_layer);

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
    types_timestamp_t now = { 0 };

    if (!util_get_now_time_stamp(&now)) {
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

static int check_time_valid(pull_descriptor *desc)
{
    int ret = 0;
    parser_error err = NULL;
    size_t i = 0;
    docker_image_config_v2 *conf = NULL;

    // oci/docker's configs are compatable
    conf = docker_image_config_v2_parse_file(desc->config.file, NULL, &err);
    if (conf == NULL) {
        ERROR("parse config failed: %s", err);
        ret = -1;
        goto out;
    }

    if (!oci_valid_time(conf->created)) {
        ERROR("Invalid created time %s", conf->created);
        ret = -1;
        goto out;
    }

    for (i = 0; i < conf->history_len; i++) {
        if (!oci_valid_time(conf->history[i]->created)) {
            ERROR("Invalid history created time %s", conf->history[i]->created);
            ret = -1;
            goto out;
        }
    }

out:
    free_docker_image_config_v2(conf);
    conf = NULL;
    free(err);
    err = NULL;

    return ret;
}

static int register_image(pull_descriptor *desc)
{
    int ret = 0;
    char *image_id = NULL;
    bool image_created = false;
    bool reuse = false;

    if (desc == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    // lock when create image to make sure image content all exist
    mutex_lock(&g_shared->image_mutex);
    image_id = util_without_sha256_prefix(desc->config.digest);
    ret = create_image(desc, image_id, &reuse);
    if (ret != 0) {
        ERROR("create image %s failed", desc->image_name);
        isulad_try_set_error_message("create image failed");
        goto out;
    }

    // If image is reused, no need to set file and infos.
    if (reuse) {
        goto out;
    }

    // associated layers with image already if run to here, so no need to
    // rollback layers manually on failure, delete image will delete all layers.
    desc->rollback_layers_on_failure = false;
    image_created = true;

    ret = set_config(desc, image_id);
    if (ret != 0) {
        ERROR("set image config for image %s failed", desc->image_name);
        isulad_try_set_error_message("set image config failed");
        goto out;
    }

    ret = set_manifest(desc, image_id);
    if (ret != 0) {
        ERROR("set manifest for image %s failed", desc->image_name);
        isulad_try_set_error_message("set manifest failed");
        goto out;
    }

    ret = set_loaded_time(desc, image_id);
    if (ret != 0) {
        ERROR("set loaded time for image %s failed", desc->image_name);
        isulad_try_set_error_message("set loaded time failed");
        goto out;
    }

    ret = storage_img_set_image_size(image_id);
    if (ret != 0) {
        ERROR("set image size failed for %s failed", desc->image_name);
        isulad_try_set_error_message("set image size failed");
        goto out;
    }

out:
    mutex_unlock(&g_shared->image_mutex);

    if (ret != 0 && image_created) {
        if (storage_img_delete(image_id, true)) {
            ERROR("delete image %s failed", image_id);
        }
    }

    return ret;
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

    desc->config.create_time = util_to_timestamp_from_str(config->created);

out:

    free_docker_image_config_v2(config);
    config = NULL;
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

    desc->config.create_time = util_to_timestamp_from_str(config->created);

out:
    free_oci_image_spec(config);
    config = NULL;
    free(err);
    err = NULL;

    return ret;
}

static int parse_config(pull_descriptor *desc)
{
    int ret = 0;
    char *media_type = NULL;
    char *manifest_media_type = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    media_type = desc->config.media_type;
    manifest_media_type = desc->manifest.media_type;
    if (!strcmp(media_type, DOCKER_IMAGE_V1) || !strcmp(manifest_media_type, DOCKER_MANIFEST_SCHEMA2_JSON)) {
        ret = parse_docker_config(desc);
    } else if (!strcmp(media_type, OCI_IMAGE_V1) || !strcmp(manifest_media_type, OCI_MANIFEST_V1_JSON)) {
        ret = parse_oci_config(desc);
    } else {
        ERROR("Unsupported config media type %s %s", media_type, manifest_media_type);
        return -1;
    }
    if (ret != 0) {
        ERROR("parse config failed, media type %s %s", media_type, manifest_media_type);
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
    file_elem *elem = NULL;
    thread_fetch_info *info = NULL;

    cache = (cached_layer *)map_search(g_shared->cached_layers, blob_digest);
    if (cache == NULL) {
        ERROR("can't get cache for %s, this should never happen", blob_digest);
        return;
    }
    cache->result = result;
    cache->complete = true;

    if (result != 0) {
        return;
    }

    // Do hard links to let the layer exist in every downloader's directory, and
    // fill necessary item fields to do layer register.
    linked_list_for_each_safe(item, &cache->file_list, next) {
        elem = (file_elem *)item->elem;
        info = elem->info;
        if (info->diffid == NULL) {
            info->diffid = util_strdup_s(diffid);
        }
        if (!strcmp(src_file, elem->file)) {
            continue;
        }
        if (link(src_file, elem->file) != 0) {
            ERROR("link %s to %s failed: %s", src_file, elem->file, strerror(errno));
            info->desc->cancel = true;
            continue;
        }
    }

    return;
}

// broadcast to notify unpack thread to register completed layers
static void register_layer_notify(pull_descriptor *desc)
{
    mutex_lock(&desc->mutex);
    if (pthread_cond_broadcast(&desc->cond)) {
        ERROR("Failed to broadcast");
    }
    mutex_unlock(&desc->mutex);
}

static void notify_cached_descs(char *blob_digest)
{
    cached_layer *cache = NULL;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    thread_fetch_info *info = NULL;

    cache = (cached_layer *)map_search(g_shared->cached_layers, blob_digest);
    if (cache == NULL) {
        ERROR("can't get cache for %s, this should never happen", blob_digest);
        return;
    }

    // notify all related register threads to do register
    linked_list_for_each_safe(item, &cache->file_list, next) {
        info = ((file_elem*)item->elem)->info;
        info->notified = true;
        register_layer_notify(info->desc);
    }
}

static void *fetch_layer_in_thread(void *arg)
{
    thread_fetch_info *info = (thread_fetch_info *)arg;
    pull_descriptor *desc = info->desc;
    int ret = 0;
    char *diffid = NULL;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        ERROR("Set thread detach fail");
        goto out;
    }

    prctl(PR_SET_NAME, "fetch_layer");

    if (fetch_layer(desc, info->index) != 0) {
        ERROR("fetch layer %zu failed", info->index);
        ret = -1;
        goto out;
    }

    // calc diffid only if it's schema v1. schema v1 have
    // no diff id so we need to calc it. schema v2 have
    // diff id in config and we do not want to calc it again
    // as it cost too much time.
    if (is_manifest_schemav1(desc->manifest.media_type)) {
        diffid = oci_calc_diffid(info->file);
        if (diffid == NULL) {
            ERROR("calc diffid for layer %zu failed", info->index);
            ret = -1;
            goto out;
        }
    }

out:
    // notify to continue downloading
    mutex_lock(&g_shared->mutex);
    if (ret != 0) {
        desc->cancel = true;
        if (desc->errmsg == NULL && g_isulad_errmsg != NULL) {
            desc->errmsg = util_strdup_s(g_isulad_errmsg);
        }
    }
    DAEMON_CLEAR_ERRMSG();
    desc->pulling_number--;
    set_cached_layers_info(info->blob_digest, diffid, ret, info->file);
    notify_cached_descs(info->blob_digest);
    // notify to continue pull
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
    struct timespec ts = {0};

    mutex_lock(&g_shared->mutex);
    cache = get_cached_layer(info->blob_digest);
    if (cache == NULL) {
        // If there are too many download threads, wait until anyone completed.
        while (info->desc->pulling_number >= MAX_CONCURRENT_DOWNLOAD_NUM) {
            ts.tv_sec = time(NULL) + DEFAULT_WAIT_TIMEOUT; // avoid wait forever
            cond_ret = pthread_cond_timedwait(&g_shared->cond, &g_shared->mutex, &ts);
            if (cond_ret != 0 && cond_ret != ETIMEDOUT) {
                ERROR("condition wait failed, ret %d", cond_ret);
                ret = -1;
                goto out;
            }
        }
        // retry get cached layer after some time of unlock
        cache = get_cached_layer(info->blob_digest);
    }

    ret = add_cached_layer(info->blob_digest, info->file, info);
    if (ret != 0) {
        ERROR("add fetch info failed, ret %d", cond_ret);
        ret = -1;
        goto out;
    }
    cached_layers_added = true;

    if (cache == NULL) {
        ret = pthread_create(&tid, NULL, fetch_layer_in_thread, info);
        if (ret != 0) {
            ERROR("failed to start thread fetch layer %zu", info->index);
            goto out;
        }
        info->desc->pulling_number++;
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
    free(info->diffid);
    info->diffid = NULL;
    return;
}

static bool all_fetch_complete(pull_descriptor *desc, thread_fetch_info *infos, int *result)
{
    int i = 0;

    if (!desc->config.complete) {
        return false;
    }

    *result = 0;

    if (desc->config.result != 0) {
        *result = desc->config.result;
    }

    if (!desc->register_layers_complete) {
        return false;
    }

    // wait all fetch threads completed
    for (i = 0; i < desc->layers_len; i++) {
        if (infos[i].use && !infos[i].notified) {
            return false;
        }
    }

    if (desc->cancel) {
        *result = -1;
    }

    return true;
}

static void *fetch_config_in_thread(void *arg)
{
    pull_descriptor *desc = (pull_descriptor *)arg;
    int ret = 0;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        ERROR("Set thread detach fail");
        goto out;
    }

    prctl(PR_SET_NAME, "fetch_config");

    ret = fetch_and_parse_config(desc);
    if (ret != 0) {
        ERROR("fetch and parse config failed for image %s", desc->image_name);
        isulad_try_set_error_message("fetch and parse config failed");
        goto out;
    }

out:
    mutex_lock(&g_shared->mutex);
    if (ret != 0) {
        desc->cancel = true;
        if (desc->errmsg == NULL && g_isulad_errmsg != NULL) {
            desc->errmsg = util_strdup_s(g_isulad_errmsg);
        }
    }
    DAEMON_CLEAR_ERRMSG();
    desc->config.complete = true;
    desc->config.result = ret;
    register_layer_notify(desc);
    if (pthread_cond_broadcast(&g_shared->cond)) {
        ERROR("Failed to broadcast");
    }
    mutex_unlock(&g_shared->mutex);

    return NULL;
}

static bool wait_fetch_complete(thread_fetch_info *info)
{
    pull_descriptor *desc = info->desc;

    if (desc->cancel) {
        return false;
    }

    if (!desc->config.complete) {
        return true;
    }

    if (!info->use || info->notified) {
        return false;
    }

    return true;
}

static void *register_layers_in_thread(void *arg)
{
    thread_fetch_info *infos = (thread_fetch_info *)arg;
    pull_descriptor *desc = infos[0].desc;
    int ret = 0;
    int cond_ret = 0;
    size_t i = 0;
    struct timespec ts = {0};

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        ERROR("Set thread detach fail");
        goto out;
    }

    prctl(PR_SET_NAME, "register_layer");

    for (i = 0; i < desc->layers_len; i++) {
        mutex_lock(&desc->mutex);
        while (wait_fetch_complete(&infos[i])) {
            ts.tv_sec = time(NULL) + DEFAULT_WAIT_TIMEOUT; // avoid wait forever
            cond_ret = pthread_cond_timedwait(&desc->cond, &desc->mutex, &ts);
            if (cond_ret != 0 && cond_ret != ETIMEDOUT) {
                // here we can't just break and cleanup resources because threads are running.
                // desc is freed if we break and then isulad crash. sleep some time
                // instead to avoid cpu full running and then retry.
                ERROR("condition wait for layer %zu to complete failed, ret %d, error: %s",
                      i, cond_ret, strerror(errno));
                sleep(10);
                continue;
            }
        }
        mutex_unlock(&desc->mutex);

        if (desc->cancel) {
            ret = -1;
            goto out;
        }

        ret = set_cached_info_to_desc(&infos[i]);
        if (ret != 0) {
            ERROR("set cached infos to desc failed");
            goto out;
        }

        // register layer
        ret = register_layer(desc, i);
        if (ret != 0) {
            ERROR("register layers for image %s failed", desc->image_name);
            isulad_try_set_error_message("register layers failed");
            goto out;
        }
    }

out:
    mutex_lock(&g_shared->mutex);
    if (ret != 0) {
        desc->cancel = true;
        if (desc->errmsg == NULL && g_isulad_errmsg != NULL) {
            desc->errmsg = util_strdup_s(g_isulad_errmsg);
        }
    }
    DAEMON_CLEAR_ERRMSG();
    desc->register_layers_complete = true;
    if (pthread_cond_broadcast(&g_shared->cond)) {
        ERROR("Failed to broadcast");
    }
    mutex_unlock(&g_shared->mutex);

    return NULL;
}

static int add_fetch_config_task(pull_descriptor *desc)
{
    pthread_t tid = 0;

    // manifest schema1 cann't pull config, the config is composited by
    // the history[0].v1Compatibility in manifest and rootfs's diffID
    if (is_manifest_schemav1(desc->manifest.media_type)) {
        desc->config.complete = true;
        desc->config.result = 0;
        return 0;
    }

    if (pthread_create(&tid, NULL, fetch_config_in_thread, desc)) {
        ERROR("failed to start thread to fetch config");
        return -1;
    }

    return 0;
}

static int fetch_all(pull_descriptor *desc)
{
    size_t i = 0;
    size_t j = 0;
    int ret = 0;
    int sret = 0;
    thread_fetch_info *infos = NULL;
    char file[PATH_MAX] = { 0 };
    int cond_ret = 0;
    int result = 0;
    char *parent_chain_id = NULL;
    struct layer_list *list = NULL;
    pthread_t tid = 0;
    struct timespec ts = {0};

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    infos = util_common_calloc_s(sizeof(thread_fetch_info) * desc->layers_len);
    if (infos == NULL) {
        ERROR("out of memory");
        return -1;
    }

    // fetch config in thread
    ret = add_fetch_config_task(desc);
    if (ret != 0) {
        ERROR("add fetch config task failed");
        free(infos);
        return -1;
    }

    // fetch layers
    for (i = 0; i < desc->layers_len; i++) {
        infos[i].desc = desc;
        infos[i].index = i;
        // Skip empty layer
        if (desc->layers[i].empty_layer) {
            continue;
        }

        // Skip layer that already exist in local store
        list = storage_layers_get_by_compress_digest(desc->layers[i].digest);
        if (list != NULL) {
            for (j = 0; j < list->layers_len; j++) {
                if ((list->layers[j]->parent == NULL && i == 0) ||
                    (parent_chain_id != NULL && list->layers[j]->parent != NULL &&
                     !strcmp(list->layers[j]->parent, util_without_sha256_prefix(parent_chain_id)) &&
                     strcmp(list->layers[j]->uncompressed_digest, list->layers[j]->compressed_digest))) {
                    // If can't set hold refs, it means it not exist anymore.
                    if (storage_inc_hold_refs(list->layers[j]->id) != 0) {
                        continue;
                    }
                    free(desc->layer_of_hold_refs);
                    desc->layer_of_hold_refs = util_strdup_s(list->layers[j]->id);
                    if (parent_chain_id != NULL && storage_dec_hold_refs(parent_chain_id) != 0) {
                        continue;
                    }
                    desc->layers[i].already_exist = true;
                    // oci or schema2 get diff id and chain id when get config
                    if (is_manifest_schemav1(desc->manifest.media_type)) {
                        desc->layers[i].diff_id = util_strdup_s(list->layers[j]->uncompressed_digest);
                        desc->layers[i].chain_id = util_string_append(list->layers[j]->id, SHA256_PREFIX);
                    }
                    parent_chain_id = desc->layers[i].chain_id;
                    break;
                }
            }
            free_layer_list(list);
            list = NULL;
            if (desc->layers[i].already_exist) {
                continue;
            }
        }

        // parent_chain_id = NULL means no parent chain match from now on, so no longer need
        // to get layers by compressed digest to reuse layer.
        parent_chain_id = NULL;

        sret = snprintf(file, sizeof(file), "%s/%zu", desc->blobpath, i);
        if (sret < 0 || (size_t)sret >= sizeof(file)) {
            ERROR("Failed to sprintf file for layer %zu", i);
            ret = -1;
            break;
        }

        infos[i].use = true;
        infos[i].file = util_strdup_s(file);
        infos[i].blob_digest = util_strdup_s(desc->layers[i].digest);

        ret = add_fetch_task(&infos[i]);
        if (ret != 0) {
            infos[i].use = false;
            break;
        }
    }
    if (ret != 0) {
        desc->cancel = true;
        desc->register_layers_complete = true;
    } else {
        // create layers unpack thread
        if (pthread_create(&tid, NULL, register_layers_in_thread, infos)) {
            ERROR("failed to start thread to unpack layers");
            ret = -1;
            desc->register_layers_complete = true;
        }
    }

    // wait until all pulled or cancelled
    mutex_lock(&g_shared->mutex);
    while (!all_fetch_complete(desc, infos, &result)) {
        ts.tv_sec = time(NULL) + DEFAULT_WAIT_TIMEOUT; // avoid wait forever
        cond_ret = pthread_cond_timedwait(&g_shared->cond, &g_shared->mutex, &ts);
        if (cond_ret != 0 && cond_ret != ETIMEDOUT) {
            // here we can't just break and cleanup resources because threads are running.
            // desc is freed if we break and then isulad crash. sleep some time
            // instead to avoid cpu full running and then retry.
            ERROR("condition wait for all layers to complete failed, ret %d, error: %s",
                  cond_ret, strerror(errno));
            sleep(10);
            continue;
        }
    }

    if (ret == 0) {
        ret = result;
    }

    if (ret != 0 && desc->errmsg != NULL) {
        ERROR("pull image %s failed: %s", desc->image_name, desc->errmsg);
        isulad_try_set_error_message(desc->errmsg);
    }

    mutex_unlock(&g_shared->mutex);

    for (i = 0; i < desc->layers_len; i++) {
        if (infos[i].use) {
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

static int create_config_from_v1config(pull_descriptor *desc)
{
    int ret = 0;
    parser_error err = NULL;
    docker_image_config_v2 *config = NULL;
    registry_manifest_schema1 *manifest = NULL;
    char *json = NULL;
    int sret = 0;
    char file[PATH_MAX] = { 0 };

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
        ERROR("Invalid length manifest, fs layers length %zu, histroy length %zu, layers length %zu",
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
    ret = add_rootfs_and_history(desc->layers, desc->layers_len, manifest, config);
    if (ret != 0) {
        ERROR("Add rootfs and history to config failed");
        goto out;
    }

    desc->config.create_time = util_to_timestamp_from_str(config->created);

    free(err);
    err = NULL;
    json = docker_image_config_v2_generate_json(config, NULL, &err);
    if (json == NULL) {
        ret = -1;
        ERROR("generate json from config failed for image %s", desc->image_name);
        goto out;
    }

    sret = snprintf(file, sizeof(file), "%s/config", desc->blobpath);
    if (sret < 0 || (size_t)sret >= sizeof(file)) {
        ERROR("Failed to sprintf file for config");
        ret = -1;
        goto out;
    }

    desc->config.file = util_strdup_s(file);
    ret = util_write_file(desc->config.file, json, strlen(json), CONFIG_FILE_MODE);
    if (ret != 0) {
        ERROR("Write config file failed");
        goto out;
    }
    desc->config.digest = sha256_full_file_digest(desc->config.file);

out:
    free(json);
    json = NULL;
    free_registry_manifest_schema1(manifest);
    manifest = NULL;
    free_docker_image_config_v2(config);
    config = NULL;
    free(err);
    err = NULL;

    return ret;
}

static bool reuse_image(pull_descriptor *desc)
{
    imagetool_image_summary *image = NULL;
    bool reuse = false;
    char *id = NULL;

    // If the image already exist, do not pull it again.
    image = storage_img_get_summary(desc->dest_image_name);
    if (image == NULL || desc->config.digest == NULL || image->id == NULL) {
        goto out;
    }

    id = util_without_sha256_prefix(desc->config.digest);
    if (id == NULL) {
        goto out;
    }

    if (!strcmp(id, image->id)) {
        DEBUG("image %s with id %s already exist, ignore pulling", desc->image_name, image->id);
        reuse = true;
    }

out:
    free_imagetool_image_summary(image);
    image = NULL;

    return reuse;
}

static int registry_fetch(pull_descriptor *desc, bool *reuse)
{
    int ret = 0;

    if (desc == NULL || reuse == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = fetch_and_parse_manifest(desc);
    if (ret != 0) {
        ERROR("fetch and parse manifest failed for image %s", desc->image_name);
        isulad_try_set_error_message("fetch and parse manifest failed");
        goto out;
    }

    *reuse = reuse_image(desc);
    if (*reuse) {
        goto out;
    }

    ret = fetch_all(desc);
    if (ret != 0) {
        ERROR("fetch layers failed for image %s", desc->image_name);
        isulad_try_set_error_message("fetch layers failed");
        goto out;
    }

    // If it's manifest schema1, create config. The config is composited by
    // the history[0].v1Compatibility in manifest and rootfs's diffID
    // note: manifest schema1 has been deprecated.
    if (is_manifest_schemav1(desc->manifest.media_type)) {
        ret = create_config_from_v1config(desc);
        if (ret != 0) {
            ERROR("create config from v1 config failed for image %s", desc->image_name);
            isulad_try_set_error_message("create config from v1 config failed");
            goto out;
        }
    }

    if (check_time_valid(desc) != 0) {
        ret = -1;
        goto out;
    }

out:

    return ret;
}

static void update_host(pull_descriptor *desc, const json_map_string_string *registry_transformation)
{
    size_t i = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return;
    }

    if (registry_transformation == NULL) {
        return;
    }

    // replace specific registry to another due to compatability reason, for example:
    // registry-1.docker.io is the real docker.io's registry. index.docker.io is V1 registry, we do not support
    // V1 registry, try use registry-1.docker.io.
    for (i = 0; i < registry_transformation->len; i++) {
        if (registry_transformation->keys[i] == NULL || registry_transformation->values[i] == NULL) {
            continue;
        }
        if (strcmp(desc->host, registry_transformation->keys[i]) == 0) {
            free(desc->host);
            desc->host = util_strdup_s(registry_transformation->values[i]);
            break;
        }
    }

    return;
}

static int prepare_pull_desc(pull_descriptor *desc, const registry_pull_options *options)
{
    int ret = 0;
    int sret = 0;
    char blobpath[PATH_MAX] = { 0 };
    char scope[PATH_MAX] = { 0 };
    char *image_tmp_path = NULL;
    struct oci_image_module_data *oci_image_data = NULL;

    if (desc == NULL || options == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    if (!util_valid_image_name(options->dest_image_name)) {
        ERROR("Invalid dest image name %s", options->image_name);
        isulad_try_set_error_message("Invalid image name");
        return -1;
    }

    if (!util_valid_image_name(options->image_name)) {
        ERROR("Invalid image name %s", options->image_name);
        isulad_try_set_error_message("Invalid image name");
        return -1;
    }

    ret = oci_split_image_name(options->image_name, &desc->host, &desc->name, &desc->tag);
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

    update_host(desc, options->registry_transformation);

    oci_image_data = get_oci_image_data();
    ret = makesure_isulad_tmpdir_perm_right(oci_image_data->root_dir);
    if (ret != 0) {
        ERROR("failed to make sure permission of image tmp work dir");
        goto out;
    }

    image_tmp_path = oci_get_isulad_tmpdir(oci_image_data->root_dir);
    if (image_tmp_path == NULL) {
        ERROR("failed to get image tmp work dir");
        ret = -1;
        goto out;
    }

    sret = snprintf(blobpath, PATH_MAX, "%s/registry-XXXXXX", image_tmp_path);
    if (sret < 0 || (size_t)sret > PATH_MAX) {
        ERROR("image tmp work path too long");
        ret = -1;
        goto out;
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

    ret = pthread_mutex_init(&desc->mutex, NULL);
    if (ret != 0) {
        ERROR("Failed to init mutex for pull");
        goto out;
    }
    desc->mutex_inited = true;

    ret = pthread_mutex_init(&desc->challenges_mutex, NULL);
    if (ret != 0) {
        ERROR("Failed to init challenges mutex for pull");
        goto out;
    }
    desc->challenges_mutex_inited = true;

    ret = pthread_cond_init(&desc->cond, NULL);
    if (ret != 0) {
        ERROR("Failed to init cond for pull");
        goto out;
    }
    desc->cond_inited = true;

    desc->image_name = util_strdup_s(options->image_name);
    desc->dest_image_name = util_strdup_s(options->dest_image_name);
    desc->scope = util_strdup_s(scope);
    desc->blobpath = util_strdup_s(blobpath);
    desc->use_decrypted_key = oci_image_data->use_decrypted_key;
    desc->skip_tls_verify = options->skip_tls_verify;
    desc->insecure_registry = options->insecure_registry;
    desc->cancel = false;
    desc->parent_chain_id = "";
    desc->rollback_layers_on_failure = true;

    if (options->auth.username != NULL && options->auth.password != NULL) {
        desc->username = util_strdup_s(options->auth.username);
        desc->password = util_strdup_s(options->auth.password);
    } else {
        ret = auths_load(desc->host, &desc->username, &desc->password);
        if (ret != 0) {
            ERROR("Failed to load auths for host %s", desc->host);
            isulad_try_set_error_message("Failed to load auths for host %s", desc->host);
            goto out;
        }
    }

out:
    free(image_tmp_path);
    return ret;
}

static int find_rollback_layer_index(pull_descriptor *desc)
{
    int i = 0;

    if (!desc->rollback_layers_on_failure) {
        return -1;
    }

    if (desc->layers_len == 0) {
        return -1;
    }

    for (i = (int)desc->layers_len - 1; i >= 0; i--) {
        if (!desc->layers[i].registered) {
            continue;
        }
        break;
    }

    return i;
}

static void try_rollback_layers(pull_descriptor *desc)
{
    int i = 0;
    char *id = NULL;

    i = find_rollback_layer_index(desc);
    if (i < 0 || i >= desc->layers_len) {
        return;
    }

    id = util_without_sha256_prefix(desc->layers[i].chain_id);
    if (id == NULL) {
        ERROR("this should never happen, layer %d have NULL digest for image %s", i, desc->image_name);
        return;
    }

    if (storage_layer_chain_delete(id) != 0) {
        ERROR("rollback layer %d failed for image %s, layerid %s", i, desc->image_name, id);
    }
}

int registry_pull(const registry_pull_options *options)
{
    int ret = 0;
    pull_descriptor *desc = NULL;
    bool reuse = false;

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
        isulad_try_set_error_message("registry prepare failed");
        ret = -1;
        goto out;
    }

    ret = registry_fetch(desc, &reuse);
    if (ret != 0) {
        ERROR("error fetching %s", options->image_name);
        isulad_try_set_error_message("error fetching %s", options->image_name);
        ret = -1;
        goto out;
    }

    if (!reuse) {
        ret = register_image(desc);
        if (ret != 0) {
            ERROR("error register image %s to store", options->image_name);
            isulad_try_set_error_message("error register image %s to store", options->image_name);
            ret = -1;
            goto out;
        }
    }

    INFO("Pull images %s success", options->image_name);

out:
    if (desc->layer_of_hold_refs != NULL && storage_dec_hold_refs(desc->layer_of_hold_refs) != 0) {
        ERROR("decrease hold refs failed for layer %s", desc->layer_of_hold_refs);
    }

    if (ret != 0) {
        try_rollback_layers(desc);
    }

    if (desc->blobpath != NULL) {
        if (util_recursive_rmdir(desc->blobpath, 0)) {
            WARN("failed to remove directory %s", desc->blobpath);
        }
    }
    free_pull_desc(desc);
    desc = NULL;

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
            free_file_elem(item->elem);
            free(item);
            item = NULL;
        }
        cache->file_list_len = 0;

        free(cache);
        cache = NULL;
    }
    free(key);
    return;
}

int registry_init(char *auths_dir, char *certs_dir)
{
    int ret = 0;

    auths_set_dir(auths_dir);
    certs_set_dir(certs_dir);

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

    ret = pthread_mutex_init(&g_shared->image_mutex, NULL);
    if (ret != 0) {
        ERROR("Failed to init image mutex for create image");
        goto out;
    }
    g_shared->image_mutex_inited = true;

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
        if (g_shared->image_mutex_inited) {
            pthread_mutex_destroy(&g_shared->image_mutex);
        }
        map_free(g_shared->cached_layers);
        g_shared->cached_layers = NULL;
        free(g_shared);
        g_shared = NULL;
    }

    return ret;
}

int registry_login(const registry_login_options *options)
{
    int ret = 0;
    pull_descriptor *desc = NULL;
    struct oci_image_module_data *oci_image_data = NULL;

    if (options == NULL || options->host == NULL || options->auth.username == NULL || options->auth.password == NULL ||
        strlen(options->auth.username) == 0 || strlen(options->auth.password) == 0) {
        ERROR("Invalid NULL param");
        return -1;
    }

    desc = util_common_calloc_s(sizeof(pull_descriptor));
    if (desc == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    oci_image_data = get_oci_image_data();

    desc->host = util_strdup_s(options->host);
    update_host(desc, options->registry_transformation);
    desc->use_decrypted_key = oci_image_data->use_decrypted_key;
    desc->skip_tls_verify = options->skip_tls_verify;
    desc->insecure_registry = options->insecure_registry;
    desc->username = util_strdup_s(options->auth.username);
    desc->password = util_strdup_s(options->auth.password);

    ret = pthread_mutex_init(&desc->challenges_mutex, NULL);
    if (ret != 0) {
        ERROR("Failed to init challenges mutex for login");
        goto out;
    }
    desc->challenges_mutex_inited = true;

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
    util_free_sensitive_string(auth->username);
    auth->username = NULL;
    util_free_sensitive_string(auth->password);
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
    free(options->dest_image_name);
    options->dest_image_name = NULL;
    free(options);
    return;
}
