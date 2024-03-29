/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2023-03-03
 * Description: provide remote image store functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "remote_support.h"

#include <isula_libutils/log.h>
#include <stdio.h>

#include "ro_symlink_maintain.h"
#include "map.h"
#include "utils_file.h"
#include "utils.h"
#include "layer_store.h"
#include "image_store.h"
#include "utils_array.h"

static map_t *image_byid_old = NULL;
static map_t *image_byid_new = NULL;

struct remote_image_data *remote_image_create(const char *remote_home, const char *remote_ro)
{
    if (remote_home == NULL) {
        ERROR("Empty remote home");
        return NULL;
    }

    struct remote_image_data *data = util_common_calloc_s(sizeof(struct remote_image_data));
    if (data == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    data->image_home = remote_home;
    image_byid_old = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (image_byid_old == NULL) {
        ERROR("Failed to cerate image_byid_old");
        goto free_out;
    }

    image_byid_new = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (image_byid_new == NULL) {
        ERROR("Failed to cerate image_byid_new");
        goto free_out;
    }

    return data;

free_out:
    map_free(image_byid_old);
    map_free(image_byid_new);
    free(data);

    return NULL;
}

void remote_image_destroy(struct remote_image_data *data)
{
    if (data == NULL) {
        return;
    }

    map_free(image_byid_old);
    map_free(image_byid_new);

    free(data);
    return;
}

static int remote_dir_scan(void *data)
{
    int ret = 0;
    int nret;
    char **image_dirs = NULL;
    size_t image_dirs_num = 0;
    size_t i;
    char *id_patten = "^[a-f0-9]{64}$";
    char image_path[PATH_MAX] = { 0x00 };
    bool exist = true;
    struct remote_image_data *img_data = (struct remote_image_data *)data;

    ret = util_list_all_subdir(img_data->image_home, &image_dirs);
    if (ret != 0) {
        ERROR("Failed to get images directory");
        goto out;
    }
    image_dirs_num = util_array_len((const char **)image_dirs);

    for (i = 0; i < image_dirs_num; i++) {
        bool is_v1_image = false;

        if (util_reg_match(id_patten, image_dirs[i]) != 0) {
            DEBUG("Image's json is placed inside image's data directory, so skip any other file or directory: %s",
                  image_dirs[i]);
            continue;
        }

        nret = snprintf(image_path, sizeof(image_path), "%s/%s", img_data->image_home, image_dirs[i]);
        if (nret < 0 || (size_t)nret >= sizeof(image_path)) {
            ERROR("Failed to get image path");
            continue;
        }

        if (image_store_validate_manifest_schema_version_1(image_path, &is_v1_image) != 0) {
            ERROR("Failed to validate manifest schema version 1 format");
            continue;
        }

        // for refresh, we don't care v1 image, cause image should be handled by master isulad
        // when master isulad pull images
        if (!is_v1_image) {
            if (!map_insert(image_byid_new, image_dirs[i], (void *)&exist)) {
                WARN("Failed to insert image %s to map", image_dirs[i]);
            }
        }
    }

out:
    util_free_array(image_dirs);
    return ret;
}

static int check_top_layer_and_add_image(const char *id)
{
    char *top_layer = NULL;
    int ret = 0;

    top_layer = remote_image_get_top_layer_from_json(id);
    if (top_layer == NULL) {
        WARN("Can't get top layer id for image: %s, image not add", id);
        return 0;
    }

    if (!remote_layer_layer_valid(top_layer)) {
        WARN("Current not find valid under layer, remote image:%s not add", id);
        if (!map_remove(image_byid_new, (void *)id)) {
            WARN("image %s will not be loaded from remote.", id);
        }
        goto out;
    }

    if (remote_append_image_by_directory_with_lock(id) != 0) {
        ERROR("Failed to load image into memrory: %s", id);
        if (!map_remove(image_byid_new, (void *)id)) {
            WARN("image %s will not be loaded from remote", id);
        }
        ret = -1;
    }

out:
    free(top_layer);

    return ret;
}

static int remote_image_add(void *data)
{
    char **array_added = NULL;
    char **array_deleted = NULL;
    map_t *tmp_map = NULL;
    bool exist = true;
    size_t i = 0;
    int ret = 0;

    if (data == NULL) {
        return -1;
    }

    array_added = remote_added_layers(image_byid_old, image_byid_new);
    array_deleted = remote_deleted_layers(image_byid_old, image_byid_new);

    for (i = 0; i < util_array_len((const char **)array_added); i++) {
        if (check_top_layer_and_add_image(array_added[i]) != 0) {
            ret = -1;
        }
    }

    for (i = 0; i < util_array_len((const char **)array_deleted); i++) {
        if (remote_remove_image_from_memory_with_lock(array_deleted[i]) != 0) {
            ERROR("Failed to remove remote memory store");
            if (!map_insert(image_byid_new, array_deleted[i], (void *)&exist)) {
                WARN("image %s will not be removed from local", array_deleted[i]);
            }
            ret = -1;
        }
    }

    tmp_map = image_byid_old;
    image_byid_old = image_byid_new;
    image_byid_new = tmp_map;
    map_clear(image_byid_new);

    util_free_array(array_added);
    util_free_array(array_deleted);

    return ret;
}

void remote_image_refresh(struct remote_image_data *data)
{
    if (data == NULL) {
        ERROR("Skip refresh remote image for empty data");
        return;
    }

    if (remote_dir_scan(data) != 0) {
        ERROR("remote overlay failed to scan dir, skip refresh");
        return;
    }

    if (remote_image_add(data) != 0) {
        ERROR("refresh overlay failed");
    }
}
