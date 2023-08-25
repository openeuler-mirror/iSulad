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
 * Create: 2023-02-27
 * Description: remote layer store implementation
 ******************************************************************************/
#define _GNU_SOURCE
#include "remote_support.h"

#include <pthread.h>
#include <isula_libutils/log.h>
#include <stdio.h>

#include "map.h"
#include "utils.h"
#include "ro_symlink_maintain.h"
#include "layer_store.h"
#include "path.h"
#include "driver_overlay2.h"

static map_t *layer_byid_old = NULL;
static map_t *layer_byid_new = NULL;

struct remote_layer_data *remote_layer_create(const char *layer_home, const char *layer_ro)
{
    if (layer_home == NULL || layer_ro == NULL) {
        ERROR("Empty layer home or layer ro");
        return NULL;
    }

    struct remote_layer_data *data = util_common_calloc_s(sizeof(struct remote_layer_data));
    if (data == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    data->layer_home = layer_home;
    data->layer_ro = layer_ro;

    layer_byid_old = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (layer_byid_old == NULL) {
        ERROR("Failed to cerate layer_byid_old");
        goto free_out;
    }

    layer_byid_new = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (layer_byid_new == NULL) {
        ERROR("Failed to cerate layer_byid_new");
        goto free_out;
    }

    return data;

free_out:
    map_free(layer_byid_old);
    map_free(layer_byid_new);
    free(data);

    return NULL;
}

void remote_layer_destroy(struct remote_layer_data *data)
{
    if (data == NULL) {
        return;
    }

    map_free(layer_byid_old);
    map_free(layer_byid_new);
    free(data);
}

static bool layer_walk_dir_cb(const char *path_name, const struct dirent *sub_dir, void *context)
{
    bool exist = true;

    if (!map_insert(layer_byid_new, (void *)sub_dir->d_name, (void *)&exist)) {
        ERROR("can't insert remote layer into map");
        return false;
    }

    return true;
}

static int remote_dir_scan(struct remote_layer_data *data)
{
    return util_scan_subdirs(data->layer_ro, layer_walk_dir_cb, data);
}

static int remove_one_remote_layer(struct remote_layer_data *data, char *layer_id)
{
    char *ro_symlink = NULL;
    char clean_path[PATH_MAX] = { 0 };
    int nret = 0;
    int ret = 0;

    if (layer_id == NULL) {
        ERROR("can't delete NULL remote layer");
        return -1;
    }

    nret = asprintf(&ro_symlink, "%s/%s", data->layer_home, layer_id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create layer symbol link path failed");
        ret = -1;
        goto out;
    }

    if (util_clean_path(ro_symlink, clean_path, sizeof(clean_path)) == NULL) {
        ERROR("Failed to clean path: %s", ro_symlink);
        ret = -1;
        goto out;
    }

    // return 0 if path already removed
    if (util_path_remove(clean_path) != 0) {
        SYSERROR("Failed to remove link path %s", clean_path);
        ret = -1;
        goto out;
    }

    if (remote_layer_remove_memory_stores_with_lock(layer_id) != 0) {
        ERROR("Failed to remove remote layer store memory");
        ret = -1;
    }

out:
    free(ro_symlink);
    return ret;
}

static int add_one_remote_layer(struct remote_layer_data *data, char *layer_id)
{
    char *ro_symlink = NULL;
    char *layer_dir = NULL;
    int ret = 0;

    if (layer_id == NULL) {
        ERROR("can't add NULL remote layer");
        return -1;
    }

    ro_symlink = util_path_join(data->layer_home, layer_id);
    layer_dir = util_path_join(data->layer_ro, layer_id);

    if (ro_symlink == NULL) {
        ERROR("Failed to join ro symlink path: %s", layer_id);
        ret = -1;
        goto free_out;
    }

    if (layer_dir == NULL) {
        ERROR("Failed to join ro layer dir: %s", layer_id);
        ret = -1;
        goto free_out;
    }
    // add symbol link first
    if (!util_fileself_exists(ro_symlink) && symlink(layer_dir, ro_symlink) != 0) {
        SYSERROR("Unable to create symbol link to layer directory: %s", layer_dir);
        ret = -1;
        goto free_out;
    }
    // insert layer into memory
    if (remote_load_one_layer(layer_id) != 0) {
        ERROR("Failed to load new layer: %s into memory", layer_id);
        ret = -1;
    }

free_out:
    free(ro_symlink);
    free(layer_dir);

    return ret;
}

static int remote_layer_add(struct remote_layer_data *data)
{
    int ret = 0;
    char **array_added = NULL;
    char **array_deleted = NULL;
    map_t *tmp_map = NULL;
    bool exist = true;
    size_t i = 0;

    if (data == NULL) {
        return -1;
    }

    array_added = remote_added_layers(layer_byid_old, layer_byid_new);
    array_deleted = remote_deleted_layers(layer_byid_old, layer_byid_new);

    for (i = 0; i < util_array_len((const char **)array_added); i++) {
        if (!remote_overlay_layer_valid(array_added[i])) {
            WARN("remote overlay layer current not valid: %s", array_added[i]);
            if (!map_remove(layer_byid_new, (void *)array_added[i])) {
                WARN("layer %s will not be loaded from remote", array_added[i]);
            }
            continue;
        }

        if (add_one_remote_layer(data, array_added[i]) != 0) {
            ERROR("Failed to add remote layer: %s", array_added[i]);
            if (!map_remove(layer_byid_new, (void *)array_added[i])) {
                WARN("layer %s will not be loaded from remote", array_added[i]);
            }
            ret = -1;
        }
    }

    for (i = 0; i < util_array_len((const char **)array_deleted); i++) {
        if (remove_one_remote_layer(data, array_deleted[i]) != 0) {
            ERROR("Failed to delete remote overlay layer: %s", array_deleted[i]);
            if (!map_insert(layer_byid_new, array_deleted[i], (void *)&exist)) {
                WARN("layer %s will not be removed from local", array_deleted[i]);
            }
            ret = -1;
        }
    }

    tmp_map = layer_byid_old;
    layer_byid_old = layer_byid_new;
    layer_byid_new = tmp_map;
    map_clear(layer_byid_new);

    util_free_array(array_added);
    util_free_array(array_deleted);

    return ret;
}

void remote_layer_refresh(struct remote_layer_data *data)
{
    if (data == NULL) {
        ERROR("Skip refresh remote layer for empty data");
        return;
    }

    if (remote_dir_scan(data) != 0) {
        ERROR("remote layer failed to scan dir, skip refresh");
        return;
    }

    if (remote_layer_add(data) != 0) {
        ERROR("refresh overlay failed");
    }
}


bool remote_layer_layer_valid(const char *layer_id)
{
    return map_search(layer_byid_old, (void *)layer_id) != NULL;
}
