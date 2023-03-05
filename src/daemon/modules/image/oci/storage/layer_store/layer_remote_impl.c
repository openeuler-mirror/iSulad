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
#include "layer_store.h"

#include <pthread.h>
#include <isula_libutils/log.h>
#include <stdio.h>

#include "map.h"
#include "utils.h"
#include "remote_support.h"
#include "ro_symlink_maintain.h"
#include "path.h"
#include "driver_overlay2.h"

struct remote_layer_data {
    const char *layer_home;
    const char *layer_ro;
};

static map_t *layer_byid_old = NULL;
static map_t *layer_byid_new = NULL;

static void *remote_support_create(const char *layer_home, const char *layer_ro)
{
    struct remote_layer_data *data = util_common_calloc_s(sizeof(struct remote_layer_data));
    if (data == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    data->layer_home = util_strdup_s(layer_home);
    data->layer_ro = util_strdup_s(layer_ro);
    layer_byid_old = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    layer_byid_new = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);

    return data;
};

static void remote_support_destroy(void *data)
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

    if (!map_insert(layer_byid_new, util_strdup_s(sub_dir->d_name), (void *)&exist)) {
        ERROR("can't insert remote layer into map");
        return false;
    }

    return true;
}

static int remote_support_scan(void *data)
{
    struct remote_layer_data *remote_data = data;
    return util_scan_subdirs(remote_data->layer_ro, layer_walk_dir_cb, data);
}

static int remove_one_remote_layer(struct remote_layer_data *data, char *layer_id)
{
    char *ro_symlink = NULL;
    char clean_path[PATH_MAX] = { 0 };
    int nret = 0;
    int ret = 0;

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

    if (util_path_remove(clean_path) != 0) {
        SYSERROR("Failed to remove link path %s", clean_path);
    }

    if (remove_memory_stores_with_lock(layer_id) != 0) {
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
    if (load_one_layer(layer_id) != 0) {
        ERROR("Failed to load new layer: %s into memory", layer_id);
        ret = -1;
    }

free_out:
    free(ro_symlink);
    free(layer_dir);

    return ret;
}

static int remote_support_add(void *data)
{
    int ret = 0;
    char **array_added = NULL;
    char **array_deleted = NULL;
    map_t *tmp_map = NULL;
    int i = 0;

    if (data == NULL) {
        return -1;
    }

    array_added = added_layers(layer_byid_old, layer_byid_new);
    array_deleted = deleted_layers(layer_byid_old, layer_byid_new);

    for (i = 0; i < util_array_len((const char **)array_added); i++) {
        if (!overlay_remote_layer_valid(array_added[i]) != 0) {
            map_remove(layer_byid_new, (void *)array_added[i]);
            ERROR("remote overlay layer current not valid: %s", array_added[i]);
            continue;
        }

        if (add_one_remote_layer(data, array_added[i]) != 0) {
            ERROR("Failed to add remote overlay layer: %s", array_added[i]);
            ret = -1;
        }
    }

    for (i = 0; i < util_array_len((const char **)array_deleted); i++) {
        if (remove_one_remote_layer(data, array_deleted[i]) != 0) {
            ERROR("Failed to delete remote overlay layer: %s", array_deleted[i]);
            ret = -1;
        }
    }

    tmp_map = layer_byid_old;
    layer_byid_old = layer_byid_new;
    layer_byid_new = tmp_map;
    empty_map(layer_byid_new);

    util_free_array(array_added);
    util_free_array(array_deleted);

    return ret;
}

remote_support *layer_store_impl_remote_support()
{
    remote_support *rs = util_common_calloc_s(sizeof(remote_support));
    if (rs == NULL) {
        return NULL;
    }

    rs->create = remote_support_create;
    rs->destroy = remote_support_destroy;
    rs->scan_remote_dir = remote_support_scan;
    rs->load_item = remote_support_add;

    return rs;
}

bool layer_remote_layer_valid(const char *layer_id)
{
    return map_search(layer_byid_old, (void *)layer_id) != NULL;
}
