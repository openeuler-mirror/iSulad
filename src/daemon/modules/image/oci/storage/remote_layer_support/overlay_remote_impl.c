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
 * Description: provide remote implementation for driver overlay
 ******************************************************************************/
#define _GNU_SOURCE
#include "remote_support.h"

#include <stdio.h>

#include "map.h"
#include "ro_symlink_maintain.h"
#include "driver_overlay2.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_file.h"
#include "path.h"

#define OVERLAY_LINK_DIR "l"
#define OVERLAY_LAYER_LINK "link"

// key: id, value: short id in 'l' dir
// store short id to delete symbol link in 'l' dir
static map_t *overlay_byid_old = NULL;
static map_t *overlay_byid_new = NULL;
static map_t *overlay_id_link = NULL;

struct remote_overlay_data *remote_overlay_create(const char *remote_home, const char *remote_ro)
{
    if (remote_home == NULL || remote_ro == NULL) {
        ERROR("Empty remote home or remote ro");
        return NULL;
    }

    struct remote_overlay_data *data = util_common_calloc_s(sizeof(struct remote_overlay_data));
    if (data == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    data->overlay_home = remote_home;
    data->overlay_ro = remote_ro;

    overlay_byid_old = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (overlay_byid_old == NULL) {
        ERROR("Failed to cerate overlay_byid_old");
        goto free_out;
    }

    overlay_byid_new = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (overlay_byid_new == NULL) {
        ERROR("Failed to cerate overlay_byid_new");
        goto free_out;
    }

    overlay_id_link = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (overlay_id_link == NULL) {
        ERROR("Failed to cerate overlay_id_link");
        goto free_out;
    }

    return data;

free_out:
    map_free(overlay_byid_old);
    map_free(overlay_byid_new);
    map_free(overlay_id_link);
    free(data);

    return NULL;
}

void remote_overlay_destroy(struct remote_overlay_data *data)
{
    if (data == NULL) {
        return;
    }

    map_free(overlay_byid_old);
    map_free(overlay_byid_new);
    map_free(overlay_id_link);
    free(data);
}

static bool overlay_walk_dir_cb(const char *path_name, const struct dirent *sub_dir, void *context)
{
    bool exist = true;
    if (!map_insert(overlay_byid_new, (void *)sub_dir->d_name, (void *)&exist)) {
        ERROR("can't insert remote layer into map");
        return false;
    }

    return true;
}

static int remote_dir_scan(struct remote_overlay_data *data)
{
    return util_scan_subdirs(data->overlay_ro, overlay_walk_dir_cb, data);
}

static int do_diff_symlink(const char *id, char *link_id, const char *driver_home)
{
    int ret = 0;
    int nret = 0;
    char target_path[PATH_MAX] = { 0 };
    char link_path[PATH_MAX] = { 0 };
    char clean_path[PATH_MAX] = { 0 };

    nret = snprintf(target_path, PATH_MAX, "../%s/diff", id);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to get target path %s", id);
        ret = -1;
        goto out;
    }

    nret = snprintf(link_path, PATH_MAX, "%s/%s/%s", driver_home, OVERLAY_LINK_DIR, link_id);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to get link path %s", link_id);
        ret = -1;
        goto out;
    }

    if (util_clean_path(link_path, clean_path, sizeof(clean_path)) == NULL) {
        ERROR("failed to get clean path %s", link_path);
        ret = -1;
        goto out;
    }

    if (util_fileself_exists(clean_path) && util_path_remove(clean_path) != 0) {
        ERROR("failed to remove old symbol link");
        ret = -1;
        goto out;
    }

    nret = symlink(target_path, clean_path);
    if (nret < 0) {
        SYSERROR("Failed to create symlink from \"%s\" to \"%s\"", clean_path, target_path);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int remove_one_remote_overlay_layer(struct remote_overlay_data *data, const char *overlay_id)
{
    char *ro_symlink = NULL;
    char *link_path = NULL;
    char *link_id = NULL;
    char clean_path[PATH_MAX] = { 0 };
    int nret = 0;
    int ret = 0;

    if (overlay_id == NULL) {
        ERROR("can't remove NULL remote layer");
        return -1;
    }

    nret = asprintf(&ro_symlink, "%s/%s", data->overlay_home, overlay_id);
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

    link_id = (char *)map_search(overlay_id_link, (void *)overlay_id);
    if (link_id == NULL) {
        ERROR("Failed to find link id for overlay layer: %s", overlay_id);
        ret = -1;
        goto out;
    }

    nret = asprintf(&link_path, "%s/%s/%s", data->overlay_home, OVERLAY_LINK_DIR, link_id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create link path failed");
        ret = -1;
        goto out;
    }

    if (util_clean_path(link_path, clean_path, sizeof(clean_path)) == NULL) {
        ERROR("Failed to clean path: %s", ro_symlink);
        ret = -1;
        goto out;
    }

    if (util_path_remove(clean_path) != 0) {
        SYSERROR("Failed to remove link path %s", clean_path);
    }

    if (!map_remove(overlay_id_link, (void *)overlay_id)) {
        ERROR("Failed to remove link id for overlay layers: %s", overlay_id);
        ret = -1;
        goto out;
    }

out:
    free(ro_symlink);
    free(link_path);
    return ret;
}

static int add_one_remote_overlay_layer(struct remote_overlay_data *data, const char *overlay_id)
{
    char *ro_symlink = NULL;
    char *layer_dir = NULL;
    char *link_file = NULL;
    char *diff_symlink = NULL;
    int ret = 0;

    if (overlay_id == NULL) {
        ERROR("can't add NULL remote layer");
        return -1;
    }

    ro_symlink = util_path_join(data->overlay_home, overlay_id);
    if (ro_symlink == NULL) {
        ERROR("Failed to join ro symlink path: %s", overlay_id);
        ret = -1;
        goto free_out;
    }

    layer_dir = util_path_join(data->overlay_ro, overlay_id);
    if (layer_dir == NULL) {
        ERROR("Failed to join ro layer dir: %s", overlay_id);
        ret = -1;
        goto free_out;
    }

    // add RO symbol link first
    if (!util_fileself_exists(ro_symlink) && symlink(layer_dir, ro_symlink) != 0) {
        SYSERROR("Unable to create symbol link to layer directory: %s", layer_dir);
        ret = -1;
        goto free_out;
    }

    // maintain link
    // try read link file in layer_dir
    // mk symlink between ro_symlink
    link_file = util_path_join(layer_dir, OVERLAY_LAYER_LINK);
    if (link_file == NULL) {
        ERROR("Failed to get layer link file %s", layer_dir);
        ret = -1;
        goto free_out;
    }

    if (!util_fileself_exists(link_file)) {
        ERROR("link file for layer %s not exist", layer_dir);
        ret = -1;
        goto free_out;
    }

    diff_symlink = util_read_content_from_file(link_file);
    if (link_file == NULL) {
        ERROR("Failed to read content from link file of layer %s", layer_dir);
        ret = -1;
        goto free_out;
    }

    if (do_diff_symlink(overlay_id, diff_symlink, data->overlay_home) != 0) {
        ERROR("Failed to add diff link for layer %s", overlay_id);
        ret = -1;
    }

    if (!map_insert(overlay_id_link, (void *)overlay_id, (void *)diff_symlink)) {
        ERROR("can't insert remote layer into map");
        ret = -1;
    }

free_out:
    free(ro_symlink);
    free(layer_dir);
    free(link_file);
    free(diff_symlink);

    return ret;
}

static int remote_overlay_add(struct remote_overlay_data *data)
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

    array_added = remote_added_layers(overlay_byid_old, overlay_byid_new);
    array_deleted = remote_deleted_layers(overlay_byid_old, overlay_byid_new);

    for (i = 0; i < util_array_len((const char **)array_added); i++) {
        if (add_one_remote_overlay_layer(data, array_added[i]) != 0) {
            ERROR("Failed to add remote overlay layer: %s", array_added[i]);
            if (!map_remove(overlay_byid_new, (void *)array_added[i])) {
                WARN("overlay layer %s will not be loaded from remote", array_added[i]);
            }
            ret = -1;
        }
    }

    for (i = 0; i < util_array_len((const char **)array_deleted); i++) {
        if (remove_one_remote_overlay_layer(data, array_deleted[i]) != 0) {
            ERROR("Failed to delete remote overlay layer: %s", array_deleted[i]);
            if (!map_insert(overlay_byid_new, array_deleted[i], (void *)&exist)) {
                WARN("overlay layer %s will be deleted from local", array_deleted[i]);
            }
            ret = -1;
        }
    }

    tmp_map = overlay_byid_old;
    overlay_byid_old = overlay_byid_new;
    overlay_byid_new = tmp_map;
    map_clear(overlay_byid_new);

    util_free_array(array_added);
    util_free_array(array_deleted);

    return ret;
}

void remote_overlay_refresh(struct remote_overlay_data *data)
{
    if (data == NULL) {
        ERROR("Skip refresh remote overlay for empty data");
        return;
    }

    if (remote_dir_scan(data) != 0) {
        ERROR("remote overlay failed to scan dir, skip refresh");
        return;
    }

    if (remote_overlay_add(data) != 0) {
        ERROR("refresh overlay failed");
    }
}

bool remote_overlay_layer_valid(const char *layer_id)
{
    return map_search(overlay_byid_old, (void *)layer_id) != NULL;
}
