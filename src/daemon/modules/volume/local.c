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
 * Create: 2020-09-07
 * Description: provide isula local volume functions
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>

#include "isula_libutils/log.h"
#include "isulad_config.h"
#include "volume_api.h"
#include "utils.h"
#include "map.h"
#include "path.h"
#include "err_msg.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"

#define LOCAL_VOLUME_DRIVER_NAME "local"
#define LOCAL_VOLUME_ROOT_DIR_NAME "volumes"
#define LOCAL_VOLUME_ROOT_DIR_MODE 0700
#define LOCAL_VOLUME_DATA_DIR_NAME "_data"
#define LOCAL_VOLUME_DIR_MODE 0755

struct volumes_info {
    char *root_dir;

    // map locker
    pthread_mutex_t mutex;
    bool mutex_inited;
    map_t *vols_by_name;
};

static struct volumes_info *g_volumes;

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

static void volume_kvfree(void *key, void *value)
{
    free(key);
    free_volume((struct volume *)value);
    return;
}

void free_volumes_info(struct volumes_info *vols)
{
    if (vols == NULL) {
        return;
    }
    if (vols->mutex_inited) {
        pthread_mutex_destroy(&vols->mutex);
    }
    free(vols->root_dir);
    map_free(vols->vols_by_name);
    free(vols);
    return;
}

static struct volume * dup_volume(char *name, char *path)
{
    struct volume *vol = NULL;

    vol = util_common_calloc_s(sizeof(struct volume));
    if (vol == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    vol->driver = util_strdup_s(LOCAL_VOLUME_DRIVER_NAME);
    vol->name = util_strdup_s(name);
    vol->path = util_strdup_s(path);
    vol->mount_point = util_strdup_s(path);

    return vol;
}

struct volume * local_volume_get(char *name)
{
    struct volume *v = NULL;

    if (!util_valid_volume_name(name)) {
        ERROR("failed to get volume, invalid volume name %s", name);
        isulad_try_set_error_message("failed to get volume, invalid volume name %s", name);
        return NULL;
    }

    mutex_lock(&g_volumes->mutex);
    v = map_search(g_volumes->vols_by_name, name);
    if (v == NULL) {
        goto out;
    }
    v = dup_volume(v->name, v->path);

out:
    mutex_unlock(&g_volumes->mutex);

    return v;
}

static struct volumes_info *new_empty_volumes_info()
{
    int ret = 0;
    struct volumes_info *vols_info = NULL;

    vols_info = util_common_calloc_s(sizeof(struct volumes_info));
    if (vols_info == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    vols_info->vols_by_name = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, volume_kvfree);
    if (vols_info->vols_by_name == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free_volumes_info(vols_info);
        vols_info = NULL;
    }

    return vols_info;
}

static int init_volume_root_dir(struct volumes_info *vols_info, char *root_dir)
{
    int ret = 0;
    char *userns_remap = conf_get_isulad_userns_remap();

    ret = util_mkdir_p(root_dir, LOCAL_VOLUME_ROOT_DIR_MODE);
    if (ret != 0) {
        ERROR("create volume directory %s failed: %s", root_dir, strerror(errno));
        goto out;
    }

    if (set_file_owner_for_userns_remap(root_dir, userns_remap) != 0) {
        ERROR("Unable to change directory %s owner for user remap.", root_dir);
        ret = -1;
        goto out;
    }

    vols_info->root_dir = util_strdup_s(root_dir);

out:
    free(userns_remap);
    return ret;
}

static char *build_and_valid_data_dir(const char *root_dir, const char *name)
{
    int ret = 0;
    char *data_dir = NULL;
    char *vol_dir = NULL;
    char *tmp_dir = NULL;
    struct stat st;

    if (!util_valid_volume_name(name)) {
        ERROR("Invalid volume dir %s, ignore", name);
        return NULL;
    }

    vol_dir = util_path_join(root_dir, name);
    if (vol_dir == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    tmp_dir = util_follow_symlink_in_scope(vol_dir, root_dir);
    if (tmp_dir == NULL) {
        ERROR("%s not inside %s", vol_dir, root_dir);
        ret = -1;
        goto out;
    }

    data_dir = util_path_join(vol_dir, LOCAL_VOLUME_DATA_DIR_NAME);
    if (data_dir == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    free(tmp_dir);
    tmp_dir = util_follow_symlink_in_scope(data_dir, vol_dir);
    if (tmp_dir == NULL) {
        ERROR("%s not inside %s", data_dir, root_dir);
        ret = -1;
        goto out;
    }

    if (lstat(tmp_dir, &st) != 0) {
        ERROR("lstat %s: %s", tmp_dir, strerror(errno));
        ret = -1;
        goto out;
    }

out:
    free(tmp_dir);
    free(vol_dir);
    if (ret != 0) {
        free(data_dir);
        data_dir = NULL;
    }

    return data_dir;
}

static bool load_volume(const char *root_dir, const struct dirent *dir, void *userdata)
{
    int ret = 0;
    char *data_dir = NULL;
    struct volumes_info *vols = (struct volumes_info *)userdata;
    struct volume *vol = NULL;

    data_dir = build_and_valid_data_dir(root_dir, dir->d_name);
    if (data_dir == NULL) {
        ERROR("failed to load volume %s", dir->d_name);
        // always return true so we can walk next subdir but not failed to start isulad
        return true;
    }

    mutex_lock(&g_volumes->mutex);
    vol = dup_volume((char *)dir->d_name, data_dir);
    if (vol == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    // No need to check conflict because the key is folder name in disk
    // and they are definitely unique.
    if (!map_insert(vols->vols_by_name, (char *)dir->d_name, vol)) {
        ERROR("failed to insert volume %s", dir->d_name);
        ret = -1;
        goto out;
    }

out:
    mutex_unlock(&g_volumes->mutex);

    free(data_dir);
    if (ret != 0) {
        free_volume(vol);
    }

    // always return true so we can walk next subdir but not failed to start isulad
    return true;
}

static int load_volumes(struct volumes_info *vols)
{
    return util_scan_subdirs((const char*)vols->root_dir, load_volume, vols);
}

static int local_volume_init(char *scope)
{
    int ret = 0;

    if (scope == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    g_volumes = new_empty_volumes_info();
    if (g_volumes == NULL) {
        ret = -1;
        goto out;
    }

    ret = pthread_mutex_init(&g_volumes->mutex, NULL);
    if (ret != 0) {
        ERROR("init mutex failed");
        ret = -1;
        goto out;
    }
    g_volumes->mutex_inited = true;

    ret = init_volume_root_dir(g_volumes, scope);
    if (ret != 0) {
        goto out;
    }

    ret = load_volumes(g_volumes);
    if (ret != 0) {
        goto out;
    }

out:
    if (ret != 0) {
        free_volumes_info(g_volumes);
        g_volumes = NULL;
    }

    return ret;
}

static int create_volume_meminfo(char *name, struct volume **vol)
{
    struct volume *v = NULL;
    int ret = 0;
    int sret = 0;
    char path[PATH_MAX] = {0};

    v = util_common_calloc_s(sizeof(struct volume));
    if (v == NULL) {
        ERROR("out of memory");
        return -1;
    }

    v->name = util_strdup_s(name);

    sret = snprintf(path, sizeof(path), "%s/%s/%s", g_volumes->root_dir, v->name, LOCAL_VOLUME_DATA_DIR_NAME);
    if (sret < 0 || (size_t)sret >= sizeof(path)) {
        ERROR("failed to sprintf to create volume");
        ret = -1;
        goto out;
    }

    v->path = util_strdup_s(path);

    *vol = v;
    v = NULL;

out:
    free_volume(v);

    return ret;
}

static struct volume * volume_create_nolock(char *name)
{
    struct volume *v = NULL;
    int ret = 0;

    v = map_search(g_volumes->vols_by_name, name);
    if (v != NULL) {
        // volume already exist, consider it as success
        return v;
    }

    ret = create_volume_meminfo(name, &v);
    if (ret != 0) {
        return NULL;
    }

    ret = util_mkdir_p(v->path, LOCAL_VOLUME_DIR_MODE);
    if (ret != 0) {
        ERROR("failed to create %s for volume %s: %s", v->path, v->name, strerror(errno));
        goto out;
    }

    if (!map_insert(g_volumes->vols_by_name, v->name, v)) {
        ERROR("failed to insert volume %s", v->name);
        goto out;
    }

out:
    if (ret != 0) {
        (void)util_recursive_rmdir(v->path, 0);
        free_volume(v);
        v = NULL;
    }

    return v;
}

struct volume * local_volume_create(char *name)
{
    struct volume *v_out = NULL;
    struct volume *v = NULL;

    if (name == NULL) {
        ERROR("invalid null volume name when create volume");
        return NULL;
    }

    if (!util_valid_volume_name(name)) {
        ERROR("failed to create volume, invalid volume name %s", name);
        isulad_try_set_error_message("failed to create volume, invalid volume name %s", name);
        return NULL;
    }

    mutex_lock(&g_volumes->mutex);
    v = volume_create_nolock(name);
    if (v == NULL) {
        goto out;
    }
    v_out = dup_volume(v->name, v->path);
out:
    mutex_unlock(&g_volumes->mutex);

    return v_out;
}

int local_volume_mount(char *name)
{
    // local volume do not need mount
    return 0;
}

int local_volume_umount(char *name)
{
    // local volume do not need umount
    return 0;
}

static struct volumes *new_empty_volumes(size_t size)
{
    struct volumes *vols = NULL;

    vols = util_common_calloc_s(sizeof(struct volumes));
    if (vols == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    if (size == 0) {
        return vols;
    }

    vols->vols = util_common_calloc_s(sizeof(struct volume*) * size);
    if (vols->vols == NULL) {
        ERROR("out of memory");
        free_volumes(vols);
        return NULL;
    }

    return vols;
}

struct volumes * local_volume_list(void)
{
    int ret = 0;
    map_itor *itor = NULL;
    struct volume *vol = NULL;
    struct volume *v = NULL;
    struct volumes *vols = NULL;
    size_t size = 0;

    mutex_lock(&g_volumes->mutex);

    size = map_size(g_volumes->vols_by_name);

    vols = new_empty_volumes(size);
    if (vols == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    itor = map_itor_new(g_volumes->vols_by_name);
    if (itor == NULL) {
        ERROR("failed to get volumes's iterator to get all volumes");
        ret = -1;
        goto out;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        v = map_itor_value(itor);
        vol = dup_volume(v->name, v->path);
        if (vol == NULL) {
            ERROR("out of memory");
            ret = -1;
            goto out;
        }
        vols->vols[vols->vols_len] = vol;
        vols->vols_len++;
    }

out:
    map_itor_free(itor);
    mutex_unlock(&g_volumes->mutex);

    if (ret != 0) {
        free_volumes(vols);
        vols = NULL;
    }

    return vols;
}

static int remove_volume_dir(char *path)
{
    int ret = 0;
    char *vol_dir = NULL;

    if (path == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    vol_dir = util_path_dir(path);
    if (!util_has_prefix(vol_dir, g_volumes->root_dir) ||
        strlen(vol_dir) <= (strlen(g_volumes->root_dir) + strlen("/"))) {
        ERROR("remove volume dir %s failed, path invalid. volume root is %s", vol_dir, g_volumes->root_dir);
        ret = -1;
        goto out;
    }

    // First we remove data directory of volume to keep structure of volume directory
    // remain untouched if we remove the data directory failed.
    ret = util_recursive_rmdir(path, 0);
    if (ret != 0) {
        ERROR("failed to remove volume data dir %s: %s", path, strerror(errno));
        isulad_try_set_error_message("failed to remove volume data dir %s: %s", path, strerror(errno));
        goto out;
    }

    ret = util_recursive_rmdir(vol_dir, 0);
    if (ret != 0) {
        ERROR("failed to remove volume dir %s: %s", vol_dir, strerror(errno));
        isulad_try_set_error_message("failed to remove volume dir %s: %s", vol_dir, strerror(errno));
        goto out;
    }

out:
    free(vol_dir);

    return ret;
}

static int volume_remove_nolock(char *name)
{
    struct volume *v = NULL;

    v = map_search(g_volumes->vols_by_name, name);
    if (v == NULL) {
        ERROR("No such volume: %s", name);
        isulad_try_set_error_message("No such volume: %s", name);
        return VOLUME_ERR_NOT_EXIST;
    }

    if (remove_volume_dir(v->path) != 0) {
        ERROR("failed to remove volume dir %s: %s", v->path, strerror(errno));
        return -1;
    }

    if (!map_remove(g_volumes->vols_by_name, name)) {
        ERROR("remove volume %s in memory failed", name);
        return -1;
    }

    return 0;
}

int local_volume_remove(char *name)
{
    int ret = 0;

    if (name == NULL) {
        ERROR("invalid param");
        return -1;
    }

    if (!util_valid_volume_name(name)) {
        ERROR("failed to remove volume, invalid volume name %s", name);
        isulad_try_set_error_message("failed to remove volume, invalid volume name %s", name);
        return -1;
    }

    mutex_lock(&g_volumes->mutex);
    ret = volume_remove_nolock(name);
    mutex_unlock(&g_volumes->mutex);

    return ret;
}

int register_local_volume(char *root_dir)
{
    int ret = 0;
    char *local_volume_root_dir = NULL;

    if (root_dir == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    local_volume_root_dir = util_path_join(root_dir, LOCAL_VOLUME_ROOT_DIR_NAME);
    if (root_dir == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    if (local_volume_init(local_volume_root_dir) != 0) {
        ret = -1;
        goto out;
    }

    // support local driver only right now
    volume_driver driver = {
        .create = local_volume_create,
        .get = local_volume_get,
        .mount = local_volume_mount,
        .umount = local_volume_umount,
        .list = local_volume_list,
        .remove = local_volume_remove,
    };

    ret = register_driver(LOCAL_VOLUME_DRIVER_NAME, &driver);
    if (ret != 0) {
        goto out;
    }

out:
    free(local_volume_root_dir);

    return ret;
}

