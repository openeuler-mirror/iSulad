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
 * Description: provide isula volume functions
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>

#include "isula_libutils/log.h"
#include "volume.h"
#include "utils.h"
#include "map.h"
#include "path.h"
#include "local.h"
#include "err_msg.h"

#define LOCAL_VOLUME_ROOT_DIR_NAME "volumes"

typedef struct {
    char * (*driver_name)(void);

    int (*init)(char *scope);

    struct volume * (*create)(char *name);

    int (*mount)(char *name);

    int (*umount)(char *name);

    struct volumes * (*list)(void);

    int (*remove)(char *name);
} volume_driver;

typedef struct {
    volume_driver driver_local;

    pthread_mutex_t mutex;
    map_t *name_refs;
} volume_store;

// volume store object
static volume_store g_vs;

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

// key: name of volume
// valume: ids map of contianer
static void refs_kvfree(void *key, void *value)
{
    free(key);
    map_free((map_t*)value);
    return;
}

static int add_name_ref(map_t *name_refs, char *name, char *ref)
{
    map_t *refs = NULL;

    refs = map_search(name_refs, name);
    if (refs == NULL) {
        refs = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
        if (refs == NULL) {
            ERROR("out of memory");
            return -1;
        }
        if (!map_insert(name_refs, name, refs)) {
            ERROR("insert refs to %s failed, ref is %s", name, ref);
            map_free(refs);
            return -1;
        }
    }

    if (map_search(refs, ref) == NULL) {
        bool b = true;
        if (!map_insert(refs, ref, &b)) {
            ERROR("insert name %s ref %s failed", name, ref);
            if (map_size(refs) == 0) {
                (void)map_remove(name_refs, refs);
            }
            return -1;
        }
    }

    return 0;
}

static struct volume_names * empty_volume_names(size_t size)
{
    int ret = 0;
    struct volume_names *vns = NULL;

    vns = util_common_calloc_s(sizeof(struct volume_names));
    if (vns == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    vns->names = util_common_calloc_s(sizeof(char *) * size);
    if (vns->names == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }
out:
    if (ret != 0) {
        free_volume_names(vns);
        vns = NULL;
    }

    return vns;
}

static struct volume_names * get_name_refs(map_t *name_refs, char *name)
{
    int ret = 0;
    map_itor *itor = NULL;
    struct volume_names *vns = NULL;
    map_t *refs = NULL;

    refs = map_search(name_refs, name);
    if (refs == NULL) {
        return NULL;
    }

    vns = empty_volume_names(map_size(refs));
    if (vns == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    itor = map_itor_new(refs);
    if (itor == NULL) {
        ERROR("failed to get volumes's iterator to get all volumes");
        ret = -1;
        goto out;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        vns->names[vns->names_len] = util_strdup_s(map_itor_key(itor));
        vns->names_len++;
    }

out:
    map_itor_free(itor);

    if (ret != 0) {
        free_volume_names(vns);
        vns = NULL;
    }

    return vns;
}

static int del_name_ref(map_t *name_refs, char *name, char *ref)
{
    map_t *refs = NULL;

    refs = map_search(name_refs, name);
    if (refs == NULL) {
        return 0;
    }

    if (map_size(refs) != 0) {
        if (!map_remove(refs, ref)) {
            ERROR("failed to delete ref %s for volume %s", ref, name);
            return -1;
        }
    }

    if (map_size(refs) == 0) {
        if (!map_remove(name_refs, name)) {
            ERROR("delete volume %s ref %s failed", name, ref);
            return -1;
        }
    }

    return 0;
}

int volume_init(char *root_dir)
{
    int ret = 0;
    char *local_volume_root_dir = NULL;

    g_vs.driver_local.init = local_volume_init;
    g_vs.driver_local.driver_name = local_volume_driver_name;
    g_vs.driver_local.create = local_volume_create;
    g_vs.driver_local.mount = local_volume_mount;
    g_vs.driver_local.umount = local_volume_umount;
    g_vs.driver_local.list = local_volume_list;
    g_vs.driver_local.remove = local_volume_remove;

    local_volume_root_dir = util_path_join(root_dir, LOCAL_VOLUME_ROOT_DIR_NAME);
    if (root_dir == NULL) {
        ERROR("out of memory");
        return -1;
    }

    if (local_volume_init(local_volume_root_dir) != 0) {
        ret = -1;
        goto out;
    }

    g_vs.name_refs = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, refs_kvfree);
    if (g_vs.name_refs == NULL) {
        ret = -1;
        goto out;
    }

out:
    free(local_volume_root_dir);

    return ret;
}

static volume_driver * lookup_driver(char *driver)
{
    if (driver == NULL || strcmp(driver, VOLUME_DEFAULT_DRIVER_NAME) != 0) {
        ERROR("invalid volume driver %s", driver);
        return NULL;
    }
    return &g_vs.driver_local;
}

struct volume * volume_create(char *driver_name, char *name, struct volume_options *opts)
{
    int ret = 0;
    struct volume * vol = NULL;
    volume_driver *driver = NULL;
    char volume_name[VOLUME_DEFAULT_NAME_LEN + 1] = {0};

    if (driver_name == NULL || opts == NULL || opts->ref == NULL) {
        ERROR("invalid null param for volume create");
        return NULL;
    }

    driver = lookup_driver(driver_name);
    if (driver == NULL) {
        return NULL;
    }

    if (name == NULL) {
        if (util_generate_random_str(volume_name, VOLUME_DEFAULT_NAME_LEN) != 0) {
            ERROR("generate random string for volume name failed");
            return NULL;
        }
        name = (char*)volume_name;
    }

    mutex_lock(&g_vs.mutex);
    vol = driver->create(name);
    if (vol == NULL) {
        ret = -1;
        goto out;
    }

    ret = add_name_ref(g_vs.name_refs, name, opts->ref);
    if (ret != 0) {
        goto out;
    }

out:
    mutex_unlock(&g_vs.mutex);

    if (ret != 0) {
        free_volume(vol);
        vol = NULL;
    }

    return vol;
}

int volume_mount(char *name)
{
    volume_driver *driver = NULL;

    if (name == NULL) {
        ERROR("invalid null param for volume mount");
        return -1;
    }

    driver = lookup_driver(VOLUME_DEFAULT_DRIVER_NAME);
    if (driver == NULL) {
        return -1;
    }

    return driver->mount(name);

}

int volume_umount(char *name)
{
    volume_driver *driver = NULL;

    if (name == NULL) {
        ERROR("invalid null param for volume umount");
        return -1;
    }

    driver = lookup_driver(VOLUME_DEFAULT_DRIVER_NAME);
    if (driver == NULL) {
        return -1;
    }

    return driver->umount(name);
}

struct volumes * volume_list(void)
{
    volume_driver *driver = NULL;

    driver = lookup_driver(VOLUME_DEFAULT_DRIVER_NAME);
    if (driver == NULL) {
        return NULL;
    }

    return driver->list();
}

int volume_add_ref(char *name, char *ref)
{
    int ret = 0;

    if (name == NULL || ref == NULL) {
        ERROR("invalid null param for volume release");
        return -1;
    }

    mutex_lock(&g_vs.mutex);
    ret = add_name_ref(g_vs.name_refs, name, ref);
    mutex_unlock(&g_vs.mutex);

    return ret;
}

int volume_del_ref(char *name, char *ref)
{
    int ret = 0;

    if (name == NULL || ref == NULL) {
        ERROR("invalid null param for volume release");
        return -1;
    }

    mutex_lock(&g_vs.mutex);
    ret = del_name_ref(g_vs.name_refs, name, ref);
    mutex_unlock(&g_vs.mutex);

    return ret;
}

int volume_remove(char *name)
{
    int ret = 0;
    volume_driver *driver = NULL;
    struct volume_names *vns = NULL;

    if (name == NULL) {
        ERROR("invalid null param for volume remove");
        return -1;
    }

    driver = lookup_driver(VOLUME_DEFAULT_DRIVER_NAME);
    if (driver == NULL) {
        return -1;
    }

    mutex_lock(&g_vs.mutex);

    vns = get_name_refs(g_vs.name_refs, name);
    if (vns != NULL && vns->names_len > 0) {
        ERROR("remove volume %s failed: volume is used by container %s", name, vns->names[0]);
        isulad_try_set_error_message("remove volume %s failed: volume is used by container %s", name, vns->names[0]);
        ret = -1;
        goto out;
    }

    ret = driver->remove(name);
    if (ret != 0) {
        goto out;
    }

out:
    mutex_unlock(&g_vs.mutex);
    free_volume_names(vns);

    return ret;
}

int volume_prune(struct volume_names **pruned)
{
    size_t i = 0;
    int ret = 0;
    struct volumes *list = NULL;

    if (pruned == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    *pruned = util_common_calloc_s(sizeof(struct volume_names));
    if (*pruned == NULL) {
        ERROR("out of memory");
        return -1;
    }

    list = volume_list();
    if (list == NULL) {
        ret = -1;
        goto out;
    }

    if (list->vols_len != 0) {
        (*pruned)->names = util_common_calloc_s(sizeof(char*) * list->vols_len);
        if ((*pruned)->names == NULL) {
            ret = -1;
            goto out;
        }

        for (i = 0; i < list->vols_len; i++) {
            if (volume_remove(list->vols[i]->name)) {
                continue;
            }
            (*pruned)->names[(*pruned)->names_len] = util_strdup_s(list->vols[i]->name);
            (*pruned)->names_len++;
        }
    }

out:
    if (ret != 0) {
        free_volume_names(*pruned);
        *pruned = NULL;
    }
    free_volumes(list);

    return ret;
}

void free_volume_names(struct volume_names *vns)
{
    size_t i = 0;

    if (vns == NULL) {
        return;
    }

    for (i = 0; i < vns->names_len; i++) {
        free(vns->names[i]);
        vns->names[i] = NULL;
    }
    vns->names_len = 0;
    free(vns->names);
    vns->names = NULL;
    free(vns);

    return;
}

void free_volume(struct volume *vol)
{
    if (vol == NULL) {
        return;
    }
    free(vol->driver);
    vol->driver = NULL;
    free(vol->name);
    vol->name = NULL;
    free(vol->path);
    vol->path = NULL;
    free(vol->mount_point);
    vol->mount_point = NULL;
    free(vol);
    return;
}

void free_volumes(struct volumes *vols)
{
    size_t i = 0;
    if (vols == NULL) {
        return;
    }
    for (i = 0; i < vols->vols_len; i++) {
        free_volume(vols->vols[i]);
        vols->vols[i] = NULL;
    }
    vols->vols_len = 0;
    free(vols->vols);
    vols->vols = NULL;
    free(vols);
    return;
}
