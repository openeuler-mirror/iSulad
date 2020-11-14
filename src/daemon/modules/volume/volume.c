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
#include <pthread.h>

#include "isula_libutils/log.h"
#include "volume_api.h"
#include "utils.h"
#include "map.h"
#include "local.h"
#include "err_msg.h"
#include "utils_file.h"

typedef struct {
    pthread_mutex_t mutex;
    map_t *drivers;
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

static int valid_driver(volume_driver *driver)
{
    if (driver->create == NULL || driver->get == NULL || driver->mount == NULL ||
        driver->umount == NULL || driver->list == NULL || driver->remove == NULL) {
        ERROR("Invalid volume driver, NULL function found");
        return -1;
    }
    return 0;
}

static volume_driver * lookup_driver(char *name)
{
    if (name == NULL) {
        ERROR("invalid NULL volume driver name");
        return NULL;
    }
    return map_search(g_vs.drivers, name);
}

static volume_driver * lookup_driver_by_volume_name(char *name)
{
    struct volume *vol = NULL;
    static volume_driver *driver = NULL;
    map_itor *itor = NULL;

    if (name == NULL) {
        ERROR("invalid NULL volume name");
        return NULL;
    }

    itor = map_itor_new(g_vs.drivers);
    if (itor == NULL) {
        ERROR("failed to get volumes's iterator to query volume driver by volume name");
        goto out;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        driver = map_itor_value(itor);
        vol = driver->get(name);
        if (vol != NULL) {
            free_volume(vol);
            break;
        }
    }

out:
    map_itor_free(itor);

    return driver;
}

static volume_driver * dup_driver(volume_driver *driver)
{
    volume_driver *d = NULL;

    d = util_common_calloc_s(sizeof(volume_driver));
    if (d == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    *d = *driver;

    return d;
}

static int insert_driver(char *name, volume_driver *driver)
{
    int ret = 0;
    volume_driver *d = NULL;

    if (valid_driver(driver) != 0) {
        return -1;
    }

    d = dup_driver(driver);
    if (d == NULL) {
        return -1;
    }

    if (!map_insert(g_vs.drivers, name, d)) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        free(d);
        d = NULL;
    }

    return ret;
}

int register_driver(char *name, volume_driver *driver)
{
    int ret = 0;

    if (name == NULL || driver == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    mutex_lock(&g_vs.mutex);

    if (lookup_driver(name) != NULL) {
        ERROR("driver %s already exist", name);
        ret = -1;
        goto out;
    }

    ret = insert_driver(name, driver);

out:
    mutex_unlock(&g_vs.mutex);

    return ret;
}

// key: name of volume
// value: ids map of contianer
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

static int register_drivers(char *root_dir)
{
    // support local volume driver only right now
    return register_local_volume(root_dir);
}

int volume_init(char *root_dir)
{
    int ret = 0;

    g_vs.drivers = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (g_vs.drivers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    g_vs.name_refs = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, refs_kvfree);
    if (g_vs.name_refs == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    ret = register_drivers(root_dir);

out:
    if (ret != 0) {
        map_free((map_t*)g_vs.drivers);
        g_vs.drivers = NULL;
        map_free((map_t*)g_vs.name_refs);
        g_vs.name_refs = NULL;
    }

    return ret;
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

    mutex_lock(&g_vs.mutex);
    driver = lookup_driver(driver_name);
    if (driver == NULL) {
        ret = -1;
        ERROR("volume driver %s not found", driver_name);
        goto out;
    }

    if (name == NULL) {
        if (util_generate_random_str(volume_name, VOLUME_DEFAULT_NAME_LEN) != 0) {
            ERROR("generate random string for volume name failed");
            ret = -1;
            goto out;
        }
        name = (char*)volume_name;
    }

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
    int ret = 0;
    volume_driver *driver = NULL;

    if (name == NULL) {
        ERROR("invalid null param for volume mount");
        return -1;
    }

    mutex_lock(&g_vs.mutex);
    driver = lookup_driver_by_volume_name(name);
    if (driver == NULL) {
        ret = -1;
        goto out;
    }
    ret = driver->mount(name);

out:
    mutex_unlock(&g_vs.mutex);

    return ret;
}

int volume_umount(char *name)
{
    int ret = 0;
    volume_driver *driver = NULL;

    if (name == NULL) {
        ERROR("invalid null param for volume umount");
        return -1;
    }

    mutex_lock(&g_vs.mutex);
    driver = lookup_driver_by_volume_name(name);
    if (driver == NULL) {
        ret = -1;
        goto out;
    }
    ret = driver->umount(name);

out:
    mutex_unlock(&g_vs.mutex);

    return ret;
}

static struct volumes * list_all_driver_volumes()
{
    int ret = 0;
    volume_driver *driver = NULL;
    map_itor *itor = NULL;
    struct volumes *vols = NULL;

    itor = map_itor_new(g_vs.drivers);
    if (itor == NULL) {
        ERROR("failed to get volumes's iterator to list all volumes");
        ret = -1;
        goto out;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        driver = map_itor_value(itor);
        vols = driver->list();
        // only one driver currently
        break;
    }

out:
    map_itor_free(itor);
    if (ret != 0) {
        free_volumes(vols);
        vols = NULL;
    }

    return vols;
}

struct volumes * volume_list(void)
{
    struct volumes *vols = NULL;

    mutex_lock(&g_vs.mutex);
    vols = list_all_driver_volumes();
    mutex_unlock(&g_vs.mutex);

    return vols;
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

    mutex_lock(&g_vs.mutex);
    driver = lookup_driver_by_volume_name(name);
    if (driver == NULL) {
        ret = -1;
        goto out;
    }

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
