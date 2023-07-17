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
 * Author: zhongtao
 * Create: 2023-06-27
 * Description: provide id and name manage functions
 ******************************************************************************/

#include "id_name_manager.h"

#include <pthread.h>

#include <isula_libutils/log.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils.h"
#include "map.h"

typedef struct map_store_t {
    map_t *map; // map string bool
    pthread_mutex_t lock;
} map_store;

static map_store *g_id_store = NULL;
static map_store *g_name_store = NULL;

static void map_store_free(map_store *store)
{
    if (store == NULL) {
        return;
    }
    map_free(store->map);
    store->map = NULL;
    pthread_mutex_destroy(&(store->lock));
    free(store);
}

void id_store_free(void)
{
    map_store_free(g_id_store);
    g_id_store = NULL;
}

void name_store_free(void)
{
    map_store_free(g_name_store);
    g_name_store = NULL;
}

static map_store *map_store_new(void)
{
    int ret;
    map_store *store = NULL;

    store = util_common_calloc_s(sizeof(map_store));
    if (store == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret = pthread_mutex_init(&(store->lock), NULL);
    if (ret != 0) {
        ERROR("Failed to init memory store lock");
        free(store);
        return NULL;
    }
    store->map = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (store->map == NULL) {
        ERROR("Out of memory");
        map_store_free(store);
        return NULL;
    }
    return store;
}

static bool map_store_add(map_store *map_store, const char *item)
{
    bool val = true;
    bool existed = false;
    __isula_auto_pm_unlock pthread_mutex_t *local_mutex = NULL;

    if (map_store == NULL) {
        ERROR("Invalid map_store");
        return false;
    }

    if (!util_valid_container_id_or_name(item)) {
        ERROR("Invalid sandbox id or name: %s", item);
        return false;
    }

    if (pthread_mutex_lock(&map_store->lock)) {
        ERROR("Failed to lock map_store");
        return false;
    }

    local_mutex = &map_store->lock;

    existed = map_search(map_store->map, (void *)item);
    if (existed) {
        ERROR("%s already exists in map_store", item);
        return false;
    }

    if (!map_replace(map_store->map, (void *)item, (void *)&val)) {
        ERROR("Failed to add id: %s", item);
        return false;
    }

    return true;
}

static bool map_store_remove(map_store *map_store, const char *item)
{
    __isula_auto_pm_unlock pthread_mutex_t *local_mutex = NULL;

    if (map_store == NULL) {
        ERROR("Invalid map_store");
        return false;
    }

    if (!util_valid_container_id_or_name(item)) {
        ERROR("Invalid sandbox id or name: %s", item);
        return false;
    }

    if (pthread_mutex_lock(&map_store->lock)) {
        ERROR("Failed to lock map_store");
        return false;
    }

    local_mutex = &map_store->lock;

    if (!map_remove(map_store->map, (void *)item)) {
        ERROR("Failed to remove id: %s", item);
        return false;
    }
    return true;
}

int id_store_init(void)
{
    g_id_store = map_store_new();
    if (g_id_store == NULL) {
        return -1;
    }
    return 0;
}

int name_store_init(void)
{
    g_name_store = map_store_new();
    if (g_name_store == NULL) {
        return -1;
    }
    return 0;
}

char *get_new_id(void)
{
    int i = 0;
    const int max_time = 10;
    char *id = NULL;

    if (g_id_store == NULL) {
        ERROR("Invalid g_id_store");
        return NULL;
    }

    id = util_smart_calloc_s(sizeof(char), (CONTAINER_ID_MAX_LEN + 1));
    if (id == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (i = 0; i < max_time; i++) {
        if (util_generate_random_str(id, (size_t)CONTAINER_ID_MAX_LEN)) {
            break;
        }

        if (try_add_id(id)) {
            return id;
        }
    }
    ERROR("Failed to generate random str or failed to get new id after %d times retries", max_time);
    free(id);
    return NULL;
}

bool try_add_id(const char *id)
{
    if (map_store_add(g_id_store, id)) {
        return true;
    }
    ERROR("Failed to add %s to g_id_store", id);
    return false;
}

bool try_remove_id(const char *id)
{
    if (map_store_remove(g_id_store, id)) {
        return true;
    }
    ERROR("Failed to remove %s from g_id_store", id);
    return false;
}

bool try_add_name(const char *name)
{
    if (map_store_add(g_name_store, name)) {
        return true;
    }
    ERROR("Failed to add %s to g_name_store", name);
    return false;
}

bool try_remove_name(const char *name)
{
    if (map_store_remove(g_name_store, name)) {
        return true;
    }
    ERROR("Failed to remove %s from g_name_store", name);
    return false;
}