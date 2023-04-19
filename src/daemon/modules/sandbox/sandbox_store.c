/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-01-30
 * Description: provide sandbox store functions
 ******************************************************************************/

#include <pthread.h>

#include "sandbox_api.h"
#include "container_api.h"
#include "isula_libutils/log.h"
#include "map.h"

typedef struct sandbox_store_t {
    map_t *map; // map string sandbox_t
    pthread_rwlock_t rwlock;
} sandbox_store;

typedef struct name_index_t {
    map_t *map;
    pthread_rwlock_t rwlock;
} sandbox_name_index;

static sandbox_store *g_sandboxes_store = NULL;

static sandbox_name_index *g_sandbox_indexs = NULL;

static void sandbox_store_map_kvfree(void *key, void *value)
{
    free(key);

    sandbox_unref((sandbox_t *)value);
}

static void sandbox_store_free(sandbox_store *store)
{
    if (store == NULL) {
        return;
    }
    map_free(store->map);
    store->map = NULL;
    pthread_rwlock_destroy(&(store->rwlock));
    free(store);
}

/* Sandbox store */
int sandboxes_store_init(void)
{
    int ret;
    sandbox_store *store = NULL;

    store = util_common_calloc_s(sizeof(sandbox_store));
    if (store == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ret = pthread_rwlock_init(&(store->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init sandbox store rwlock");
        free(store);
        return -1;
    }

    store->map = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, sandbox_store_map_kvfree);
    if (store->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    g_sandboxes_store = store;
    return 0;

error_out:
    sandbox_store_free(store);
    return -1;
}

bool sandboxes_store_add(const char *id, sandbox_t *sandbox)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_sandboxes_store->rwlock)) {
        ERROR("lock sandbox store failed");
        return false;
    }
    ret = map_replace(g_sandboxes_store->map, (void *)id, (void *)sandbox);
    if (pthread_rwlock_unlock(&g_sandboxes_store->rwlock)) {
        ERROR("unlock store store failed");
        return false;
    }
    return ret;
}

sandbox_t *sandboxes_store_get_by_id(const char *id)
{
    sandbox_t *sandbox = NULL;

    if (id == NULL) {
        return NULL;
    }
    if (pthread_rwlock_rdlock(&g_sandboxes_store->rwlock) != 0) {
        ERROR("lock sandbox store failed");
        return sandbox;
    }
    sandbox = map_search(g_sandboxes_store->map, (void *)id);
    sandbox_refinc(sandbox);
    if (pthread_rwlock_unlock(&g_sandboxes_store->rwlock) != 0) {
        ERROR("unlock sandbox store failed");
        return sandbox;
    }
    return sandbox;
}

sandbox_t *sandboxes_store_get_by_name(const char *name)
{
    char *id = NULL;
    sandbox_t *sandbox = NULL;

    if (name == NULL) {
        ERROR("No sandbox name supplied");
        return NULL;
    }

    id = sandbox_name_index_get(name);
    if (id == NULL) {
        WARN("Could not find entity for %s", name);
        return NULL;
    }

    sandbox = sandboxes_store_get_by_id(id);

    free(id);
    return sandbox;
}

sandbox_t *sandboxes_store_get_by_prefix(const char *prefix)
{
    bool ret = false;
    char *sandbox_id = NULL;
    sandbox_t *sandbox = NULL;
    map_itor *itor = NULL;

    if (prefix == NULL) {
        return NULL;
    }
    if (pthread_rwlock_rdlock(&g_sandboxes_store->rwlock) != 0) {
        ERROR("lock sandbox store failed");
        return NULL;
    }

    itor = map_itor_new(g_sandboxes_store->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        ret = false;
        goto unlock;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        sandbox_id = map_itor_key(itor);
        if (sandbox_id == NULL) {
            ERROR("Out of memory");
            ret = false;
            goto unlock;
        }
        if (strncmp(sandbox_id, prefix, strlen(prefix)) == 0) {
            if (sandbox != NULL) {
                ERROR("Multiple IDs found with provided prefix: %s", prefix);
                ret = false;
                goto unlock;
            } else {
                sandbox = map_itor_value(itor);
            }
        }
    }

    ret = true;
    sandbox_refinc(sandbox);

unlock:
    if (pthread_rwlock_unlock(&g_sandboxes_store->rwlock) != 0) {
        ERROR("unlock sandbox store failed");
    }
    map_itor_free(itor);
    if (!ret) {
        sandbox = NULL;
    }
    return sandbox;
}

sandbox_t *sandboxes_store_get(const char *id_or_name)
{
    sandbox_t *sandbox = NULL;

    if (id_or_name == NULL) {
        ERROR("No sandbox name or ID supplied");
        return NULL;
    }

    // A full sandbox ID, which will exact match a sandbox in daemon's list
    sandbox = sandboxes_store_get_by_id(id_or_name);
    if (sandbox != NULL) {
        return sandbox;
    }

    // A sandbox name, which will only exact match via the sandboxes_store_get_by_name() function
    sandbox = sandboxes_store_get_by_name(id_or_name);
    if (sandbox != NULL) {
        return sandbox;
    }

    // A partial sandbox ID prefix
    sandbox = sandboxes_store_get_by_prefix(id_or_name);
    if (sandbox != NULL) {
        return sandbox;
    }

    return NULL;
}

bool sandboxes_store_remove(const char *id)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_sandboxes_store->rwlock) != 0) {
        ERROR("lock sandbox store failed");
        return false;
    }
    ret = map_remove(g_sandboxes_store->map, (void *)id);
    if (pthread_rwlock_unlock(&g_sandboxes_store->rwlock) != 0) {
        ERROR("unlock sandbox store failed");
        return false;
    }
    return ret;
}

/* name index */
static void sandbox_name_index_free(sandbox_name_index *indexs)
{
    if (indexs == NULL) {
        return;
    }
    map_free(indexs->map);
    indexs->map = NULL;
    pthread_rwlock_destroy(&(indexs->rwlock));
    free(indexs);
}

int sandbox_name_index_init(void)
{
    int ret;
    sandbox_name_index *indexs = NULL;

    indexs = util_common_calloc_s(sizeof(sandbox_name_index));
    if (indexs == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    ret = pthread_rwlock_init(&(indexs->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init sandbox name-index rwlock");
        free(indexs);
        return -1;
    }
    indexs->map = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (indexs->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }
    g_sandbox_indexs = indexs;
    return 0;
error_out:
    sandbox_name_index_free(indexs);
    return -1;
}

bool sandbox_name_index_remove(const char *name)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_sandbox_indexs->rwlock) != 0) {
        ERROR("lock sandbox name index failed");
        return false;
    }
    ret = map_remove(g_sandbox_indexs->map, (void *)name);
    if (pthread_rwlock_unlock(&g_sandbox_indexs->rwlock) != 0) {
        ERROR("unlock sandbox name index failed");
        return false;
    }
    return ret;
}

char *sandbox_name_index_get(const char *name)
{
    char *id = NULL;
    char *result = NULL;

    if (name == NULL) {
        return id;
    }
    if (pthread_rwlock_rdlock(&g_sandbox_indexs->rwlock) != 0) {
        ERROR("lock sandbox name index failed");
        return id;
    }

    id = map_search(g_sandbox_indexs->map, (void *)name);
    result = util_strdup_s(id);

    if (pthread_rwlock_unlock(&g_sandbox_indexs->rwlock) != 0) {
        ERROR("unlock sandbox name index failed");
    }
    return result;
}

bool sandbox_name_index_add(const char *name, const char *id)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_sandbox_indexs->rwlock) != 0) {
        ERROR("lock sandbox name index failed");
        return false;
    }
    ret = map_insert(g_sandbox_indexs->map, (void *)name, (void *)id);
    if (pthread_rwlock_unlock(&g_sandbox_indexs->rwlock) != 0) {
        ERROR("unlock sandbox name index failed");
        return false;
    }
    return ret;
}

map_t *sandbox_name_index_get_all(void)
{
    bool ret = false;
    map_t *map_id_name = NULL;
    map_itor *itor = NULL;

    map_id_name = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (map_id_name == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (pthread_rwlock_rdlock(&g_sandbox_indexs->rwlock) != 0) {
        ERROR("lock memory store failed");
        goto out;
    }

    if (map_size(g_sandbox_indexs->map) == 0) {
        ret = true;
        goto unlock;
    }

    itor = map_itor_new(g_sandbox_indexs->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        goto unlock;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        if (!map_insert(map_id_name, map_itor_value(itor), map_itor_key(itor))) {
            ERROR("Insert failed");
            goto unlock;
        }
    }
    ret = true;
unlock:
    if (pthread_rwlock_unlock(&g_sandbox_indexs->rwlock)) {
        ERROR("unlock memory store failed");
    }
out:
    map_itor_free(itor);
    if (!ret) {
        map_free(map_id_name);
        map_id_name = NULL;
    }
    return map_id_name;
}
