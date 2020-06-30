/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container store functions
 ******************************************************************************/
#include <stdlib.h>
#include <pthread.h>

#include "container_api.h"
#include "isula_libutils/log.h"
#include "utils.h"

typedef struct memory_store_t {
    map_t *map; // map string container_t
    pthread_rwlock_t rwlock;
} memory_store;

typedef struct name_index_t {
    map_t *map;
    pthread_rwlock_t rwlock;
} name_index;

static memory_store *g_containers_store = NULL;

static name_index *g_indexs = NULL;

/* memory store map kvfree */
static void memory_store_map_kvfree(void *key, void *value)
{
    free(key);

    container_unref((container_t *)value);
}

/* memory store free */
static void memory_store_free(memory_store *store)
{
    if (store == NULL) {
        return;
    }
    map_free(store->map);
    store->map = NULL;
    pthread_rwlock_destroy(&(store->rwlock));
    free(store);
}

/* memory store new */
static memory_store *memory_store_new(void)
{
    int ret;
    memory_store *store = NULL;

    store = util_common_calloc_s(sizeof(memory_store));
    if (store == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret = pthread_rwlock_init(&(store->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init memory store rwlock");
        free(store);
        return NULL;
    }
    store->map = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, memory_store_map_kvfree);
    if (store->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }
    return store;
error_out:
    memory_store_free(store);
    return NULL;
}

/* containers store add */
bool containers_store_add(const char *id, container_t *cont)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_containers_store->rwlock)) {
        ERROR("lock memory store failed");
        return false;
    }
    ret = map_replace(g_containers_store->map, (void *)id, (void *)cont);
    if (pthread_rwlock_unlock(&g_containers_store->rwlock)) {
        ERROR("unlock memory store failed");
        return false;
    }
    return ret;
}

/* containers store get */
static container_t *containers_store_get_by_id(const char *id)
{
    container_t *cont = NULL;

    if (id == NULL) {
        return NULL;
    }
    if (pthread_rwlock_rdlock(&g_containers_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return cont;
    }
    cont = map_search(g_containers_store->map, (void *)id);
    container_refinc(cont);
    if (pthread_rwlock_unlock(&g_containers_store->rwlock) != 0) {
        ERROR("unlock memory store failed");
        return cont;
    }
    return cont;
}

/* containers store get container by container name */
static container_t *containers_store_get_by_name(const char *name)
{
    char *id = NULL;

    if (name == NULL) {
        ERROR("No container name supplied");
        return NULL;
    }

    id = container_name_index_get(name);
    if (id == NULL) {
        WARN("Could not find entity for %s", name);
        return NULL;
    }

    return containers_store_get_by_id(id);
}

/* containers store get container by prefix */
container_t *containers_store_get_by_prefix(const char *prefix)
{
    bool ret = false;
    char *container_id = NULL;
    container_t *cont = NULL;
    map_itor *itor = NULL;

    if (prefix == NULL) {
        return NULL;
    }
    if (pthread_rwlock_rdlock(&g_containers_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return NULL;
    }

    itor = map_itor_new(g_containers_store->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        ret = false;
        goto unlock;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        container_id = map_itor_key(itor);
        if (container_id == NULL) {
            ERROR("Out of memory");
            ret = false;
            goto unlock;
        }
        if (strncmp(container_id, prefix, strlen(prefix)) == 0) {
            if (cont != NULL) {
                ERROR("Multiple IDs found with provided prefix: %s", prefix);
                ret = false;
                goto unlock;
            } else {
                cont = map_itor_value(itor);
            }
        }
    }

    ret = true;
    container_refinc(cont);

unlock:
    if (pthread_rwlock_unlock(&g_containers_store->rwlock) != 0) {
        ERROR("unlock memory store failed");
    }
    map_itor_free(itor);
    if (!ret) {
        cont = NULL;
    }
    return cont;
}

// containers_store_get looks for a container using the provided information, which could be
// one of the following inputs from the caller:
//  - A full container ID, which will exact match a container in daemon's list
//  - A container name, which will only exact match via the containers_store_get_by_name() function
//  - A partial container ID prefix (e.g. short ID) of any length that is
//    unique enough to only return a single container object
//  If none of these searches succeed, an error is returned
container_t *containers_store_get(const char *id_or_name)
{
    container_t *cont = NULL;

    if (id_or_name == NULL) {
        ERROR("No container name or ID supplied");
        return NULL;
    }

    // A full container ID, which will exact match a container in daemon's list
    cont = containers_store_get_by_id(id_or_name);
    if (cont != NULL) {
        return cont;
    }

    // A container name, which will only exact match via the containers_store_get_by_name() function
    cont = containers_store_get_by_name(id_or_name);
    if (cont != NULL) {
        return cont;
    }

    // A partial container ID prefix
    cont = containers_store_get_by_prefix(id_or_name);
    if (cont != NULL) {
        return cont;
    }

    return NULL;
}

/* containers store list */
int containers_store_list(container_t ***out, size_t *size)
{
    int ret = -1;
    size_t i;
    container_t **conts = NULL;
    map_itor *itor = NULL;

    if (pthread_rwlock_rdlock(&g_containers_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return -1;
    }

    *size = map_size(g_containers_store->map);
    if (*size == 0) {
        ret = 0;
        goto unlock;
    }
    if (*size > SIZE_MAX / sizeof(container_t *)) {
        ERROR("Containers store list is too long!");
        goto unlock;
    }
    conts = util_common_calloc_s(sizeof(container_t *) * (*size));
    if (conts == NULL) {
        ERROR("Out of memory");
        goto unlock;
    }

    itor = map_itor_new(g_containers_store->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        goto unlock;
    }

    for (i = 0; map_itor_valid(itor) && i < *size; map_itor_next(itor), i++) {
        conts[i] = map_itor_value(itor);
        container_refinc(conts[i]);
    }
    ret = 0;
unlock:
    if (pthread_rwlock_unlock(&g_containers_store->rwlock)) {
        ERROR("unlock memory store failed");
    }
    map_itor_free(itor);
    if (ret != 0) {
        free(conts);
        *size = 0;
        conts = NULL;
    }
    *out = conts;
    return ret;
}

/* containers store list names */
char **containers_store_list_ids(void)
{
    bool ret = false;
    char **idsarray = NULL;
    map_itor *itor = NULL;

    if (pthread_rwlock_rdlock(&g_containers_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return NULL;
    }

    if (map_size(g_containers_store->map) == 0) {
        ret = true;
        goto unlock;
    }

    itor = map_itor_new(g_containers_store->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        goto unlock;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        char *id = map_itor_key(itor);
        if (util_array_append(&idsarray, id ? id : "-")) {
            ERROR("Out of memory");
            goto unlock;
        }
    }
    ret = true;
unlock:
    if (pthread_rwlock_unlock(&g_containers_store->rwlock)) {
        ERROR("unlock memory store failed");
    }
    map_itor_free(itor);
    if (!ret) {
        util_free_array(idsarray);
        idsarray = NULL;
    }
    return idsarray;
}

/* containers store remove */
bool containers_store_remove(const char *id)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_containers_store->rwlock) != 0) {
        ERROR("lock memory store failed");
        return false;
    }
    ret = map_remove(g_containers_store->map, (void *)id);
    if (pthread_rwlock_unlock(&g_containers_store->rwlock) != 0) {
        ERROR("unlock memory store failed");
        return false;
    }
    return ret;
}

/* containers store init */
int containers_store_init(void)
{
    g_containers_store = memory_store_new();
    if (g_containers_store == NULL) {
        return -1;
    }
    return 0;
}

/* name index free */
static void name_index_free(name_index *indexs)
{
    if (indexs == NULL) {
        return;
    }
    map_free(indexs->map);
    indexs->map = NULL;
    pthread_rwlock_destroy(&(indexs->rwlock));
    free(indexs);
}

/* name index new */
static name_index *name_index_new(void)
{
    int ret;
    name_index *indexs = NULL;

    indexs = util_common_calloc_s(sizeof(name_index));
    if (indexs == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    ret = pthread_rwlock_init(&(indexs->rwlock), NULL);
    if (ret != 0) {
        ERROR("Failed to init name g_indexs rwlock");
        free(indexs);
        return NULL;
    }
    indexs->map = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (indexs->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }
    return indexs;
error_out:
    name_index_free(indexs);
    return NULL;
}

/* name index add */
bool container_name_index_add(const char *name, const char *id)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_indexs->rwlock) != 0) {
        ERROR("lock name index failed");
        return false;
    }
    ret = map_insert(g_indexs->map, (void *)name, (void *)id);
    if (pthread_rwlock_unlock(&g_indexs->rwlock) != 0) {
        ERROR("unlock name index failed");
        return false;
    }
    return ret;
}

/* name index rename */
bool container_name_index_rename(const char *new_name, const char *old_name, const char *id)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_indexs->rwlock) != 0) {
        ERROR("lock name index failed");
        return false;
    }
    ret = map_insert(g_indexs->map, (void *)new_name, (void *)id);
    if (!ret) {
        goto unlock_out;
    }

    ret = map_remove(g_indexs->map, (void *)old_name);

unlock_out:
    if (pthread_rwlock_unlock(&g_indexs->rwlock) != 0) {
        ERROR("unlock name index failed");
        return false;
    }
    return ret;
}

/* name index get */
char *container_name_index_get(const char *name)
{
    char *id = NULL;

    if (name == NULL) {
        return id;
    }
    if (pthread_rwlock_rdlock(&g_indexs->rwlock) != 0) {
        ERROR("lock name index failed");
        return id;
    }
    id = map_search(g_indexs->map, (void *)name);
    if (pthread_rwlock_unlock(&g_indexs->rwlock) != 0) {
        ERROR("unlock name index failed");
    }
    return id;
}

/* name index remove */
bool container_name_index_remove(const char *name)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_indexs->rwlock) != 0) {
        ERROR("lock name index failed");
        return false;
    }
    ret = map_remove(g_indexs->map, (void *)name);
    if (pthread_rwlock_unlock(&g_indexs->rwlock) != 0) {
        ERROR("unlock name index failed");
        return false;
    }
    return ret;
}

/* name index get all */
map_t *container_name_index_get_all(void)
{
    bool ret = false;
    map_t *map_id_name = NULL;
    map_itor *itor = NULL;

    map_id_name = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (map_id_name == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (pthread_rwlock_rdlock(&g_indexs->rwlock) != 0) {
        ERROR("lock memory store failed");
        goto out;
    }

    if (map_size(g_indexs->map) == 0) {
        ret = true;
        goto unlock;
    }

    itor = map_itor_new(g_indexs->map);
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
    if (pthread_rwlock_unlock(&g_indexs->rwlock)) {
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

/* name index init */
int container_name_index_init(void)
{
    g_indexs = name_index_new();
    if (g_indexs == NULL) {
        return -1;
    }
    return 0;
}