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
 * Author: gaohuatao
 * Create: 2020-06-12
 * Description: provide overlay2 function definition
 ******************************************************************************/

#include <pthread.h>
#include "metadata_store.h"
#include "utils.h"
#include "isula_libutils/log.h"

typedef struct {
    map_t *map; // map string image_devmapper_device_info*   key string will be strdup  value ptr will not
    pthread_rwlock_t rwlock;
} metadata_store_t;

static metadata_store_t *g_metadata_store = NULL;

/* metadata store map kvfree */
static void metadata_store_map_kvfree(void *key, void *value)
{
    free(key);

    free_image_devmapper_device_info((image_devmapper_device_info *)value);
}

/* metadata store free */
static void metadata_store_free(metadata_store_t *store)
{
    if (store == NULL) {
        return;
    }
    map_free(store->map);
    store->map = NULL;
    pthread_rwlock_destroy(&(store->rwlock));
    free(store);
}

/* metadata store new */
static metadata_store_t *metadata_store_new(void)
{
    int ret;
    metadata_store_t *store = NULL;

    store = util_common_calloc_s(sizeof(metadata_store_t));
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
    store->map = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, metadata_store_map_kvfree);
    if (store->map == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }
    return store;
error_out:
    metadata_store_free(store);
    return NULL;
}

int metadata_store_init(void)
{
    g_metadata_store = metadata_store_new();
    if (g_metadata_store == NULL) {
        return -1;
    }
    return 0;
}

bool metadata_store_add(const char *hash, image_devmapper_device_info *device)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_metadata_store->rwlock)) {
        ERROR("devmapper: lock metadata store failed");
        return false;
    }

    ret = map_replace(g_metadata_store->map, (void *)hash, (void *)device);
    if (pthread_rwlock_unlock(&g_metadata_store->rwlock)) {
        ERROR("devmapper: unlock metadata store failed");
        return false;
    }
    return ret;
}

image_devmapper_device_info *metadata_store_get(const char *hash)
{
    image_devmapper_device_info *device = NULL;

    if (hash == NULL) {
        return NULL;
    }
    if (pthread_rwlock_rdlock(&g_metadata_store->rwlock) != 0) {
        ERROR("devmapper:lock memory store failed");
        return device;
    }
    device = map_search(g_metadata_store->map, (void *)hash);
    if (pthread_rwlock_unlock(&g_metadata_store->rwlock) != 0) {
        ERROR("devmapper:unlock memory store failed");
    }

    return device;
}

bool metadata_store_remove(const char *hash)
{
    bool ret = false;

    if (pthread_rwlock_wrlock(&g_metadata_store->rwlock) != 0) {
        ERROR("devmapper:lock memory store failed");
        return false;
    }

    ret = map_remove(g_metadata_store->map, (void *)hash);
    if (pthread_rwlock_unlock(&g_metadata_store->rwlock) != 0) {
        ERROR("devmapper:unlock memory store failed");
        return false;
    }
    return ret;
}

/* metadata store list hashes */
char **metadata_store_list_hashes(void)
{
    bool ret = false;
    char **hashes_array = NULL;
    map_itor *itor = NULL;

    if (pthread_rwlock_rdlock(&g_metadata_store->rwlock) != 0) {
        ERROR("devmapper:lock memory store failed");
        return NULL;
    }

    if (map_size(g_metadata_store->map) == 0) {
        ret = true;
        goto unlock;
    }

    itor = map_itor_new(g_metadata_store->map);
    if (itor == NULL) {
        ERROR("Out of memory");
        goto unlock;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        char *id = map_itor_key(itor);
        if (util_array_append(&hashes_array, id ? id : "-")) {
            ERROR("Out of memory");
            goto unlock;
        }
    }
    ret = true;
unlock:
    if (pthread_rwlock_unlock(&g_metadata_store->rwlock)) {
        ERROR("unlock metadata store failed");
    }
    map_itor_free(itor);
    if (!ret) {
        util_free_array(hashes_array);
        hashes_array = NULL;
    }
    return hashes_array;
}