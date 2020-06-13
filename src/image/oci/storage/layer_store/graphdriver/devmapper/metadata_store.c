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
    free(store);
}

/* metadata store new */
metadata_store_t *metadata_store_new(void)
{
    metadata_store_t *store = NULL;

    store = util_common_calloc_s(sizeof(metadata_store_t));
    if (store == NULL) {
        ERROR("Out of memory");
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

bool metadata_store_add(const char *hash, image_devmapper_device_info *device, metadata_store_t *meta_store)
{
    return map_replace(meta_store->map, (void *)hash, (void *)device);
}

image_devmapper_device_info *metadata_store_get(const char *hash, metadata_store_t *meta_store)
{
    return map_search(meta_store->map, (void *)hash);
}

bool metadata_store_remove(const char *hash, metadata_store_t *meta_store)
{
    return map_remove(meta_store->map, (void *)hash);
}

/* metadata store list hashes */
char **metadata_store_list_hashes(metadata_store_t *meta_store)
{
    bool ret = false;
    char **hashes_array = NULL;
    map_itor *itor = NULL;

    if (map_size(meta_store->map) == 0) {
        ret = true;
        goto unlock;
    }

    itor = map_itor_new(meta_store->map);
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
    map_itor_free(itor);
    if (!ret) {
        util_free_array(hashes_array);
        hashes_array = NULL;
    }
    return hashes_array;
}