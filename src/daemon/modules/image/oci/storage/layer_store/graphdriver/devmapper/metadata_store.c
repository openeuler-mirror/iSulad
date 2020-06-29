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
#include "util_atomic.h"

void devmapper_device_info_ref_inc(devmapper_device_info_t *device_info)
{
    if (device_info == NULL) {
        return;
    }
    atomic_int_inc(&device_info->refcnt);
}

static void free_devmapper_device_info_t(devmapper_device_info_t *ptr)
{
    if (ptr == NULL) {
        return;
    }

    free_image_devmapper_device_info(ptr->info);
    ptr->info = NULL;

    free(ptr);
}

void devmapper_device_info_ref_dec(devmapper_device_info_t *device_info)
{
    bool is_zero = false;

    if (device_info == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&device_info->refcnt);
    if (!is_zero) {
        return;
    }

    free_devmapper_device_info_t(device_info);
}

/* metadata store map kvfree */
static void metadata_store_map_kvfree(void *key, void *value)
{
    free(key);

    devmapper_device_info_ref_dec((devmapper_device_info_t *)value);
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

static devmapper_device_info_t *create_empty_device_info()
{
    devmapper_device_info_t *result = NULL;

    result = (devmapper_device_info_t *)util_common_calloc_s(sizeof(devmapper_device_info_t));
    if (result == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    atomic_int_set(&result->refcnt, 1);

    return result;

err_out:
    free_devmapper_device_info_t(result);
    return NULL;
}

devmapper_device_info_t *new_device_info(image_devmapper_device_info *device)
{
    devmapper_device_info_t *device_info = NULL;

    if (device == NULL) {
        ERROR("Empty device info");
        return NULL;
    }

    device_info = create_empty_device_info();
    if (device_info == NULL) {
        return NULL;
    }

    device_info->info = device;

    return device_info;
}

bool metadata_store_add(const char *hash, image_devmapper_device_info *device, metadata_store_t *meta_store)
{
    bool ret = false;
    devmapper_device_info_t *device_info = NULL;

    if (hash == NULL || device == NULL || meta_store == NULL) {
        return false;
    }

    device_info = new_device_info(device);
    if (device_info == NULL) {
        ERROR("Failed to get new device info");
        goto out;
    }

    if (!map_replace(meta_store->map, (void *)hash, (void *)device_info)) {
        ERROR("Failed to insert device %s to meta store", hash);
        goto out;
    }

    ret = true;
out:
    if (!ret) {
        free_devmapper_device_info_t(device_info);
    }
    return ret;
}

devmapper_device_info_t *metadata_store_get(const char *hash, metadata_store_t *meta_store)
{
    devmapper_device_info_t *value = NULL;

    if (hash == NULL || meta_store == NULL) {
        ERROR("Invalid input parameter, id is NULL");
        return NULL;
    }

    value = map_search(meta_store->map, (void *)hash);
    if (value != NULL) {
        goto found;
    }

    return NULL;

found:
    devmapper_device_info_ref_inc(value);
    return value;
}

bool metadata_store_remove(const char *hash, metadata_store_t *meta_store)
{
    if (hash == NULL || meta_store == NULL) {
        ERROR("Invalid input parameter, id is NULL");
        return false;
    }

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