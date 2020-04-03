/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: liuhao
 * Create: 2020-03-26
 * Description: provide layer store functions
 ******************************************************************************/

#include "layer_store.h"

#include <pthread.h>

#include "layer.h"
#include "linked_list.h"
#include "map.h"
#include "log.h"

typedef struct __layer_store_metadata_t {
    pthread_rwlock_t rwlock;
    map_t *by_id;
    map_t *by_name;
    map_t *by_compress_digest;
    map_t *by_uncompress_digest;
    struct linked_list layers_list;
} layer_store_metadata;

static layer_store_metadata g_metadata;

void layer_store_cleanup()
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    linked_list_for_each_safe(item, &(g_metadata.layers_list), next) {
        linked_list_del(item);
    }

    pthread_rwlock_destroy(&(g_metadata.rwlock));
    map_free(g_metadata.by_id);
    map_free(g_metadata.by_name);
    map_free(g_metadata.by_compress_digest);
    map_free(g_metadata.by_uncompress_digest);
}

/* layers map kvfree */
static void layer_map_kvfree(void *key, void *value)
{
    free(key);

    layer_ref_dec((layer_t *)value);
}

int layer_store_init(const struct storage_module_init_options *conf)
{
    int nret;

    // init manager structs
    linked_list_init(&g_metadata.layers_list);
    nret = pthread_rwlock_init(&(g_metadata.rwlock), NULL);
    if (nret != 0) {
        ERROR("Failed to init metadata rwlock");
        goto free_out;
    }
    g_metadata.by_id = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, layer_map_kvfree);
    if (g_metadata.by_id == NULL) {
        ERROR("Failed to new ids map");
        goto free_out;
    }
    g_metadata.by_name = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, layer_map_kvfree);
    if (g_metadata.by_name == NULL) {
        ERROR("Failed to new names map");
        goto free_out;
    }
    g_metadata.by_compress_digest = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, layer_map_kvfree);
    if (g_metadata.by_compress_digest == NULL) {
        ERROR("Failed to new compress map");
        goto free_out;
    }
    g_metadata.by_uncompress_digest = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, layer_map_kvfree);
    if (g_metadata.by_uncompress_digest == NULL) {
        ERROR("Failed to new uncompress map");
        goto free_out;
    }
    //TODO: load layer json files

    return 0;
free_out:
    layer_store_cleanup();
    return -1;
}

bool layer_store_check(const char *id)
{
    return true;
}

int layer_store_create(const char *id, const struct layer_opts *opts, const struct io_read_wrapper *content,
                       char **new_id)
{
    return 0;
}
int layer_store_delete(const char *id)
{
    return 0;
}
bool layer_store_exists(const char *id)
{
    return true;
}
struct layer** layer_store_list()
{
    return NULL;
}
bool layer_store_is_used(const char *id)
{
    return true;
}
struct layer** layer_store_by_compress_digest(const char *digest)
{
    return NULL;
}
struct layer** layer_store_by_uncompress_digest(const char *digest)
{
    return NULL;
}
int layer_store_lookup(const char *name, char **found_id)
{
    return 0;
}
int layer_store_mount(const char *id, const struct layer_store_mount_opts *opts)
{
    return 0;
}
int layer_store_umount(const char *id, bool force)
{
    return 0;
}
int layer_store_mounted(const char *id)
{
    return 0;
}
int layer_store_set_names(const char *id, const char * const* names, size_t names_len)
{
    return 0;
}
struct graphdriver_status* layer_store_status()
{
    return NULL;
}
int layer_store_try_repair_lowers(const char *id)
{
    return 0;
}

void free_layer(struct layer *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->id);
    ptr->id = NULL;
    free(ptr->parent);
    ptr->parent = NULL;
    free(ptr->mount_point);
    ptr->mount_point = NULL;
    free(ptr->compressed_digest);
    ptr->compressed_digest = NULL;
    free(ptr->uncompressed_digest);
    ptr->uncompressed_digest = NULL;
    free(ptr);
}

void free_layer_opts(struct layer_opts *ptr)
{
    if (ptr == NULL) {
        return;
    }

    //TODO: free mount options
}
