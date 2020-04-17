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
#define _GNU_SOURCE
#include "layer_store.h"

#include <pthread.h>
#include <stdio.h>
#include <limits.h>

#include "layer.h"
#include "driver.h"
#include "linked_list.h"
#include "map.h"
#include "types_def.h"
#include "utils.h"
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
static char *g_root_dir;
static char *g_run_dir;

void layer_store_cleanup()
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    map_free(g_metadata.by_id);
    map_free(g_metadata.by_name);
    map_free(g_metadata.by_compress_digest);
    map_free(g_metadata.by_uncompress_digest);

    linked_list_for_each_safe(item, &(g_metadata.layers_list), next) {
        linked_list_del(item);
        layer_ref_dec((layer_t *)item->elem);
        free(item);
    }

    pthread_rwlock_destroy(&(g_metadata.rwlock));
}

/* layers map kvfree */
static void layer_map_kvfree(void *key, void *value)
{
    free(key);
}

static void digest_map_kvfree(void *key, void *value)
{
    free(key);

    util_free_array((char **)value);
}

static bool init_from_conf(const struct storage_module_init_options *conf)
{
    int nret = 0;
    char *tmp_path = NULL;

    if (conf == NULL) {
        return false;
    }

    if (conf->storage_root == NULL || conf->storage_run_root == NULL || conf->driver_name == NULL) {
        ERROR("Invalid argument");
        return false;
    }
    nret = asprintf(&tmp_path, "%s/%s-layers", conf->storage_run_root, conf->driver_name);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create run root path failed");
        goto free_out;
    }
    g_run_dir = tmp_path;
    tmp_path = NULL;
    nret = asprintf(&tmp_path, "%s/%s-layers", conf->storage_root, conf->driver_name);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create root path failed");
        goto free_out;
    }
    g_root_dir = tmp_path;
    tmp_path = NULL;

    return true;
free_out:
    free(g_run_dir);
    g_run_dir = NULL;
    free(g_root_dir);
    g_root_dir = NULL;
    free(tmp_path);
    return false;
}

int layer_store_init(const struct storage_module_init_options *conf)
{
    int nret;

    if (!init_from_conf(conf)) {
        goto free_out;
    }
    // build root dir and run dir
    nret = util_mkdir_p(g_root_dir, IMAGE_STORE_PATH_MODE);
    if (nret != 0) {
        ERROR("build root dir of layer store failed");
        goto free_out;
    }
    nret = util_mkdir_p(g_run_dir, IMAGE_STORE_PATH_MODE);
    if (nret != 0) {
        ERROR("build run dir of layer store failed");
        goto free_out;
    }

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
    g_metadata.by_compress_digest = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, digest_map_kvfree);
    if (g_metadata.by_compress_digest == NULL) {
        ERROR("Failed to new compress map");
        goto free_out;
    }
    g_metadata.by_uncompress_digest = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, digest_map_kvfree);
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

static inline char *tar_split_path(const char *id)
{
    char *result = NULL;
    int nret;

    nret = asprintf(&result, "%s/%s/%s.tar-split.gz", g_root_dir, id, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create tar split path failed");
        return NULL;
    }

    return result;
}

static inline char *layer_json_path(const char *id)
{
    char *result = NULL;
    int nret;

    nret = asprintf(&result, "%s/%s/layer.json", g_root_dir, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create layer json path failed");
        return NULL;
    }

    return result;
}

static inline char *mountpoint_json_path(const char *id)
{
    char *result = NULL;
    int nret;

    nret = asprintf(&result, "%s/%s.json", g_run_dir, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create mount point json path failed");
        return NULL;
    }

    return result;
}

static layer_t *lookup(const char *id)
{
    layer_t *l = NULL;

    l = map_search(g_metadata.by_id, (void *)id);
    if (l != NULL) {
        goto out;
    }
    l = map_search(g_metadata.by_name, (void *)id);
    if (l != NULL) {
        goto out;
    }
    DEBUG("can not found layer: %s", id);

    return NULL;
out:
    layer_ref_inc(l);
    return l;
}

bool layer_store_check(const char *id)
{
    layer_t *l = NULL;
    if (id == NULL) {
        return false;
    }

    DEBUG("Checking layer %s", id);
    if (!graphdriver_layer_exists(id)) {
        WARN("Invalid data of layer %s", id);
        return false;
    }

    l = lookup(id);
    if (l == NULL) {
        ERROR("layer not known");
        goto err_out;
    }
    //TODO: read tar split file and verify

    layer_ref_dec(l);
    return true;
err_out:
    layer_ref_dec(l);
    return false;
}

static char *generate_random_layer_id()
{
    char *id = NULL;
    const size_t max_layer_id_len = 64;
    const size_t max_retry_cnt = 5;
    size_t i = 0;

    id = util_smart_calloc_s(sizeof(char), max_layer_id_len + 1);
    if (id == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (; i < max_retry_cnt; i++) {
        if (util_generate_random_str(id, max_layer_id_len) != 0) {
            ERROR("Generate random str failed");
            goto err_out;
        }
        layer_t *l = map_search(g_metadata.by_id, (void *)id);
        if (l == NULL) {
            break;
        }
    }
    if (i >= max_retry_cnt) {
        ERROR("Retry generate id too much");
        goto err_out;
    }

    return id;
err_out:
    free(id);
    return NULL;
}

static int driver_create_layer(const char *id, const char *parent, bool writable,
                               const struct layer_store_mount_opts *opt)
{
    struct driver_create_opts c_opts = { 0 };
    int ret = 0;
    size_t i = 0;

    if (opt != NULL) {
        c_opts.mount_label = util_strdup_s(opt->mount_label);
        if (opt->mount_opts != NULL) {
            c_opts.storage_opt = util_smart_calloc_s(sizeof(json_map_string_string), 1);
            if (c_opts.storage_opt == NULL) {
                ERROR("Out of memory");
                ret = -1;
                goto free_out;
            }
            for (i = 0; i < opt->mount_opts->len; i++) {
                ret = append_json_map_string_string(c_opts.storage_opt, opt->mount_opts->keys[i], opt->mount_opts->values[i]);
                if (ret != 0) {
                    ERROR("Out of memory");
                    goto free_out;
                }
            }
        }
    }

    if (writable) {
        ret = graphdriver_create_rw(id, parent, &c_opts);
    } else {
        ret = graphdriver_create_rw(id, parent, &c_opts);
    }
    if (ret != 0) {
        if (id != NULL) {
            ERROR("error creating %s layer with ID %s", writable ? "read-write" : "", id);
        } else {
            ERROR("error creating %s layer", writable ? "read-write" : "");
        }
        goto free_out;
    }

free_out:
    free(c_opts.mount_label);
    free_json_map_string_string(c_opts.storage_opt);
    return ret;
}

static int update_layer_datas(const char *id, const struct layer_opts *opts, layer_t *l)
{
    int ret = 0;
    storage_layer *slayer = NULL;
    char timebuffer[TIME_STR_SIZE] = { 0 };
    size_t i = 0;

    slayer = util_smart_calloc_s(sizeof(storage_layer), 1);
    if (slayer == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto free_out;
    }

    slayer->id = util_strdup_s(id);
    slayer->parent = util_strdup_s(opts->parent);
    if (opts->opts != NULL) {
        slayer->mountlabel = util_strdup_s(opts->opts->mount_label);
    }
    if (!get_now_local_utc_time_buffer(timebuffer, TIME_STR_SIZE)) {
        ERROR("Get create time failed");
        ret = -1;
        goto free_out;
    }
    slayer->created = util_strdup_s(timebuffer);

    if (opts->names_len > 0) {
        slayer->names = util_smart_calloc_s(sizeof(char *), opts->names_len);
        if (slayer->names == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto free_out;
        }
    }
    for (i = 0; i < opts->names_len; i++) {
        slayer->names[i] = util_strdup_s(opts->names[i]);
        slayer->names_len++;
    }
    l->slayer = slayer;
    l->layer_json_path = layer_json_path(id);
    l->incompelte = true;

free_out:
    if (ret != 0) {
        free_storage_layer(slayer);
    }
    return ret;
}

static int update_digest_map(map_t *by_digest, const char *old_val, const char *new_val, const char *id)
{
    char **old_list = NULL;
    size_t old_len = 0;
    int ret = 0;
    size_t i = 0;

    if (new_val != NULL) {
        char **tmp_new_list = NULL;
        char **new_list = (char **)map_search(by_digest, (void *)new_val);
        size_t new_len = util_array_len((const char **)new_list);

        tmp_new_list = util_smart_calloc_s(sizeof(char *), new_len + 2);
        if (tmp_new_list == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < new_len; i++) {
            tmp_new_list[new_len] = new_list[i];
            new_list[i] = NULL;
        }
        tmp_new_list[new_len] = util_strdup_s(id);

        if (!map_replace(by_digest, (void *)new_val, (void *)tmp_new_list)) {
            ERROR("Insert new digest failed");
            // recover new list
            for (i = 0; i < new_len; i++) {
                new_list[i] = tmp_new_list[i];
            }
            free(tmp_new_list[new_len]);
            free(tmp_new_list);
            ret = -1;
            goto out;
        }
    }

    if (old_val != NULL) {
        size_t idx = 0;
        old_list = (char **)map_search(by_digest, (void *)old_val);
        old_len = util_array_len((const char **)old_list);

        for (; idx < old_len; idx++) {
            if (strcmp(old_list[idx], id) == 0) {
                free(old_list[idx]);
                old_list[idx] = NULL;
                break;
            }
        }
        for (idx = idx + 1; idx < old_len; idx++) {
            old_list[idx - 1] = old_list[idx];
            old_list[idx] = NULL;
        }

        if (idx == 0 && !map_remove(by_digest, (void *)old_val)) {
            WARN("Remove old failed");
        }
    }

out:
    return ret;
}

static int remove_memory_stores(const char *id)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    layer_t *l = NULL;
    size_t i = 0;

    l = lookup(id);
    if (l == NULL) {
        ERROR("layer not known");
        return -1;
    }

    if (update_digest_map(g_metadata.by_compress_digest, l->slayer->compressed_diff_digest, NULL, l->slayer->id) != 0) {
        return -1;
    }
    if (update_digest_map(g_metadata.by_uncompress_digest, l->slayer->diff_digest, NULL, l->slayer->id) != 0) {
        // ignore this error, because only happen at out of memory;
        // we cannot to recover before operator, so just go on.
        WARN("Remove digest failed");
    }

    if (!map_remove(g_metadata.by_id, (void *)l->slayer->id)) {
        WARN("Remove by id: %s failed", id);
    }

    for (; i < l->slayer->names_len; i++) {
        if (!map_remove(g_metadata.by_name, (void *)l->slayer->names[i])) {
            WARN("Remove by name: %s failed", l->slayer->names[i]);
        }
    }

    linked_list_for_each_safe(item, &(g_metadata.layers_list), next) {
        layer_t *l = (layer_t *)item->elem;
        if (strcmp(l->slayer->id, id) != 0) {
            continue;
        }
        linked_list_del(item);
        layer_ref_dec(l);
        free(item);
        break;
    }

    return 0;
}

static int insert_memory_stores(const char *id, const struct layer_opts *opts, layer_t *l)
{
    size_t i = 0;
    struct linked_list *item = NULL;
    int ret = 0;

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    linked_list_add_elem(item, l);
    linked_list_add_tail(&g_metadata.layers_list, item);
    if (!map_insert(g_metadata.by_id, (void *)id, (void *)l)) {
        ERROR("Update by id failed");
        ret = -1;
        goto clear_list;
    }
    for (; i < opts->names_len; i++) {
        if (!map_insert(g_metadata.by_name, (void *)opts->names[i], (void *)l)) {
            ERROR("Update by names failed");
            ret = -1;
            goto clear_by_name;
        }
    }

    goto out;
clear_by_name:
    for (i = i - 1; i >= 0; i--) {
        if (!map_remove(g_metadata.by_name, (void *)opts->names[i])) {
            WARN("Remove name: %s failed", opts->names[i]);
        }
    }
    if (!map_remove(g_metadata.by_id, (void *)id)) {
        WARN("Remove layer: %s failed", id);
    }
clear_list:
    linked_list_del(item);
    free(item);
out:
    return ret;
}

int layer_store_create(const char *id, const struct layer_opts *opts, const struct io_read_wrapper *diff,
                       char **new_id)
{
    int ret = 0;
    char *lid = util_strdup_s(id);
    layer_t *l = NULL;
    size_t i = 0;

    if (new_id == NULL || opts == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (lid == NULL) {
        lid = generate_random_layer_id();
    }
    if (lid == NULL) {
        return -1;
    }

    l = map_search(g_metadata.by_id, (void *)lid);
    if (l != NULL) {
        ERROR("that ID is already in use");
        ret = -1;
        goto free_out;
    }
    // check names whether used
    for (; i < opts->names_len; i++) {
        l = map_search(g_metadata.by_name, (void *)opts->names[i]);
        if (l != NULL) {
            ERROR("that name is already in use");
            ret = -1;
            goto free_out;
        }
    }

    // create layer by driver
    ret = driver_create_layer(lid, opts->parent, opts->writable, opts->opts);
    if (ret != 0) {
        ret = -1;
        goto free_out;
    }

    l = create_empty_layer();
    if (l == NULL) {
        ret = -1;
        goto driver_remove;
    }

    ret = update_layer_datas(lid, opts, l);
    if (ret != 0) {
        goto driver_remove;
    }
    // update memory store
    ret = insert_memory_stores(lid, opts, l);
    if (ret != 0) {
        goto driver_remove;
    }

    // TODO: write diff data
    goto clear_memory;

    // TODO: save json file
    //goto free_out;
clear_memory:
    ret = remove_memory_stores(lid);
driver_remove:
    if (ret != 0) {
        (void)graphdriver_rm_layer(lid);
    }
free_out:
    if (ret != 0) {
        layer_ref_dec(l);
    }
    free(lid);
    return ret;
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

char *layer_store_lookup(const char *name)
{
    return NULL;
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

void free_layer_opts(struct layer_opts *ptr)
{
    if (ptr == NULL) {
        return;
    }

    //TODO: free mount options
}
