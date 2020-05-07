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

#include "storage.h"
#include "json_common.h"
#include "layer.h"
#include "driver.h"
#include "linked_list.h"
#include "map.h"
#include "types_def.h"
#include "utils.h"
#include "util_atomic.h"
#include "utils_array.h"
#include "utils_file.h"
#include "log.h"

typedef struct __layer_store_metadata_t {
    pthread_rwlock_t rwlock;
    map_t *by_id;
    map_t *by_name;
    map_t *by_compress_digest;
    map_t *by_uncompress_digest;
    struct linked_list layers_list;
    size_t layers_list_len;
} layer_store_metadata;

static layer_store_metadata g_metadata;
static char *g_root_dir;
static char *g_run_dir;

static inline char *layer_json_path(const char *id);
static inline char *tar_split_path(const char *id);
static inline char *mountpoint_json_path(const char *id);
static inline char *layer_json_path(const char *id);

static bool remove_name(const char *name);
static void recover_name(const char *name);
static int update_digest_map(map_t *by_digest, const char *old_val, const char *new_val, const char *id);

static inline bool layer_store_lock(bool writable)
{
    int nret = 0;

    if (writable) {
        nret = pthread_rwlock_wrlock(&g_metadata.rwlock);
    } else {
        nret = pthread_rwlock_rdlock(&g_metadata.rwlock);
    }
    if (nret != 0) {
        ERROR("Lock memory store failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void layer_store_unlock()
{
    int nret = 0;

    nret = pthread_rwlock_unlock(&g_metadata.rwlock);
    if (nret != 0) {
        FATAL("Unlock memory store failed: %s", strerror(nret));
    }
}

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
    g_metadata.layers_list_len = 0;

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

static inline void insert_g_layer_list_item(struct linked_list *item)
{
    if (item == NULL) {
        return;
    }

    linked_list_add_tail(&g_metadata.layers_list, item);
    g_metadata.layers_list_len += 1;
}

static bool append_layer_into_list(layer_t *l)
{
    struct linked_list *item = NULL;

    if (l == NULL) {
        return true;
    }

    item = util_smart_calloc_s(sizeof(struct linked_list), 1);
    if (item == NULL) {
        ERROR("Out of memory");
        return false;
    }

    linked_list_add_elem(item, l);

    insert_g_layer_list_item(item);
    return true;
}

static inline void delete_g_layer_list_item(struct linked_list *item)
{
    if (item == NULL) {
        return;
    }

    linked_list_del(item);

    layer_ref_dec((layer_t *)item->elem);
    item->elem = NULL;
    free(item);
    g_metadata.layers_list_len -= 1;
}

static void remove_layer_list_tail()
{
    struct linked_list *item = NULL;

    if (linked_list_empty(&g_metadata.layers_list)) {
        return;
    }

    item = g_metadata.layers_list.prev;

    delete_g_layer_list_item(item);
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

    nret = graphdriver_init(conf);
    if (nret != 0) {
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

static bool load_layer_json_cb(const char *path_name, const struct dirent *sub_dir)
{
#define LAYER_NAME_LEN 64
    bool ret = true;
    char tmpdir[PATH_MAX] = { 0 };
    int nret = 0;
    char *rpath = NULL;
    char *mount_point_path = NULL;
    layer_t *l = NULL;

    nret = snprintf(tmpdir, PATH_MAX, "%s/%s", path_name, sub_dir->d_name);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Sprintf: %s failed", sub_dir->d_name);
        return false;
    }

    if (!util_dir_exists(tmpdir)) {
        // ignore non-dir
        DEBUG("%s is not directory", sub_dir->d_name);
        return true;
    }

    if (strlen(sub_dir->d_name) != LAYER_NAME_LEN) {
        DEBUG("%s is invalid subdir name", sub_dir->d_name);
        return true;
    }

    rpath = layer_json_path(sub_dir->d_name);
    if (rpath == NULL) {
        return false;
    }
    mount_point_path = mountpoint_json_path(sub_dir->d_name);
    if (mount_point_path == NULL) {
        ret = false;
        goto free_out;
    }

    l = load_layer(rpath, mount_point_path);
    if (l == NULL) {
        WARN("load layer: %s failed", sub_dir->d_name);
        goto free_out;
    }
    if (l->slayer->diff_digest == NULL &&
        (!util_file_exists(rpath) || !graphdriver_layer_exists(sub_dir->d_name))) {
        ERROR("Invalid data of layer: %s, remove it", sub_dir->d_name);
        if (util_path_remove(rpath) != 0) {
            ERROR("Remove layer: %s failed", rpath);
        }
        if (graphdriver_rm_layer(sub_dir->d_name) != 0) {
            ERROR("Remove driver data of %s failed", sub_dir->d_name);
        }
        goto free_out;
    }
    // update memory store list
    ret = append_layer_into_list(l);

free_out:
    free(rpath);
    free(mount_point_path);
    return ret;
}

static int load_layers_from_json_files()
{
    int ret = 0;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    bool should_save = false;

    if (!layer_store_lock(true)) {
        return -1;
    }

    ret = util_scan_subdirs(g_root_dir, load_layer_json_cb);
    if (ret != 0) {
        goto unlock_out;
    }

    linked_list_for_each_safe(item, &(g_metadata.layers_list), next) {
        layer_t *tl = (layer_t *)item->elem;
        size_t i = 0;

        for (; i < tl->slayer->names_len; i++) {
            if (remove_name(tl->slayer->names[i])) {
                should_save = true;
            }
            if (!map_insert(g_metadata.by_name, (void *)tl->slayer->names[i], (void *)tl)) {
                ERROR("Insert name: %s for layer failed", tl->slayer->names[i]);
                goto err_out;
            }
        }

        ret = update_digest_map(g_metadata.by_compress_digest, NULL, tl->slayer->compressed_diff_digest, tl->slayer->id);
        if (ret != 0) {
            ERROR("update layer: %s compress failed", tl->slayer->id);
            goto err_out;
        }

        ret = update_digest_map(g_metadata.by_uncompress_digest, NULL, tl->slayer->diff_digest, tl->slayer->id);
        if (ret != 0) {
            ERROR("update layer: %s uncompress failed", tl->slayer->id);
            goto err_out;
        }

        // check complete
        if (tl->incompelte) {
            if (layer_store_delete(tl->slayer->id) != 0) {
                ERROR("delete layer: %s failed", tl->slayer->id);
                goto err_out;
            }
            should_save = true;
        }

        if (should_save && save_layer(tl) != 0) {
            ERROR("save layer: %s failed", tl->slayer->id);
            goto err_out;
        }
    }

    ret = 0;
    goto unlock_out;
err_out:
    // clear memory store
    layer_store_cleanup();
    ret = -1;
unlock_out:
    layer_store_unlock();
    return ret;
}

int layer_store_init(const struct storage_module_init_options *conf)
{
    int nret = 0;

    if (!init_from_conf(conf)) {
        return -1;
    }

    // init manager structs
    g_metadata.layers_list_len = 0;
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

    // TODO: load layer json files
    if (load_layers_from_json_files() != 0) {
        goto free_out;
    }

    DEBUG("Init layer store success");
    return 0;
free_out:
    layer_store_cleanup();
    return -1;
}

static inline char *tar_split_path(const char *id)
{
    char *result = NULL;
    int nret = 0;

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
    int nret = 0;

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
    int nret = 0;

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

static inline layer_t *lookup_with_lock(const char *id)
{
    layer_t *ret = NULL;

    if (!layer_store_lock(false)) {
        return NULL;
    }

    ret = lookup(id);
    layer_store_unlock();
    return ret;
}

bool layer_store_check(const char *id)
{
    layer_t *l = NULL;
    bool ret = false;

    if (id == NULL) {
        return false;
    }

    DEBUG("Checking layer %s", id);
    if (!graphdriver_layer_exists(id)) {
        WARN("Invalid data of layer %s", id);
        return false;
    }

    l = lookup_with_lock(id);
    if (l == NULL) {
        ERROR("layer not known");
        goto out;
    }
    //TODO: read tar split file and verify

    ret = true;
out:
    layer_ref_dec(l);
    return ret;
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

    if (!layer_store_lock(false)) {
        goto err_out;
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

    goto unlock;
err_out:
    free(id);
    id = NULL;
unlock:
    layer_store_unlock();
    return id;
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
    int ret = 0;

    if (!layer_store_lock(true)) {
        return -1;
    }

    l = lookup(id);
    if (l == NULL) {
        ERROR("layer not known");
        ret = -1;
        goto unlock;
    }

    if (update_digest_map(g_metadata.by_compress_digest, l->slayer->compressed_diff_digest, NULL, l->slayer->id) != 0) {
        ERROR("Remove %s from compress digest failed", id);
        ret = -1;
        goto unlock;
    }
    if (update_digest_map(g_metadata.by_uncompress_digest, l->slayer->diff_digest, NULL, l->slayer->id) != 0) {
        // ignore this error, because only happen at out of memory;
        // we cannot to recover before operator, so just go on.
        WARN("Remove %s from uncompress failed", id);
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
        layer_t *tl = (layer_t *)item->elem;
        if (strcmp(tl->slayer->id, id) != 0) {
            continue;
        }
        delete_g_layer_list_item(item);
        break;
    }

unlock:
    layer_store_unlock();
    layer_ref_dec(l);
    return ret;
}

static int insert_memory_stores(const char *id, const struct layer_opts *opts, layer_t *l)
{
    int ret = 0;
    size_t i = 0;

    if (!layer_store_lock(true)) {
        return -1;
    }

    if (!append_layer_into_list(l)) {
        ret = -1;
        goto out;
    }

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
    remove_layer_list_tail();
out:
    layer_store_unlock();
    return ret;
}

static int apply_diff(const char *id, const struct io_read_wrapper *diff)
{
    int64_t size = 0;
    int ret = 0;

    if (diff == NULL) {
        return 0;
    }

    ret = graphdriver_apply_diff(id, diff, &size);

    INFO("Apply layer get size: %lld", size);

    return ret;
}

static int check_create_layer_used(const char *id, const struct layer_opts *opts)
{
    layer_t *l = NULL;
    int ret = 0;
    size_t i = 0;

    if (!layer_store_lock(false)) {
        return -1;
    }
    l = map_search(g_metadata.by_id, (void *)id);
    if (l != NULL) {
        ERROR("that ID is already in use");
        ret = -1;
        goto out;
    }
    // check names whether used
    for (; i < opts->names_len; i++) {
        l = map_search(g_metadata.by_name, (void *)opts->names[i]);
        if (l != NULL) {
            ERROR("that name is already in use");
            ret = -1;
        }
    }

out:
    layer_store_unlock();
    return ret;
}

int layer_store_create(const char *id, const struct layer_opts *opts, const struct io_read_wrapper *diff,
                       char **new_id)
{
    int ret = 0;
    char *lid = util_strdup_s(id);
    layer_t *l = NULL;

    if (opts == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (lid == NULL) {
        lid = generate_random_layer_id();
    }
    if (lid == NULL) {
        return -1;
    }

    ret = check_create_layer_used(lid, opts);
    if (ret != 0) {
        goto free_out;
    }

    // create layer by driver
    ret = driver_create_layer(lid, opts->parent, opts->writable, opts->opts);
    if (ret != 0) {
        goto free_out;
    }

    l = create_empty_layer();
    if (l == NULL) {
        ret = -1;
        goto driver_remove;
    }

    // lock this layer
    layer_lock(l);

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
    ret = apply_diff(lid, diff);
    if (ret != 0) {
        goto clear_memory;
    }

    ret = save_layer(l);
    if (ret == 0) {
        DEBUG("create layer success");
        if (new_id != NULL) {
            *new_id = lid;
            lid = NULL;
        }
        goto free_out;
    }
    ERROR("Save layer failed");
clear_memory:
    ret = remove_memory_stores(lid);
driver_remove:
    if (ret != 0) {
        (void)graphdriver_rm_layer(lid);
    }
free_out:
    layer_unlock(l);
    if (ret != 0) {
        layer_ref_dec(l);
    }
    free(lid);
    return ret;
}

static int umount_helper(layer_t *l, bool force)
{
    int ret = 0;
    int32_t save_cnt = 0;
    char *save_path = NULL;

    if (l->smount_point == NULL) {
        return 0;
    }
    save_cnt = l->smount_point->count;
    save_path = l->smount_point->path;

    if (!force && l->smount_point->count > 1) {
        l->smount_point->count -= 1;
        goto save_json;
    }

    // TODO: not exist file error need to ignore
    ret = graphdriver_umount_layer(l->slayer->id);
    if (ret != 0) {
        ERROR("Call driver umount failed");
        goto err_out;
    }
    l->smount_point->count = 0;
    l->smount_point->path = NULL;

save_json:
    ret = save_mount_point(l);
    if (ret != 0) {
        l->smount_point->count = save_cnt;
        l->smount_point->path = save_path;
        save_path = NULL;
    }
    free(save_path);
err_out:
    return ret;
}

int layer_store_remove_layer(const char *id)
{
    char *rpath = NULL;
    int ret = 0;

    if (id == NULL) {
        return 0;
    }

    rpath = layer_json_path(id);
    if (rpath == NULL) {
        WARN("Generate rpath for layer %s failed, jsut ignore", id);
        return 0;
    }
    ret = util_path_remove(rpath);
    free(rpath);

    return ret;
}

int layer_store_delete(const char *id)
{
    layer_t *l = NULL;
    size_t i = 0;
    int ret = 0;
    char *tspath = NULL;

    if (id == NULL) {
        return -1;
    }

    l = lookup_with_lock(id);
    if (l == NULL) {
        ERROR("layer not known");
        return -1;
    }
    layer_lock(l);
    if (l->smount_point != NULL) {
        for (; i < l->smount_point->count; i++) {
            if (umount_helper(l, false) != 0) {
                ret = -1;
                goto free_out;
            }
        }
    }
    tspath = tar_split_path(l->slayer->id);
    if (tspath != NULL && util_path_remove(tspath) != 0) {
        SYSERROR("Can not remove layer files, just ignore.");
    }

    ret = remove_memory_stores(l->slayer->id);
    if (ret != 0) {
        goto free_out;
    }

    ret = graphdriver_rm_layer(l->slayer->id);
    if (ret != 0) {
        ERROR("Remove layer: %s by driver failed", l->slayer->id);
        goto free_out;
    }

    ret = layer_store_remove_layer(l->slayer->id);

free_out:
    free(tspath);
    layer_unlock(l);
    layer_ref_dec(l);
    return ret;
}

bool layer_store_exists(const char *id)
{
    layer_t *l = lookup_with_lock(id);

    if (l == NULL) {
        return false;
    }

    layer_ref_dec(l);
    return true;
}

static void copy_json_to_layer(const layer_t *jl, struct layer *l)
{

    if (jl->slayer == NULL) {
        return;
    }
    l->id = util_strdup_s(jl->slayer->id);
    l->parent = util_strdup_s(jl->slayer->parent);
    l->compressed_digest = util_strdup_s(jl->slayer->compressed_diff_digest);
    l->compress_size = jl->slayer->compressed_size;
    l->uncompressed_digest = util_strdup_s(jl->slayer->diff_digest);
    l->uncompress_size = jl->slayer->diff_size;
    if (jl->smount_point != NULL) {
        l->mount_point = util_strdup_s(jl->smount_point->path);
        l->mount_count = jl->smount_point->count;
    }
}

struct layer** layer_store_list(size_t *layers_len)
{
    // TODO: add lock
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    struct layer **result = NULL;
    size_t i = 0;

    result = (struct layer**)util_smart_calloc_s(sizeof(struct layer*), g_metadata.layers_list_len + 1);
    if (result == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (!layer_store_lock(false)) {
        goto err_out;
    }

    linked_list_for_each_safe(item, &(g_metadata.layers_list), next) {
        layer_t *l = (layer_t *)item->elem;
        result[i] = util_common_calloc_s(sizeof(struct layer));
        if (result[i] == NULL) {
            ERROR("Out of memory");
            goto err_out;
        }
        layer_lock(l);
        copy_json_to_layer(l, result[i]);
        layer_unlock(l);
        i++;
    }

    *layers_len = g_metadata.layers_list_len;
    goto unlock;
err_out:
    while (i >= 0) {
        free_layer(result[i]);
        i--;
    }
    free(result);
    result = NULL;
unlock:
    layer_store_unlock();
    return result;
}

bool layer_store_is_used(const char *id)
{
    layer_t *l = NULL;

    l = lookup_with_lock(id);
    if (l == NULL) {
        return false;
    }

    layer_ref_dec(l);
    return true;
}

static struct layer **layers_by_digest_map(map_t *m, const char *digest, size_t *layers_len)
{
    char **ids = NULL;
    struct layer **result = NULL;
    size_t len = 0;
    size_t i = 0;

    if (!layer_store_lock(false)) {
        return NULL;
    }
    ids = map_search(m, (void *)digest);
    if (ids == NULL) {
        goto unlock;
    }
    len = util_array_len((const char **)ids);
    if (len > 0) {
        layer_t *l = NULL;

        result = util_smart_calloc_s(sizeof(struct layer*), len + 1);
        for (; i < len; i++) {
            struct layer *t_layer = util_common_calloc_s(sizeof(struct layer));
            if (t_layer == NULL) {
                ERROR("Out of memory");
                goto free_out;
            }
            l = lookup(ids[i]);
            if (l == NULL) {
                ERROR("layer not known");
                free(t_layer);
                goto free_out;
            }
            layer_lock(l);
            copy_json_to_layer(l, t_layer);
            result[i] = t_layer;
            layer_unlock(l);
            layer_ref_dec(l);
        }
    }

    *layers_len = len;
    goto unlock;
free_out:
    while (result != NULL && i >= 0) {
        free_layer(result[i]);
    }
    free(result);
    result = NULL;
unlock:
    layer_store_unlock();
    return result;
}

struct layer** layer_store_by_compress_digest(const char *digest, size_t *layers_len)
{
    if (layers_len == NULL) {
        return NULL;
    }
    // TODO: add lock
    return layers_by_digest_map(g_metadata.by_compress_digest, digest, layers_len);
}

struct layer** layer_store_by_uncompress_digest(const char *digest, size_t *layers_len)
{
    if (layers_len == NULL) {
        return NULL;
    }
    // TODO: add lock
    return layers_by_digest_map(g_metadata.by_uncompress_digest, digest, layers_len);
}

struct layer *layer_store_lookup(const char *name)
{
    struct layer *ret = NULL;
    layer_t *l = NULL;

    if (name == NULL) {
        return ret;
    }
    ret = util_common_calloc_s(sizeof(struct layer));
    if (ret == NULL) {
        ERROR("Out of memory");
        return ret;
    }

    l = lookup_with_lock(name);
    if (l == NULL) {
        return ret;
    }
    layer_lock(l);
    copy_json_to_layer(l, ret);
    layer_unlock(l);
    layer_ref_dec(l);
    return ret;
}

static char *mount_helper(layer_t *l, const struct layer_store_mount_opts *opts)
{
    char *mount_point = NULL;
    int nret = 0;
    int32_t save_cnt = 0;
    char *save_path = NULL;
    struct driver_mount_opts *d_opts = NULL;
    size_t i = 0;

    if (l->smount_point == NULL) {
        l->smount_point = util_common_calloc_s(sizeof(storage_mount_point));
        if (l->smount_point == NULL) {
            ERROR("Out of memory");
            return NULL;
        }
    }
    if (l->mount_point_json_path == NULL) {
        l->mount_point_json_path = mountpoint_json_path(l->slayer->id);
        if (l->mount_point_json_path == NULL) {
            return NULL;
        }
    }

    save_cnt = l->smount_point->count;
    save_path = l->smount_point->path;

    if (l->smount_point->count > 0) {
        l->smount_point->count += 1;
        mount_point = util_strdup_s(save_path);
        goto save_json;
    }

    d_opts = util_common_calloc_s(sizeof(struct driver_mount_opts));
    if (d_opts == NULL) {
        ERROR("Out of meoroy");
        goto err_out;
    }
    if (opts->mount_label == NULL) {
        d_opts->mount_label = util_strdup_s(l->slayer->mountlabel);
    } else {
        d_opts->mount_label = util_strdup_s(opts->mount_label);
    }
    if (opts->mount_opts->len > 0) {
        d_opts->options = util_smart_calloc_s(sizeof(char *), opts->mount_opts->len);
        for (; i < opts->mount_opts->len; i++) {
            char *tmp_opt = NULL;
            if (asprintf(&tmp_opt, "%s=%s", opts->mount_opts->keys[i], opts->mount_opts->values[i]) != 0) {
                ERROR("Out of memory");
                goto err_out;
            }
            d_opts->options_len += 1;
        }
    }

    mount_point = graphdriver_mount_layer(l->slayer->id, d_opts);
    if (mount_point == NULL) {
        ERROR("Call driver mount: %s failed", l->slayer->id);
        goto err_out;
    }
    l->smount_point->count += 1;
    l->smount_point->path = util_strdup_s(mount_point);

save_json:
    nret = save_mount_point(l);
    if (nret != 0) {
        l->smount_point->count = save_cnt;
        free(l->smount_point->path);
        l->smount_point->path = save_path;
        save_path = NULL;
        goto err_out;
    }
    free_graphdriver_mount_opts(d_opts);
    free(save_path);
    return mount_point;
err_out:
    free_graphdriver_mount_opts(d_opts);
    free(mount_point);
    free(save_path);
    return NULL;
}

char *layer_store_mount(const char *id, const struct layer_store_mount_opts *opts)
{
    layer_t *l = NULL;
    char *result = NULL;

    if (id == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    l = lookup_with_lock(id);
    if (l == NULL) {
        ERROR("layer not known");
        return NULL;
    }
    layer_lock(l);
    result = mount_helper(l, opts);
    layer_unlock(l);

    layer_ref_dec(l);
    return result;
}

int layer_store_umount(const char *id, bool force)
{
    layer_t *l = NULL;
    int ret = 0;

    if (id == NULL) {
        // ignore null id
        return 0;
    }
    l = lookup_with_lock(id);
    if (l == NULL) {
        ERROR("layer not known");
        return -1;
    }
    layer_lock(l);
    ret = umount_helper(l, force);
    layer_unlock(l);

    layer_ref_dec(l);
    return ret;
}

int layer_store_mounted(const char *id)
{
    layer_t *l = NULL;
    int ret = 0;

    if (id == NULL) {
        return ret;
    }
    // TODO: add lock
    l = lookup_with_lock(id);
    if (l == NULL) {
        ERROR("layer not known");
        return ret;
    }

    layer_lock(l);
    if (l->smount_point != NULL) {
        ret = l->smount_point->count;
    }
    layer_unlock(l);

    layer_ref_dec(l);
    return ret;
}

static bool remove_name(const char *name)
{
    size_t i = 0;
    bool ret = false;
    layer_t *l = map_search(g_metadata.by_name, (void *)name);
    if (l == NULL) {
        return false;
    }

    layer_lock(l);
    while (i < l->slayer->names_len) {
        if (strcmp(name, l->slayer->names[i]) == 0) {
            free(l->slayer->names[i]);
            size_t j = i + 1;
            for (; j < l->slayer->names_len; j++) {
                l->slayer->names[j - 1] = l->slayer->names[j];
                l->slayer->names[j] = NULL;
            }
            l->slayer->names_len -= 1;
            ret = true;
            continue;
        }
        i++;
    }
    layer_unlock(l);

    return ret;
}

// only use to recover name which remove by remove_name
static void recover_name(const char *name)
{
    layer_t *l = map_search(g_metadata.by_name, (void *)name);
    if (l == NULL) {
        return;
    }

    layer_lock(l);
    l->slayer->names[l->slayer->names_len] = util_strdup_s(name);
    l->slayer->names_len += 1;
    layer_unlock(l);
}

int layer_store_set_names(const char *id, const char * const* names, size_t names_len)
{
    layer_t *l = NULL;
    int ret = 0;
    size_t i = 0;
    size_t j = 0;
    bool *founds = NULL;

    if (id == NULL) {
        return -1;
    }

    founds = util_smart_calloc_s(sizeof(bool), names_len);
    if (founds == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (!layer_store_lock(true)) {
        ret = -1;
        goto unlock;
    }

    l = lookup(id);
    if (l == NULL) {
        ERROR("layer not known");
        ret = -1;
        goto unlock;
    }
    // remove old names relation
    for (; i < l->slayer->names_len; i++) {
        if (!map_remove(g_metadata.by_name, (void *)l->slayer->names[i])) {
            ERROR("Remove name %s failed", l->slayer->names[i]);
            ret = -1;
            goto recover_out;
        }
    }

    // replace new names
    for (; j < names_len; j++) {
        founds[j] = remove_name(names[j]);
        if (!map_replace(g_metadata.by_name, (void *)names[j], (void *)l)) {
            ERROR("Replace new name %s failed", names[j]);
            ret = -1;
            goto recover_out;
        }
    }

    goto unlock;
recover_out:
    while (i > 0) {
        i--;
        if (!map_insert(g_metadata.by_name, (void *)l->slayer->names[i], (void *)l)) {
            NOTICE("Recover name: %s failed", l->slayer->names[i]);
        }
    }
    while (j > 0) {
        j--;
        if (!map_remove(g_metadata.by_name, (void *)names[j])) {
            NOTICE("Recover new name %s failed", names[j]);
        }
        if (names[j]) {
            recover_name(names[j]);
        }
    }
unlock:
    layer_ref_dec(l);
    free(founds);
    layer_store_unlock();
    return ret;
}

struct layer_store_status *layer_store_status()
{
    struct graphdriver_status *d_status = NULL;
    struct layer_store_status *result = NULL;

    d_status = graphdriver_get_status();

    if (d_status == NULL) {
        return NULL;
    }
    result = util_common_calloc_s(sizeof(struct layer_store_status));
    if (result == NULL) {
        ERROR("Out of memory");
        goto out;
    }
    result->backing_fs = d_status->backing_fs;
    d_status->backing_fs = NULL;
    result->status = d_status->status;
    d_status->status = NULL;
    result->driver_name = d_status->driver_name;
    d_status->driver_name = NULL;

out:
    free_graphdriver_status(d_status);
    return result;
}

int layer_store_try_repair_lowers(const char *id)
{
    // TODO: driver need add this api
    return 0;
}

void free_layer_opts(struct layer_opts *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->parent);
    ptr->parent = NULL;
    util_free_array_by_len(ptr->names, ptr->names_len);
    ptr->names = NULL;
    ptr->names_len = 0;

    free_layer_store_mount_opts(ptr->opts);
    ptr->opts = NULL;
    free(ptr);
}

void free_layer_store_mount_opts(struct layer_store_mount_opts *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->mount_label);
    ptr->mount_label = NULL;
    free_json_map_string_string(ptr->mount_opts);
    ptr->mount_opts = NULL;
    free(ptr);
}

void free_layer_store_status(struct layer_store_status *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free(ptr->backing_fs);
    ptr->backing_fs = NULL;
    free(ptr->driver_name);
    ptr->driver_name = NULL;
    free(ptr->status);
    ptr->status = NULL;
    free(ptr);
}

