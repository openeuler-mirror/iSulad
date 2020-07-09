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
 * Author: liuhao
 * Create: 2020-03-26
 * Description: provide layer store functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "layer_store.h"

#include <pthread.h>
#include <stdio.h>
#include <limits.h>
#include <dirent.h>
#include <isula_libutils/container_inspect.h>
#include <isula_libutils/storage_layer.h>
#include <isula_libutils/storage_mount_point.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "storage.h"
#include "isula_libutils/json_common.h"
#include "layer.h"
#include "driver.h"
#include "linked_list.h"
#include "map.h"
#include "utils_timestamp.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_file.h"
#include "isula_libutils/log.h"
#include "constants.h"

struct io_read_wrapper;

typedef struct __layer_store_metadata_t {
    pthread_rwlock_t rwlock;
    map_t *by_id;
    map_t *by_name;
    map_t *by_compress_digest;
    map_t *by_uncompress_digest;
    struct linked_list layers_list;
    size_t layers_list_len;
} layer_store_metadata;

typedef struct digest_layer {
    struct linked_list layer_list;
    size_t layer_list_len;
} digest_layer_t;

static layer_store_metadata g_metadata;
static char *g_root_dir;
static char *g_run_dir;

static inline char *tar_split_path(const char *id);
static inline char *mountpoint_json_path(const char *id);
static inline char *layer_json_path(const char *id);

static int insert_digest_into_map(map_t *by_digest, const char *digest, const char *id);
static int delete_digest_from_map(map_t *by_digest, const char *digest, const char *id);

static bool remove_name(const char *name);

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
    g_metadata.by_id = NULL;
    map_free(g_metadata.by_name);
    g_metadata.by_name = NULL;
    map_free(g_metadata.by_compress_digest);
    g_metadata.by_compress_digest = NULL;
    map_free(g_metadata.by_uncompress_digest);
    g_metadata.by_uncompress_digest = NULL;

    linked_list_for_each_safe(item, &(g_metadata.layers_list), next) {
        linked_list_del(item);
        layer_ref_dec((layer_t *)item->elem);
        free(item);
        item = NULL;
    }
    g_metadata.layers_list_len = 0;

    pthread_rwlock_destroy(&(g_metadata.rwlock));

    free(g_run_dir);
    g_run_dir = NULL;
    free(g_root_dir);
    g_root_dir = NULL;
}

/* layers map kvfree */
static void layer_map_kvfree(void *key, void *value)
{
    free(key);
}

static void free_digest_layer_t(digest_layer_t *ptr)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (ptr == NULL) {
        return;
    }

    linked_list_for_each_safe(item, &(ptr->layer_list), next) {
        linked_list_del(item);
        free(item->elem);
        item->elem = NULL;
        free(item);
        item = NULL;
    }

    ptr->layer_list_len = 0;
    free(ptr);
}

static void digest_map_kvfree(void *key, void *value)
{
    digest_layer_t *val = (digest_layer_t *)value;

    free(key);
    free_digest_layer_t(val);
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

//TODO check layer of a image, check if tar-splite and driver data exist
static int do_validate_image_layer(layer_t *l)
{
    // it is not a layer of image
    if (l->slayer->diff_digest == NULL) {
        return 0;
    }

    // TODO check if tar-splite and driver data exist

    return 0;
}

static int update_mount_point(layer_t *l)
{
    container_inspect_graph_driver *d_meta = NULL;
    int ret = 0;

    if (l->smount_point == NULL) {
        l->smount_point = util_common_calloc_s(sizeof(storage_mount_point));
        if (l->smount_point == NULL) {
            ERROR("Out of memory");
            return -1;
        }
    }

    d_meta = graphdriver_get_metadata(l->slayer->id);
    if (d_meta == NULL) {
        ERROR("Get metadata of driver failed");
        ret = -1;
        goto out;
    }
    if (d_meta->data != NULL) {
        free(l->smount_point->path);
        l->smount_point->path = util_strdup_s(d_meta->data->merged_dir);
    }

    if (l->mount_point_json_path == NULL) {
        l->mount_point_json_path = mountpoint_json_path(l->slayer->id);
        if (l->mount_point_json_path == NULL) {
            ERROR("Failed to get layer %s mount point json", l->slayer->id);
            ret = -1;
            goto out;
        }
    }

out:
    free_container_inspect_graph_driver(d_meta);
    return ret;
}

static struct driver_mount_opts *fill_driver_mount_opts(const struct layer_store_mount_opts *opts, const layer_t *l)
{
    size_t i = 0;
    struct driver_mount_opts *d_opts = NULL;

    d_opts = util_common_calloc_s(sizeof(struct driver_mount_opts));
    if (d_opts == NULL) {
        ERROR("Out of meoroy");
        goto err_out;
    }

    if (opts == NULL || opts->mount_label == NULL) {
        d_opts->mount_label = util_strdup_s(l->slayer->mountlabel);
    } else {
        d_opts->mount_label = util_strdup_s(opts->mount_label);
    }

    if (opts != NULL && opts->mount_opts->len > 0) {
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

    return d_opts;

err_out:
    free_graphdriver_mount_opts(d_opts);
    return NULL;
}

static char *mount_helper(layer_t *l, const struct layer_store_mount_opts *opts)
{
    char *mount_point = NULL;
    int nret = 0;
    struct driver_mount_opts *d_opts = NULL;

    nret = update_mount_point(l);
    if (nret != 0) {
        ERROR("Failed to update mount point");
        return NULL;
    }

    if (l->smount_point->count > 0) {
        l->smount_point->count += 1;
        mount_point = util_strdup_s(l->smount_point->path);
        goto save_json;
    }

    d_opts = fill_driver_mount_opts(opts, l);
    if (d_opts == NULL) {
        ERROR("Failed to fill layer %s driver mount opts", l->slayer->id);
        goto out;
    }

    mount_point = graphdriver_mount_layer(l->slayer->id, d_opts);
    if (mount_point == NULL) {
        ERROR("Call driver mount: %s failed", l->slayer->id);
        goto out;
    }

    l->smount_point->count += 1;

save_json:
    (void)save_mount_point(l);

out:
    free_graphdriver_mount_opts(d_opts);
    return mount_point;
}

static int do_validate_rootfs_layer(layer_t *l)
{
    int ret = 0;
    char *mount_point = NULL;

    // it is a layer of image, just ignore
    if (l->slayer->diff_digest != NULL) {
        return 0;
    }

    if (update_mount_point(l) != 0) {
        ERROR("Failed to update mount point");
        ret = -1;
        goto out;
    }

    // try to mount the layer, and set mount count to 1
    if (l->smount_point->count > 0) {
        l->smount_point->count = 0;
        mount_point = mount_helper(l, NULL);
        if (mount_point == NULL) {
            ERROR("Failed to mount layer %s", l->slayer->id);
            ret = -1;
            goto out;
        }
    }

out:
    free(mount_point);
    return ret;
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
        ret = false;
        goto free_out;
    }

    if (!util_dir_exists(tmpdir)) {
        // ignore non-dir
        DEBUG("%s is not directory", sub_dir->d_name);
        ret = true;
        goto free_out;
    }

    if (strlen(sub_dir->d_name) != LAYER_NAME_LEN) {
        DEBUG("%s is invalid subdir name", sub_dir->d_name);
        ret = true;
        goto free_out;
    }

    rpath = layer_json_path(sub_dir->d_name);
    if (rpath == NULL) {
        ret = false;
        goto remove_invalid_dir;
    }
    mount_point_path = mountpoint_json_path(sub_dir->d_name);
    if (mount_point_path == NULL) {
        ret = false;
        goto remove_invalid_dir;
    }

    l = load_layer(rpath, mount_point_path);
    if (l == NULL) {
        WARN("load layer: %s failed", sub_dir->d_name);
        ret = false;
        goto remove_invalid_dir;
    }

    if (do_validate_image_layer(l) != 0) {
        ret = false;
        goto remove_invalid_dir;
    }

    if (do_validate_rootfs_layer(l) != 0) {
        ret = false;
        goto remove_invalid_dir;
    }

    if (!append_layer_into_list(l)) {
        ERROR("Failed to append layer info to list");
        ret = false;
        goto remove_invalid_dir;
    }

    ret = true;
    goto free_out;

remove_invalid_dir:
    (void)graphdriver_umount_layer(sub_dir->d_name);
    (void)graphdriver_rm_layer(sub_dir->d_name);
    (void)util_recursive_rmdir(tmpdir, 0);

free_out:
    free(rpath);
    free(mount_point_path);
    if (!ret) {
        free_layer_t(l);
    }
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

        if (!map_insert(g_metadata.by_id, (void *)tl->slayer->id, (void *)tl)) {
            ERROR("Insert id: %s for layer failed", tl->slayer->id);
            ret = -1;
            goto unlock_out;
        }

        for (; i < tl->slayer->names_len; i++) {
            if (remove_name(tl->slayer->names[i])) {
                should_save = true;
            }
            if (!map_insert(g_metadata.by_name, (void *)tl->slayer->names[i], (void *)tl)) {
                ret = -1;
                ERROR("Insert name: %s for layer failed", tl->slayer->names[i]);
                goto unlock_out;
            }
        }

        ret = insert_digest_into_map(g_metadata.by_compress_digest, tl->slayer->compressed_diff_digest, tl->slayer->id);
        if (ret != 0) {
            ERROR("update layer: %s compress failed", tl->slayer->id);
            goto unlock_out;
        }

        ret = insert_digest_into_map(g_metadata.by_uncompress_digest, tl->slayer->diff_digest, tl->slayer->id);
        if (ret != 0) {
            ERROR("update layer: %s uncompress failed", tl->slayer->id);
            goto unlock_out;
        }

        // check complete
        if (tl->slayer->incompelte) {
            if (layer_store_delete(tl->slayer->id) != 0) {
                ERROR("delete layer: %s failed", tl->slayer->id);
                ret = -1;
                goto unlock_out;
            }
            should_save = true;
        }

        if (should_save && save_layer(tl) != 0) {
            ERROR("save layer: %s failed", tl->slayer->id);
            ret = -1;
            goto unlock_out;
        }
    }

    ret = 0;
    goto unlock_out;
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

    if (load_layers_from_json_files() != 0) {
        goto free_out;
    }

    DEBUG("Init layer store success");
    return 0;
free_out:
    layer_store_cleanup();
    return -1;
}

void layer_store_exit()
{
    graphdriver_cleanup();
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

    goto out;
err_out:
    free(id);
    id = NULL;
out:
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
                ret = append_json_map_string_string(c_opts.storage_opt, opt->mount_opts->keys[i],
                                                    opt->mount_opts->values[i]);
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
        ret = graphdriver_create_ro(id, parent, &c_opts);
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
    slayer->diff_digest = util_strdup_s(opts->uncompressed_digest);
    slayer->compressed_diff_digest = util_strdup_s(opts->compressed_digest);

    l->layer_json_path = layer_json_path(id);
    if (l->layer_json_path == NULL) {
        ret = -1;
        goto free_out;
    }

    l->slayer = slayer;

free_out:
    if (ret != 0) {
        free_storage_layer(slayer);
    }
    return ret;
}

static int delete_digest_from_map(map_t *by_digest, const char *digest, const char *id)
{
    digest_layer_t *old_list = NULL;
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;

    if (digest == NULL) {
        return 0;
    }

    old_list = (digest_layer_t *)map_search(by_digest, (void *)digest);
    if (old_list == NULL) {
        return 0;
    }

    linked_list_for_each_safe(item, &(old_list->layer_list), next) {
        char *t_id = (char *)item->elem;
        if (strcmp(t_id, id) == 0) {
            linked_list_del(item);
            free(item->elem);
            item->elem = NULL;
            free(item);
            old_list->layer_list_len -= 1;
            break;
        }
    }

    if (old_list->layer_list_len == 0 && !map_remove(by_digest, (void *)digest)) {
        WARN("Remove old failed");
    }

    return 0;
}

static int insert_new_digest_list(map_t *by_digest, const char *digest, struct linked_list *item)
{
    digest_layer_t *new_list = NULL;

    new_list = (digest_layer_t *)util_common_calloc_s(sizeof(digest_layer_t));
    if (new_list == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    linked_list_init(&(new_list->layer_list));
    linked_list_add_tail(&(new_list->layer_list), item);
    new_list->layer_list_len += 1;
    if (!map_insert(by_digest, (void *)digest, (void *)new_list)) {
        linked_list_del(item);
        goto free_out;
    }

    return 0;
free_out:
    free_digest_layer_t(new_list);
    return -1;
}

static int insert_digest_into_map(map_t *by_digest, const char *digest, const char *id)
{
    digest_layer_t *old_list = NULL;
    struct linked_list *item = NULL;

    if (digest == NULL) {
        INFO("Layer: %s with empty digest", id);
        return 0;
    }

    item = (struct linked_list *)util_common_calloc_s(sizeof(struct linked_list));
    if (item == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    linked_list_add_elem(item, (void *)util_strdup_s(id));

    old_list = (digest_layer_t *)map_search(by_digest, (void *)digest);
    if (old_list == NULL) {
        if (insert_new_digest_list(by_digest, digest, item) != 0) {
            ERROR("Insert new digest: %s failed", digest);
            goto free_out;
        }
    } else {
        linked_list_add_tail(&(old_list->layer_list), item);
        old_list->layer_list_len += 1;
    }

    return 0;
free_out:
    free(item->elem);
    free(item);
    return -1;
}

static int remove_memory_stores(const char *id)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    layer_t *l = NULL;
    size_t i = 0;
    int ret = 0;

    l = lookup(id);
    if (l == NULL) {
        ERROR("layer not known");
        return -1;
    }

    if (delete_digest_from_map(g_metadata.by_compress_digest, l->slayer->compressed_diff_digest, l->slayer->id) != 0) {
        ERROR("Remove %s from compress digest failed", id);
        ret = -1;
        goto out;
    }
    if (delete_digest_from_map(g_metadata.by_uncompress_digest, l->slayer->diff_digest, l->slayer->id) != 0) {
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

out:
    layer_ref_dec(l);
    return ret;
}

static int insert_memory_stores(const char *id, const struct layer_opts *opts, layer_t *l)
{
    int ret = 0;
    size_t i = 0;

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

    if (l->slayer->compressed_diff_digest != NULL) {
        ret = insert_digest_into_map(g_metadata.by_compress_digest, l->slayer->compressed_diff_digest, id);
        if (ret != 0) {
            goto clear_by_name;
        }
    }

    if (l->slayer->diff_digest != NULL) {
        ret = insert_digest_into_map(g_metadata.by_uncompress_digest, l->slayer->diff_digest, id);
        if (ret != 0) {
            goto clear_compress_digest;
        }
    }

    goto out;
clear_compress_digest:
    if (l->slayer->compressed_diff_digest != NULL) {
        (void)delete_digest_from_map(g_metadata.by_compress_digest, l->slayer->compressed_diff_digest, id);
    }
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
    return ret;
}

static int apply_diff(layer_t *l, const struct io_read_wrapper *diff)
{
    int64_t size = 0;
    int ret = 0;

    if (diff == NULL) {
        return 0;
    }

    ret = graphdriver_apply_diff(l->slayer->id, diff, &size);

    INFO("Apply layer get size: %ld", size);
    l->slayer->diff_size = size;
    // uncompress digest get from up caller

    // TODO: save split tar

    return ret;
}

static int check_create_layer_used(char **id, const struct layer_opts *opts)
{
    layer_t *l = NULL;
    int ret = 0;
    size_t i = 0;
    char *lid = *id;

    if (lid == NULL) {
        lid = generate_random_layer_id();
    }
    if (lid == NULL) {
        return -1;
    }
    *id = lid;

    l = map_search(g_metadata.by_id, (void *)lid);
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
    return ret;
}

static bool build_layer_dir(const char *id)
{
    char *result = NULL;
    int nret = 0;
    bool ret = true;

    nret = asprintf(&result, "%s/%s", g_root_dir, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create layer json path failed");
        return false;
    }

    if (util_mkdir_p(result, IMAGE_STORE_PATH_MODE) != 0) {
        ret = false;
    }

    free(result);
    return ret;
}

static int new_layer_by_opts(const char *id, const struct layer_opts *opts)
{
    int ret = 0;
    layer_t *l = NULL;

    l = create_empty_layer();
    if (l == NULL) {
        ret = -1;
        goto out;
    }
    if (!build_layer_dir(id)) {
        ret = -1;
        goto out;
    }

    ret = update_layer_datas(id, opts, l);
    if (ret != 0) {
        goto out;
    }

    // update memory store
    ret = insert_memory_stores(id, opts, l);

out:
    if (ret != 0) {
        layer_ref_dec(l);
    }
    return ret;
}

static int layer_store_remove_layer(const char *id)
{
    char *rpath = NULL;
    int ret = 0;
    int nret = 0;

    if (id == NULL) {
        return 0;
    }

    nret = asprintf(&rpath, "%s/%s", g_root_dir, id);
    if (nret < 0 || nret > PATH_MAX) {
        SYSERROR("Create layer json path failed");
        return -1;
    }

    ret = util_recursive_rmdir(rpath, 0);
    free(rpath);
    return ret;
}

int layer_store_create(const char *id, const struct layer_opts *opts, const struct io_read_wrapper *diff, char **new_id)
{
    int ret = 0;
    char *lid = util_strdup_s(id);
    layer_t *l = NULL;

    if (opts == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (!layer_store_lock(true)) {
        return -1;
    }

    ret = check_create_layer_used(&lid, opts);
    if (ret != 0) {
        goto free_out;
    }

    // create layer by driver
    ret = driver_create_layer(lid, opts->parent, opts->writable, opts->opts);
    if (ret != 0) {
        goto free_out;
    }
    ret = new_layer_by_opts(lid, opts);
    if (ret != 0) {
        goto driver_remove;
    }

    l = lookup(lid);
    if (l == NULL) {
        ret = -1;
        goto driver_remove;
    }
    l->slayer->incompelte = true;
    if (save_layer(l) != 0) {
        ret = -1;
        goto driver_remove;
    }

    ret = apply_diff(l, diff);
    if (ret != 0) {
        goto clear_memory;
    }
    ret = update_mount_point(l);
    if (ret != 0) {
        goto clear_memory;
    }

    l->slayer->incompelte = false;

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
    (void)remove_memory_stores(lid);
driver_remove:
    if (ret != 0) {
        (void)graphdriver_rm_layer(lid);
        (void)layer_store_remove_layer(lid);
    }
free_out:
    layer_store_unlock();
    layer_ref_dec(l);
    free(lid);
    return ret;
}

static int umount_helper(layer_t *l, bool force)
{
    int ret = 0;

    if (l->smount_point == NULL) {
        return 0;
    }

    if (!force && l->smount_point->count > 1) {
        l->smount_point->count -= 1;
        goto save_json;
    }

    // TODO: not exist file error need to ignore
    ret = graphdriver_umount_layer(l->slayer->id);
    if (ret != 0) {
        ERROR("Call driver umount failed");
        ret = -1;
        goto out;
    }
    l->smount_point->count = 0;

save_json:
    (void)save_mount_point(l);
out:
    return ret;
}

int layer_store_delete(const char *id)
{
    layer_t *l = NULL;
    int ret = 0;
    char *tspath = NULL;

    if (id == NULL) {
        return -1;
    }
    if (!layer_store_lock(true)) {
        return -1;
    }

    l = lookup(id);
    if (l == NULL) {
        ERROR("layer not known");
        ret = -1;
        goto free_out;
    }

    if (umount_helper(l, true) != 0) {
        ret = -1;
        ERROR("Failed to umount layer %s", l->slayer->id);
        goto free_out;
    }

    if (l->mount_point_json_path != NULL && util_path_remove(l->mount_point_json_path) != 0) {
        SYSERROR("Can not remove mount point file of layer %s, just ignore.", l->mount_point_json_path);
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
    layer_ref_dec(l);
    layer_store_unlock();
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

int layer_store_list(struct layer_list *resp)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    size_t i = 0;
    int ret = 0;

    if (resp == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (!layer_store_lock(false)) {
        return -1;
    }

    resp->layers = (struct layer **)util_smart_calloc_s(sizeof(struct layer *), g_metadata.layers_list_len);
    if (resp->layers == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto unlock;
    }

    linked_list_for_each_safe(item, &(g_metadata.layers_list), next) {
        layer_t *l = (layer_t *)item->elem;
        resp->layers[i] = util_common_calloc_s(sizeof(struct layer));
        if (resp->layers[i] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto unlock;
        }
        copy_json_to_layer(l, resp->layers[i]);
        i++;
        resp->layers_len += 1;
    }

unlock:
    layer_store_unlock();
    return ret;
}

static int layers_by_digest_map(map_t *m, const char *digest, struct layer_list *resp)
{
    struct linked_list *item = NULL;
    struct linked_list *next = NULL;
    int ret = -1;
    digest_layer_t *id_list = NULL;
    size_t i = 0;

    if (!layer_store_lock(false)) {
        return -1;
    }

    id_list = (digest_layer_t *)map_search(m, (void *)digest);
    if (id_list == NULL) {
        ERROR("Not found digest: %s", digest);
        goto free_out;
    }

    if (id_list->layer_list_len == 0) {
        ret = 0;
        goto free_out;
    }

    resp->layers = (struct layer **)util_smart_calloc_s(sizeof(struct layer *), id_list->layer_list_len);
    if (resp->layers == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    linked_list_for_each_safe(item, &(id_list->layer_list), next) {
        layer_t *l = NULL;
        resp->layers[i] = util_common_calloc_s(sizeof(struct layer));
        if (resp->layers[i] == NULL) {
            ERROR("Out of memory");
            goto free_out;
        }
        l = lookup((char *)item->elem);
        if (l == NULL) {
            ERROR("layer not known");
            goto free_out;
        }
        copy_json_to_layer(l, resp->layers[i]);
        layer_ref_dec(l);
        resp->layers_len += 1;
        i++;
    }

    ret = 0;
free_out:
    layer_store_unlock();
    return ret;
}

int layer_store_by_compress_digest(const char *digest, struct layer_list *resp)
{
    if (resp == NULL) {
        return -1;
    }
    return layers_by_digest_map(g_metadata.by_compress_digest, digest, resp);
}

int layer_store_by_uncompress_digest(const char *digest, struct layer_list *resp)
{
    if (resp == NULL) {
        return -1;
    }
    return layers_by_digest_map(g_metadata.by_uncompress_digest, digest, resp);
}

struct layer *layer_store_lookup(const char *name)
{
    struct layer *ret = NULL;
    layer_t *l = NULL;

    if (name == NULL) {
        return ret;
    }

    l = lookup_with_lock(name);
    if (l == NULL) {
        return ret;
    }

    ret = util_common_calloc_s(sizeof(struct layer));
    if (ret == NULL) {
        ERROR("Out of memory");
        layer_ref_dec(l);
        return ret;
    }

    copy_json_to_layer(l, ret);
    layer_ref_dec(l);
    return ret;
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
    if (result == NULL) {
        ERROR("Failed to mount layer %s", id);
    }
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

int layer_store_try_repair_lowers(const char *id)
{
    layer_t *l = NULL;
    int ret = 0;

    l = lookup_with_lock(id);
    if (l == NULL) {
        return -1;
    }
    ret = graphdriver_try_repair_lowers(id, l->slayer->parent);
    layer_ref_dec(l);

    return ret;
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
    free(ptr->uncompressed_digest);
    ptr->uncompressed_digest = NULL;
    free(ptr->compressed_digest);
    ptr->compressed_digest = NULL;

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

int layer_store_get_layer_fs_info(const char *layer_id, imagetool_fs_info *fs_info)
{
    return graphdriver_get_layer_fs_info(layer_id, fs_info);
}
