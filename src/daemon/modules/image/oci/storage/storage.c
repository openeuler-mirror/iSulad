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
 * Author: lifeng
 * Create: 2020-04-01
 * Description: provide storage functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "storage.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <isula_libutils/imagetool_fs_info.h>
#include <isula_libutils/imagetool_images_list.h>
#include <isula_libutils/storage_rootfs.h>
#include <pthread.h>

#include "io_wrapper.h"
#include "utils.h"
#include "utils_images.h"
#include "isula_libutils/log.h"
#include "isulad_config.h"
#include "layer_store.h"
#include "image_store.h"
#include "rootfs_store.h"
#include "err_msg.h"
#include "constants.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"
#include "sha256.h"

static pthread_rwlock_t g_storage_rwlock;
static char *g_storage_run_root;

static bool storage_integration_check();

static inline bool storage_lock(pthread_rwlock_t *store_lock, bool writable)
{
    int nret = 0;

    if (writable) {
        nret = pthread_rwlock_wrlock(store_lock);
    } else {
        nret = pthread_rwlock_rdlock(store_lock);
    }
    if (nret != 0) {
        ERROR("Lock memory store failed: %s", strerror(nret));
        return false;
    }

    return true;
}

static inline void storage_unlock(pthread_rwlock_t *store_lock)
{
    int nret = 0;

    nret = pthread_rwlock_unlock(store_lock);
    if (nret != 0) {
        FATAL("Unlock memory store failed: %s", strerror(nret));
    }
}

static ssize_t layer_archive_io_read(void *context, void *buf, size_t buf_len)
{
    int *read_fd = (int *)context;

    return util_read_nointr(*read_fd, buf, buf_len);
}

static int layer_archive_io_close(void *context, char **err)
{
    int *read_fd = (int *)context;

    close(*read_fd);

    free(read_fd);

    return 0;
}

static int fill_read_wrapper(const char *layer_data_path, struct io_read_wrapper **reader)
{
    int ret = 0;
    int *fd_ptr = NULL;
    struct io_read_wrapper *reader_tmp = NULL;

    if (layer_data_path == NULL) {
        return 0;
    }

    reader_tmp = util_common_calloc_s(sizeof(struct io_read_wrapper));
    if (reader_tmp == NULL) {
        ERROR("Memory out");
        return -1;
    }

    fd_ptr = util_common_calloc_s(sizeof(int));
    if (fd_ptr == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto err_out;
    }

    *fd_ptr = util_open(layer_data_path, O_RDONLY, 0);
    if (*fd_ptr == -1) {
        ERROR("Failed to open layer data %s", layer_data_path);
        ret = -1;
        goto err_out;
    }

    reader_tmp->context = fd_ptr;
    reader_tmp->read = layer_archive_io_read;
    reader_tmp->close = layer_archive_io_close;
    *reader = reader_tmp;

    fd_ptr = NULL;
    reader_tmp = NULL;

err_out:
    free(fd_ptr);
    free(reader_tmp);

    return ret;
}

static struct layer_opts *fill_create_layer_opts(storage_layer_create_opts_t *copts, const char *mount_label)
{
    struct layer_opts *opts = NULL;

    opts = util_common_calloc_s(sizeof(struct layer_opts));
    if (opts == NULL) {
        ERROR("Memory out");
        goto out;
    }

    opts->parent = util_strdup_s(copts->parent);
    opts->uncompressed_digest = util_strdup_s(copts->uncompress_digest);
    opts->compressed_digest = util_strdup_s(copts->compressed_digest);
    opts->writable = copts->writable;

    opts->opts = util_common_calloc_s(sizeof(struct layer_store_mount_opts));
    if (opts->opts == NULL) {
        ERROR("Memory out");
        goto err_out;
    }

    if (mount_label != NULL) {
        opts->opts->mount_label = util_strdup_s(mount_label);
    }

    if (copts->storage_opts != NULL) {
        opts->opts->mount_opts = util_common_calloc_s(sizeof(json_map_string_string));
        if (opts->opts->mount_opts == NULL) {
            ERROR("Memory out");
            goto err_out;
        }
        if (dup_json_map_string_string(copts->storage_opts, opts->opts->mount_opts) != 0) {
            ERROR("Failed to dup storage opts");
            goto err_out;
        }
    }

    goto out;

err_out:
    free_layer_opts(opts);
    opts = NULL;

out:
    return opts;
}

int storage_inc_hold_refs(const char *layer_id)
{
    int ret = 0;

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock image store when increase hold refs number for layer %s", layer_id);
        return -1;
    }

    ret = layer_inc_hold_refs(layer_id);

    storage_unlock(&g_storage_rwlock);

    return ret;
}

int storage_dec_hold_refs(const char *layer_id)
{
    int ret = 0;

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock image store when decrease hold refs number for layer %s", layer_id);
        return -1;
    }

    ret = layer_dec_hold_refs(layer_id);

    storage_unlock(&g_storage_rwlock);

    return ret;
}

int storage_layer_create(const char *layer_id, storage_layer_create_opts_t *copts)
{
    int ret = 0;
    struct io_read_wrapper *reader = NULL;
    struct layer_opts *opts = NULL;

    if (copts == NULL) {
        ERROR("Create opts is null");
        return -1;
    }

    if (!copts->writable && copts->layer_data_path == NULL) {
        ERROR("Invalid arguments for put ro layer");
        ret = -1;
        goto out;
    }

    if (fill_read_wrapper(copts->layer_data_path, &reader) != 0) {
        ERROR("Failed to fill layer read wrapper");
        ret = -1;
        goto out;
    }

    opts = fill_create_layer_opts(copts, NULL);
    if (opts == NULL) {
        ERROR("Failed to fill create ro layer options");
        ret = -1;
        goto out;
    }

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock image store, not allowed to create new layer");
        ret = -1;
        goto out;
    }

    ret = layer_store_create(layer_id, opts, reader, NULL);
    if (ret != 0) {
        ERROR("Failed to call layer store create");
        ret = -1;
        goto unlock_out;
    }

unlock_out:
    storage_unlock(&g_storage_rwlock);

out:
    if (reader != NULL) {
        if (reader->close != NULL) {
            reader->close(reader->context, NULL);
        }
        free(reader);
    }
    free_layer_opts(opts);
    return ret;
}

struct layer_list *storage_layers_get_by_compress_digest(const char *digest)
{
    int ret = 0;
    struct layer_list *layers = NULL;

    layers = util_common_calloc_s(sizeof(struct layer_list));
    if (layers == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ret = layer_store_by_compress_digest(digest, layers);
    if (ret != 0) {
        WARN("get layers by compressed digest failed");
        goto out;
    }

out:

    if (ret != 0) {
        free(layers);
        layers = NULL;
    }

    return layers;
}

struct layer *storage_layer_get(const char *layer_id)
{
    return layer_store_lookup(layer_id);
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

int storage_layer_try_repair_lowers(const char *layer_id, const char *last_layer_id)
{
    return layer_store_try_repair_lowers(layer_id);
}

int storage_img_create(const char *id, const char *parent_id, const char *metadata,
                       struct storage_img_create_options *opts)
{
    int ret = 0;
    char *image_id = NULL;

    if (id == NULL || opts == NULL) {
        ERROR("Invalid arguments for image create");
        ret = -1;
        goto out;
    }

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock storage, not allowed to create new images");
        ret = -1;
        goto out;
    }

    image_id = image_store_create(id, NULL, 0, parent_id, metadata, opts->create_time, opts->digest);
    if (image_id == NULL) {
        ERROR("Failed to create img");
        ret = -1;
        goto unlock_out;
    }

unlock_out:
    storage_unlock(&g_storage_rwlock);
out:
    free(image_id);
    return ret;
}

imagetool_image *storage_img_get(const char *img_id)
{
    char *normalized_name = NULL;
    imagetool_image *image_info = NULL;

    if (img_id == NULL) {
        ERROR("Invalid arguments for image get");
        return NULL;
    }

    if (util_valid_short_sha256_id(img_id) && image_store_exists(img_id)) {
        image_info = image_store_get_image(img_id);
    } else {
        normalized_name = oci_normalize_image_name(img_id);
        image_info = image_store_get_image(normalized_name);
    }

    free(normalized_name);
    return image_info;
}

imagetool_image_summary *storage_img_get_summary(const char *img_id)
{
    char *normalized_name = NULL;
    imagetool_image_summary *image_summary = NULL;

    if (img_id == NULL) {
        ERROR("Invalid arguments for image get summary");
        return NULL;
    }

    if (util_valid_short_sha256_id(img_id) && image_store_exists(img_id)) {
        image_summary = image_store_get_image_summary(img_id);
    } else {
        normalized_name = oci_normalize_image_name(img_id);
        image_summary = image_store_get_image_summary(normalized_name);
    }

    free(normalized_name);
    return image_summary;
}

int storage_img_set_big_data(const char *img_id, const char *key, const char *val)
{
    int ret = 0;

    if (img_id == NULL || key == NULL || val == NULL) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    if (image_store_set_big_data(img_id, key, val) != 0) {
        ERROR("Failed to set img %s big data %s=%s", img_id, key, val);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int storage_img_get_names(const char *img_id, char ***names, size_t *names_len)
{
    int ret = 0;

    if (img_id == NULL || names == NULL || names_len == NULL) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    if (image_store_get_names(img_id, names, names_len) != 0) {
        ERROR("Failed to get img %s names", img_id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int storage_img_set_names(const char *img_id, const char **names, size_t names_len)
{
    int ret = 0;
    char **unique_names = NULL;
    size_t unique_names_len = 0;

    if (img_id == NULL || names == NULL || names_len == 0) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    if (util_string_array_unique(names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    if (image_store_set_names(img_id, (const char **)unique_names, unique_names_len) != 0) {
        ERROR("Failed to set img %s names", img_id);
        ret = -1;
        goto out;
    }

out:
    util_free_array_by_len(unique_names, unique_names_len);
    return ret;
}

int storage_img_add_name(const char *img_id, const char *img_name)
{
    int ret = 0;

    if (img_id == NULL || img_name == NULL) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    if (image_store_add_name(img_id, img_name) != 0) {
        ERROR("Failed to add img %s name %s", img_id, img_name);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

char *storage_img_get_image_id(const char *img_name)
{
    if (img_name == NULL) {
        ERROR("Invalid arguments");
        return NULL;
    }

    return image_store_lookup(img_name);
}

bool is_top_layer_of_other_image(const char *img_id, const imagetool_images_list *all_images, const char *layer_id)
{
    size_t i = 0;

    for (i = 0; i < all_images->images_len; i++) {
        if (strcmp(all_images->images[i]->top_layer, layer_id) == 0 &&
            strcmp(all_images->images[i]->id, layer_id) != 0) {
            return true;
        }
    }

    return false;
}

bool is_parent_layer_of_other_layer(const char *layer_id, const char *last_deleted_layer_id,
                                    const struct layer_list *all_layers)
{
    size_t i = 0;

    for (i = 0; i < all_layers->layers_len; i++) {
        if (all_layers->layers[i]->parent != NULL && strcmp(all_layers->layers[i]->parent, layer_id) == 0) {
            if (last_deleted_layer_id == NULL || strcmp(all_layers->layers[i]->id, last_deleted_layer_id) != 0) {
                return true;
            }
        }
    }

    return false;
}

static int do_delete_related_layers(const char *img_id, const char *img_top_layer_id,
                                    const imagetool_images_list *all_images, const struct layer_list *all_layers)
{
    int ret = 0;
    char *layer_id = NULL;
    char *last_deleted_layer_id = NULL;
    struct layer *layer_info = NULL;
    int refs_num = 0;

    layer_id = util_strdup_s(img_top_layer_id);
    if (layer_id == NULL) {
        ERROR("Memory out %s", img_id);
        ret = -1;
        goto out;
    }

    while (layer_id != NULL) {
        ret = layer_get_hold_refs(layer_id, &refs_num);
        if (ret != 0) {
            break;
        }
        // if the layer's hold refs number not 0, it means it's pulling/importing/loading or
        // other layer creating actions, so do not delete it
        if (refs_num > 0) {
            break;
        }

        // if the layer is the top layer of other image, then break
        if (is_top_layer_of_other_image(img_id, all_images, layer_id)) {
            break;
        }

        if (is_parent_layer_of_other_layer(layer_id, last_deleted_layer_id, all_layers)) {
            break;
        }

        layer_info = layer_store_lookup(layer_id);
        if (layer_info == NULL) {
            ERROR("Failed to get layer info for layer %s", layer_id);
            ret = -1;
            goto out;
        }

        if (layer_store_delete(layer_id) != 0) {
            ERROR("Failed to remove layer %s", layer_id);
            ret = -1;
            goto out;
        }

        free(last_deleted_layer_id);
        last_deleted_layer_id = util_strdup_s(layer_id);
        free(layer_id);
        layer_id = util_strdup_s(layer_info->parent);
        free_layer(layer_info);
        layer_info = NULL;
    }
out:
    free(last_deleted_layer_id);
    free(layer_id);
    free_layer(layer_info);
    return ret;
}

static int delete_img_related_layers(const char *img_id, const char *img_top_layer_id)
{
    int ret = 0;
    imagetool_images_list *all_images = NULL;
    struct layer_list *all_layers = NULL;

    all_images = util_common_calloc_s(sizeof(imagetool_images_list));
    if (all_images == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    all_layers = util_common_calloc_s(sizeof(struct layer_list));
    if (all_layers == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    if (image_store_get_all_images(all_images) != 0) {
        ERROR("Failed to get all images info");
        ret = -1;
        goto out;
    }

    if (layer_store_list(all_layers) != 0) {
        ERROR("Failed to get all images info");
        ret = -1;
        goto out;
    }

    ret = do_delete_related_layers(img_id, img_top_layer_id, all_images, all_layers);

out:
    free_imagetool_images_list(all_images);
    free_layer_list(all_layers);

    return ret;
}

int storage_layer_chain_delete(const char *layer_id)
{
    int ret = 0;

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock image store, not allowed to create new layer");
        return -1;
    }

    ret = delete_img_related_layers("", layer_id);
    if (ret != 0) {
        ERROR("Failed to call layer store delete");
    }

    storage_unlock(&g_storage_rwlock);

    return ret;
}

static void free_rootfs_list(struct rootfs_list *list)
{
    size_t i;

    if (list == NULL) {
        return;
    }

    for (i = 0; i < list->rootfs_len; i++) {
        free_storage_rootfs(list->rootfs[i]);
        list->rootfs[i] = NULL;
    }

    free(list->rootfs);
    list->rootfs = NULL;
    list->rootfs_len = 0;

    free(list);
}

static int check_image_occupancy_status(const char *img_id, bool *in_using)
{
    bool ret = 0;
    size_t i;
    struct rootfs_list *all_rootfs = NULL;
    char *img_long_id = NULL;

    img_long_id = image_store_lookup(img_id);
    if (img_long_id == NULL) {
        ERROR("Image not known");
        return -1;
    }

    all_rootfs = util_common_calloc_s(sizeof(struct rootfs_list));
    if (all_rootfs == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (rootfs_store_get_all_rootfs(all_rootfs) != 0) {
        ERROR("Failed to get all container rootfs information");
        ret = -1;
        goto out;
    }

    for (i = 0; i < all_rootfs->rootfs_len; i++) {
        if (strcmp(all_rootfs->rootfs[i]->image, img_long_id) == 0) {
            isulad_set_error_message("Image used by %s", all_rootfs->rootfs[i]->id);
            ERROR("Image used by %s", all_rootfs->rootfs[i]->id);
            *in_using = true;
            goto out;
        }
    }

out:
    free(img_long_id);
    free_rootfs_list(all_rootfs);
    return ret;
}

static int do_storage_img_delete(const char *img_id, bool commit)
{
    int ret = 0;
    bool in_using = false;
    imagetool_image_summary *image_info = NULL;

    if (!image_store_exists(img_id)) {
        WARN("Image %s not exists", img_id);
        ret = 0;
        goto out;
    }

    image_info = image_store_get_image_summary(img_id);
    if (image_info == NULL) {
        ERROR("Failed to get image %s info", img_id);
        ret = -1;
        goto out;
    }

    if (check_image_occupancy_status(img_id, &in_using) != 0) {
        ERROR("Failed to check image occupancy status");
        ret = -1;
        goto out;
    }

    if (in_using) {
        ERROR("Image is in use by a container");
        ret = -1;
        goto out;
    }

    if (image_store_delete(image_info->id) != 0) {
        ERROR("Failed to delete img %s", img_id);
        ret = -1;
        goto out;
    }

    if (delete_img_related_layers(image_info->id, image_info->top_layer) != 0) {
        ERROR("Failed to delete img related layer %s", img_id);
        ret = -1;
        goto out;
    }

out:
    free_imagetool_image_summary(image_info);
    return ret;
}

int storage_img_delete(const char *img_id, bool commit)
{
    int ret = 0;

    if (img_id == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock storage, not allowed to delete image");
        return -1;
    }

    ret = do_storage_img_delete(img_id, commit);

    storage_unlock(&g_storage_rwlock);
    return ret;
}

int storage_img_set_loaded_time(const char *img_id, types_timestamp_t *loaded_time)
{
    int ret = 0;

    if (img_id == NULL || loaded_time == NULL) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    if (image_store_set_load_time(img_id, loaded_time) != 0) {
        ERROR("Failed to set img %s loaded time", img_id);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int64_t storage_img_cal_image_size(const char *image_id)
{
    size_t i = 0;
    int64_t total_size = -1;
    char *layer_id = NULL;
    char **big_data_names = NULL;
    size_t big_data_len = 0;
    struct layer *layer_info = NULL;

    if (image_id == NULL) {
        ERROR("Invalid arguments");
        total_size = -1;
        goto out;
    }

    if (image_store_big_data_names(image_id, &big_data_names, &big_data_len) != 0) {
        ERROR("Failed to read image %s big datas", image_id);
        total_size = -1;
        goto out;
    }

    for (i = 0; i < big_data_len; i++) {
        int64_t tmp = image_store_big_data_size(image_id, big_data_names[i]);
        if (tmp == -1) {
            ERROR("Failed to read big data %s for image %s", big_data_names[i], image_id);
            total_size = -1;
            goto out;
        }
        total_size += tmp;
    }

    layer_id = image_store_top_layer(image_id);
    if (layer_id == NULL) {
        ERROR("Failed to get top layer of image %s", image_id);
        total_size = -1;
        goto out;
    }

    while (layer_id != NULL) {
        layer_info = layer_store_lookup(layer_id);
        if (layer_info == NULL) {
            ERROR("Failed to get layer info for layer %s", layer_id);
            total_size = -1;
            goto out;
        }

        if (layer_info->uncompress_size < 0 || layer_info->uncompressed_digest == NULL) {
            ERROR("size for layer %s unknown", layer_id);
            total_size = -1;
            goto out;
        }

        total_size += layer_info->uncompress_size;

        free(layer_id);
        layer_id = util_strdup_s(layer_info->parent);
        free_layer(layer_info);
        layer_info = NULL;
    }

out:
    free(layer_id);
    free_layer(layer_info);
    util_free_array_by_len(big_data_names, big_data_len);
    return total_size;
}

int storage_img_set_image_size(const char *image_id)
{
    int ret = 0;
    int64_t image_size = 0;

    image_size = storage_img_cal_image_size(image_id);
    if (image_size < 0) {
        ERROR("Failed to get image %s size", image_id);
        ret = -1;
        goto out;
    }

    if (image_store_set_image_size(image_id, (uint64_t)image_size) != 0) {
        ERROR("Failed to set image %s size %lu", image_id, (uint64_t)image_size);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

char *storage_get_img_top_layer(const char *id)
{
    return image_store_top_layer(id);
}

int storage_get_all_images(imagetool_images_list *images)
{
    int ret = 0;

    if (images == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    ret = image_store_get_all_images(images);

out:
    return ret;
}

int storage_get_images_fs_usage(imagetool_fs_info *fs_info)
{
    return image_store_get_fs_info(fs_info);
}

bool storage_image_exist(const char *image_or_id)
{
    return image_store_exists(image_or_id);
}

size_t storage_get_img_count()
{
    return image_store_get_images_number();
}

static int check_module_init_opt(struct storage_module_init_options *opts)
{
    if (opts == NULL || opts->driver_name == NULL || opts->storage_root == NULL || opts->storage_run_root == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    return 0;
}

static int make_storage_directory(struct storage_module_init_options *opts)
{
    int ret = 0;
    char* userns_remap = conf_get_isulad_userns_remap();

    if (util_mkdir_p(opts->storage_root, IMAGE_STORE_PATH_MODE) != 0) {
        SYSERROR("Failed to make %s", opts->storage_root);
        ret = -1;
        goto out;
    }

    if (set_file_owner_for_userns_remap(opts->storage_root, userns_remap) != 0) {
        ERROR("Unable to change directory %s owner for user remap.", opts->storage_root);
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(opts->storage_run_root, IMAGE_STORE_PATH_MODE) != 0) {
        SYSERROR("Failed to make %s", opts->storage_run_root);
        ret = -1;
        goto out;
    }

out:
    free(userns_remap);
    return ret;
}

// recal size of images which do not have valid size
static int restore_images_size()
{
    int ret = 0;
    size_t i = 0;
    imagetool_images_list *images = NULL;

    images = util_common_calloc_s(sizeof(imagetool_images_list));
    if (images == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    if (image_store_get_all_images(images) != 0) {
        ERROR("Failed to list all images");
        ret = -1;
        goto out;
    }

    for (i = 0; i < images->images_len; i++) {
        if (images->images[i]->size == 0) {
            (void)storage_img_set_image_size(images->images[i]->id);
        }
    }

out:
    free_imagetool_images_list(images);
    return ret;
}

void free_storage_module_init_options(struct storage_module_init_options *opts)
{
    if (opts == NULL) {
        return;
    }

    free(opts->driver_name);
    opts->driver_name = NULL;

    free(opts->storage_root);
    opts->storage_root = NULL;

    free(opts->storage_run_root);
    opts->storage_run_root = NULL;

    util_free_array_by_len(opts->driver_opts, opts->driver_opts_len);
    opts->driver_opts = NULL;
    opts->driver_opts_len = 0;

    free(opts);
}

void storage_module_exit()
{
    free(g_storage_run_root);
    g_storage_run_root = NULL;
    layer_store_exit();
}

void free_layer_list(struct layer_list *ptr)
{
    size_t i = 0;
    if (ptr == NULL) {
        return;
    }

    for (; i < ptr->layers_len; i++) {
        free_layer(ptr->layers[i]);
        ptr->layers[i] = NULL;
    }
    free(ptr->layers);
    ptr->layers = NULL;
    free(ptr);
}

static int do_create_container_rw_layer(const char *container_id, const char *image_top_layer, const char *mount_label,
                                        json_map_string_string *storage_opts)
{
    int ret = 0;
    struct layer_opts *opts = NULL;

    storage_layer_create_opts_t copts = {
        .parent = image_top_layer,
        .writable = true,
        .storage_opts = storage_opts,
    };

    opts = fill_create_layer_opts(&copts, mount_label);
    if (opts == NULL) {
        ERROR("Failed to fill create opts");
        ret = -1;
        goto out;
    }

    if (layer_store_create(container_id, opts, NULL, NULL) != 0) {
        ERROR("Failed to create container rootfs layer");
        ret = -1;
        goto out;
    }

out:
    free_layer_opts(opts);
    return ret;
}

int storage_rootfs_create(const char *container_id, const char *image, const char *mount_label,
                          json_map_string_string *storage_opts, char **mountpoint)
{
    int ret = 0;
    char *rootfs_id = NULL;
    imagetool_image_summary *image_summary = NULL;
    struct layer *layer_info = NULL;

    if (container_id == NULL || image == NULL) {
        ERROR("Invalid arguments for rootfs create");
        ret = -1;
        goto out;
    }

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock storage, not allowed to create new rootfs");
        ret = -1;
        goto out;
    }

    image_summary = storage_img_get_summary(image);
    if (image_summary == NULL) {
        ERROR("No such image:%s", image);
        ret = -1;
        goto unlock_out;
    }

    // note: we use container id as the layer id of the container
    if (do_create_container_rw_layer(container_id, image_summary->top_layer, mount_label, storage_opts) != 0) {
        ERROR("Failed to do create rootfs layer");
        ret = -1;
        goto unlock_out;
    }

    rootfs_id = rootfs_store_create(container_id, NULL, 0, image_summary->id, container_id, NULL, NULL);
    if (rootfs_id == NULL) {
        ERROR("Failed to create rootfs");
        ret = -1;
        goto remove_layer;
    }

    layer_info = layer_store_lookup(container_id);
    if (layer_info == NULL) {
        ERROR("Failed to get created rootfs layer info");
        ret = -1;
        goto remove_layer;
    }

    if (mountpoint != NULL) {
        *mountpoint = util_strdup_s(layer_info->mount_point);
    }

    goto unlock_out;

remove_layer:
    if (layer_store_delete(container_id) != 0) {
        ERROR("Failed to delete layer %s due rootfs create fail", container_id);
    }

unlock_out:
    storage_unlock(&g_storage_rwlock);
out:
    free(rootfs_id);
    free_imagetool_image_summary(image_summary);
    free_layer(layer_info);
    return ret;
}

static int do_storage_rootfs_delete(const char *container_id)
{
    int ret = 0;
    storage_rootfs *rootfs_info = NULL;

    if (!rootfs_store_exists(container_id)) {
        WARN("Container rootfs %s not exists", container_id);
        ret = 0;
        goto out;
    }

    rootfs_info = rootfs_store_get_rootfs(container_id);
    if (rootfs_info == NULL) {
        ERROR("Failed to get rootfs %s info", container_id);
        ret = -1;
        goto out;
    }

    if (layer_store_delete(rootfs_info->layer) != 0) {
        ERROR("Failed to remove layer %s", rootfs_info->layer);
        ret = -1;
        goto out;
    }

    if (rootfs_store_delete(container_id) != 0) {
        ERROR("Failed to remove rootfs %s", container_id);
        ret = -1;
        goto out;
    }
out:
    free_storage_rootfs(rootfs_info);
    return ret;
}

int storage_rootfs_delete(const char *container_id)
{
    int ret = 0;

    if (container_id == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock storage, not allowed to delete image");
        return -1;
    }

    ret = do_storage_rootfs_delete(container_id);

    storage_unlock(&g_storage_rwlock);
    return ret;
}

int storage_rootfs_fs_usgae(const char *container_id, imagetool_fs_info *fs_info)
{
    int ret = 0;
    storage_rootfs *rootfs_info = NULL;

    if (container_id == NULL || fs_info == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    rootfs_info = rootfs_store_get_rootfs(container_id);
    if (rootfs_info == NULL) {
        ERROR("Failed to get rootfs %s info", container_id);
        ret = -1;
        goto out;
    }

    if (layer_store_get_layer_fs_info(rootfs_info->layer, fs_info) != 0) {
        ERROR("Failed to get layer %s fs usgae info", rootfs_info->layer);
        ret = -1;
        goto out;
    }

out:
    free_storage_rootfs(rootfs_info);
    return ret;
}

char *storage_rootfs_mount(const char *container_id)
{
    char *mount_point = NULL;
    storage_rootfs *rootfs_info = NULL;

    if (container_id == NULL) {
        ERROR("Invalid input arguments");
        goto out;
    }

    rootfs_info = rootfs_store_get_rootfs(container_id);
    if (rootfs_info == NULL) {
        ERROR("Failed to get rootfs %s info", container_id);
        goto out;
    }

    mount_point = layer_store_mount(rootfs_info->layer);
    if (mount_point == NULL) {
        ERROR("Failed to mount %s", rootfs_info->layer);
        goto out;
    }

out:
    free_storage_rootfs(rootfs_info);
    return mount_point;
}

int storage_rootfs_umount(const char *container_id, bool force)
{
    int ret = 0;
    storage_rootfs *rootfs_info = NULL;

    if (container_id == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    rootfs_info = rootfs_store_get_rootfs(container_id);
    if (rootfs_info == NULL) {
        ERROR("Failed to get rootfs %s info, skip umount", container_id);
        ret = 0;
        goto out;
    }

    if (layer_store_umount(rootfs_info->layer, force) != 0) {
        ERROR("Failed to umount layer %s", rootfs_info->layer);
        ret = -1;
        goto out;
    }

out:
    free_storage_rootfs(rootfs_info);
    return ret;
}

static char *get_check_layer_data_path()
{
    char *ret = NULL;
    char *sum = NULL;

    sum = sha256_digest_str(g_storage_run_root);
    if (sum == NULL) {
        return NULL;
    }
    if (asprintf(&ret, "%s/%s.json", g_storage_run_root, sum) == -1) {
        free(sum);
        return NULL;
    }

    free(sum);
    return ret;
}

static void free_layers_linked_list(struct linked_list *layers)
{
    struct linked_list *iter = NULL;
    struct linked_list *next = NULL;

    if (layers == NULL) {
        return;
    }
    linked_list_for_each_safe(iter, layers, next) {
        linked_list_del(iter);
        free(iter->elem);
        iter->elem = NULL;
        free(iter);
    }
    free(layers);
}

static struct linked_list *get_image_layers(const char *top_lid)
{
    struct linked_list *head = NULL;
    struct linked_list *work = NULL;
    char *parent = NULL;
    struct layer *l = NULL;

    if (top_lid == NULL) {
        return NULL;
    }

    head = util_common_calloc_s(sizeof(struct linked_list));
    if (head == NULL) {
        return NULL;
    }

    linked_list_init(head);
    parent = util_strdup_s(top_lid);
    for (;;) {
        if (parent == NULL) {
            break;
        }
        work = util_common_calloc_s(sizeof(struct linked_list));
        if (work == NULL) {
            ERROR("Out of memory");
            goto err_out;
        }
        work->elem = (void *)parent;
        linked_list_add_tail(head, work);
        l = layer_store_lookup(parent);
        parent = NULL;
        if (l == NULL) {
            break;
        }
        parent = util_strdup_s(l->parent);
        free_layer(l);
    }

    return head;
err_out:
    free_layers_linked_list(head);
    return NULL;
}

static bool parse_checked_layer_cb(const char *line, void *context)
{
    static bool default_value = true;
    map_t *checked_layers = (map_t *)context;

    if (!map_replace(checked_layers, (void *)line, (void *)&default_value)) {
        WARN("Add layer: %s failed, ignore it, cause to recheck it", line);
    }
    return true;
}

static int parse_checked_layer_file(const char *path, map_t *checked_layers)
{
    FILE *fp = NULL;
    int ret = 0;

    fp = util_fopen(path, "r");
    if (fp == NULL) {
        return (errno == ENOENT ? 0 : -1);
    }

    ret = util_proc_file_line_by_line(fp, parse_checked_layer_cb, (void *)checked_layers);

    fclose(fp);
    return ret;
}

static int do_add_checked_layer(const char *lid, int fd, map_t *checked_layers)
{
    bool default_value = true;
    char buf[PATH_MAX] = { 0 };
    int ret = 0;

    if (strlen(lid) >= PATH_MAX - 1) {
        ERROR("Invalid layer id: %s", lid);
        ret = -1;
        goto out;
    }
    (void)memcpy(buf, lid, strlen(lid));
    buf[strlen(lid)] = '\n';
    // save checked layer ids into file
    if (util_write_nointr(fd, buf, strlen(lid) + 1) < 0) {
        ERROR("Write checked layer data failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }
    if (!map_replace(checked_layers, (void *)lid, (void *)&default_value)) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int do_check_layers_list(const char *path, struct linked_list *layer_ids, map_t *checked_layers)
{
    struct linked_list *iter = NULL;
    struct linked_list *next = NULL;
    char *tmp_id = NULL;
    int ret = 0;
    int fd = -1;
    int nret;

    fd = util_open(path, O_WRONLY | O_CREAT | O_APPEND, SECURE_CONFIG_FILE_MODE);
    if (fd == -1) {
        return -1;
    }

    linked_list_for_each_safe(iter, layer_ids, next) {
        tmp_id = (char *)iter->elem;
        DEBUG("Try to check layer: %s", tmp_id);
        if (map_search(checked_layers, (void *)tmp_id) != NULL) {
            INFO("Layer: %s checked, skip", tmp_id);
            continue;
        }
        nret = layer_store_check(tmp_id);
        if (nret != 0) {
            ERROR("Layer: %s check failed", tmp_id);
            // this layer is invalid
            ret = -1;
            goto out;
        }
        DEBUG("Layer: %s is integration", tmp_id);

        nret = do_add_checked_layer(tmp_id, fd, checked_layers);
        if (nret != 0) {
            ret = -1;
            goto out;
        }

        linked_list_del(iter);
        free(iter->elem);
        iter->elem = NULL;
        free(iter);
    }

out:
    close(fd);
    return ret;
}

static int do_storage_check_image(const char *path, const char *id, map_t *checked_layers)
{
    int ret = -1;
    imagetool_image *img = NULL;
    struct linked_list *layer_ids = NULL;

    if (id == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    img = image_store_get_image(id);
    if (img == NULL) {
        goto out;
    }
    layer_ids = get_image_layers(img->top_layer);
    if (layer_ids == NULL) {
        goto out;
    }

    // check for all layers belong to the image
    ret = do_check_layers_list(path, layer_ids, checked_layers);

out:
    free_imagetool_image(img);
    free_layers_linked_list(layer_ids);
    return ret;
}

static bool is_rootfs_layer(const char *layer_id, const struct rootfs_list *all_rootfs)
{
    int j;

    if (all_rootfs == NULL || layer_id == NULL) {
        return false;
    }

    for (j = 0; j < all_rootfs->rootfs_len; j++) {
        if (all_rootfs->rootfs[j]->layer == NULL) {
            continue;
        }
        if (strcmp(layer_id, all_rootfs->rootfs[j]->layer) == 0) {
            return true;
        }
    }

    return false;
}

static bool do_storage_integration_check(const char *path, map_t *checked_layers)
{
    struct rootfs_list *all_rootfs = NULL;
    bool ret = false;
    int nret = 0;
    imagetool_images_list *all_images = NULL;
    size_t i = 0;
    size_t j = 0;

    all_images = util_common_calloc_s(sizeof(imagetool_images_list));
    if (all_images == NULL) {
        ERROR("Memory out");
        goto out;
    }
    nret = storage_get_all_images(all_images);
    if (nret != 0) {
        goto out;
    }

    all_rootfs = util_common_calloc_s(sizeof(struct rootfs_list));
    if (all_rootfs == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    if (rootfs_store_get_all_rootfs(all_rootfs) != 0) {
        ERROR("Failed to get all container rootfs information");
        goto out;
    }

    for (i = 0; i < all_images->images_len; i++) {
        nret = do_storage_check_image(path, all_images->images[i]->id, checked_layers);
        if (nret == 0) {
            continue;
        }
        // invalid image
        for (j = 0; j < all_rootfs->rootfs_len; j++) {
            if (strcmp(all_rootfs->rootfs[j]->image, all_images->images[i]->id) != 0) {
                continue;
            }
            ERROR("Remove container: %s related invalid image", all_rootfs->rootfs[j]->id);
            nret = do_storage_rootfs_delete(all_rootfs->rootfs[j]->id);
            if (nret != 0) {
                ERROR("Failed to delete container: %s with invalid image: %s", all_rootfs->rootfs[j]->id,
                      all_images->images[i]->id);
            }
        }
        ERROR("Remove unintegration image: %s", all_images->images[i]->id);
        nret = do_storage_img_delete(all_images->images[i]->id, true);
        if (nret != 0) {
            ERROR("Failed to delete invalid image: %s", all_images->images[i]->id);
        }
    }

    // remove containers with can not find image
    for (j = 0; j < all_rootfs->rootfs_len; j++) {
        if (image_store_exists(all_rootfs->rootfs[j]->image)) {
            continue;
        }
        ERROR("Delete container %s due to no related image", all_rootfs->rootfs[j]->id);
        nret = do_storage_rootfs_delete(all_rootfs->rootfs[j]->id);
        if (nret != 0) {
            ERROR("Failed to delete container: %s with unfound image: %s", all_rootfs->rootfs[j]->id,
                  all_rootfs->rootfs[j]->image);
        }
    }

    ret = true;
out:
    free_imagetool_images_list(all_images);
    free_rootfs_list(all_rootfs);
    return ret;
}

static void delete_unchecked_layers(map_t *checked_layers)
{
    struct layer_list *all_layers = NULL;
    size_t i;
    struct rootfs_list *all_rootfs = NULL;

    all_layers = util_common_calloc_s(sizeof(struct layer_list));
    if (all_layers == NULL) {
        ERROR("Memory out");
        return;
    }

    if (layer_store_list(all_layers) != 0) {
        ERROR("Failed to get all images info");
        goto out;
    }

    all_rootfs = util_common_calloc_s(sizeof(struct rootfs_list));
    if (all_rootfs == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    if (rootfs_store_get_all_rootfs(all_rootfs) != 0) {
        ERROR("Failed to get all container rootfs information");
        goto out;
    }

    for (i = 0; i < all_layers->layers_len; i++) {
        if (map_search(checked_layers, (void *)all_layers->layers[i]->id) != NULL) {
            DEBUG("ignore checked layer: %s", all_layers->layers[i]->id);
            continue;
        }

        if (is_rootfs_layer(all_layers->layers[i]->id, all_rootfs)) {
            DEBUG("ignore rootfs layer: %s", all_layers->layers[i]->id);
            continue;
        }

        ERROR("Delete unchecked layer: %s due to no related image", all_layers->layers[i]->id);
        if (layer_store_delete(all_layers->layers[i]->id) != 0) {
            ERROR("Failed to delete unchecked layer %s", all_layers->layers[i]->id);
        }
    }

out:
    free_layer_list(all_layers);
    free_rootfs_list(all_rootfs);
}

static bool storage_integration_check()
{
    bool ret = false;
    map_t *checked_layers = NULL;
    char *checked_layer_data_path = NULL;

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock storage, not allowed to delete image");
        return false;
    }

    checked_layer_data_path = get_check_layer_data_path();
    if (checked_layer_data_path == NULL) {
        ERROR("Out of memory");
        goto out;
    }
    checked_layers = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (checked_layers == NULL) {
        ERROR("Out of memory");
        goto out;
    }
    // load checked layer ids
    if (parse_checked_layer_file(checked_layer_data_path, checked_layers) != 0) {
        ERROR("Load checked layer file failed");
        goto out;
    }
    ret = do_storage_integration_check(checked_layer_data_path, checked_layers);
    if (!ret) {
        goto out;
    }

    delete_unchecked_layers(checked_layers);

    ret = true;
out:
    map_free(checked_layers);
    storage_unlock(&g_storage_rwlock);
    free(checked_layer_data_path);
    return ret;
}

container_inspect_graph_driver *storage_get_metadata_by_container_id(const char *id)
{
    storage_rootfs *rootfs_info = NULL;
    container_inspect_graph_driver *container_metadata = NULL;

    rootfs_info = rootfs_store_get_rootfs(id);
    if (rootfs_info == NULL) {
        ERROR("Failed to get rootfs %s info", id);
        return NULL;
    }

    container_metadata = layer_store_get_metadata_by_layer_id(rootfs_info->layer);
    free_storage_rootfs(rootfs_info);

    return container_metadata;
}

static int do_check_img_layers_exist(const char *img_id)
{
    int ret = 0;
    char *layer_id = NULL;
    struct layer *layer_info = NULL;

    if (img_id == NULL) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    layer_id = image_store_top_layer(img_id);
    if (layer_id == NULL) {
        ERROR("Failed to get top layer of image %s", img_id);
        ret = -1;
        goto out;
    }

    while (layer_id != NULL) {
        layer_info = layer_store_lookup(layer_id);
        if (layer_info == NULL) {
            ERROR("Failed to get layer info for layer %s", layer_id);
            ret = -1;
            goto out;
        }

        free(layer_id);
        layer_id = util_strdup_s(layer_info->parent);
        free_layer(layer_info);
        layer_info = NULL;
    }

out:
    free(layer_id);
    free_layer(layer_info);
    return ret;
}

static void storage_delete_rootfs_by_img_id(const char *img_id, const struct rootfs_list *all_rootfs)
{
    size_t i = 0;

    // remove rootfs with invalid image
    for (i = 0; i < all_rootfs->rootfs_len; i++) {
        if (strcmp(all_rootfs->rootfs[i]->image, img_id) != 0) {
            continue;
        }

        ERROR("Remove container rootfs: %s related invalid image %s", all_rootfs->rootfs[i]->id, img_id);

        if (do_storage_rootfs_delete(all_rootfs->rootfs[i]->id) != 0) {
            ERROR("Failed to delete container: %s with invalid image: %s", all_rootfs->rootfs[i]->id, img_id);
        }
    }
}

static int storage_check_image_layers_exist()
{
    int ret = 0;
    int nret = 0;
    imagetool_images_list *all_images = NULL;
    struct rootfs_list *all_rootfs = NULL;
    size_t i = 0;

    all_images = util_common_calloc_s(sizeof(imagetool_images_list));
    if (all_images == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
    nret = storage_get_all_images(all_images);
    if (nret != 0) {
        ret = -1;
        goto out;
    }

    all_rootfs = util_common_calloc_s(sizeof(struct rootfs_list));
    if (all_rootfs == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (rootfs_store_get_all_rootfs(all_rootfs) != 0) {
        ERROR("Failed to get all container rootfs information");
        ret = -1;
        goto out;
    }

    for (i = 0; i < all_images->images_len; i++) {
        if (do_check_img_layers_exist(all_images->images[i]->id) == 0) {
            continue;
        }

        storage_delete_rootfs_by_img_id(all_images->images[i]->id, all_rootfs);

        ERROR("Remove invalid image: %s due to layers not exist", all_images->images[i]->id);
        nret = do_storage_img_delete(all_images->images[i]->id, true);
        if (nret != 0) {
            ERROR("Failed to delete invalid image: %s", all_images->images[i]->id);
        }
    }

out:
    free_imagetool_images_list(all_images);
    free_rootfs_list(all_rootfs);
    return ret;
}

int storage_module_init(struct storage_module_init_options *opts)
{
    int ret = 0;

    if (check_module_init_opt(opts) != 0) {
        ret = -1;
        goto out;
    }
    g_storage_run_root = util_strdup_s(opts->storage_run_root);

    if (make_storage_directory(opts) != 0) {
        ret = -1;
        goto out;
    }

    if (layer_store_init(opts) != 0) {
        ERROR("Failed to init layer store");
        ret = -1;
        goto out;
    }

    if (image_store_init(opts) != 0) {
        ERROR("Failed to init image store");
        ret = -1;
        goto out;
    }

    if (restore_images_size() != 0) {
        ERROR("Failed to recal image size");
        ret = -1;
        goto out;
    }

    if (rootfs_store_init(opts) != 0) {
        ERROR("Failed to init rootfs store");
        ret = -1;
        goto out;
    }

    if (pthread_rwlock_init(&g_storage_rwlock, NULL) != 0) {
        ERROR("Failed to init storage rwlock");
        ret = -1;
        goto out;
    }

    if (storage_check_image_layers_exist() != 0) {
        ERROR("do image layers exist check failed");
        ret = -1;
        goto out;
    }

    if (opts->integration_check && !storage_integration_check()) {
        ERROR("do integration check failed");
        ret = -1;
    }

out:
    return ret;
}
