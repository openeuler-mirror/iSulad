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
 * Author: lifeng
 * Create: 2020-04-01
 * Description: provide storage functions
 ******************************************************************************/
#include "storage.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "console.h"
#include "utils.h"
#include "log.h"
#include "layer_store.h"
#include "image_store.h"
#include "rootfs_store.h"

static pthread_rwlock_t g_storage_rwlock;

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
        ret = -1;
        goto out;
    }

    fd_ptr = util_common_calloc_s(sizeof(int));
    if (fd_ptr == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
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

    goto out;

err_out:
    free(fd_ptr);
    free(reader_tmp);
out:
    return ret;
}

static struct layer_opts *fill_create_layer_opts(storage_layer_create_opts_t *copts)
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
    opts->writable = copts->compressed_digest;

    if (copts->storage_opts != NULL) {
        opts->opts = util_common_calloc_s(sizeof(struct layer_store_mount_opts));
        if (opts->opts == NULL) {
            ERROR("Memory out");
            goto err_out;
        }
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

int storage_layer_create(const char *layer_id, storage_layer_create_opts_t *copts)
{
    int ret = 0;
    struct io_read_wrapper *reader = NULL;
    struct layer_opts *opts = NULL;

    if (copts == NULL) {
        ERROR("Create opts is null");
        return -1;
    }

    if (!copts->writeable && copts->layer_data_path == NULL) {
        ERROR("Invalid arguments for put ro layer");
        ret = -1;
        goto out;
    }

    if (fill_read_wrapper(copts->layer_data_path, &reader) != 0) {
        ERROR("Failed to fill layer read wrapper");
        ret = -1;
        goto out;
    }

    opts = fill_create_layer_opts(copts);
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

int storage_layer_set_names(const char *layer_id, const char **names, size_t names_len)
{
    int ret = 0;
    char **unique_names = NULL;
    size_t unique_names_len = 0;

    if (layer_id == NULL || names == NULL || names_len == 0) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    if (util_string_array_unique(names, names_len, &unique_names, &unique_names_len) != 0) {
        ERROR("Failed to unique names");
        ret = -1;
        goto out;
    }

    if (layer_store_set_names(layer_id, (const char **)unique_names, unique_names_len) != 0) {
        ERROR("Failed to set layer %s names", layer_id);
        ret = -1;
        goto out;
    }

out:
    return ret;
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
        if (strcmp(all_images->images[i]->top_layer, layer_id) == 0 && strcmp(all_images->images[i]->id, layer_id) != 0) {
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

    layer_id = util_strdup_s(img_top_layer_id);
    if (layer_id == NULL) {
        ERROR("Memory out %s", img_id);
        ret = -1;
        goto out;
    }

    while (layer_id != NULL) {
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

int storage_img_delete(const char *img_id, bool commit)
{
    int ret = 0;
    imagetool_image *image_info = NULL;

    if (img_id == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock storage, not allowed to delete image");
        ret = -1;
        goto out;
    }

    if (!image_store_exists(img_id)) {
        WARN("Image %s not exists");
        ret = 0;
        goto unlock_out;
    }

    image_info = image_store_get_image(img_id);
    if (image_info == NULL) {
        ERROR("Failed to get image %s info", img_id);
        ret = -1;
        goto unlock_out;
    }

    //TODO check image whether used by container

    if (image_store_delete(image_info->id) != 0) {
        ERROR("Failed to delete img %s", img_id);
        ret = -1;
        goto unlock_out;
    }

    if (delete_img_related_layers(image_info->id, image_info->top_layer) != 0) {
        ERROR("Failed to delete img related layer %s", img_id);
        ret = -1;
        goto unlock_out;
    }

unlock_out:
    storage_unlock(&g_storage_rwlock);
out:
    free_imagetool_image(image_info);
    return ret;
}

int storage_img_set_meta_data(const char *img_id, const char *meta)
{
    int ret = 0;

    if (img_id == NULL || meta == NULL) {
        ERROR("Invalid arguments");
        ret = -1;
        goto out;
    }

    if (image_store_set_metadata(img_id, meta) != 0) {
        ERROR("Failed to set img %s meta data", img_id);
        ret = -1;
        goto out;
    }

out:
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
        ERROR("Failed to set image %s size %llu", image_id, (uint64_t)image_size);
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

    if (util_mkdir_p(opts->storage_root, IMAGE_STORE_PATH_MODE) != 0) {
        SYSERROR("Failed to make %s", opts->storage_root);
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(opts->storage_run_root, IMAGE_STORE_PATH_MODE) != 0) {
        SYSERROR("Failed to make %s", opts->storage_run_root);
        ret = -1;
        goto out;
    }

out:
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


int storage_module_init(struct storage_module_init_options *opts)
{
    int ret = 0;

    if (check_module_init_opt(opts) != 0) {
        ret = -1;
        goto out;
    }

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

    if (pthread_rwlock_init(&g_storage_rwlock, NULL) != 0) {
        ERROR("Failed to init storage rwlock");
        ret = -1;
        goto out;
    }

out:
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

static int do_create_container_rw_layer(const char *container_id, const char *image_top_layer,
                                        json_map_string_string *storage_opts)
{
    int ret = 0;
    struct layer_opts *opts = NULL;

    storage_layer_create_opts_t copts = {
        .parent = image_top_layer,
        .writeable = true,
        .storage_opts = storage_opts,
    };

    opts = fill_create_layer_opts(&copts);
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

int storage_rootfs_create(const char *container_id, const char *image, json_map_string_string *storage_opts,
                          char **mountpoint)
{
    int ret = 0;
    char *rootfs_id = NULL;
    imagetool_image *image_info = NULL;
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

    image_info = storage_img_get(image);
    if (image_info == NULL) {
        ERROR("No such image:%s", image);
        ret = -1;
        goto unlock_out;
    }

    // note: we use container id as the layer id of the container
    if (do_create_container_rw_layer(container_id, image_info->top_layer, storage_opts) != 0) {
        ERROR("Failed to do create rootfs layer");
        ret = -1;
        goto unlock_out;
    }

    rootfs_id = rootfs_store_create(container_id, NULL, 0, image_info->id, container_id, NULL, NULL);
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
    free_imagetool_image(image_info);
    free_layer(layer_info);
    return ret;
}

int storage_rootfs_delete(const char *container_id)
{
    int ret = 0;
    storage_rootfs *rootfs_info = NULL;

    if (container_id == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    if (!storage_lock(&g_storage_rwlock, true)) {
        ERROR("Failed to lock storage, not allowed to delete image");
        ret = -1;
        goto out;
    }

    if (!rootfs_store_exists(container_id)) {
        WARN("Container rootfs %s not exists", container_id);
        ret = 0;
        goto unlock_out;
    }

    rootfs_info = rootfs_store_get_rootfs(container_id);
    if (rootfs_info == NULL) {
        ERROR("Failed to get rootfs %s info", container_id);
        ret = -1;
        goto unlock_out;
    }

    if (layer_store_delete(rootfs_info->layer) != 0) {
        ERROR("Failed to remove layer %s", rootfs_info->layer);
        ret = -1;
        goto unlock_out;
    }

    if (rootfs_store_delete(container_id) != 0) {
        ERROR("Failed to remove rootfs %s", container_id);
        ret = -1;
        goto unlock_out;
    }

unlock_out:
    storage_unlock(&g_storage_rwlock);
out:
    free_storage_rootfs(rootfs_info);
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
