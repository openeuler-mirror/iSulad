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
 * Description: provide storage function definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_STORAGE_STORAGE_H
#define DAEMON_MODULES_IMAGE_OCI_STORAGE_STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <isula_libutils/imagetool_image.h>
#include <isula_libutils/json_common.h>

#include "utils_timestamp.h"
#include "isula_libutils/storage_image.h"
#include "isula_libutils/storage_rootfs.h"
#include "isula_libutils/imagetool_images_list.h"
#include "isula_libutils/imagetool_fs_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCI_LOAD_TMP_WORK_DIR "/var/tmp/isulad-oci-load"

struct layer {
    char *id;
    char *parent;
    char *mount_point;
    int mount_count;
    char *compressed_digest;
    int64_t compress_size;
    char *uncompressed_digest;
    int64_t uncompress_size;
};

struct layer_list {
    struct layer **layers;
    size_t layers_len;
};

struct rootfs_list {
    storage_rootfs **rootfs;
    size_t rootfs_len;
};

struct storage_module_init_options {
    // storage_run_root is the filesystem path under which we can store run-time info
    // e.g. /var/run/isulad/storage
    char *storage_run_root;

    // storage_root is the filesystem path under which we will store the contents of layers, images, and containers
    // e.g. /var/lib/isulad/storage
    char *storage_root;

    char *driver_name;

    // driver_opts are driver-specific options.
    char **driver_opts;
    size_t driver_opts_len;
    bool integration_check;
};

struct storage_img_create_options {
    types_timestamp_t *create_time;
    char *digest;
};

struct id_map {
    int container_id;
    int host_id;
    int size;
};

struct id_mapping_options {
    bool host_uid_mapping;
    bool host_gid_mapping;

    struct id_map *uid_map;
    size_t uid_map_len;
    struct id_map *gid_map;
    size_t gid_map_len;
};

struct storage_rootfs_options {
    struct id_mapping_options id_mapping_opts;
    char **label_opts;
    size_t label_opts_len;
    char **mount_opts;
    size_t mount_opts_len;
};

typedef struct storage_layer_create_opts {
    const char *parent;
    const char *uncompress_digest;
    const char *compressed_digest;
    const char *layer_data_path;
    bool writable;
    json_map_string_string *storage_opts;
} storage_layer_create_opts_t;

int storage_module_init(struct storage_module_init_options *opts);

void storage_module_exit();

void free_storage_module_init_options(struct storage_module_init_options *opts);

/* image operations */
int storage_img_create(const char *id, const char *parent_id, const char *metadata,
                       struct storage_img_create_options *opts);

imagetool_image *storage_img_get(const char *img_id);

int storage_img_set_big_data(const char *img_id, const char *key, const char *val);

int storage_img_add_name(const char *img_id, const char *img_name);

int storage_img_delete(const char *img_id, bool commit);

int storage_img_set_loaded_time(const char *img_id, types_timestamp_t *loaded_time);

int storage_img_get_names(const char *img_id, char ***names, size_t *names_len);

int storage_img_set_names(const char *img_id, const char **names, size_t names_len);

int storage_get_all_images(imagetool_images_list *images);

int storage_get_images_fs_usage(imagetool_fs_info *fs_info);

bool storage_image_exist(const char *image_or_id);

int storage_img_set_image_size(const char *image_id);

char *storage_get_img_top_layer(const char *id);

size_t storage_get_img_count();

char *storage_img_get_image_id(const char *img_name);

/* layer operations */
int storage_layer_create(const char *layer_id, storage_layer_create_opts_t *opts);

struct layer_list *storage_layers_get_by_uncompress_digest(const char *digest);

struct layer *storage_layer_get(const char *layer_id);

int storage_layer_try_repair_lowers(const char *layer_id, const char *last_layer_id);

void free_layer(struct layer *l);

void free_layer_list(struct layer_list *ptr);

/* container rootfs operations */
int storage_rootfs_create(const char *container_id, const char *image, const char *mount_label,
                          json_map_string_string *storage_opts,
                          char **mountpoint);

int storage_rootfs_delete(const char *container_id);

int storage_rootfs_fs_usgae(const char *container_id, imagetool_fs_info *fs_info);

char *storage_rootfs_mount(const char *container_id);

int storage_rootfs_umount(const char *container_id, bool force);

#ifdef __cplusplus
}
#endif

#endif
