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
 * Description: provide storage function definition
 ******************************************************************************/
#ifndef __STORAGE_H
#define __STORAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "types_def.h"
#include "storage_image.h"
#include "imagetool_images_list.h"
#include "imagetool_fs_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GRAPH_ROOTPATH_NAME "storage"

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
};

struct storage_img_create_options {
    types_timestamp_t *create_time;
    char *digest;
};

int storage_module_init(struct storage_module_init_options *opts);

void free_storage_module_init_options(struct storage_module_init_options *opts);

/* image operations */
int storage_img_create(const char *id, const char *parent_id, const char *metadata,
                       struct storage_img_create_options *opts);

const storage_image *storage_img_get(const char *img_id);

int storage_img_set_big_data(const char *img_id, const char *key, const char *val);

int storage_img_add_name(const char *img_id, const char *img_name);

int storage_img_delete(const char *img_id, bool commit);

int storage_img_set_meta_data(const char *img_id, const char *meta);

int storage_img_set_loaded_time(const char *img_id, types_timestamp_t *loaded_time);

int storage_img_set_names(const char *img_id, const char **names, size_t names_len);

int storage_get_all_images(imagetool_images_list *images);

int storage_get_images_fs_usage(imagetool_fs_info *fs_info);

bool storage_image_exist(const char *image_or_id);

/* layer operations */
int storage_layer_create(const char *layer_id, const char *parent_id, bool writeable, const char *layer_data_path);

struct layer *storage_layer_get(const char *layer_id);

int storage_layer_try_repair_lowers(const char *layer_id, const char *last_layer_id);

int storage_layer_set_names(const char *layer_id, const char **names, size_t names_len);

void free_layer(struct layer *l);

#ifdef __cplusplus
}
#endif

#endif