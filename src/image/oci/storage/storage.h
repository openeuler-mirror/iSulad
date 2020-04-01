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
#include "layer_store.h"
#include "image_store.h"

#ifdef __cplusplus
extern "C" {
#endif

struct storage_img_create_options {
    types_timestamp_t *create_time;
    char *digest;
};


int storage_layer_create(const char *layer_id, const char *parent_id, bool writeable, const char *layer_data_path);

struct layer *storage_layer_get(const char *id);

int storage_layer_try_repair_lowers(const char *id, const char *last_layer_id);

int storage_img_create(const char *id, const char *parent_id, const char *metadata,
                       struct storage_img_create_options *opts);

storage_image *storage_img_get(const char *img_id);

int storage_img_set_big_data(const char *img_id, const char *key, const char *val);

int storage_img_add_name(const char *img_id, const char *img_name);

int storage_img_delete(const char *img_id, bool commit);

int storage_img_set_meta_data(const char *img_id, const char *meta);

int storage_img_set_loaded_time(const char *img_id, types_timestamp_t *loaded_time);

#ifdef __cplusplus
}
#endif

#endif