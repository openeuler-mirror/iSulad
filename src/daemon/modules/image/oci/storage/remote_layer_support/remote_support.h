/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2023-03-03
 * Description: provide remote support functions
 ******************************************************************************/

#ifndef DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_REMOTE_LAYER_SUPPORT_REMOTE_SUPPORT_H
#define DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_REMOTE_LAYER_SUPPORT_REMOTE_SUPPORT_H

#include <pthread.h>

#include "linked_list.h"
#include "map.h"
#include "ro_symlink_maintain.h"

#ifdef __cplusplus
extern "C" {
#endif

struct remote_overlay_data {
    const char *overlay_home;
    const char *overlay_ro;
};

struct remote_layer_data {
    const char *layer_home;
    const char *layer_ro;
};

struct remote_image_data {
    const char *image_home;
};

// image impl
struct remote_image_data *remote_image_create(const char *image_home, const char *image_ro);

void remote_image_destroy(struct remote_image_data *data);

void remote_image_refresh(struct remote_image_data *data);

// layer impl
struct remote_layer_data *remote_layer_create(const char *layer_home, const char *layer_ro);

void remote_layer_destroy(struct remote_layer_data *data);

void remote_layer_refresh(struct remote_layer_data *data);

bool remote_layer_layer_valid(const char *layer_id);

// overlay impl
struct remote_overlay_data *remote_overlay_create(const char *overlay_home, const char *overlay_ro);

void remote_overlay_destroy(struct remote_overlay_data *data);

void remote_overlay_refresh(struct remote_overlay_data *data);

bool remote_overlay_layer_valid(const char *layer_id);

// start refresh remote
int remote_start_refresh_thread(pthread_rwlock_t *remote_lock);

// extra map utils
char **remote_deleted_layers(const map_t *old, const map_t *new_l);

char **remote_added_layers(const map_t *old, const map_t *new_l);

#ifdef __cplusplus
}
#endif

#endif
