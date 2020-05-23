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
 * Description: provide layer function definition
 ******************************************************************************/
#ifndef __OCI_STORAGE_LAYER_H
#define __OCI_STORAGE_LAYER_H

#include <stdint.h>
#include <pthread.h>

#include "isula_libutils/storage_layer.h"
#include "isula_libutils/storage_mount_point.h"
#include "isula_libutils/log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _layer_t_ {
    pthread_mutex_t mutex;
    bool init_mutex;

    char *layer_json_path;
    storage_layer *slayer;

    char *mount_point_json_path;
    storage_mount_point *smount_point;

    uint64_t refcnt;
} layer_t;

layer_t *create_empty_layer();

void layer_ref_inc(layer_t *layer);
void layer_ref_dec(layer_t *layer);
layer_t *load_layer(const char *fname, const char *mountpoint_fname);
int save_layer(layer_t *layer);
int save_mount_point(layer_t *layer);

static inline void layer_lock(layer_t *l)
{
    if (l == NULL || !(l->init_mutex)) {
        return;
    }

    if (pthread_mutex_lock(&l->mutex)) {
        ERROR("Failed to lock atomic mutex");
    }
}

static inline void layer_unlock(layer_t *l)
{
    if (l == NULL || !(l->init_mutex)) {
        return;
    }

    if (pthread_mutex_unlock(&l->mutex)) {
        ERROR("Failed to lock atomic mutex");
    }
}

#ifdef __cplusplus
}
#endif

#endif
