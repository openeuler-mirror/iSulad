/******************************************************************************
 * Copyright (c) China Unicom Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Chenwei
 * Create: 2023-08-25
 * Description: provide pthread safe pull progress status map definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_PROGRESS_STATUS_MAP_H
#define DAEMON_MODULES_IMAGE_OCI_PROGRESS_STATUS_MAP_H

#include "map.h"
#include <pthread.h>
#include <stdint.h>

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef struct progress_status_map {
    struct _map_t *map;
    pthread_mutex_t mutex;
} progress_status_map;

typedef struct progress {
   int64_t dlnow;
   int64_t dltotal; 
} progress;

bool progress_status_map_insert(progress_status_map *progress_status_map, char *key, progress *value);

progress_status_map *progress_status_map_new();

size_t progress_status_map_size(progress_status_map *progress_status_map);

void progress_status_map_free(progress_status_map *map);

bool progress_status_map_lock(progress_status_map *progress_status_map);

void progress_status_map_unlock(progress_status_map *progress_status_map);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif // DAEMON_MODULES_IMAGE_OCI_PROGRESS_STATUS_MAP_H
