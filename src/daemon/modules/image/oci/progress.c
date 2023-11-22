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
#include "progress.h"
#include <isula_libutils/log.h>
#include <stdlib.h>

#include "utils.h"

/* function to get size of map */
size_t progress_status_map_size(progress_status_map *progress_status_map)
{
    size_t ret = 0;

    if (progress_status_map == NULL) {
        ERROR("Invalid parameter");
        return 0;
    }

    if (!progress_status_map_lock(progress_status_map)) {
        ERROR("Cannot get the progress status map size for locking failed");
        return 0;
    }
    ret = map_size(progress_status_map->map);
    progress_status_map_unlock(progress_status_map);
    
    return ret;
}

bool progress_status_map_insert(progress_status_map *progress_status_map, char *key, progress *value)
{
    bool ret = false;

    if (progress_status_map == NULL || key == NULL || value == NULL) {
        ERROR("Invalid parameter");
        return false;
    }

    if (!progress_status_map_lock(progress_status_map)) {
        ERROR("Cannot replace the progress status map item for locking failed");
        return false;
    }
    ret = map_insert(progress_status_map->map, key, value);
    progress_status_map_unlock(progress_status_map);

    return ret;
}

// malloc a new map by type
progress_status_map *progress_status_map_new()
{
    progress_status_map *progress_status_map = NULL;
    progress_status_map = util_common_calloc_s(sizeof(struct progress_status_map));
    if (progress_status_map == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    progress_status_map->map = map_new(MAP_STR_PTR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (progress_status_map->map == NULL) {
        free(progress_status_map);
        ERROR("Out of memory");
        return NULL;
    }
    if (pthread_mutex_init(&(progress_status_map->mutex), NULL) != 0) {
        map_free(progress_status_map->map);
        free(progress_status_map);
        ERROR("New map failed for mutex init");
        return NULL;
    }
    return progress_status_map;
}

/* map free */
void progress_status_map_free(progress_status_map *progress_status_map)
{
    if (progress_status_map == NULL) {
        return;
    }

    pthread_mutex_destroy(&(progress_status_map->mutex));
    map_free(progress_status_map->map);
    free(progress_status_map);
}

bool progress_status_map_lock(progress_status_map *progress_status_map)
{
    int ret = 0;

    if (progress_status_map == NULL) {
        return false;
    }

    ret = pthread_mutex_lock(&(progress_status_map->mutex));
    if (ret != 0) {
        ERROR("Lock progress status map failed: %s", strerror(ret));
        return false;
    }
    return true;
}

void progress_status_map_unlock(progress_status_map *progress_status_map)
{
    int ret = 0;

    if (progress_status_map == NULL) {
        return;
    }

    ret = pthread_mutex_unlock(&(progress_status_map->mutex));
    if (ret != 0) {
        ERROR("Unlock progress status map failed: %s", strerror(ret));
    }
}
