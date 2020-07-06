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
 * Create: 2020-06-15
 * Description: provide container isulad functions
 ******************************************************************************/
#ifndef __EVENT_FORMAT_H
#define __EVENT_FORMAT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "utils_timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EVENTS_TYPE_EXIT = 0,
    EVENTS_TYPE_STOPPED1 = 1,
    EVENTS_TYPE_STARTING = 2,
    EVENTS_TYPE_RUNNING1 = 3,
    EVENTS_TYPE_STOPPING = 4,
    EVENTS_TYPE_ABORTING = 5,
    EVENTS_TYPE_FREEZING = 6,
    EVENTS_TYPE_FROZEN = 7,
    EVENTS_TYPE_THAWED = 8,
    EVENTS_TYPE_OOM = 9,
    EVENTS_TYPE_CREATE = 10,
    EVENTS_TYPE_START,
    EVENTS_TYPE_RESTART,
    EVENTS_TYPE_STOP,
    EVENTS_TYPE_EXEC_CREATE,
    EVENTS_TYPE_EXEC_START,
    EVENTS_TYPE_EXEC_DIE,
    EVENTS_TYPE_ATTACH,
    EVENTS_TYPE_KILL,
    EVENTS_TYPE_TOP,
    EVENTS_TYPE_RENAME,
    EVENTS_TYPE_ARCHIVE_PATH,
    EVENTS_TYPE_EXTRACT_TO_DIR,
    EVENTS_TYPE_UPDATE,
    EVENTS_TYPE_PAUSE,
    EVENTS_TYPE_UNPAUSE,
    EVENTS_TYPE_EXPORT,
    EVENTS_TYPE_RESIZE,
    EVENTS_TYPE_PAUSED1,
    EVENTS_TYPE_MAX_STATE
} container_events_type_t;

typedef enum {
    EVENTS_TYPE_IMAGE_LOAD = 0,
    EVENTS_TYPE_IMAGE_REMOVE,
    EVENTS_TYPE_IMAGE_PULL,
    EVENTS_TYPE_IMAGE_LOGIN,
    EVENTS_TYPE_IMAGE_LOGOUT,
    EVENTS_TYPE_IMAGE_MAX_STATE
} image_events_type_t;

struct isulad_events_format {
    types_timestamp_t timestamp;
    uint32_t has_type;
    container_events_type_t type;
    char *opt;
    char *id;
    char **annotations;
    size_t annotations_len;
    uint32_t has_pid;
    uint32_t pid;
    uint32_t has_exit_status;
    uint32_t exit_status;
};

void isulad_events_format_free(struct isulad_events_format *value);

int event_copy(const struct isulad_events_format *src, struct isulad_events_format *dest);

struct isulad_events_format *dup_event(const struct isulad_events_format *event);

#ifdef __cplusplus
}
#endif

#endif
