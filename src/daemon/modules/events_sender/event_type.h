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
 * Create: 2020-06-23
 * Description: provide container collector definition
 ******************************************************************************/
#ifndef __EVENT_TYPE_H
#define __EVENT_TYPE_H

#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EXIT,
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING,
    ABORTING,
    FREEZING,
    FROZEN,
    THAWED,
    OOM,
    CREATE,
    START,
    RESTART,
    STOP,
    EXEC_CREATE,
    EXEC_START,
    EXEC_DIE,
    ATTACH,
    KILL,
    TOP,
    RENAME,
    ARCHIVE_PATH,
    EXTRACT_TO_DIR,
    UPDATE,
    PAUSE,
    UNPAUSE,
    EXPORT,
    RESIZE,
    PAUSED1,
    MAX_STATE,
} runtime_state_t;

typedef enum { IM_LOAD, IM_REMOVE, IM_PULL, IM_LOGIN, IM_LOGOUT, IM_IMPORT } image_state_t;

typedef enum { CONTAINER_EVENT, IMAGE_EVENT } msg_event_type_t;
typedef enum { MONITORD_MSG_STATE, MONITORD_MSG_PRIORITY, MONITORD_MSG_EXIT_CODE } msg_type_t;

struct monitord_msg {
    msg_type_t type;
    msg_event_type_t event_type;
    char name[CONTAINER_ID_MAX_LEN + 1];
    char args[EVENT_ARGS_MAX];
    char extra_annations[EVENT_EXTRA_ANNOTATION_MAX];
    int value;
    int exit_code;
    int pid;
};

#ifdef __cplusplus
}
#endif

#endif /* __EVENT_TYPE_H */
