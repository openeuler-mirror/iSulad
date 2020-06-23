/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide monitord definition
 ******************************************************************************/
#ifndef __ISULAD_MONITORD_H
#define __ISULAD_MONITORD_H
#include <pthread.h>
#include <semaphore.h>
#include <limits.h>
#include "libisulad.h"
#include "utils.h"

#define ARGS_MAX 255 /* # args chars in a monitord msg */
#define EXTRA_ANNOTATION_MAX 255 /* # annotation chars in a monitord msg */

typedef enum { CONTAINER_EVENT, IMAGE_EVENT } msg_event_type_t;
typedef enum { MONITORD_MSG_STATE, MONITORD_MSG_PRIORITY, MONITORD_MSG_EXIT_CODE } msg_type_t;

struct monitord_msg {
    msg_type_t type;
    msg_event_type_t event_type;
    char name[CONTAINER_ID_MAX_LEN + 1];
    char args[ARGS_MAX];
    char extra_annations[EXTRA_ANNOTATION_MAX];
    int value;
    int exit_code;
    int pid;
};

struct monitord_sync_data {
    sem_t *monitord_sem;
    int *exit_code;
};

char *isulad_monitor_fifo_name(const char *rootpath);

int connect_monitord(const char *rootpath);

int read_monitord_message_timeout(int fd, struct monitord_msg *msg, int timeout);

int new_monitord(struct monitord_sync_data *msync);

#endif
