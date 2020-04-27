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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container events handler definition
 ******************************************************************************/
#ifndef __EVENTS_HANDLER_H
#define __EVENTS_HANDLER_H

#include <stdint.h>
#include <pthread.h>
#include "linked_list.h"

#include "libisulad.h"

typedef struct _events_handler_t {
    pthread_mutex_t mutex;
    bool init_mutex;
    struct linked_list events_list;
    bool has_handler;
} events_handler_t;


events_handler_t *events_handler_new();

void events_handler_free(events_handler_t *handler);

int events_handler_post_events(events_handler_t *handler, const struct isulad_events_format *event);

#endif /* __EVENTS_HANDLER_H */

