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
 * Description: provide container collector definition
 ******************************************************************************/
#ifndef __COLLECTOR_H
#define __COLLECTOR_H

#include <pthread.h>
#include <semaphore.h>
#include "linked_list.h"
#include "stream_wrapper.h"
#include "event_type.h"

#ifdef __cplusplus
extern "C" {
#endif

struct context_lists {
    pthread_mutex_t context_mutex;
    struct linked_list context_list;
};

void events_handler(struct monitord_msg *msg);

int add_monitor_client(char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                       const stream_func_wrapper *stream);

int events_subscribe(const char *name, const types_timestamp_t *since, const types_timestamp_t *until,
                     const stream_func_wrapper *stream);

struct isulad_events_format *dup_event(const struct isulad_events_format *event);

int events_module_init(char **msg);

#ifdef __cplusplus
}
#endif

#endif /* __COLLECTOR_H */
