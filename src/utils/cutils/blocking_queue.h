/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikai
 * Create: 2024-03-25
 * Description: provide blocking queue definition
 ******************************************************************************/

#ifndef DAEMON_UTILS_CUTILS_BLOCKING_QUEUE_H
#define DAEMON_UTILS_CUTILS_BLOCKING_QUEUE_H

#include <pthread.h>
#include <time.h>
#include <isula_libutils/auto_cleanup.h>

#include "utils_timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLOCKING_QUEUE_NO_TIMEOUT -1

typedef struct blocking_node {
    void *data;
    struct blocking_node *next;
} blocking_node;

typedef struct blocking_queue {
    blocking_node *head;
    blocking_node *tail;
    pthread_mutex_t lock;
    struct timespec timeout;
    pthread_cond_t not_empty;
    void (*release)(void *);
} blocking_queue;

// create blocking queue with timeout(ms), if timeout < 0, then with no timeout
blocking_queue *blocking_queue_create(int64_t timeout, void (*release)(void *));

int blocking_queue_push(blocking_queue *queue, void *data);

int blocking_queue_pop(blocking_queue *queue, void **data);

void blocking_queue_clear(blocking_queue *queue);

// ensure there is no other thread executing enqueue or dequeue operation
void blocking_queue_destroy(blocking_queue *queue);

// define auto free function callback for blocking queue
define_auto_cleanup_callback(blocking_queue_destroy, blocking_queue);
// define auto free macro for blocking queue
#define __isula_auto_blocking_queue auto_cleanup_tag(blocking_queue_destroy)

#ifdef __cplusplus
}
#endif

#endif
