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

#include "blocking_queue.h"

#include <pthread.h>
#include <time.h>
#include <isula_libutils/log.h>

#include "utils.h"
#include "utils_timestamp.h"

// create blocking queue with timeout(ms), if timeout < 0, then with no timeout
blocking_queue *blocking_queue_create(int64_t timeout, void (*release)(void *))
{
    __isula_auto_free blocking_queue *queue = NULL;
    __isula_auto_free blocking_node *node = NULL;
    queue = (blocking_queue *)util_common_calloc_s(sizeof(blocking_queue));
    if (queue == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    node = (blocking_node *)util_common_calloc_s(sizeof(blocking_node));
    if (node == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        ERROR("Failed to init mutex");
        return NULL;
    }

    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        ERROR("Failed to init cond");
        (void)pthread_mutex_destroy(&queue->lock);
        return NULL;
    }

    queue->head = node;
    queue->tail = node;
    node = NULL;
    queue->release = release;

    if (timeout >= 0) {
        queue->timeout.tv_sec = timeout / (Time_Second / Time_Milli);
        queue->timeout.tv_nsec = (timeout % (Time_Second / Time_Milli) ) * Time_Milli;
    } else {
        queue->timeout.tv_sec = -1;
    }
    
    return isula_transfer_ptr(queue);
}

int blocking_queue_push(blocking_queue *queue, void *data)
{
    __isula_auto_free blocking_node *new_node = NULL;
    __isula_auto_pm_unlock pthread_mutex_t *lock = NULL;
    if (queue == NULL) {
        ERROR("Invalid NULL arguments");
        return -1;
    }

    new_node = (blocking_node *)util_common_calloc_s(sizeof(blocking_node));
    if (new_node == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    new_node->data = data;
    new_node->next = NULL;

    if (pthread_mutex_lock(&queue->lock) != 0) {
        ERROR("Failed to lock mutex");
        return -1;
    }
    lock = &queue->lock;

    queue->tail->next = new_node;
    queue->tail = new_node;
    new_node = NULL;

    if (pthread_cond_broadcast(&queue->not_empty) != 0) {
        ERROR("Failed to broadcast cond");
    }

    return 0;
}

int blocking_queue_pop(blocking_queue *queue, void **data) {
    if (queue == NULL || data == NULL) {
        ERROR("Invalid NULL arguments");
        return -1;
    }

    __isula_auto_pm_unlock pthread_mutex_t *lock = NULL;
    if (pthread_mutex_lock(&queue->lock) != 0) {
        ERROR("Failed to lock mutex");
        return -1;
    }
    lock = &queue->lock;

    while (queue->head->next == NULL) {
        if (queue->timeout.tv_sec >= 0) {
            int ret = pthread_cond_timedwait(&queue->not_empty, &queue->lock, &queue->timeout);
            if (ret != 0) {
                if (ret != ETIMEDOUT) {
                    ERROR("Failed to wait cond");
                }
                return ret;
            }
        } else {
            int ret = pthread_cond_wait(&queue->not_empty, &queue->lock);
            if (ret != 0) {
                ERROR("Failed to wait cond");
                return ret;
            }
        }
    }

    blocking_node *old_head = queue->head;
    blocking_node *new_head = old_head->next;
    *data = new_head->data;
    queue->head = new_head;

    free(old_head);
    return 0;
}

void blocking_queue_clear(blocking_queue *queue)
{
    if (queue == NULL) {
        return;
    }

    __isula_auto_pm_unlock pthread_mutex_t *lock = NULL;
    // clear all nodes in queue
    if (queue == NULL) {
        ERROR("Invalid NULL arguments");
        return;
    }

    if (pthread_mutex_lock(&queue->lock) != 0) {
        ERROR("Failed to lock mutex");
        return;
    }
    lock = &queue->lock;

    while (queue->head->next != NULL) {
        blocking_node *old_head = queue->head;
        blocking_node *new_head = old_head->next;
        if (queue->release) {
            queue->release(old_head->data);
        }
        free(old_head);
        queue->head = new_head;
    }
}

// ensure there is no other thread executing enqueue or dequeue operation
void blocking_queue_destroy(blocking_queue *queue)
{
    if (queue == NULL) {
        return;
    }

    blocking_queue_clear(queue);

    (void)pthread_mutex_destroy(&queue->lock);

    (void)pthread_cond_destroy(&queue->not_empty);

    free(queue);
}
