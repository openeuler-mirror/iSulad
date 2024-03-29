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
 * Description: provide message subscriber definition
 ******************************************************************************/

#include "message_subscriber.h"

#include <isula_libutils/log.h>

#include "utils.h"

message_subscriber *message_subscriber_create(int64_t timeout, void (*release)(void *))
{
    message_subscriber *sub = (message_subscriber *)util_common_calloc_s(sizeof(message_subscriber));
    if (sub == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    sub->queue = blocking_queue_create(timeout, release);
    if (sub->queue == NULL) {
        ERROR("Failed to create blocking queue");
        free(sub);
        return NULL;
    }
    return sub;
}

int message_subscriber_push(message_subscriber *sub, mailbox_message *msg)
{
    if (sub == NULL || msg == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (mailbox_message_ref(msg) != 0) {
        ERROR("Failed to get message");
        return -1;
    }

    if (blocking_queue_push(sub->queue, msg) != 0) {
        ERROR("Failed to push message to queue");
        mailbox_message_unref(msg);
        return -1;
    }

    return 0;
}

int message_subscriber_pop(message_subscriber *sub, mailbox_message **msg)
{
    if (sub == NULL) {
        ERROR("Invalid argument");
        return -1;
    }
    return blocking_queue_pop(sub->queue, (void **)msg);
}

void message_subscriber_shutdown(message_subscriber *sub)
{
    if (sub == NULL) {
        return;
    }

    blocking_queue_clear(sub->queue);
    (void)blocking_queue_push(sub->queue, NULL);
}

void message_subscriber_destroy(message_subscriber *sub)
{
    if (sub == NULL) {
        return;
    }
    blocking_queue_destroy(sub->queue);
    free(sub);
}
