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
 * Description: provide message queue definition
 ******************************************************************************/

#ifndef DAEMON_MESSAGE_MESSAGE_QUEUE_H
#define DAEMON_MESSAGE_MESSAGE_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#include "blocking_queue.h"
#include "mailbox_message.h"
#include "map.h"
#include "message_subscriber.h"

typedef struct message_queue {
    blocking_queue *messages;

    // lock for set of subscribers
    pthread_rwlock_t rwlock;

    map_t *subscribers;

    int64_t sub_timeout;
} message_queue;

message_queue *message_queue_create(void (*release)(void *));

void message_queue_shutdown(message_queue *mq);

message_subscriber *message_queue_subscribe(message_queue *mq, void (*release)(void *));

void message_queue_unsubscribe(message_queue *mq, message_subscriber *sub);

int message_queue_publish(message_queue *mq, mailbox_message *msg);

bool message_queue_have_subscribers(message_queue *mq);

#ifdef __cplusplus
}
#endif

#endif
