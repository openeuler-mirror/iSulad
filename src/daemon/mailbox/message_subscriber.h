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

#ifndef SRC_DAEMON_MAILBOX_MESSAGE_SUBSCRIBER_H
#define SRC_DAEMON_MAILBOX_MESSAGE_SUBSCRIBER_H

#include "blocking_queue.h"
#include "mailbox_message.h"

typedef struct {
    blocking_queue *queue;
} message_subscriber;

message_subscriber *message_subscriber_create(int64_t timeout, void (*release)(void *));

void message_subscriber_shutdown(message_subscriber *sub);

void message_subscriber_destroy(message_subscriber *sub);

int message_subscriber_push(message_subscriber *sub, mailbox_message *msg);

int message_subscriber_pop(message_subscriber *sub, mailbox_message **msg);

// define auto free function callback for blocking queue
define_auto_cleanup_callback(message_subscriber_destroy, message_subscriber);
// define auto free macro for blocking queue
#define __isula_auto_subscriber auto_cleanup_tag(message_subscriber_destroy)

#endif
