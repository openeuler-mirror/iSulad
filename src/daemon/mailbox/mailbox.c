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
 * Description: provide common event definition
 ******************************************************************************/

#include "mailbox.h"

#include <isula_libutils/log.h>

#include "message_queue.h"
#include "mailbox_message.h"
#include "message_subscriber.h"

mailbox_topic_handler_t mailbox_topic_handlers[MAILBOX_TOPIC_MAX] = { 0 };

static bool mailbox_topic_valid(mailbox_topic topic) {
    return topic > MAILBOX_TOPIC_INVALID && topic < MAILBOX_TOPIC_MAX;
}

static bool mailbox_should_publish(mailbox_topic topic)
{
    if (!mailbox_topic_valid(topic)) {
        ERROR("Invalid topic %d", topic);
        return false;
    }

    if (!mailbox_topic_handlers[topic].registered) {
        return false;
    }

    if (mailbox_topic_handlers[topic].queue == NULL) {
        return true;
    }

    // for async queues, only publish if anyone subscribe
    return message_queue_have_subscribers(mailbox_topic_handlers[topic].queue);
}

// only register once when iSulad start, no need to free the queue
int mailbox_register_topic_handler(mailbox_topic topic, message_generator_t generator, void *context,
                                   message_release_t release, bool async)
{
    if (!mailbox_topic_valid(topic)) {
        ERROR("Invalid topic %d", topic);
        return -1;
    }

    if (generator == NULL) {
        ERROR("Invalid generator for topic %d", topic);
        return -1;
    }

    mailbox_topic_handlers[topic].generator = generator;
    mailbox_topic_handlers[topic].context = context;
    mailbox_topic_handlers[topic].release = release;
    if (async) {
        mailbox_topic_handlers[topic].queue = message_queue_create(release);
        if (mailbox_topic_handlers[topic].queue == NULL) {
            ERROR("Failed to create message queue for topic %d", topic);
            return -1;
        }
    }
    mailbox_topic_handlers[topic].registered = true;
    return 0;
}

// unregister only when iSulad shutdown, no need to free the queue
void mailbox_unregister_topic_handler(mailbox_topic topic)
{
    if (!mailbox_topic_valid(topic)) {
        ERROR("Invalid topic %d", topic);
        return;
    }

    if (mailbox_topic_handlers[topic].queue != NULL) {
        message_queue_shutdown(mailbox_topic_handlers[topic].queue);
    }
    mailbox_topic_handlers[topic].registered = false;
}

void mailbox_publish(mailbox_topic topic, void *data)
{
    if (!mailbox_should_publish(topic)) {
        return;
    }

    message_generator_t  generator = mailbox_topic_handlers[topic].generator;
    void *context = mailbox_topic_handlers[topic].context;
    message_release_t release = mailbox_topic_handlers[topic].release;
    message_queue *queue = mailbox_topic_handlers[topic].queue;

    if (generator == NULL) {
        ERROR("No handler for topic %d", topic);
        return;
    }

    void *middle = generator(context, data);
    if (middle == NULL) {
        return;
    }

    if (queue != NULL) {
        mailbox_message *msg = mailbox_message_create(middle, release);
        if (msg == NULL) {
            ERROR("Failed to create mailbox message");
            if (release) {
                release(middle);
            }
            return;
        }
        if (message_queue_publish(queue, msg) != 0) {
            ERROR("Failed to publish event");
            mailbox_message_unref(msg);
            return;
        }
    }
}

message_subscriber *mailbox_subscribe(mailbox_topic topic)
{
    if (!mailbox_topic_valid(topic)) {
        ERROR("Invalid topic %d", topic);
        return NULL;
    }

    if (!mailbox_topic_handlers[topic].registered) {
        ERROR("Handler for topic %d not registered", topic);
        return NULL;
    }

    if (mailbox_topic_handlers[topic].queue != NULL) {
        return message_queue_subscribe(mailbox_topic_handlers[topic].queue,
                                       mailbox_topic_handlers[topic].release);
    }

    // For sync queues, there is no need to subscribe, just return
    return NULL;
}

void mailbox_unsubscribe(mailbox_topic topic, message_subscriber *sub)
{
    if (!mailbox_topic_valid(topic)) {
        ERROR("Invalid topic %d", topic);
        return;
    }

    if (!mailbox_topic_handlers[topic].registered) {
        ERROR("Handler for topic %d not registered", topic);
        return;
    }

    if (mailbox_topic_handlers[topic].queue != NULL) {
        return message_queue_unsubscribe(mailbox_topic_handlers[topic].queue, sub);
    }

    return;
}
