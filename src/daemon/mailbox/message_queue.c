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

#include "message_queue.h"

#include <sys/prctl.h>
#include <isula_libutils/log.h>

#include "utils.h"

// default set subscriber timeout to 1000ms, maybe could be configured later
const int64_t subscribe_timeout = 1000;

static void message_queue_subscriber_free(void *key, void *val)
{
    return;
}

static void *message_queue_thread(void *arg)
{
    int ret = 0;

    ret = pthread_detach(pthread_self());
    if (ret != 0) {
        CRIT("Set thread detach fail");
        return NULL;
    }

    prctl(PR_SET_NAME, "Message Queue");

    message_queue *mq = (message_queue *)arg;
    if (mq == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }

    for (;;) {
        void *data = NULL;
        if (blocking_queue_pop(mq->messages, &data) != 0) {
            ERROR("Fail to get message, message queue thread exit");
            break;
        }

        __isula_auto_mailbox_message mailbox_message *msg = (mailbox_message *)data;
        // an empty msg indicates shutdown
        if (pthread_rwlock_rdlock(&mq->rwlock) != 0) {
            ERROR("Failed to lock rwlock");
            continue;
        }

        bool should_shutdown = (msg == NULL);
        map_itor *itor = map_itor_new(mq->subscribers);
        if (itor == NULL) {
            ERROR("Out of memory");
            if (pthread_rwlock_unlock(&mq->rwlock) != 0) {
                ERROR("Failed to lock rwlock");
            }
            break;
        }

        for (; map_itor_valid(itor); map_itor_next(itor)) {
            void *sub = map_itor_key(itor);
            if (should_shutdown) {
                message_subscriber_shutdown(sub);
            } else {
                if (message_subscriber_push(sub, msg) != 0) {
                    ERROR("Failed to push event to subscriber");
                }
            }
        }
        map_itor_free(itor);

        if (pthread_rwlock_unlock(&mq->rwlock) != 0) {
            ERROR("Failed to unlock rwlock");
        }

        // if msg is NULL, it is a shutdown signal
        if (should_shutdown) {
            break;
        }
    }

    return NULL;
}

message_queue *message_queue_create(void (*release)(void *))
{
    __isula_auto_free message_queue *mq = NULL;
    __isula_auto_blocking_queue blocking_queue *bq = NULL;
    pthread_t message_queue_tid;
    mq = util_common_calloc_s(sizeof(message_queue));
    if (mq == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    mq->messages = blocking_queue_create(BLOCKING_QUEUE_NO_TIMEOUT, release);
    if (mq->messages == NULL) {
        ERROR("Failed to create events queue");
        return NULL;
    }
    bq = mq->messages;

    mq->subscribers = map_new(MAP_PTR_INT, MAP_DEFAULT_CMP_FUNC, message_queue_subscriber_free);
    if (mq->subscribers == NULL) {
        ERROR("Failed to create subscribers map");
        return NULL;
    }

    if (pthread_rwlock_init(&mq->rwlock, NULL) != 0) {
        ERROR("Failed to init rwlock");
        map_free(mq->subscribers);
        return NULL;
    }

    if (pthread_create(&message_queue_tid, NULL, message_queue_thread, mq) != 0) {
        ERROR("Failed to create message queue thread");
        pthread_rwlock_destroy(&mq->rwlock);
        map_free(mq->subscribers);
        return NULL;
    }

    bq = NULL;
    return isula_transfer_ptr(mq);
}

// message queue should be global value, it will be destroyed when daemon exit
void message_queue_shutdown(message_queue *mq)
{
    if (mq == NULL) {
        return;
    }

    blocking_queue_clear(mq->messages);

    // push a nullptr to notify the thread to exit
    if (blocking_queue_push(mq->messages, NULL) != 0) {
        ERROR("Failed to push nullptr to message queue");
    }
}

message_subscriber *message_queue_subscribe(message_queue *mq, void (*release)(void *))
{
    __isula_auto_subscriber message_subscriber *sub = NULL;
    __isula_auto_prw_unlock pthread_rwlock_t *lock = NULL;
    int val = 0;
    if (mq == NULL) {
        ERROR("Invalid argument");
        return NULL;
    }

    sub = message_subscriber_create(subscribe_timeout, release);
    if (sub == NULL) {
        ERROR("Failed to create subscriber");
        return NULL;
    }

    if (pthread_rwlock_wrlock(&mq->rwlock) != 0) {
        ERROR("Failed to lock rwlock");
        return NULL;
    }
    lock = &mq->rwlock;

    if (map_insert(mq->subscribers, sub, (void *)&val) == false) {
        ERROR("Failed to insert subscriber");
        return NULL;
    }

    return isula_transfer_ptr(sub);
}

void message_queue_unsubscribe(message_queue *mq, message_subscriber *sub)
{
    __isula_auto_prw_unlock pthread_rwlock_t *lock = NULL;
    if (mq == NULL) {
        ERROR("Invalid argument");
        return;
    }

    if (pthread_rwlock_wrlock(&mq->rwlock) != 0) {
        ERROR("Failed to lock rwlock");
        return;
    }
    lock = &mq->rwlock;

    if (map_remove(mq->subscribers, sub) == false) {
        ERROR("Failed to remove subscriber");
        return;
    }

    return;
}

int message_queue_publish(message_queue *mq, mailbox_message *msg)
{
    if (mq == NULL || msg == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (blocking_queue_push(mq->messages, msg) != 0) {
        ERROR("Failed to push message");
        return -1;
    }
    return 0;
}

bool message_queue_have_subscribers(message_queue *mq)
{
    __isula_auto_prw_unlock pthread_rwlock_t *lock = NULL;
    if (mq == NULL) {
        ERROR("Invalid argument");
        return false;
    }

    if (pthread_rwlock_wrlock(&mq->rwlock) != 0) {
        ERROR("Failed to lock rwlock");
        return false;
    }
    lock = &mq->rwlock;

    return map_size(mq->subscribers) > 0;
}
