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
 * Description: provide mailbox message definition
 ******************************************************************************/

#include "mailbox_message.h"

#include <isula_libutils/log.h>

#include "utils.h"

// Once the create succeeds, the ownership is transferred to the mailbox_message.
mailbox_message *mailbox_message_create(void *data, void (*destroy)(void *)) {
    __isula_auto_free mailbox_message *msg = NULL;
    msg = util_common_calloc_s(sizeof(mailbox_message));
    if (msg == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    msg->data = data;
    msg->destroy = destroy;
    msg->ref_count = 1;

    if (pthread_mutex_init(&msg->lock, NULL) != 0) {
        ERROR("Failed to init mutex");
        return NULL;
    }

    return isula_transfer_ptr(msg);
}

int mailbox_message_ref(mailbox_message *dest) {
    __isula_auto_pm_unlock pthread_mutex_t *lock = NULL;
    if (dest == NULL) {
        ERROR("Invalid mailbox_message");
        return -1;
    }

    if (pthread_mutex_lock(&dest->lock) != 0) {
        ERROR("Failed to lock mutex");
        return -1;
    }
    lock = &dest->lock;

    if (dest->ref_count == INT_MAX) {
        ERROR("Reference count overflow");
        return -1;
    }

    dest->ref_count++;

    return 0;
}

void mailbox_message_unref(mailbox_message *dest) {
    __isula_auto_pm_unlock pthread_mutex_t *lock = NULL;
    if (dest == NULL) {
        return;
    }

    if (pthread_mutex_lock(&dest->lock) != 0) {
        ERROR("Failed to lock mutex");
        return;
    }
    lock = &dest->lock;

    if (dest->ref_count == 0) {
        ERROR("Reference count underflow, should not reach here");
        return;
    }

    dest->ref_count--;
    if (dest->ref_count == 0) {
        if (dest->destroy) {
            dest->destroy(dest->data);
        }
        lock = NULL;
        (void)pthread_mutex_unlock(&dest->lock);
        (void)pthread_mutex_destroy(&dest->lock);
        free(dest);
    }
    return;
}
