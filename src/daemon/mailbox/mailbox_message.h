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
 * Description: provide ref counted ptr definition
 ******************************************************************************/

#ifndef DAEMON_MAILBOX_MAILBOX_MESSAGE_H
#define DAEMON_MAILBOX_MAILBOX_MESSAGE_H

#include <pthread.h>
#include <stdbool.h>

#include <isula_libutils/auto_cleanup.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mailbox_message {
    void *data;
    size_t ref_count;
    pthread_mutex_t lock;
    void (*destroy)(void *);
} mailbox_message;

mailbox_message *mailbox_message_create(void *ptr, void (*destroy)(void *));

int mailbox_message_ref(mailbox_message *p);

void mailbox_message_unref(mailbox_message *p);

// define auto free function callback for mailbox_message
define_auto_cleanup_callback(mailbox_message_unref, mailbox_message);
// define auto free macro for char *
#define __isula_auto_mailbox_message auto_cleanup_tag(mailbox_message_unref)

#ifdef __cplusplus
}
#endif

#endif
