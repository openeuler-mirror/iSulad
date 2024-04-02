/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikai
 * Create: 2024-04-02
 * Description: mailbox mock
 ******************************************************************************/

#include "mailbox_mock.h"

MockMailbox *g_mailbox_mock = nullptr;

void Mailbox_SetMock(MockMailbox* mock)
{
    g_mailbox_mock = mock;
}

void mailbox_publish(mailbox_topic topic, void *data)
{
    if (g_mailbox_mock != nullptr) {
        g_mailbox_mock->MailboxPublish(topic, data);
    }
}
