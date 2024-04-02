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

#ifndef _ISULAD_TEST_MOCKS_MAILBOX_MOCK_H
#define _ISULAD_TEST_MOCKS_MAILBOX_MOCK_H

#include <gmock/gmock.h>
#include "mailbox.h"

class MockMailbox {
public:
    virtual ~MockMailbox() = default;
    MOCK_METHOD2(MailboxPublish, void(mailbox_topic topic, void *data));
};

void Mailbox_SetMock(MockMailbox* mock);

#endif
