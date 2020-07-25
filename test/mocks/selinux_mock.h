/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-02-11
 * Description: provide selinux mock
 ******************************************************************************/


#ifndef _ISULAD_TEST_MOCKS_SELINUX_MOCK_H
#define _ISULAD_TEST_MOCKS_SELINUX_MOCK_H

#include <gmock/gmock.h>
#include <selinux/selinux.h>

class MockSelinux {
public:
    virtual ~MockSelinux() = default;
    MOCK_METHOD0(SelinuxfsExists, int(void));
};

void Selinux_SetMock(MockSelinux* mock);

#endif // _ISULAD_TEST_MOCKS_SELINUX_MOCK_H
