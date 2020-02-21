/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wujing
 * Create: 2020-02-11
 * Description: provide selinux mock
 ******************************************************************************/


#ifndef SELINUX_MOCK_H_
#define SELINUX_MOCK_H_

#include <gmock/gmock.h>
#include <selinux/selinux.h>

class MockSelinux {
public:
    virtual ~MockSelinux() = default;
    MOCK_METHOD0(SelinuxfsExists, int(void));
};

void Selinux_SetMock(MockSelinux* mock);

#endif  // SELINUX_LABEL_MOCK_H_
