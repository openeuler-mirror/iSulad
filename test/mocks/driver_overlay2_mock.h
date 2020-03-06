/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2020-02-19
 * Description: provide driver overlay2 mock
 ******************************************************************************/

#ifndef DRIVER_OVERLAY2_MOCK_H_
#define DRIVER_OVERLAY2_MOCK_H_

#include <gmock/gmock.h>
#include "driver_overlay2.h"

class MockDriverOverlay2 {
public:
    virtual ~MockDriverOverlay2() = default;
    MOCK_METHOD1(Overlay2Init, int(struct graphdriver *));
    MOCK_METHOD3(Overlay2ParseOptions, int(struct graphdriver *, const char **, size_t));
    MOCK_METHOD2(Overlay2IsQuotaOptions, bool(struct graphdriver *, const char *));
};

void MockDriverOverlay2_SetMock(MockDriverOverlay2* mock);

#endif  // DRIVER_OVERLAY2_MOCK_H_
