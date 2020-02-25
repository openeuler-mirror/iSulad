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
 * Author: jikui
 * Create: 2020-02-25
 * Description: provide health_check mock
 ******************************************************************************/

#ifndef HEALTH_CHECK_MOCK_H_
#define HEALTH_CHECK_MOCK_H_

#include <gmock/gmock.h>
#include "health_check.h"

class MockHealthCheck {
public:
    MOCK_METHOD1(UpdateHealthMonitor, void(const char *container_id));
};

void MockHealthCheck_SetMock(MockHealthCheck* mock);

#endif
