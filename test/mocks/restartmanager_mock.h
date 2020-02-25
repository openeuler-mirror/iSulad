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
 * Description: provide restartmanager mock
 ******************************************************************************/

#ifndef RESTARTMANAGER_MOCK_H_
#define RESTARTMANAGER_MOCK_H_

#include <gmock/gmock.h>
#include "restartmanager.h"

class MockRestartmanager {
public:
};

void MockRestartmanager_SetMock(MockRestartmanager *mock);

#endif
