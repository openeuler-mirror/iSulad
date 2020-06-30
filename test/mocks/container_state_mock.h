/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikui
 * Create: 2020-02-25
 * Description: provide container_state mock
 ******************************************************************************/

#ifndef CONTAINER_STATE_MOCK_H_
#define CONTAINER_STATE_MOCK_H_

#include <gmock/gmock.h>
#include "container_state.h"

class MockContainerState {
public:
    MOCK_METHOD1(IsRunning, bool(container_state_t *s));
    MOCK_METHOD1(IsPaused, bool(container_state_t *s));
    MOCK_METHOD1(IsRestarting, bool(container_state_t *s));
    MOCK_METHOD1(IsDead, bool(container_state_t *s));
    MOCK_METHOD1(StateResetPaused, void(container_state_t *s));
    MOCK_METHOD2(ContainerStateSetError, void(container_state_t *s, const char *err));
    MOCK_METHOD1(StateSetPaused, void(container_state_t *s));
    MOCK_METHOD1(IsRemovalInProgress, bool(container_state_t *s));
};

void MockContainerState_SetMock(MockContainerState *mock);

#endif
