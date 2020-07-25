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

#include "container_state_mock.h"

namespace {
MockContainerState *g_container_state_mock = NULL;
}

void MockContainerState_SetMock(MockContainerState *mock)
{
    g_container_state_mock = mock;
}

bool container_is_running(container_state_t *s)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->IsRunning(s);
    }
    return true;
}

bool container_is_restarting(container_state_t *s)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->IsRestarting(s);
    }
    return false;
}

bool container_is_dead(container_state_t *s)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->IsDead(s);
    }
    return true;
}

void container_state_set_error(container_state_t *s, const char *err)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->ContainerStateSetError(s, err);
    }
}

bool container_is_paused(container_state_t *s)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->IsPaused(s);
    }
    return true;
}

void container_state_reset_paused(container_state_t *s)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->StateResetPaused(s);
    }
}

void container_state_set_paused(container_state_t *s)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->StateSetPaused(s);
    }
}

bool container_is_removal_in_progress(container_state_t *s)
{
    if (g_container_state_mock != nullptr) {
        return g_container_state_mock->IsRemovalInProgress(s);
    }
    return true;
}
