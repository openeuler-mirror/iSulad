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
 * Description: provide verify mock
 ******************************************************************************/

#include "verify_mock.h"

namespace {
MockVerify *g_verify_mock = NULL;
}

void MockVerify_SetMock(MockVerify *mock)
{
    g_verify_mock = mock;
}

int verify_host_config_settings(host_config *hostconfig, bool update)
{
    if (g_verify_mock != nullptr) {
        return g_verify_mock->VerifyHostConfigSettings(hostconfig, update);
    }
    return 0;
}
