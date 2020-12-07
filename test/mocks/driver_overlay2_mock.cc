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
 * Author: wangfengtu
 * Create: 2020-02-19
 * Description: provide driver overlay2 mock
 ******************************************************************************/

#include "driver_overlay2_mock.h"

namespace {
MockDriverOverlay2 *g_driver_overlay2_mock = nullptr;
}

void MockDriverOverlay2_SetMock(MockDriverOverlay2* mock)
{
    g_driver_overlay2_mock = mock;
}

int overlay2_init(struct graphdriver *driver)
{
    if (g_driver_overlay2_mock != nullptr) {
        return g_driver_overlay2_mock->Overlay2Init(driver);
    }
    return -1;
}

int overlay2_parse_options(struct graphdriver *driver, const char **options, size_t options_len)
{
    if (g_driver_overlay2_mock != nullptr) {
        return g_driver_overlay2_mock->Overlay2ParseOptions(driver, options, options_len);
    }
    return -1;
}

bool overlay2_is_quota_options(struct graphdriver *driver, const char *option)
{
    if (g_driver_overlay2_mock != nullptr) {
        return g_driver_overlay2_mock->Overlay2IsQuotaOptions(driver, option);
    }
    return false;
}
