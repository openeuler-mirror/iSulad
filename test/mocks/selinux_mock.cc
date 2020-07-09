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

#include "selinux_mock.h"

namespace {
MockSelinux *g_selinux_mock = NULL;
}

void Selinux_SetMock(MockSelinux* mock)
{
    g_selinux_mock = mock;
}

int selinuxfs_exists(void)
{
    if (g_selinux_mock != nullptr) {
        return g_selinux_mock->SelinuxfsExists();
    }
    return 0;
}

