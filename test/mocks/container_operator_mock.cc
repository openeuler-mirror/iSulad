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
 * Description: provide containers_gc mock
 ******************************************************************************/

#include "container_operator_mock.h"

namespace {
MockContainersOperator *g_containers_operator_mock = NULL;
}

void MockContainersOperator_SetMock(MockContainersOperator *mock)
{
    g_containers_operator_mock = mock;
}

bool container_is_in_gc_progress(const char *id)
{
    if (g_containers_operator_mock != nullptr) {
        return g_containers_operator_mock->IsGcProgress(id);
    }
    return true;
}
