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
 * Create: 2020-08-20
 * Description: provide oci image mock
 ******************************************************************************/

#include "oci_image_mock.h"

namespace {
MockOciImage *g_oci_image_mock = nullptr;
}

void MockOciImage_SetMock(MockOciImage* mock)
{
    g_oci_image_mock = mock;
}

bool oci_valid_time(char *time)
{
    if (g_oci_image_mock != nullptr) {
        return g_oci_image_mock->OciValidTime(time);
    }
    return false;
}

struct oci_image_module_data *get_oci_image_data(void)
{
    if (g_oci_image_mock != nullptr) {
        return g_oci_image_mock->GetOciImageData();
    }
    return { 0 };
}
