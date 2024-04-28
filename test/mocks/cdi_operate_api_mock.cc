/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikai
 * Create: 2023-10-20
 * Description: provide image api mock
 ******************************************************************************/

#include "cdi_operate_api_mock.h"

namespace {
std::shared_ptr<MockCdiOperateApi> g_cdi_operate_api_mock = nullptr;
}

void MockCdiOperateApi_SetMock(std::shared_ptr<MockCdiOperateApi> mock)
{
    g_cdi_operate_api_mock = mock;
}

int cdi_operate_registry_init(char **specs_dirs, size_t specs_dirs_len)
{
    if (g_cdi_operate_api_mock != nullptr) {
        return g_cdi_operate_api_mock->CdiOperateRegistryInit(specs_dirs, specs_dirs_len);
    }
    return 0;
}

int cdi_operate_refresh(void)
{
    if (g_cdi_operate_api_mock != nullptr) {
        return g_cdi_operate_api_mock->CdiOperateRefresh();
    }
    return 0;
}

int cdi_operate_inject_devices(oci_runtime_spec *spec, string_array *devices)
{
    if (g_cdi_operate_api_mock != nullptr) {
        return g_cdi_operate_api_mock->CdiOperateInjectDevices(spec, devices);
    }
    return 0;
}

int cdi_operate_parse_annotations(json_map_string_string *annotations, string_array **keys,
                                  string_array **devices, char **error)
{
    if (g_cdi_operate_api_mock != nullptr) {
        return g_cdi_operate_api_mock->CdiOperateParseAnnotations(annotations, keys, devices, error);
    }
    return 0;
}