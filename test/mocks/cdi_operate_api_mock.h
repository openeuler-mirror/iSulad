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
 * Author: liuxu
 * Create: 2024-04-24
 * Description: provide cdi api mock
 ******************************************************************************/

#ifndef ISULAD_TEST_MOCKS_CDI_OPERATE_API_MOCK_H
#define ISULAD_TEST_MOCKS_CDI_OPERATE_API_MOCK_H

#include <gmock/gmock.h>
#include <memory>

#include "cdi_operate_api.h"

class MockCdiOperateApi {
public:
    MOCK_METHOD2(CdiOperateRegistryInit, int(char **specs_dirs, size_t specs_dirs_len));
    MOCK_METHOD0(CdiOperateRefresh, int(void));
    MOCK_METHOD2(CdiOperateInjectDevices, int(oci_runtime_spec *spec, string_array *devices));
    MOCK_METHOD4(CdiOperateParseAnnotations, int(json_map_string_string *annotations, string_array **keys,
                                                 string_array **devices, char **error));
};

void MockCdiOperateApi_SetMock(std::shared_ptr<MockCdiOperateApi> mock);

#endif
