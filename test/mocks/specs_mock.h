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
 * Description: provide specs mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SPECS_MOCK_H
#define _ISULAD_TEST_MOCKS_SPECS_MOCK_H

#include <gmock/gmock.h>
#include "specs_api.h"

class MockSpecs {
public:
    MOCK_METHOD2(LoadOciConfig, oci_runtime_spec * (const char *rootpath, const char *name));
    MOCK_METHOD2(MergeConfCgroup, int(oci_runtime_spec *oci_spec, const host_config *host_spec));
    MOCK_METHOD3(SaveOciConfig, int(const char *id, const char *rootpath, const oci_runtime_spec *oci_spec));
};

void MockSpecs_SetMock(MockSpecs *mock);

#endif
