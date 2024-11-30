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
 * Create: 2024-11-21
 * Description: provide sandbox mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SANDBOXER_SANDBOX_MOCK_H
#define _ISULAD_TEST_MOCKS_SANDBOXER_SANDBOX_MOCK_H

#include <gmock/gmock.h>
#include "sandbox_mock.h"
#include "sandboxer_sandbox.h"

namespace sandbox {

class MockSandboxerSandbox : public MockSandbox {
public:
    MockSandboxerSandbox() = default;
    virtual ~MockSandboxerSandbox() = default;

    MOCK_METHOD0(LoadSandboxTasks, void());
    MOCK_METHOD4(PrepareContainer, int(const char *containerId, const char *baseFs,
                                       const oci_runtime_spec *ociSpec,
                                       const char *consoleFifos[]));
    MOCK_METHOD4(PrepareExec, int(const char *containerId, const char *execId,
                                  defs_process *processSpec, const char *consoleFifos[]));
    MOCK_METHOD1(PurgeContainer, int(const char *containerId));
    MOCK_METHOD2(PurgeExec, int(const char *containerId, const char *execId));
};

void MockSandboxerSandbox_SetMock(MockSandboxerSandbox *mock);

}

#endif
