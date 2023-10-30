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
 * Description: provide callback mock
 ******************************************************************************/

#ifndef ISULAD_TEST_MOCKS_CALLBACK_MOCK_H
#define ISULAD_TEST_MOCKS_CALLBACK_MOCK_H

#include <gmock/gmock.h>

#include <memory>

#include "callback.h"

class MockContainerCallback {
public:
    MOCK_METHOD2(ContainerCreate, int(const container_create_request *request, container_create_response **response));
    MOCK_METHOD5(ContainerStart, int(const container_start_request *request, container_start_response **response,
                                     int stdinfd, io_write_wrapper *stdout, io_write_wrapper *stderr));
    MOCK_METHOD2(ContainerStop, int(const container_stop_request *request, container_stop_response **response));
    MOCK_METHOD2(ContainerRemove, int(const container_delete_request *request, container_delete_response **response));
    MOCK_METHOD2(ContainerWait, int(const container_wait_request *request, container_wait_response **response));
    MOCK_METHOD2(ContainerUpdateNetworkSettings, int(const container_update_network_settings_request *request,
                                                     container_update_network_settings_response **response));
};

void MockCallback_SetMock(std::shared_ptr<MockContainerCallback> mock);

#endif
