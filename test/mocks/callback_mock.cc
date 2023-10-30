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

#include "callback_mock.h"

namespace {
std::shared_ptr<MockContainerCallback> g_container_callback_mock = nullptr;
service_executor_t g_service_executor_mock;
}

void MockCallback_SetMock(std::shared_ptr<MockContainerCallback> mock)
{
    g_container_callback_mock = mock;
}

static int service_executor_container_create(const container_create_request *request, container_create_response **response)
{
    if (g_container_callback_mock != nullptr) {
        return g_container_callback_mock->ContainerCreate(request, response);
    }
    return 0;
}

static int service_executor_container_start(const container_start_request *request, container_start_response **response,
                                            int stdinfd, io_write_wrapper *stdout, io_write_wrapper *stderr)
{
    if (g_container_callback_mock != nullptr) {
        return g_container_callback_mock->ContainerStart(request, response, stdinfd, stdout, stderr);
    }
    return 0;
}

static int service_executor_container_stop(const container_stop_request *request, container_stop_response **response)
{
    if (g_container_callback_mock != nullptr) {
        return g_container_callback_mock->ContainerStop(request, response);
    }
    return 0;
}

static int service_executor_container_remove(const container_delete_request *request, container_delete_response **response)
{
    if (g_container_callback_mock != nullptr) {
        return g_container_callback_mock->ContainerRemove(request, response);
    }
    return 0;
}

static int service_executor_container_wait(const container_wait_request *request, container_wait_response **response)
{
    if (g_container_callback_mock != nullptr) {
        return g_container_callback_mock->ContainerWait(request, response);
    }
    return 0;
}

static int service_executor_container_update_network_settings(const container_update_network_settings_request *request,
                                                               container_update_network_settings_response **response)
{
    if (g_container_callback_mock != nullptr) {
        return g_container_callback_mock->ContainerUpdateNetworkSettings(request, response);
    }
    return 0;
}

static void container_callback_init(service_container_callback_t *cb)
{
    cb->create = service_executor_container_create;
    cb->start = service_executor_container_start;
    cb->stop = service_executor_container_stop;
    cb->remove = service_executor_container_remove;
    cb->wait = service_executor_container_wait;
    cb->update_network_settings = service_executor_container_update_network_settings;
}

/* service callback */
int service_callback_init(void)
{
    container_callback_init(&g_service_executor_mock.container);

    return 0;
}

service_executor_t *get_service_executor()
{
    return &g_service_executor_mock;
}
