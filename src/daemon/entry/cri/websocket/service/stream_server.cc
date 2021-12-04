/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide websocket server functions
 ******************************************************************************/

#include "stream_server.h"
#include <memory>
#include <string>
#include "ws_server.h"
#include "exec_serve.h"
#include "attach_serve.h"

void websocket_server_init(Errors &err)
{
    auto *server = WebsocketServer::GetInstance();
    server->RegisterCallback(std::string("exec"), std::make_shared<ExecServe>());
    server->RegisterCallback(std::string("attach"), std::make_shared<AttachServe>());
    server->Start(err);
}

void websocket_server_wait(void)
{
    auto *server = WebsocketServer::GetInstance();
    server->Wait();
}

void websocket_server_shutdown(void)
{
    auto *server = WebsocketServer::GetInstance();
    server->Shutdown();
}

