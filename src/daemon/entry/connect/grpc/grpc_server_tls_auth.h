/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangsong
 * Create: 2019-04-26
 * Description: provide grpc tls request authorization
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CONNECT_GRPC_GRPC_SERVER_TLS_AUTH_H
#define DAEMON_ENTRY_CONNECT_GRPC_GRPC_SERVER_TLS_AUTH_H
#include <string>
#include <grpc++/grpc++.h>

using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;

namespace AuthorizationPluginConfig {
extern std::string auth_plugin;
};

namespace GrpcServerTlsAuth {
Status auth(ServerContext *context, std::string action);
};

#endif // DAEMON_ENTRY_CONNECT_GRPC_GRPC_SERVER_TLS_AUTH_H

