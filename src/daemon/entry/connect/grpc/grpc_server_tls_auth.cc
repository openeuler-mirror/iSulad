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

#include "grpc_server_tls_auth.h"
#include <map>
#include <stdlib.h>
#include "http.h"

namespace AuthorizationPluginConfig {
std::string auth_plugin = "";
} // namespace AuthorizationPluginConfig

namespace GrpcServerTlsAuth {
Status auth(ServerContext *context, std::string action)
{
    const std::multimap<grpc::string_ref, grpc::string_ref> &init_metadata = context->client_metadata();
    auto tls_mode_kv = init_metadata.find("tls_mode");
    if (tls_mode_kv == init_metadata.end()) {
        return Status(StatusCode::UNKNOWN, "unknown error");
    }
    std::string tls_mode = std::string(tls_mode_kv->second.data(), tls_mode_kv->second.length());
    if (tls_mode == "0") {
        return Status::OK;
    }
    if (AuthorizationPluginConfig::auth_plugin.empty()) {
        return Status::OK;
    } else if (AuthorizationPluginConfig::auth_plugin == "authz-broker") {
        auto username_kv = init_metadata.find("username");
        if (username_kv == init_metadata.end()) {
            return Status(StatusCode::UNKNOWN, "unknown error");
        }
        std::string username = std::string(username_kv->second.data(), username_kv->second.length());
        char *errmsg = nullptr;
        if (authz_http_request(username.c_str(), action.c_str(), &errmsg)) {
            std::string err = errmsg;
            free(errmsg);
            return Status(StatusCode::PERMISSION_DENIED, err);
        } else {
            if (errmsg != nullptr) {
                free(errmsg);
            }
        }
    } else {
        return Status(StatusCode::UNIMPLEMENTED, "authorization plugin invalid");
    }
    return Status::OK;
}
} // namespace GrpcServerTlsAuth
