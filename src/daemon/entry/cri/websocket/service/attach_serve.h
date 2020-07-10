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
 * Description: Attach streaming service implementation.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ATTACH_SERVE_H
#define DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ATTACH_SERVE_H

#include "route_callback_register.h"
#include <chrono>
#include <string>
#include <thread>
#include "ws_server.h"

#include "api.pb.h"
#include "isula_libutils/log.h"
#include "callback.h"
#include "request_cache.h"

class AttachServe : public StreamingServeInterface {
public:
    AttachServe() = default;
    AttachServe(const AttachServe &) = delete;
    AttachServe &operator=(const AttachServe &) = delete;
    virtual ~AttachServe() = default;
    int Execute(struct lws *wsi, const std::string &token, int read_pipe_fd) override;
private:
    int RequestFromCri(const runtime::v1alpha2::AttachRequest *grequest,
                       container_attach_request **request);
};
#endif // DAEMON_ENTRY_CRI_WEBSOCKET_SERVICE_ATTACH_SERVE_H

