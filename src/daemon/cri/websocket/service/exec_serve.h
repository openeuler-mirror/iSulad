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
 * Description: Exec streaming service implementation.
 * Author: wujing
 * Create: 2019-01-02
 ******************************************************************************/

#ifndef __EXEC_SERVE_H_
#define __EXEC_SERVE_H_

#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <grpc++/grpc++.h>
#include "api.grpc.pb.h"
#include "container.grpc.pb.h"

#include "route_callback_register.h"
#include "isula_libutils/log.h"
#include "callback.h"
#include "ws_server.h"
#include "request_cache.h"
#include "api.pb.h"

class ExecServe : public StreamingServeInterface {
public:
    ExecServe() = default;
    ExecServe(const ExecServe &) = delete;
    ExecServe &operator=(const ExecServe &) = delete;
    virtual ~ExecServe() = default;
    int Execute(struct lws *wsi, const std::string &token, int read_pipe_fd) override;

private:
    int RequestFromCri(const runtime::v1alpha2::ExecRequest *grequest, container_exec_request **request);
};
#endif /* __EXEC_SERVE_H_ */
