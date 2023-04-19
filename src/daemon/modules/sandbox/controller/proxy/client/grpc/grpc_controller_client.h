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
 * Author: xuxuepeng
 * Create: 2023-02-06
 * Description: controller grpc client
 ******************************************************************************/

#include "github.com/containerd/containerd/api/types/mount.pb.h"
#include "sandbox.pb.h"
#include "sandbox.grpc.pb.h"
#include "proxy_client.h"

using grpc::ClientContext;
using grpc::Status;
using containerd::types::Sandbox;
using containerd::types::Mount;
using namespace containerd::services::sandbox::v1;

class ControllerClient {
public:
    ControllerClient(const char *sandboxer, const ctrl_client_config_t *config);

    auto create(const char *sandbox_id, const ctrl_create_params_t *params) -> int;

    auto start(const char *sandbox_id) -> int;

    auto platform(const char *sandbox_id, ctrl_platform_response_t *response) -> int;

    auto prepare(const char *sandbox_id, const ctrl_prepare_params_t *params, ctrl_prepare_response_t *response) -> int;

    auto purge(const char *sandbox_id, const ctrl_purge_params_t *params) -> int;

    auto update_resources(const char *sandbox_id, const ctrl_update_resources_params_t *params) -> int;

    auto stop(const char *sandbox_id, uint32_t timeout_secs) -> int;

    auto wait(const char *sandbox_id, uint32_t *exit_status, uint64_t *exited_at) -> int;

    auto status(const char *sandbox_id, bool verbose, ctrl_status_response_t *response) -> int;

    auto shutdown(const char *sandbox_id) -> int;

private:
    void convert_mount_info(Mount* rootfs_entry, ctrl_mount_t *mount);
    void init_grpc_create_request(ControllerCreateRequest &grpc_request, const char *sandbox_id,
                                  const ctrl_create_params_t *params);
    void convert_platform_response(ControllerPlatformResponse &grpc_response,
                                   ctrl_platform_response_t *response);
    void init_grpc_prepare_request(PrepareRequest &grpc_request, const char *sandbox_id,
                                   const ctrl_prepare_params_t *params);
    void convert_status_response(ControllerStatusResponse &grpc_response,
                                 ctrl_status_response_t *response);
    std::unique_ptr<Controller::Stub> stub_;
    std::string sandboxer;
};
