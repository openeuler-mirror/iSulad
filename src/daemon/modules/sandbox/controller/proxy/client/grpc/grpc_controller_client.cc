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

#include <fstream>
#include <grpc++/grpc++.h>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "grpc_controller_client.h"
#include "github.com/containerd/containerd/api/types/platform.pb.h"
#include "sandbox.pb.h"
#include "sandbox.grpc.pb.h"
#include "utils.h"

using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::Status;
using grpc::StatusCode;
using google::protobuf::Timestamp;
using containerd::types::Platform;

ControllerClient::ControllerClient(const char *sandboxer, const ctrl_client_config_t *config)
{
    this->sandboxer = sandboxer;
    // TODO: Address validation
    std::string socket_address = config->address;
    const std::string unix_prefix = "unix:";

    if (socket_address.compare(0, unix_prefix.length(), unix_prefix) != 0) {
        socket_address.insert(0, unix_prefix);
    }

    // TODO: Add tls
    // For now just connect without ssl/tls
    // TODO: Error handling
    stub_ = Controller::NewStub(grpc::CreateChannel(socket_address, grpc::InsecureChannelCredentials()));
}

void ControllerClient::convert_mount_info(Mount* rootfs_entry, ctrl_mount_t *mount)
{
    rootfs_entry->set_type(mount->type);
    rootfs_entry->set_source(mount->source);
    rootfs_entry->set_target(mount->target);
    // TODO: Options not implemented
    // rootfs_entry->set_options(mount->.options);
}

void ControllerClient::init_grpc_create_request(ControllerCreateRequest &grpc_request, const char *sandbox_id,
                                                const ctrl_create_params_t *params)
{
    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    for (size_t i = 0; i < params->mounts_len; i++) {
        Mount* rootfs_entry = grpc_request.add_rootfs();
        convert_mount_info(rootfs_entry, &params->mounts[i]);
    }
    grpc_request.mutable_options()->set_value(std::string(params->config));
    if (params->netns_path == nullptr) {
        grpc_request.set_netns_path("");
    } else {
        grpc_request.set_netns_path(params->netns_path);
    }
}

auto ControllerClient::create(const char *sandbox_id, const ctrl_create_params_t *params) -> int
{
    ClientContext context;
    ControllerCreateRequest grpc_request;
    ControllerCreateResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL || params == NULL) {
        ERROR("Invalid arguments for grpc controller create request");
        return -1;
    }

    init_grpc_create_request(grpc_request, sandbox_id, params);
    
    status = this->stub_->Create(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    return 0;
}

auto ControllerClient::start(const char *sandbox_id) -> int
{
    ClientContext context;
    ControllerStartRequest grpc_request;
    ControllerStartResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL) {
        ERROR("Invalid arguments for grpc controller start request");
        return -1;
    }

    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    
    status = this->stub_->Start(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }
    // ignore response
    return 0;
}

void ControllerClient::convert_platform_response(ControllerPlatformResponse &grpc_response,
                                                 ctrl_platform_response_t *response)
{
    const Platform &platform = grpc_response.platform();
    response->os = util_strdup_s(platform.os().c_str());
    response->architecture = util_strdup_s(platform.architecture().c_str());
    response->variant = util_strdup_s(platform.variant().c_str());
}

auto ControllerClient::platform(const char *sandbox_id, ctrl_platform_response_t *response) -> int
{
    ClientContext context;
    ControllerPlatformRequest grpc_request;
    ControllerPlatformResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL || response == NULL) {
        ERROR("Invalid arguments for grpc controller platform request");
        return -1;
    }

    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    
    status = this->stub_->Platform(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    convert_platform_response(grpc_response, response);
    return 0;
}

void ControllerClient::init_grpc_prepare_request(PrepareRequest &grpc_request, const char *sandbox_id,
                                                 const ctrl_prepare_params_t *params)
{
    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    if (params->container_id != NULL) {
        grpc_request.set_container_id(params->container_id);
    }
    if (params->exec_id != NULL) {
        grpc_request.set_exec_id(params->exec_id);
    }
    grpc_request.mutable_spec()->set_value(std::string(params->oci_spec));
    for (size_t i = 0; i < params->rootfs_len; i++) {
        Mount* rootfs_entry = grpc_request.add_rootfs();
        convert_mount_info(rootfs_entry, &params->rootfs[i]);
    }

    if (params->stdin != NULL) {
        grpc_request.set_stdin(params->stdin);
    } else {
        grpc_request.set_stdin("");
    }
    if (params->stdout != NULL) {
        grpc_request.set_stdout(params->stdout);
    } else {
        grpc_request.set_stdout("");
    }
    if (params->stderr != NULL) {
        grpc_request.set_stderr(params->stderr);
    } else {
        grpc_request.set_stderr("");
    }
    grpc_request.set_terminal(params->terminal);
}

auto ControllerClient::prepare(const char *sandbox_id, const ctrl_prepare_params_t *params, ctrl_prepare_response_t *response) -> int
{
    ClientContext context;
    PrepareRequest grpc_request;
    PrepareResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL || params == NULL || response == NULL) {
        ERROR("Invalid arguments for grpc controller prepare request");
        return -1;
    }

    init_grpc_prepare_request(grpc_request, sandbox_id, params);

    status = this->stub_->Prepare(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    response->bundle = util_strdup_s(grpc_response.bundle().c_str());

    return 0;
}

auto ControllerClient::purge(const char *sandbox_id, const ctrl_purge_params_t *params) -> int
{
    ClientContext context;
    PurgeRequest grpc_request;
    PurgeResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL || params == NULL) {
        ERROR("Invalid arguments for grpc controller purge request");
        return -1;
    }

    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    if (params->container_id != NULL) {
        grpc_request.set_container_id(params->container_id);
    }
    if (params->exec_id != NULL) {
        grpc_request.set_exec_id(params->exec_id);
    }
    
    status = this->stub_->Purge(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    return 0;
}

auto ControllerClient::update_resources(const char *sandbox_id, const ctrl_update_resources_params_t *params) -> int
{
    // TODO: Unimplemented
    ERROR("Controller update resources not implemented");
    return -1;
}

auto ControllerClient::stop(const char *sandbox_id, uint32_t timeout_secs) -> int
{
    ClientContext context;
    ControllerStopRequest grpc_request;
    ControllerStopResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL) {
        ERROR("Invalid arguments for grpc controller stop request");
        return -1;
    }

    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    grpc_request.set_timeout_secs(timeout_secs);

    status = this->stub_->Stop(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    return 0;
}

auto ControllerClient::wait(const char *sandbox_id, uint32_t *exit_status, uint64_t *exited_at) -> int
{
    ClientContext context;
    ControllerWaitRequest grpc_request;
    ControllerWaitResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL || exit_status == NULL || exited_at == NULL) {
        ERROR("Invalid arguments for grpc controller wait request");
        return -1;
    }

    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);

    status = this->stub_->Wait(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    *exit_status = grpc_response.exit_status();
    *exited_at = grpc_response.exited_at().seconds();

    return 0;
}

void ControllerClient::convert_status_response(ControllerStatusResponse &grpc_response,
                                               ctrl_status_response_t *response)
{
    response->pid = grpc_response.pid();
    response->state = util_strdup_s(grpc_response.state().c_str());
    response->task_address = util_strdup_s(grpc_response.task_address().c_str());
    response->exited_at = grpc_response.exited_at().seconds() * 1000000000 + grpc_response.exited_at().nanos();
    response->created_at = grpc_response.created_at().seconds()* 1000000000 + grpc_response.exited_at().nanos();
    // TODO: info and extra
}

auto ControllerClient::status(const char *sandbox_id, bool verbose, ctrl_status_response_t *response) -> int
{
    ClientContext context;
    ControllerStatusRequest grpc_request;
    ControllerStatusResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL || response == NULL) {
        ERROR("Invalid arguments for grpc controller status request");
        return -1;
    }

    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    grpc_request.set_verbose(verbose);

    status = this->stub_->Status(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    convert_status_response(grpc_response, response);

    return 0;
}

auto ControllerClient::shutdown(const char *sandbox_id) -> int
{
    ClientContext context;
    ControllerShutdownRequest grpc_request;
    ControllerShutdownResponse grpc_response;
    grpc::Status status;

    if (sandbox_id == NULL) {
        ERROR("Invalid arguments for grpc controller shutdown request");
        return -1;
    }

    grpc_request.set_sandboxer(this->sandboxer);
    grpc_request.set_sandbox_id(sandbox_id);
    
    status = this->stub_->Shutdown(&context, grpc_request, &grpc_response);
    if (!status.ok()) {
        ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
        return -1;
    }

    return 0;
}
