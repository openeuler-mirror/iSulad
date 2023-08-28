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
 * Description: provide grpc container service private functions
 ******************************************************************************/
#include "grpc_containers_service.h"
#include <isula_libutils/log.h>
#include "utils.h"
#include "error.h"

int ContainerServiceImpl::wait_request_from_grpc(const WaitRequest *grequest, container_wait_request **request)
{
    container_wait_request *tmpreq = (container_wait_request *)util_common_calloc_s(sizeof(container_wait_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    tmpreq->condition = grequest->condition();

    *request = tmpreq;
    return 0;
}

void ContainerServiceImpl::wait_response_to_grpc(const container_wait_response *response, WaitResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    gresponse->set_cc(response->cc);
    gresponse->set_exit_code(response->exit_code);
    if (response->errmsg != nullptr) {
        gresponse->set_errmsg(response->errmsg);
    }
    return;
}

int ContainerServiceImpl::events_request_from_grpc(const EventsRequest *grequest,
                                                   struct isulad_events_request **request)
{
    struct isulad_events_request *tmpreq =
        (struct isulad_events_request *)util_common_calloc_s(sizeof(struct isulad_events_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    tmpreq->storeonly = grequest->storeonly();

    if (grequest->has_since()) {
        protobuf_timestamp_from_grpc(&tmpreq->since, grequest->since());
    }

    if (grequest->has_until()) {
        protobuf_timestamp_from_grpc(&tmpreq->until, grequest->until());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::copy_from_container_request_from_grpc(const CopyFromContainerRequest *grequest,
                                                                struct isulad_copy_from_container_request **request)
{
    struct isulad_copy_from_container_request *tmpreq =
        (struct isulad_copy_from_container_request *)util_common_calloc_s(
            sizeof(isulad_copy_from_container_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!grequest->id().empty()) {
        tmpreq->id = util_strdup_s(grequest->id().c_str());
    }

    if (!grequest->runtime().empty()) {
        tmpreq->runtime = util_strdup_s(grequest->runtime().c_str());
    }

    if (!grequest->srcpath().empty()) {
        tmpreq->srcpath = util_strdup_s(grequest->srcpath().c_str());
    }

    *request = tmpreq;
    return 0;
}

int ContainerServiceImpl::remote_exec_request_from_stream(ServerContext *context, container_exec_request **request,
                                                          std::string &errmsg)
{
    const std::multimap<grpc::string_ref, grpc::string_ref> init_metadata = context->client_metadata();
    auto iter = init_metadata.find("isulad-remote-exec");
    if (iter != init_metadata.end()) {
        char *err = nullptr;
        std::string json = std::string(iter->second.data(), iter->second.length());
        *request = container_exec_request_parse_data(json.c_str(), nullptr, &err);
        if (*request == nullptr) {
            errmsg = "Invalid remote exec container json: ";
            errmsg += (err != nullptr) ? err : "unknown";
            free(err);
            return -1;
        }
    } else {
        errmsg = "No metadata 'isulad-remote-exec' received";
        return -1;
    }
    return 0;
}

void ContainerServiceImpl::add_exec_trailing_metadata(ServerContext *context, container_exec_response *response)
{
    if (response == nullptr) {
        context->AddTrailingMetadata("cc", std::to_string((int)ISULAD_ERR_MEMOUT));
        return;
    }
    context->AddTrailingMetadata("cc", std::to_string(response->cc));
    context->AddTrailingMetadata("exit_code", std::to_string(response->exit_code));
    if (response->errmsg != nullptr) {
        char *marshaled = util_marshal_string(response->errmsg);
        if (marshaled != nullptr) {
            context->AddTrailingMetadata("errmsg", marshaled);
        }
        free(marshaled);
    }
}

int ContainerServiceImpl::attach_request_from_stream(const std::multimap<grpc::string_ref, grpc::string_ref> &metadata,
                                                     container_attach_request **request)
{
    container_attach_request *tmpreq =
        (container_attach_request *)util_common_calloc_s(sizeof(container_attach_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator std_kv;
    std_kv = metadata.find("container-id");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->container_id = util_strdup_s(std::string(std_kv->second.data(), std_kv->second.length()).c_str());

    std_kv = metadata.find("attach-stdin");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdin = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stdout");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdout = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stderr");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stderr = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    *request = tmpreq;
    return 0;
cleanup:
    free_container_attach_request(tmpreq);
    return -1;
}

void ContainerServiceImpl::add_attach_trailing_metadata(ServerContext *context, container_attach_response *response)
{
    if (response == nullptr) {
        context->AddTrailingMetadata("cc", std::to_string((int)ISULAD_ERR_MEMOUT));
        return;
    }
    context->AddTrailingMetadata("cc", std::to_string(response->cc));

    if (response->errmsg != nullptr) {
        char *marshaled = util_marshal_string(response->errmsg);
        if (marshaled != nullptr) {
            context->AddTrailingMetadata("errmsg", marshaled);
        }
        free(marshaled);
    }
}

int ContainerServiceImpl::remote_start_request_from_stream(
    const std::multimap<grpc::string_ref, grpc::string_ref> &metadata, container_start_request **request)
{
    container_start_request *tmpreq = (container_start_request *)util_common_calloc_s(sizeof(container_start_request));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator std_kv;
    std_kv = metadata.find("container-id");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->id = util_strdup_s(std::string(std_kv->second.data(), std_kv->second.length()).c_str());

    std_kv = metadata.find("attach-stdin");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdin = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stdout");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stdout = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    std_kv = metadata.find("attach-stderr");
    if (std_kv == metadata.end()) {
        goto cleanup;
    }
    tmpreq->attach_stderr = (std::string(std_kv->second.data(), std_kv->second.length()) == "true");

    *request = tmpreq;
    return 0;
cleanup:
    free_container_start_request(tmpreq);
    return -1;
}

void ContainerServiceImpl::add_start_trailing_metadata(ServerContext *context, container_start_response *response)
{
    if (response == nullptr) {
        context->AddTrailingMetadata("cc", std::to_string((int)ISULAD_ERR_MEMOUT));
        return;
    }
    context->AddTrailingMetadata("cc", std::to_string(response->cc));

    if (response->errmsg != nullptr) {
        char *marshaled = util_marshal_string(response->errmsg);
        if (marshaled != nullptr) {
            context->AddTrailingMetadata("errmsg", marshaled);
        }
        free(marshaled);
    }
}
