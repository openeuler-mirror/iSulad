/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Start: 2022-09-29
 * Description: implement query infomation service functions
 ******************************************************************************/
#include "info_service.h"

void QueryInfoService::SetThreadName()
{
    SetOperationThreadName("InfoOp");
}

Status QueryInfoService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "docker_info");
}

bool QueryInfoService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.info != nullptr;
}

int QueryInfoService::FillRequestFromgRPC(const containers::InfoRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<host_info_request *>(util_common_calloc_s(sizeof(host_info_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    *static_cast<host_info_request **>(contReq) = tmpreq;

    return 0;
}

void QueryInfoService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.info(static_cast<host_info_request *>(containerReq),
                             static_cast<host_info_response **>(containerRes));
}

void QueryInfoService::PackOSInfo(const host_info_response *response, containers::InfoResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    if (response->kversion != nullptr) {
        gresponse->set_kversion(response->kversion);
    }

    if (response->os_type != nullptr) {
        gresponse->set_os_type(response->os_type);
    }

    if (response->architecture != nullptr) {
        gresponse->set_architecture(response->architecture);
    }

    if (response->nodename != nullptr) {
        gresponse->set_nodename(response->nodename);
    }

    gresponse->set_cpus((::google::protobuf::uint32)response->cpus);

    if (response->operating_system != nullptr) {
        gresponse->set_operating_system(response->operating_system);
    }

    if (response->cgroup_driver != nullptr) {
        gresponse->set_cgroup_driver(response->cgroup_driver);
    }

    if (response->huge_page_size != nullptr) {
        gresponse->set_huge_page_size(response->huge_page_size);
    }
}

void QueryInfoService::PackProxyInfo(const host_info_response *response, containers::InfoResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    if (response->http_proxy != nullptr) {
        gresponse->set_http_proxy(response->http_proxy);
    }

    if (response->https_proxy != nullptr) {
        gresponse->set_https_proxy(response->https_proxy);
    }

    if (response->no_proxy != nullptr) {
        gresponse->set_no_proxy(response->no_proxy);
    }
}

void QueryInfoService::PackDriverInfo(const host_info_response *response, containers::InfoResponse *gresponse)
{
    if (response == nullptr) {
        gresponse->set_cc(ISULAD_ERR_MEMOUT);
        return;
    }

    if (response->driver_name != nullptr) {
        gresponse->set_driver_name(response->driver_name);
    }

    if (response->driver_status != nullptr) {
        gresponse->set_driver_status(response->driver_status);
    }
}

void QueryInfoService::FillResponseTogRPC(void *containerRes, containers::InfoResponse *gresponse)
{
    const host_info_response *response = static_cast<const host_info_response *>(containerRes);

    ResponseToGrpc(response, gresponse);

    if (response->version != nullptr) {
        gresponse->set_version(response->version);
    }
    gresponse->set_containers_num((::google::protobuf::uint32)response->containers_num);

    gresponse->set_c_running((::google::protobuf::uint32)response->c_running);

    gresponse->set_c_paused((::google::protobuf::uint32)response->c_paused);

    gresponse->set_c_stopped((::google::protobuf::uint32)response->c_stopped);

    gresponse->set_images_num(response->images_num);

    PackOSInfo(response, gresponse);

    if (response->logging_driver != nullptr) {
        gresponse->set_logging_driver(response->logging_driver);
    }

    if (response->isulad_root_dir != nullptr) {
        gresponse->set_isulad_root_dir(response->isulad_root_dir);
    }

    gresponse->set_total_mem(response->total_mem);

    PackProxyInfo(response, gresponse);

    PackDriverInfo(response, gresponse);
}

void QueryInfoService::CleanUp(void *containerReq, void *containerRes)
{
    free_host_info_request(static_cast<host_info_request *>(containerReq));
    free_host_info_response(static_cast<host_info_response *>(containerRes));
}