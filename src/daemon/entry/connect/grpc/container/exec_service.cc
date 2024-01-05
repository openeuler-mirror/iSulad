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
 * Start: 2022-06-24
 * Description: implement grpc container exec service functions
 ******************************************************************************/
#include "exec_service.h"

void ContainerExecService::SetThreadName()
{
    SetOperationThreadName("ContExec");
}

Status ContainerExecService::Authenticate(ServerContext *context)
{
    return AuthenticateOperation(context, "container_exec_create");
}

bool ContainerExecService::WithServiceExecutorOperator(service_executor_t *cb)
{
    return cb->container.exec != nullptr;
}

int ContainerExecService::FillRequestFromgRPC(const containers::ExecRequest *request, void *contReq)
{
    auto *tmpreq = static_cast<container_exec_request *>(util_common_calloc_s(sizeof(container_exec_request)));
    if (tmpreq == nullptr) {
        ERROR("Out of memory");
        return -1;
    }

    if (!request->container_id().empty()) {
        tmpreq->container_id = util_strdup_s(request->container_id().c_str());
    }

    if (!request->suffix().empty()) {
        tmpreq->suffix = util_strdup_s(request->suffix().c_str());
    }

    tmpreq->tty = request->tty();
    tmpreq->attach_stdin = request->attach_stdin();
    tmpreq->attach_stdout = request->attach_stdout();
    tmpreq->attach_stderr = request->attach_stderr();

    if (!request->workdir().empty()) {
        tmpreq->workdir = util_strdup_s(request->workdir().c_str());
    }
    if (!request->stdin().empty()) {
        tmpreq->stdin = util_strdup_s(request->stdin().c_str());
    }
    if (!request->stdout().empty()) {
        tmpreq->stdout = util_strdup_s(request->stdout().c_str());
    }
    if (!request->stderr().empty()) {
        tmpreq->stderr = util_strdup_s(request->stderr().c_str());
    }

    if (request->argv_size() > 0) {
        tmpreq->argv = (char **)util_smart_calloc_s(sizeof(char *), request->argv_size());
        if (tmpreq->argv == nullptr) {
            ERROR("Out of memory");
            free_container_exec_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < request->argv_size(); i++) {
            tmpreq->argv[i] = util_strdup_s(request->argv(i).c_str());
        }
        tmpreq->argv_len = request->argv_size();
    }

    if (request->env_size() > 0) {
        tmpreq->env = (char **)util_smart_calloc_s(sizeof(char *), request->env_size());
        if (tmpreq->env == nullptr) {
            ERROR("Out of memory");
            free_container_exec_request(tmpreq);
            return -1;
        }
        for (int i = 0; i < request->env_size(); i++) {
            tmpreq->env[i] = util_strdup_s(request->env(i).c_str());
        }
        tmpreq->env_len = request->env_size();
    }

    if (!request->user().empty()) {
        tmpreq->user = util_strdup_s(request->user().c_str());
    }

    *static_cast<container_exec_request **>(contReq) = tmpreq;

    return 0;
}

void ContainerExecService::ServiceRun(service_executor_t *cb, void *containerReq, void *containerRes)
{
    (void)cb->container.exec(static_cast<container_exec_request *>(containerReq),
                             static_cast<container_exec_response **>(containerRes), -1, nullptr, nullptr);
}

void ContainerExecService::FillResponseTogRPC(void *containerRes, containers::ExecResponse *gresponse)
{
    const container_exec_response *response = static_cast<const container_exec_response *>(containerRes);

    ResponseToGrpc(response, gresponse);
    gresponse->set_exit_code(response->exit_code);
}

void ContainerExecService::CleanUp(void *containerReq, void *containerRes)
{
    free_container_exec_request(static_cast<container_exec_request *>(containerReq));
    free_container_exec_response(static_cast<container_exec_response *>(containerRes));
}