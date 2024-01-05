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
 * Description: provide grpc container functions
 ******************************************************************************/
#ifndef DAEMON_ENTRY_CONNECT_GRPC_GRPC_CONTAINERS_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_GRPC_CONTAINERS_SERVICE_H
#include <string>
#include <map>
#include <grpc++/grpc++.h>
#include <semaphore.h>
#include "container.grpc.pb.h"
#include "callback.h"
#include "error.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;
using grpc::Status;
using grpc::StatusCode;
using google::protobuf::Timestamp;

void protobuf_timestamp_to_grpc(types_timestamp_t *timestamp, Timestamp *gtimestamp);
void protobuf_timestamp_from_grpc(types_timestamp_t *timestamp, const Timestamp &gtimestamp);

bool grpc_is_call_cancelled(void *context);
bool grpc_add_initial_metadata(void *context, const char *header, const char *val);
bool grpc_event_write_function(void *writer, void *data);

// Implement of containers service
class ContainerServiceImpl final : public containers::ContainerService::Service {
public:
    ContainerServiceImpl() = default;
    ContainerServiceImpl(const ContainerServiceImpl &) = delete;
    ContainerServiceImpl &operator=(const ContainerServiceImpl &) = delete;
    virtual ~ContainerServiceImpl() = default;

    Status Version(ServerContext *context, const containers::VersionRequest *request, containers::VersionResponse *reply) override;

    Status Info(ServerContext *context, const containers::InfoRequest *request, containers::InfoResponse *reply) override;

    Status Create(ServerContext *context, const containers::CreateRequest *request, containers::CreateResponse *reply) override;

    Status Start(ServerContext *context, const containers::StartRequest *request, containers::StartResponse *reply) override;

    Status Top(ServerContext *context, const containers::TopRequest *request, containers::TopResponse *reply) override;

    Status Stop(ServerContext *context, const containers::StopRequest *request, containers::StopResponse *reply) override;

    Status Restart(ServerContext *context, const containers::RestartRequest *request, containers::RestartResponse *reply) override;

    Status Kill(ServerContext *context, const containers::KillRequest *request, containers::KillResponse *reply) override;

    Status Delete(ServerContext *context, const containers::DeleteRequest *request, containers::DeleteResponse *reply) override;

    Status Exec(ServerContext *context, const containers::ExecRequest *request, containers::ExecResponse *reply) override;

    Status Inspect(ServerContext *context, const containers::InspectContainerRequest *request,
                   containers::InspectContainerResponse *reply) override;

    Status List(ServerContext *context, const containers::ListRequest *request, containers::ListResponse *reply) override;

    Status Attach(ServerContext *context, ServerReaderWriter<containers::AttachResponse, containers::AttachRequest> *stream) override;

    Status Pause(ServerContext *context, const containers::PauseRequest *request, containers::PauseResponse *reply) override;

    Status Resume(ServerContext *context, const containers::ResumeRequest *request, containers::ResumeResponse *reply) override;

    Status Rename(ServerContext *context, const containers::RenameRequest *request, containers::RenameResponse *reply) override;

    Status Resize(ServerContext *context, const containers::ResizeRequest *request, containers::ResizeResponse *reply) override;

    Status Update(ServerContext *context, const containers::UpdateRequest *request, containers::UpdateResponse *reply) override;

    Status Stats(ServerContext *context, const containers::StatsRequest *request, containers::StatsResponse *reply) override;

    Status Wait(ServerContext *context, const containers::WaitRequest *request, containers::WaitResponse *reply) override;

    Status Events(ServerContext *context, const containers::EventsRequest *request, ServerWriter<containers::Event> *writer) override;

    Status Export(ServerContext *context, const containers::ExportRequest *request, containers::ExportResponse *reply) override;

    Status RemoteStart(ServerContext *context,
                       ServerReaderWriter<containers::RemoteStartResponse, containers::RemoteStartRequest> *stream) override;

    Status RemoteExec(ServerContext *context,
                      ServerReaderWriter<containers::RemoteExecResponse, containers::RemoteExecRequest> *stream) override;

    Status CopyFromContainer(ServerContext *context, const containers::CopyFromContainerRequest *request,
                             ServerWriter<containers::CopyFromContainerResponse> *writer) override;

    Status CopyToContainer(ServerContext *context,
                           ServerReaderWriter<containers::CopyToContainerResponse, containers::CopyToContainerRequest> *stream) override;

    Status Logs(ServerContext *context, const containers::LogsRequest *request, ServerWriter<containers::LogsResponse> *writer) override;

private:
    template <class T1, class T2>
    void response_to_grpc(const T1 *response, T2 *gresponse)
    {
        if (response == nullptr) {
            gresponse->set_cc(ISULAD_ERR_MEMOUT);
            return;
        }

        gresponse->set_cc(response->cc);

        if (response->errmsg != nullptr) {
            gresponse->set_errmsg(response->errmsg);
        }
    }

    int wait_request_from_grpc(const containers::WaitRequest *grequest, container_wait_request **request);

    void wait_response_to_grpc(const container_wait_response *response, containers::WaitResponse *gresponse);

    int events_request_from_grpc(const containers::EventsRequest *grequest, struct isulad_events_request **request);

    int copy_from_container_request_from_grpc(const containers::CopyFromContainerRequest *grequest,
                                              struct isulad_copy_from_container_request **request);

    int remote_exec_request_from_stream(ServerContext *context, container_exec_request **request, std::string &errmsg);

    void add_exec_trailing_metadata(ServerContext *context, container_exec_response *response);

    int attach_request_from_stream(const std::multimap<grpc::string_ref, grpc::string_ref> &metadata,
                                   container_attach_request **request);

    Status AttachInit(ServerContext *context, service_executor_t **cb, container_attach_request **req,
                      container_attach_response **res, sem_t *sem_stderr, int pipefd[]);

    void add_attach_trailing_metadata(ServerContext *context, container_attach_response *response);

    int remote_start_request_from_stream(const std::multimap<grpc::string_ref, grpc::string_ref> &metadata,
                                         container_start_request **request);

    void add_start_trailing_metadata(ServerContext *context, container_start_response *response);

    int logs_request_from_grpc(const containers::LogsRequest *grequest, struct isulad_logs_request **request);
};

#endif // DAEMON_ENTRY_CONNECT_GRPC_GRPC_CONTAINERS_SERVICE_H
