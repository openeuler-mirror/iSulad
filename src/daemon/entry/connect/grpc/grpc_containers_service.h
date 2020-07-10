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

using namespace containers;

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

// Implement of containers service
class ContainerServiceImpl final : public ContainerService::Service {
public:
    ContainerServiceImpl() = default;
    ContainerServiceImpl(const ContainerServiceImpl &) = delete;
    ContainerServiceImpl &operator=(const ContainerServiceImpl &) = delete;
    virtual ~ContainerServiceImpl() = default;

    Status Version(ServerContext *context, const VersionRequest *request, VersionResponse *reply) override;

    Status Info(ServerContext *context, const InfoRequest *request, InfoResponse *reply) override;

    Status Create(ServerContext *context, const CreateRequest *request, CreateResponse *reply) override;

    Status Start(ServerContext *context, const StartRequest *request, StartResponse *reply) override;

    Status Top(ServerContext *context, const TopRequest *request, TopResponse *reply) override;

    Status Stop(ServerContext *context, const StopRequest *request, StopResponse *reply) override;

    Status Restart(ServerContext *context, const RestartRequest *request, RestartResponse *reply) override;

    Status Kill(ServerContext *context, const KillRequest *request, KillResponse *reply) override;

    Status Delete(ServerContext *context, const DeleteRequest *request, DeleteResponse *reply) override;

    Status Exec(ServerContext *context, const ExecRequest *request, ExecResponse *reply) override;

    Status Inspect(ServerContext *context, const InspectContainerRequest *request,
                   InspectContainerResponse *reply) override;

    Status List(ServerContext *context, const ListRequest *request, ListResponse *reply) override;

    Status Attach(ServerContext *context, ServerReaderWriter<AttachResponse, AttachRequest> *stream) override;

    Status Pause(ServerContext *context, const PauseRequest *request, PauseResponse *reply) override;

    Status Resume(ServerContext *context, const ResumeRequest *request, ResumeResponse *reply) override;

    Status Rename(ServerContext *context, const RenameRequest *request, RenameResponse *reply) override;

    Status Resize(ServerContext *context, const ResizeRequest *request, ResizeResponse *reply) override;

    Status Update(ServerContext *context, const UpdateRequest *request, UpdateResponse *reply) override;

    Status Stats(ServerContext *context, const StatsRequest *request, StatsResponse *reply) override;

    Status Wait(ServerContext *context, const WaitRequest *request, WaitResponse *reply) override;

    Status Events(ServerContext *context, const EventsRequest *request, ServerWriter<Event> *writer) override;

    Status Export(ServerContext *context, const ExportRequest *request, ExportResponse *reply) override;

    Status RemoteStart(ServerContext *context,
                       ServerReaderWriter<RemoteStartResponse, RemoteStartRequest> *stream) override;

    Status RemoteExec(ServerContext *context,
                      ServerReaderWriter<RemoteExecResponse, RemoteExecRequest> *stream) override;

    Status CopyFromContainer(ServerContext *context, const CopyFromContainerRequest *request,
                             ServerWriter<CopyFromContainerResponse> *writer) override;

    Status CopyToContainer(ServerContext *context,
                           ServerReaderWriter<CopyToContainerResponse, CopyToContainerRequest> *stream) override;

    Status Logs(ServerContext *context, const LogsRequest *request, ServerWriter<LogsResponse> *writer) override;

private:
    template <class T1, class T2>
    int response_to_grpc(const T1 *response, T2 *gresponse)
    {
        if (response == nullptr) {
            gresponse->set_cc(ISULAD_ERR_MEMOUT);
            return 0;
        }
        gresponse->set_cc(response->cc);
        if (response->errmsg != nullptr) {
            gresponse->set_errmsg(response->errmsg);
        }
        return 0;
    }

    int version_request_from_grpc(const VersionRequest *grequest, container_version_request **request);

    int version_response_to_grpc(const container_version_response *response, VersionResponse *gresponse);

    int info_request_from_grpc(const InfoRequest *grequest, host_info_request **request);

    int info_response_to_grpc(const host_info_response *response, InfoResponse *gresponse);

    int create_request_from_grpc(const CreateRequest *grequest, container_create_request **request);

    int create_response_to_grpc(const container_create_response *response, CreateResponse *gresponse);

    int start_request_from_grpc(const StartRequest *grequest, container_start_request **request);

    int top_request_from_grpc(const TopRequest *grequest, container_top_request **request);

    int top_response_to_grpc(const container_top_response *response, TopResponse *gresponse);

    int stop_request_from_grpc(const StopRequest *grequest, container_stop_request **request);

    int restart_request_from_grpc(const RestartRequest *grequest, container_restart_request **request);

    int kill_request_from_grpc(const KillRequest *grequest, container_kill_request **request);

    int delete_request_from_grpc(const DeleteRequest *grequest, container_delete_request **request);

    int delete_response_to_grpc(const container_delete_response *response, DeleteResponse *gresponse);

    int exec_request_from_grpc(const ExecRequest *grequest, container_exec_request **request);

    int exec_response_to_grpc(const container_exec_response *response, ExecResponse *gresponse);

    int inspect_request_from_grpc(const InspectContainerRequest *grequest, container_inspect_request **request);

    int inspect_response_to_grpc(const container_inspect_response *response, InspectContainerResponse *gresponse);

    int list_request_from_grpc(const ListRequest *grequest, container_list_request **request);

    int list_response_to_grpc(const container_list_response *response, ListResponse *gresponse);

    int pause_request_from_grpc(const PauseRequest *grequest, container_pause_request **request);

    int resume_request_from_grpc(const ResumeRequest *grequest, container_resume_request **request);

    int container_rename_request_from_grpc(const RenameRequest *grequest,
                                           struct isulad_container_rename_request **request);

    int container_rename_response_to_grpc(const struct isulad_container_rename_response *response,
                                          RenameResponse *gresponse);

    int container_resize_request_from_grpc(const ResizeRequest *grequest,
                                           struct isulad_container_resize_request **request);

    int container_resize_response_to_grpc(const struct isulad_container_resize_response *response,
                                          ResizeResponse *gresponse);

    int update_request_from_grpc(const UpdateRequest *grequest, container_update_request **request);

    int update_response_to_grpc(const container_update_response *response, UpdateResponse *gresponse);

    int stats_request_from_grpc(const StatsRequest *grequest, container_stats_request **request);

    int stats_response_to_grpc(const container_stats_response *response, StatsResponse *gresponse);

    int wait_request_from_grpc(const WaitRequest *grequest, container_wait_request **request);

    int wait_response_to_grpc(const container_wait_response *response, WaitResponse *gresponse);

    int events_request_from_grpc(const EventsRequest *grequest, struct isulad_events_request **request);

    int copy_from_container_request_from_grpc(const CopyFromContainerRequest *grequest,
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

    int export_request_from_grpc(const ExportRequest *grequest, container_export_request **request);

    int pack_os_info_to_grpc(const host_info_response *response, InfoResponse *gresponse);

    int pack_proxy_info_to_grpc(const host_info_response *response, InfoResponse *gresponse);

    int pack_driver_info_to_grpc(const host_info_response *response, InfoResponse *gresponse);

    int logs_request_from_grpc(const LogsRequest *grequest, struct isulad_logs_request **request);
};

#endif // DAEMON_ENTRY_CONNECT_GRPC_GRPC_CONTAINERS_SERVICE_H
