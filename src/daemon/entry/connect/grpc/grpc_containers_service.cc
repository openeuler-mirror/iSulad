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
#include "grpc_containers_service.h"
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>
#include "isula_libutils/log.h"
#include "utils.h"
#include "error.h"
#include "cxxutils.h"
#include "stoppable_thread.h"
#include "grpc_server_tls_auth.h"
#include "container_api.h"
#include "isula_libutils/logger_json_file.h"

void protobuf_timestamp_to_grpc(const types_timestamp_t *timestamp, Timestamp *gtimestamp)
{
    gtimestamp->set_seconds(timestamp->seconds);
    gtimestamp->set_nanos(timestamp->nanos);
}

void protobuf_timestamp_from_grpc(types_timestamp_t *timestamp, const Timestamp &gtimestamp)
{
    timestamp->has_seconds = gtimestamp.seconds() != 0;
    timestamp->seconds = gtimestamp.seconds();
    timestamp->has_nanos = gtimestamp.nanos() != 0;
    timestamp->nanos = gtimestamp.nanos();
}

int event_to_grpc(const struct isulad_events_format *event, Event *gevent)
{
    gevent->Clear();

    if (event->timestamp.has_seconds != 0 || event->timestamp.has_nanos != 0) {
        protobuf_timestamp_to_grpc((const types_timestamp_t *)(&event->timestamp), gevent->mutable_timestamp());
    }

    if (event->opt != nullptr) {
        gevent->set_opt(event->opt);
    }

    if (event->id != nullptr) {
        gevent->set_id(event->id);
    }

    if (event->annotations_len != 0 && event->annotations != nullptr) {
        google::protobuf::Map<std::string, std::string> *map = gevent->mutable_annotations();
        for (size_t i { 0 }; i < event->annotations_len; i++) {
            char **elems = util_string_split_n(event->annotations[i], '=', 2);
            if (util_array_len((const char **)elems) != 2) {
                ERROR("Invalid annotation info");
                util_free_array(elems);
                return -1;
            }
            (*map)[elems[0]] = elems[1];
            util_free_array(elems);
        }
    }

    return 0;
}

void copy_from_container_response_to_grpc(const struct isulad_copy_from_container_response *copy,
                                          CopyFromContainerResponse *gcopy)
{
    gcopy->Clear();
    if (copy == nullptr) {
        return;
    }
    if (copy->data != nullptr && copy->data_len > 0) {
        gcopy->set_data(copy->data, copy->data_len);
    }
}

bool grpc_is_call_cancelled(void *context)
{
    return ((ServerContext *)context)->IsCancelled();
}

bool grpc_add_initial_metadata(void *context, const char *header, const char *val)
{
    ((ServerContext *)context)->AddInitialMetadata(header, val);
    return true;
}

bool grpc_event_write_function(void *writer, void *data)
{
    struct isulad_events_format *event = (struct isulad_events_format *)data;
    ServerWriter<Event> *gwriter = (ServerWriter<Event> *)writer;
    Event gevent;
    if (event_to_grpc(event, &gevent) != 0) {
        return false;
    }
    return gwriter->Write(gevent);
}

bool grpc_copy_from_container_write_function(void *writer, void *data)
{
    struct isulad_copy_from_container_response *copy = (struct isulad_copy_from_container_response *)data;
    ServerWriter<CopyFromContainerResponse> *gwriter = (ServerWriter<CopyFromContainerResponse> *)writer;
    CopyFromContainerResponse gcopy;
    copy_from_container_response_to_grpc(copy, &gcopy);
    return gwriter->Write(gcopy);
}

static bool copy_to_container_data_from_grpc(struct isulad_copy_to_container_data *copy, CopyToContainerRequest *gcopy)
{
    size_t len = (size_t)gcopy->data().length();
    if (len > 0) {
        char *data = nullptr;
        data = (char *)util_common_calloc_s(len);
        if (data == nullptr) {
            ERROR("Out of memory");
            return false;
        }
        (void)memcpy(data, gcopy->data().c_str(), len);
        copy->data = data;
        copy->data_len = len;
        return true;
    }
    return false;
}

bool grpc_copy_to_container_read_function(void *reader, void *data)
{
    struct isulad_copy_to_container_data *copy = (struct isulad_copy_to_container_data *)data;
    ServerReaderWriter<CopyToContainerResponse, CopyToContainerRequest> *stream =
            (ServerReaderWriter<CopyToContainerResponse, CopyToContainerRequest> *)reader;
    CopyToContainerRequest gcopy;
    if (!stream->Read(&gcopy)) {
        return false;
    }
    return copy_to_container_data_from_grpc(copy, &gcopy);
}

Status ContainerServiceImpl::Version(ServerContext *context, const VersionRequest *request, VersionResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_version_request *container_req = nullptr;
    container_version_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "docker_version");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.version == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = version_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.version(container_req, &container_res);
    tret = version_response_to_grpc(container_res, reply);

    free_container_version_request(container_req);
    free_container_version_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Info(ServerContext *context, const InfoRequest *request, InfoResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    host_info_request *container_req = nullptr;
    host_info_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "docker_info");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.info == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = info_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.info(container_req, &container_res);
    tret = info_response_to_grpc(container_res, reply);

    free_host_info_request(container_req);
    free_host_info_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Create(ServerContext *context, const CreateRequest *request, CreateResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_create_response *container_res = nullptr;
    container_create_request *container_req = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_create");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.create == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = create_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.create(container_req, &container_res);
    tret = create_response_to_grpc(container_res, reply);

    free_container_create_request(container_req);
    free_container_create_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Start(ServerContext *context, const StartRequest *request, StartResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_start_request *req = nullptr;
    container_start_response *res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_start");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.start == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = start_request_from_grpc(request, &req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::CANCELLED;
    }

    ret = cb->container.start(req, &res, -1, nullptr, nullptr);
    tret = response_to_grpc(res, reply);

    free_container_start_request(req);
    free_container_start_response(res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

struct RemoteStartContext {
    ServerReaderWriter<RemoteStartResponse, RemoteStartRequest> *stream;
    bool isStdout;
    sem_t *sem;
};

ssize_t WriteStartResponseToRemoteClient(void *context, const void *data, size_t len)
{
    if (context == nullptr || data == nullptr || len == 0) {
        return 0;
    }

    struct RemoteStartContext *ctx = (struct RemoteStartContext *)context;
    RemoteStartResponse response;
    if (ctx->isStdout) {
        response.set_stdout((char *)data, len);
    } else {
        response.set_stderr((char *)data, len);
    }
    if (!ctx->stream->Write(response)) {
        ERROR("Failed to write request to grpc client");
        return 0;
    }

    return (ssize_t)len;
}

int grpc_start_stream_close(void *context, char **err)
{
    int ret = 0;
    (void)err;
    struct RemoteStartContext *ctx = (struct RemoteStartContext *)context;
    RemoteStartResponse finish_response;
    finish_response.set_finish(true);
    if (!ctx->stream->Write(finish_response)) {
        ERROR("Failed to write finish request to grpc client");
        ret = -1;
    }
    if (ctx->sem != nullptr) {
        (void)sem_post(ctx->sem);
    }

    return ret;
}

Status ContainerServiceImpl::RemoteStart(ServerContext *context,
                                         ServerReaderWriter<RemoteStartResponse, RemoteStartRequest> *stream)
{
    service_executor_t *cb = nullptr;
    container_start_request *container_req = nullptr;
    container_start_response *container_res = nullptr;
    sem_t sem;

    cb = get_service_executor();
    if (cb == nullptr || cb->container.start == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    if (remote_start_request_from_stream(context->client_metadata(), &container_req) != 0) {
        ERROR("Failed to transform grpc request!");
        return Status(StatusCode::UNKNOWN, "Transform request failed");
    }

    if (sem_init(&sem, 0, 0) != 0) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, "Semaphore initialization failed");
        ;
    }

    int read_pipe_fd[2];
    if ((pipe2(read_pipe_fd, O_NONBLOCK | O_CLOEXEC)) < 0) {
        ERROR("create read pipe failed");
        (void)sem_destroy(&sem);
        return Status(StatusCode::UNKNOWN, "create read pipe failed");
    }

    struct RemoteStartContext stdoutCtx = { 0 };
    stdoutCtx.stream = stream;
    stdoutCtx.isStdout = true;
    struct io_write_wrapper stdoutWriter = { 0 };
    stdoutWriter.context = (void *)(&stdoutCtx);
    stdoutWriter.write_func = WriteStartResponseToRemoteClient;
    stdoutWriter.close_func = nullptr;

    struct RemoteStartContext stderrCtx = { 0 };
    stderrCtx.stream = stream;
    stderrCtx.sem = &sem;
    struct io_write_wrapper stderrWriter = { 0 };
    stderrWriter.context = (void *)(&stderrCtx);
    stderrWriter.write_func = WriteStartResponseToRemoteClient;
    stderrWriter.close_func = grpc_start_stream_close;

    int ret = cb->container.start(container_req, &container_res, container_req->attach_stdin ? read_pipe_fd[0] : -1,
                                  container_req->attach_stdout ? &stdoutWriter : nullptr,
                                  container_req->attach_stderr ? &stderrWriter : nullptr);
    if (container_req->attach_stdin && ret == 0) {
        RemoteStartRequest request;
        while (stream->Read(&request)) {
            if (request.finish()) {
                break;
            }
            std::string command = request.stdin();
            if (write(read_pipe_fd[1], (void *)(command.c_str()), command.length()) < 0) {
                ERROR("sub write over!");
                break;
            }
        }
    }

    // close pipe 1 first, make sure io copy thread exit
    close(read_pipe_fd[1]);
    if (container_req->attach_stderr && ret == 0) {
        (void)sem_wait(&sem);
    }
    (void)sem_destroy(&sem);
    close(read_pipe_fd[0]);

    add_start_trailing_metadata(context, container_res);
    free_container_start_request(container_req);
    free_container_start_response(container_res);
    return Status::OK;
}

Status ContainerServiceImpl::Top(ServerContext *context, const TopRequest *request, TopResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_top_request *req = nullptr;
    container_top_response *res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_top");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.top == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = top_request_from_grpc(request, &req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::CANCELLED;
    }

    ret = cb->container.top(req, &res);
    tret = top_response_to_grpc(res, reply);

    free_container_top_request(req);
    free_container_top_response(res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Stop(ServerContext *context, const StopRequest *request, StopResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_stop_request *container_req = nullptr;
    container_stop_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_stop");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.stop == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = stop_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.stop(container_req, &container_res);
    tret = response_to_grpc(container_res, reply);

    free_container_stop_request(container_req);
    free_container_stop_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Restart(ServerContext *context, const RestartRequest *request, RestartResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_restart_request *container_req = nullptr;
    container_restart_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_restart");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.restart == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = restart_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.restart(container_req, &container_res);
    tret = response_to_grpc(container_res, reply);

    free_container_restart_request(container_req);
    free_container_restart_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Kill(ServerContext *context, const KillRequest *request, KillResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_kill_request *container_req = nullptr;
    container_kill_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_kill");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.kill == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = kill_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.kill(container_req, &container_res);
    tret = response_to_grpc(container_res, reply);

    free_container_kill_request(container_req);
    free_container_kill_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Delete(ServerContext *context, const DeleteRequest *request, DeleteResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_delete_request *container_req = nullptr;
    container_delete_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_delete");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.remove == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = delete_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.remove(container_req, &container_res);
    tret = delete_response_to_grpc(container_res, reply);

    free_container_delete_request(container_req);
    free_container_delete_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Exec(ServerContext *context, const ExecRequest *request, ExecResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_exec_request *container_req = nullptr;
    container_exec_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_exec_create");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.exec == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = exec_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::CANCELLED;
    }

    ret = cb->container.exec(container_req, &container_res, -1, nullptr, nullptr);
    tret = exec_response_to_grpc(container_res, reply);

    free_container_exec_request(container_req);
    free_container_exec_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

ssize_t WriteExecStdoutResponseToRemoteClient(void *context, const void *data, size_t len)
{
    if (context == nullptr || data == nullptr || len == 0) {
        return 0;
    }
    auto stream = static_cast<ServerReaderWriter<RemoteExecResponse, RemoteExecRequest> *>(context);
    RemoteExecResponse response;
    response.set_stdout((char *)data, len);
    if (!stream->Write(response)) {
        ERROR("Failed to write request to grpc client");
        return -1;
    }
    return (ssize_t)len;
}

ssize_t WriteExecStderrResponseToRemoteClient(void *context, const void *data, size_t len)
{
    if (context == nullptr || data == nullptr || len == 0) {
        return 0;
    }
    auto stream = static_cast<ServerReaderWriter<RemoteExecResponse, RemoteExecRequest> *>(context);
    RemoteExecResponse response;
    response.set_stderr((char *)data, len);
    if (!stream->Write(response)) {
        ERROR("Failed to write request to grpc client");
        return -1;
    }
    return (ssize_t)len;
}

class RemoteExecReceiveFromClientTask : public StoppableThread {
public:
    RemoteExecReceiveFromClientTask() = default;
    RemoteExecReceiveFromClientTask(ServerReaderWriter<RemoteExecResponse, RemoteExecRequest> *stream, int read_pipe_fd)
            : m_stream(stream)
            , m_read_pipe_fd(read_pipe_fd)
    {
    }
    ~RemoteExecReceiveFromClientTask() = default;
    void SetStream(ServerReaderWriter<RemoteExecResponse, RemoteExecRequest> *stream)
    {
        m_stream = stream;
    }

    void SetReadPipeFd(int read_pipe_fd)
    {
        m_read_pipe_fd = read_pipe_fd;
    }

    void run()
    {
        RemoteExecRequest request;
        while (stopRequested() == false && m_stream->Read(&request)) {
            if (request.finish()) {
                return;
            }
            for (int i = 0; i < request.cmd_size(); i++) {
                std::string command = request.cmd(i);
                if (write(m_read_pipe_fd, (void *)(command.c_str()), command.length()) < 0) {
                    ERROR("sub write over!");
                    return;
                }
            }
        }
    }

private:
    ServerReaderWriter<RemoteExecResponse, RemoteExecRequest> *m_stream;
    int m_read_pipe_fd;
};

Status ContainerServiceImpl::RemoteExec(ServerContext *context,
                                        ServerReaderWriter<RemoteExecResponse, RemoteExecRequest> *stream)
{
    service_executor_t *cb = nullptr;
    container_exec_request *container_req = nullptr;
    container_exec_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_exec_create");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.exec == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    std::string errmsg;
    if (remote_exec_request_from_stream(context, &container_req, errmsg) != 0) {
        ERROR("Failed to transform grpc request!");
        return Status(StatusCode::UNKNOWN, errmsg);
    }

    int read_pipe_fd[2] = { -1, -1 };
    RemoteExecReceiveFromClientTask receive_task;
    std::thread command_writer;
    if (container_req->attach_stdin) {
        if ((pipe2(read_pipe_fd, O_NONBLOCK | O_CLOEXEC)) < 0) {
            ERROR("create read pipe(grpc server to lxc pipe) fail!");
            return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
        }

        receive_task.SetStream(stream);
        receive_task.SetReadPipeFd(read_pipe_fd[1]);
        command_writer = std::thread([&]() { receive_task.run(); });
    }

    struct io_write_wrapper StdoutstringWriter = { 0 };
    StdoutstringWriter.context = (void *)stream;
    StdoutstringWriter.write_func = WriteExecStdoutResponseToRemoteClient;
    StdoutstringWriter.close_func = nullptr;
    struct io_write_wrapper StderrstringWriter = { 0 };
    StderrstringWriter.context = (void *)stream;
    StderrstringWriter.write_func = WriteExecStderrResponseToRemoteClient;
    StderrstringWriter.close_func = nullptr;
    (void)cb->container.exec(container_req, &container_res, read_pipe_fd[0], &StdoutstringWriter, &StderrstringWriter);

    RemoteExecResponse finish_response;
    finish_response.set_finish(true);

    if (container_req->attach_stdin) {
        receive_task.stop();
    }

    if (!stream->Write(finish_response)) {
        ERROR("Failed to write finish request to grpc client");
        return Status(StatusCode::INTERNAL, "Internal errors");
    }

    if (container_req->attach_stdin) {
        command_writer.join();
    }
    add_exec_trailing_metadata(context, container_res);
    free_container_exec_request(container_req);
    free_container_exec_response(container_res);
    if (read_pipe_fd[0] != -1) {
        close(read_pipe_fd[0]);
        close(read_pipe_fd[1]);
    }
    return Status::OK;
}

Status ContainerServiceImpl::Inspect(ServerContext *context, const InspectContainerRequest *request,
                                     InspectContainerResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_inspect_request *container_req = nullptr;
    container_inspect_response *container_res = nullptr;

    cb = get_service_executor();
    if (cb == nullptr || cb->container.inspect == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = inspect_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    Status status = GrpcServerTlsAuth::auth(context, "container_inspect");
    if (!status.ok()) {
        return status;
    }

    ret = cb->container.inspect(container_req, &container_res);
    tret = inspect_response_to_grpc(container_res, reply);

    free_container_inspect_request(container_req);
    free_container_inspect_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::List(ServerContext *context, const ListRequest *request, ListResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_list_request *container_req = nullptr;
    container_list_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_list");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.list == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = list_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.list(container_req, &container_res);
    tret = list_response_to_grpc(container_res, reply);

    free_container_list_request(container_req);
    free_container_list_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

struct AttachContext {
    ServerReaderWriter<AttachResponse, AttachRequest> *stream;
    bool isStdout;
    sem_t *sem;
};

ssize_t WriteAttachResponseToRemoteClient(void *context, const void *data, size_t len)
{
    if (context == nullptr || data == nullptr || len == 0) {
        return 0;
    }
    struct AttachContext *ctx = (struct AttachContext *)context;
    AttachResponse response;
    if (ctx->isStdout) {
        response.set_stdout((char *)data, len);
    } else {
        response.set_stderr((char *)data, len);
    }

    if (!ctx->stream->Write(response)) {
        ERROR("Failed to write request to grpc client");
        return 0;
    }
    return (ssize_t)len;
}

int grpc_attach_stream_close(void *context, char **err)
{
    int ret = 0;
    (void)err;
    struct AttachContext *ctx = (struct AttachContext *)context;
    AttachResponse finish_response;
    finish_response.set_finish(true);
    if (!ctx->stream->Write(finish_response)) {
        ERROR("Failed to write finish request to grpc client");
        ret = -1;
    }
    if (ctx->sem != nullptr) {
        (void)sem_post(ctx->sem);
    }
    return ret;
}

Status ContainerServiceImpl::AttachInit(ServerContext *context, service_executor_t **cb, container_attach_request **req,
                                        container_attach_response **res, sem_t *sem_stderr, int pipefd[])
{
    auto status = GrpcServerTlsAuth::auth(context, "container_attach");
    if (!status.ok()) {
        return status;
    }
    *cb = get_service_executor();
    if (*cb == nullptr || (*cb)->container.attach == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    if (attach_request_from_stream(context->client_metadata(), req) != 0) {
        ERROR("Failed to transform grpc request!");
        return Status(StatusCode::UNKNOWN, "Transform request failed");
    }

    if ((*req)->attach_stdout != (*req)->attach_stderr) {
        free_container_attach_request(*req);
        return Status(StatusCode::UNKNOWN, "Attach stdout should always equal to attach stderr");
    }

    if (sem_init(sem_stderr, 0, 0) != 0) {
        free_container_attach_request(*req);
        return grpc::Status(grpc::StatusCode::UNKNOWN, "Semaphore initialization failed");
        ;
    }

    if ((pipe2(pipefd, O_NONBLOCK | O_CLOEXEC)) < 0) {
        ERROR("create pipe failed");
        (void)sem_destroy(sem_stderr);
        free_container_attach_request(*req);
        return Status(StatusCode::UNKNOWN, "create pipe failed");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Attach(ServerContext *context, ServerReaderWriter<AttachResponse, AttachRequest> *stream)
{
    service_executor_t *cb = nullptr;
    container_attach_request *container_req = nullptr;
    container_attach_response *container_res = nullptr;
    sem_t sem_stderr;
    int pipefd[2] = { -1, -1 };

    auto status = AttachInit(context, &cb, &container_req, &container_res, &sem_stderr, pipefd);
    if (!status.ok()) {
        return status;
    }

    struct AttachContext stdoutCtx = { 0 };
    stdoutCtx.stream = stream;
    stdoutCtx.isStdout = true;
    struct io_write_wrapper stdoutWriter = { 0 };
    stdoutWriter.context = (void *)(&stdoutCtx);
    stdoutWriter.write_func = WriteAttachResponseToRemoteClient;
    stdoutWriter.close_func = nullptr;

    struct AttachContext stderrCtx = { 0 };
    stderrCtx.stream = stream;
    stderrCtx.sem = &sem_stderr;
    struct io_write_wrapper stderrWriter = { 0 };
    stderrWriter.context = (void *)(&stderrCtx);
    stderrWriter.write_func = WriteAttachResponseToRemoteClient;
    stderrWriter.close_func = grpc_attach_stream_close;

    int ret = cb->container.attach(container_req, &container_res, container_req->attach_stdin ? pipefd[0] : -1,
                                   container_req->attach_stdout ? &stdoutWriter : nullptr,
                                   container_req->attach_stderr ? &stderrWriter : nullptr);
    if (container_req->attach_stdin && ret == 0) {
        AttachRequest request;
        while (stream->Read(&request)) {
            if (request.finish()) {
                break;
            }
            std::string command = request.stdin();
            if (write(pipefd[1], (void *)(command.c_str()), command.length()) < 0) {
                ERROR("sub write over!");
                break;
            }
        }
    }

    // Close pipe 1 first, make sure io copy thread exit
    close(pipefd[1]);
    // Waiting sem, make sure the sem is posted always in attach callback.
    if (container_req->attach_stderr) {
        (void)sem_wait(&sem_stderr);
    }
    (void)sem_destroy(&sem_stderr);
    close(pipefd[0]);

    add_attach_trailing_metadata(context, container_res);
    free_container_attach_request(container_req);
    free_container_attach_response(container_res);
    return Status::OK;
}

Status ContainerServiceImpl::Pause(ServerContext *context, const PauseRequest *request, PauseResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_pause_request *container_req = nullptr;
    container_pause_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_pause");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.pause == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = pause_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.pause(container_req, &container_res);
    tret = response_to_grpc(container_res, reply);

    free_container_pause_request(container_req);
    free_container_pause_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Resume(ServerContext *context, const ResumeRequest *request, ResumeResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_resume_request *container_req = nullptr;
    container_resume_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_unpause");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.resume == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = resume_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.resume(container_req, &container_res);
    tret = response_to_grpc(container_res, reply);

    free_container_resume_request(container_req);
    free_container_resume_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Export(ServerContext *context, const ExportRequest *request, ExportResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_export_request *container_req = nullptr;
    container_export_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_export");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.export_rootfs == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = export_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.export_rootfs(container_req, &container_res);
    tret = response_to_grpc(container_res, reply);

    free_container_export_request(container_req);
    free_container_export_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Rename(ServerContext *context, const RenameRequest *request, RenameResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    struct isulad_container_rename_request *isuladreq = nullptr;
    struct isulad_container_rename_response *isuladres = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_rename");
    if (!status.ok()) {
        return status;
    }

    cb = get_service_executor();
    if (cb == nullptr || cb->container.rename == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = container_rename_request_from_grpc(request, &isuladreq);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.rename(isuladreq, &isuladres);
    tret = container_rename_response_to_grpc(isuladres, reply);

    isulad_container_rename_request_free(isuladreq);
    isulad_container_rename_response_free(isuladres);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Resize(ServerContext *context, const ResizeRequest *request, ResizeResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    struct isulad_container_resize_request *isuladreq = nullptr;
    struct isulad_container_resize_response *isuladres = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_resize");
    if (!status.ok()) {
        return status;
    }

    cb = get_service_executor();
    if (cb == nullptr || cb->container.resize == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = container_resize_request_from_grpc(request, &isuladreq);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.resize(isuladreq, &isuladres);
    tret = container_resize_response_to_grpc(isuladres, reply);

    isulad_container_resize_request_free(isuladreq);
    isulad_container_resize_response_free(isuladres);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Update(ServerContext *context, const UpdateRequest *request, UpdateResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_update_request *container_req = nullptr;
    container_update_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_update");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.update == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = update_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.update(container_req, &container_res);
    tret = update_response_to_grpc(container_res, reply);

    free_container_update_request(container_req);
    free_container_update_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Stats(ServerContext *context, const StatsRequest *request, StatsResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_stats_request *container_req = nullptr;
    container_stats_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_stats");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.stats == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = stats_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.stats(container_req, &container_res);
    tret = stats_response_to_grpc(container_res, reply);

    free_container_stats_request(container_req);
    free_container_stats_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Wait(ServerContext *context, const WaitRequest *request, WaitResponse *reply)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    container_wait_request *container_req = nullptr;
    container_wait_response *container_res = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_wait");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.wait == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = wait_request_from_grpc(request, &container_req);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        reply->set_cc(ISULAD_ERR_INPUT);
        return Status::OK;
    }

    ret = cb->container.wait(container_req, &container_res);
    tret = wait_response_to_grpc(container_res, reply);

    free_container_wait_request(container_req);
    free_container_wait_response(container_res);
    if (tret != 0) {
        reply->set_errmsg(errno_to_error_message(ISULAD_ERR_INTERNAL));
        reply->set_cc(ISULAD_ERR_INTERNAL);
        ERROR("Failed to translate response to grpc, operation is %s", ret ? "failed" : "success");
    }
    return Status::OK;
}

Status ContainerServiceImpl::Events(ServerContext *context, const EventsRequest *request, ServerWriter<Event> *writer)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    isulad_events_request *isuladreq = nullptr;
    stream_func_wrapper stream = { 0 };

    auto status = GrpcServerTlsAuth::auth(context, "docker_events");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.events == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = events_request_from_grpc(request, &isuladreq);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        return Status(StatusCode::INTERNAL, "Failed to transform grpc request");
    }

    stream.context = (void *)context;
    stream.is_cancelled = &grpc_is_call_cancelled;
    stream.write_func = &grpc_event_write_function;
    stream.writer = (void *)writer;

    ret = cb->container.events(isuladreq, &stream);
    isulad_events_request_free(isuladreq);
    if (ret != 0) {
        return Status(StatusCode::INTERNAL, "Failed to execute events callback");
    }

    return Status::OK;
}

Status ContainerServiceImpl::CopyFromContainer(ServerContext *context, const CopyFromContainerRequest *request,
                                               ServerWriter<CopyFromContainerResponse> *writer)
{
    int ret, tret;
    service_executor_t *cb = nullptr;
    isulad_copy_from_container_request *isuladreq = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_archive");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.copy_from_container == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    tret = copy_from_container_request_from_grpc(request, &isuladreq);
    if (tret != 0) {
        ERROR("Failed to transform grpc request");
        return Status(StatusCode::UNKNOWN, "Failed to transform grpc request");
    }

    stream_func_wrapper stream = { 0 };
    stream.context = (void *)context;
    stream.is_cancelled = &grpc_is_call_cancelled;
    stream.add_initial_metadata = &grpc_add_initial_metadata;
    stream.write_func = &grpc_copy_from_container_write_function;
    stream.writer = (void *)writer;

    char *err = nullptr;
    ret = cb->container.copy_from_container(isuladreq, &stream, &err);
    isulad_copy_from_container_request_free(isuladreq);
    std::string errmsg = (err != nullptr) ? err : "Failed to execute copy_from_container callback";
    free(err);
    if (ret != 0) {
        return Status(StatusCode::UNKNOWN, errmsg);
    }
    return Status::OK;
}

Status
ContainerServiceImpl::CopyToContainer(ServerContext *context,
                                      ServerReaderWriter<CopyToContainerResponse, CopyToContainerRequest> *stream)

{
    int ret;
    service_executor_t *cb = nullptr;
    container_copy_to_request *isuladreq = nullptr;

    auto status = GrpcServerTlsAuth::auth(context, "container_archive");
    if (!status.ok()) {
        return status;
    }
    cb = get_service_executor();
    if (cb == nullptr || cb->container.copy_to_container == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    auto metadata = context->client_metadata();
    auto iter = metadata.find("isulad-copy-to-container");
    if (iter != metadata.end()) {
        char *err = nullptr;
        std::string json = std::string(iter->second.data(), iter->second.length());
        isuladreq = container_copy_to_request_parse_data(json.c_str(), nullptr, &err);
        if (isuladreq == nullptr) {
            std::string errmsg = "Invalid copy to container json: ";
            errmsg += (err != nullptr) ? err : "unknown";
            free(err);
            return Status(StatusCode::UNKNOWN, errmsg);
        }
    } else {
        return Status(StatusCode::UNKNOWN, "No metadata 'isulad-copy-to-container' received");
    }
    stream_func_wrapper wrapper = { 0 };
    wrapper.context = (void *)context;
    wrapper.is_cancelled = &grpc_is_call_cancelled;
    wrapper.reader = (void *)stream;
    wrapper.read_func = &grpc_copy_to_container_read_function;

    char *err = nullptr;
    ret = cb->container.copy_to_container(isuladreq, &wrapper, &err);
    free_container_copy_to_request(isuladreq);
    std::string msg = (err != nullptr) ? err : "Failed to execute copy_to_container callback";
    free(err);

    CopyToContainerResponse res;
    res.set_finish(true);
    stream->Write(res);
    if (ret != 0) {
        return Status(StatusCode::UNKNOWN, msg);
    }
    return Status::OK;
}

void log_to_grpc(const logger_json_file *log, LogsResponse *glog)
{
    glog->Clear();
    if (log->log != nullptr) {
        glog->set_data(log->log, log->log_len);
    }
    if (log->stream != nullptr) {
        glog->set_stream(log->stream);
    }
    if (log->time != nullptr) {
        glog->set_time(log->time);
    }
    if (log->attrs != nullptr) {
        glog->set_attrs(log->attrs, log->attrs_len);
    }
}

int ContainerServiceImpl::logs_request_from_grpc(const LogsRequest *grequest, struct isulad_logs_request **request)
{
    *request = (struct isulad_logs_request *)util_common_calloc_s(sizeof(struct isulad_logs_request));
    if (*request == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    if (!grequest->id().empty()) {
        (*request)->id = util_strdup_s(grequest->id().c_str());
    }
    if (!grequest->runtime().empty()) {
        (*request)->runtime = util_strdup_s(grequest->runtime().c_str());
    }
    if (!grequest->since().empty()) {
        (*request)->since = util_strdup_s(grequest->since().c_str());
    }
    if (!grequest->until().empty()) {
        (*request)->until = util_strdup_s(grequest->until().c_str());
    }
    (*request)->timestamps = grequest->timestamps();
    (*request)->follow = grequest->follow();
    (*request)->tail = grequest->tail();
    (*request)->details = grequest->details();

    return 0;
}

bool grpc_logs_write_function(void *writer, void *data)
{
    logger_json_file *log = static_cast<logger_json_file *>(data);
    ServerWriter<LogsResponse> *gwriter = static_cast<ServerWriter<LogsResponse> *>(writer);
    LogsResponse gresponse;
    log_to_grpc(log, &gresponse);
    return gwriter->Write(gresponse);
}

Status ContainerServiceImpl::Logs(ServerContext *context, const LogsRequest *request,
                                  ServerWriter<LogsResponse> *writer)
{
    int ret = 0;
    service_executor_t *cb = nullptr;
    struct isulad_logs_request *isulad_request = nullptr;
    struct isulad_logs_response *isulad_response = nullptr;
    stream_func_wrapper stream = { 0 };

    auto status = GrpcServerTlsAuth::auth(context, "container_logs");
    if (!status.ok()) {
        return status;
    }

    cb = get_service_executor();
    if (cb == nullptr || cb->container.logs == nullptr) {
        return Status(StatusCode::UNIMPLEMENTED, "Unimplemented callback");
    }

    ret = logs_request_from_grpc(request, &isulad_request);
    if (ret != 0) {
        ERROR("Failed to transform grpc request");
        return Status(StatusCode::UNKNOWN, "Failed to transform grpc request");
    }

    stream.context = (void *)context;
    stream.is_cancelled = &grpc_is_call_cancelled;
    stream.write_func = &grpc_logs_write_function;
    stream.writer = (void *)writer;

    ret = cb->container.logs(isulad_request, &stream, &isulad_response);
    isulad_logs_request_free(isulad_request);
    std::string errmsg = "Failed to execute logs";
    if (isulad_response == nullptr) {
        return Status(StatusCode::UNKNOWN, errmsg);
    }
    errmsg = (isulad_response->errmsg != nullptr) ? isulad_response->errmsg : "Failed to execute logs";
    isulad_logs_response_free(isulad_response);
    if (ret != 0) {
        return Status(StatusCode::UNKNOWN, errmsg);
    }
    return Status::OK;
}
