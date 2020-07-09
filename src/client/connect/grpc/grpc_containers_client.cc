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
 * Description: provide grpc containers client functions
 ******************************************************************************/
#include "grpc_containers_client.h"
#include "client_base.h"
#include "container.grpc.pb.h"
#include "isula_libutils/container_copy_to_request.h"
#include "isula_libutils/container_exec_request.h"
#include "isulad_tar.h"
#include "pack_config.h"
#include "stoppable_thread.h"
#include "utils.h"
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <utility>

using namespace containers;

using grpc::ClientContext;
using grpc::ClientReader;
using grpc::ClientReaderWriter;
using grpc::Status;
using grpc::StatusCode;
using google::protobuf::Timestamp;

class ContainerVersion : public ClientBase<ContainerService, ContainerService::Stub, isula_version_request,
    VersionRequest, isula_version_response, VersionResponse> {
public:
    explicit ContainerVersion(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerVersion() = default;

    auto response_from_grpc(VersionResponse *gresponse, isula_version_response *response) -> int override
    {
        if (!gresponse->version().empty()) {
            response->version = util_strdup_s(gresponse->version().c_str());
        }
        if (!gresponse->git_commit().empty()) {
            response->git_commit = util_strdup_s(gresponse->git_commit().c_str());
        }
        if (!gresponse->build_time().empty()) {
            response->build_time = util_strdup_s(gresponse->build_time().c_str());
        }
        if (!gresponse->root_path().empty()) {
            response->root_path = util_strdup_s(gresponse->root_path().c_str());
        }
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }
        response->server_errono = gresponse->cc();
        return 0;
    }

    auto grpc_call(ClientContext *context, const VersionRequest &req, VersionResponse *reply) -> Status override
    {
        return stub_->Version(context, req, reply);
    }
};

class ContainerInfo : public ClientBase<ContainerService, ContainerService::Stub, isula_info_request, InfoRequest,
    isula_info_response, InfoResponse> {
public:
    explicit ContainerInfo(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerInfo() = default;

    auto response_from_grpc(InfoResponse *gresponse, isula_info_response *response) -> int override
    {
        if (!gresponse->version().empty()) {
            response->version = util_strdup_s(gresponse->version().c_str());
        }
        response->containers_num = gresponse->containers_num();
        response->c_running = gresponse->c_running();
        response->c_paused = gresponse->c_paused();
        response->c_stopped = gresponse->c_stopped();
        response->images_num = gresponse->images_num();
        get_os_info_from_grpc(response, gresponse);
        if (!gresponse->logging_driver().empty()) {
            response->logging_driver = util_strdup_s(gresponse->logging_driver().c_str());
        }
        if (!gresponse->huge_page_size().empty()) {
            response->huge_page_size = util_strdup_s(gresponse->huge_page_size().c_str());
        }
        if (!gresponse->isulad_root_dir().empty()) {
            response->isulad_root_dir = util_strdup_s(gresponse->isulad_root_dir().c_str());
        }
        response->total_mem = gresponse->total_mem();
        get_proxy_info_from_grpc(response, gresponse);
        get_driver_info_from_grpc(response, gresponse);

        return 0;
    }

    auto grpc_call(ClientContext *context, const InfoRequest &req, InfoResponse *reply) -> Status override
    {
        return stub_->Info(context, req, reply);
    }

private:
    static void get_os_info_from_grpc(isula_info_response *response, InfoResponse *gresponse)
    {
        if (!gresponse->kversion().empty()) {
            response->kversion = util_strdup_s(gresponse->kversion().c_str());
        }
        if (!gresponse->os_type().empty()) {
            response->os_type = util_strdup_s(gresponse->os_type().c_str());
        }
        if (!gresponse->architecture().empty()) {
            response->architecture = util_strdup_s(gresponse->architecture().c_str());
        }
        if (!gresponse->nodename().empty()) {
            response->nodename = util_strdup_s(gresponse->nodename().c_str());
        }
        response->cpus = gresponse->cpus();
        if (!gresponse->operating_system().empty()) {
            response->operating_system = util_strdup_s(gresponse->operating_system().c_str());
        }
        if (!gresponse->cgroup_driver().empty()) {
            response->cgroup_driver = util_strdup_s(gresponse->cgroup_driver().c_str());
        }
    }

    static void get_proxy_info_from_grpc(isula_info_response *response, InfoResponse *gresponse)
    {
        if (!gresponse->http_proxy().empty()) {
            response->http_proxy = util_strdup_s(gresponse->http_proxy().c_str());
        }
        if (!gresponse->https_proxy().empty()) {
            response->https_proxy = util_strdup_s(gresponse->https_proxy().c_str());
        }
        if (!gresponse->no_proxy().empty()) {
            response->no_proxy = util_strdup_s(gresponse->no_proxy().c_str());
        }
    }

    static void get_driver_info_from_grpc(isula_info_response *response, InfoResponse *gresponse)
    {
        if (!gresponse->driver_name().empty()) {
            response->driver_name = util_strdup_s(gresponse->driver_name().c_str());
        }
        if (!gresponse->driver_status().empty()) {
            response->driver_status = util_strdup_s(gresponse->driver_status().c_str());
        }
    }
};

class ContainerCreate : public ClientBase<ContainerService, ContainerService::Stub, isula_create_request, CreateRequest,
    isula_create_response, CreateResponse> {
public:
    explicit ContainerCreate(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerCreate() = default;

    auto request_to_grpc(const isula_create_request *request, CreateRequest *grequest) -> int override
    {
        int ret = 0;
        char *host_json = nullptr;
        char *config_json = nullptr;

        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        if (request->rootfs != nullptr) {
            grequest->set_rootfs(request->rootfs);
        }
        if (request->image != nullptr) {
            grequest->set_image(request->image);
        }
        if (request->runtime != nullptr) {
            grequest->set_runtime(request->runtime);
        }
        ret = generate_hostconfig(request->hostconfig, &host_json);
        if (ret != 0) {
            ERROR("Failed to pack host config");
            return EINVALIDARGS;
        }
        grequest->set_hostconfig(host_json);

        free(host_json);

        ret = generate_container_config(request->config, &config_json);
        if (ret != 0) {
            ERROR("Failed to pack custom config");
            return EINVALIDARGS;
        }
        grequest->set_customconfig(config_json);

        free(config_json);

        return 0;
    }

    auto response_from_grpc(CreateResponse *gresponse, isula_create_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }
        if (!gresponse->id().empty()) {
            response->id = util_strdup_s(gresponse->id().c_str());
        }
        return 0;
    }

    auto check_parameter(const CreateRequest &req) -> int override
    {
        int nret = -1;

        if (req.rootfs().empty() && req.image().empty()) {
            ERROR("Missing container rootfs or image arguments in the request");
            return nret;
        }
        if (req.hostconfig().empty()) {
            ERROR("Missing hostconfig in the request");
            return nret;
        }
        if (req.customconfig().empty()) {
            ERROR("Missing customconfig in the request");
            return nret;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const CreateRequest &req, CreateResponse *reply) -> Status override
    {
        return stub_->Create(context, req, reply);
    }
};

class ContainerStart : public ClientBase<ContainerService, ContainerService::Stub, isula_start_request, StartRequest,
    isula_start_response, StartResponse> {
public:
    explicit ContainerStart(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerStart() = default;

    auto request_to_grpc(const isula_start_request *request, StartRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        if (request->stdin != nullptr) {
            grequest->set_stdin(request->stdin);
        }
        if (request->stdout != nullptr) {
            grequest->set_stdout(request->stdout);
        }
        if (request->stderr != nullptr) {
            grequest->set_stderr(request->stderr);
        }
        grequest->set_attach_stdin(request->attach_stdin);
        grequest->set_attach_stdout(request->attach_stdout);
        grequest->set_attach_stderr(request->attach_stderr);

        return 0;
    }

    auto response_from_grpc(StartResponse *gresponse, struct isula_start_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const StartRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const StartRequest &req, StartResponse *reply) -> Status override
    {
        return stub_->Start(context, req, reply);
    }
};

class RemoteStartWriteToServerTask : public StoppableThread {
public:
    explicit RemoteStartWriteToServerTask(
        std::shared_ptr<ClientReaderWriter<RemoteStartRequest, RemoteStartResponse>> stream)
        : m_stream(std::move(std::move(stream)))
    {
    }
    ~RemoteStartWriteToServerTask() = default;

    void run() override
    {
        while (!stopRequested()) {
            int cmd = 0;
            cmd = getchar();
            RemoteStartRequest request;
            if (cmd == EOF) {
                request.set_finish(true);
            } else {
                char in = static_cast<char>(cmd);
                request.set_stdin(&in, 1);
            }
            if (!m_stream->Write(request)) {
                ERROR("Failed to write request to grpc server");
                break;
            }
            if (cmd == EOF) {
                break;
            }
        }
    }

private:
    std::shared_ptr<ClientReaderWriter<RemoteStartRequest, RemoteStartResponse>> m_stream;
};

class ContainerRemoteStart : public ClientBase<ContainerService, ContainerService::Stub, isula_start_request,
    RemoteStartRequest, isula_start_response, RemoteStartResponse> {
public:
    explicit ContainerRemoteStart(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerRemoteStart() = default;

    auto set_custom_header_metadata(ClientContext &context, const struct isula_start_request *request) -> int
    {
        if (request == nullptr || request->name == nullptr) {
            ERROR("Missing container id in the request");
            return -1;
        }
        // Set common name from cert.perm
        char common_name_value[ClientBaseConstants::COMMON_NAME_LEN] = { 0 };
        int ret = get_common_name_from_tls_cert(m_certFile.c_str(), common_name_value,
                                                ClientBaseConstants::COMMON_NAME_LEN);
        if (ret != 0) {
            ERROR("Failed to get common name in: %s", m_certFile.c_str());
            return -1;
        }
        context.AddMetadata("username", std::string(common_name_value, strlen(common_name_value)));
        context.AddMetadata("tls_mode", m_tlsMode);
        context.AddMetadata("container-id", std::string(request->name));
        context.AddMetadata("attach-stdin", request->attach_stdin ? "true" : "false");
        context.AddMetadata("attach-stdout", request->attach_stdout ? "true" : "false");
        context.AddMetadata("attach-stderr", request->attach_stderr ? "true" : "false");
        return 0;
    }

    static void get_server_trailing_metadata(ClientContext &context, isula_start_response *response)
    {
        auto metadata = context.GetServerTrailingMetadata();
        auto cc = metadata.find("cc");
        if (cc != metadata.end()) {
            auto tmpstr = std::string(cc->second.data(), cc->second.length());
            response->server_errono = static_cast<uint32_t>(std::stoul(tmpstr, nullptr, 0));
        }
        auto errmsg = metadata.find("errmsg");
        if (errmsg != metadata.end()) {
            auto tmpstr = std::string(errmsg->second.data(), errmsg->second.length());
            response->errmsg = util_strdup_s(tmpstr.c_str());
        }
    }

    auto run(const struct isula_start_request *request, struct isula_start_response *response) -> int override
    {
        ClientContext context;

        if (set_custom_header_metadata(context, request) != 0) {
            ERROR("Failed to translate request to grpc");
            response->cc = ISULAD_ERR_INPUT;
            return -1;
        }

        using StreamStartRWSharedPtr = std::shared_ptr<ClientReaderWriter<RemoteStartRequest, RemoteStartResponse>>;
        StreamStartRWSharedPtr stream(stub_->RemoteStart(&context));

        RemoteStartWriteToServerTask write_task(stream);
        std::thread writer;
        if (request->attach_stdin) {
            writer = std::thread([&]() {
                write_task.run();
            });
        }

        RemoteStartResponse stream_response;
        if (request->attach_stdout || request->attach_stderr) {
            while (stream->Read(&stream_response)) {
                if (stream_response.finish()) {
                    break;
                }
                if (!stream_response.stdout().empty()) {
                    std::cout << stream_response.stdout() << std::flush;
                }
                if (!stream_response.stderr().empty()) {
                    std::cerr << stream_response.stderr() << std::flush;
                }
            }
        }
        write_task.stop();
        stream->WritesDone();
        Status status = stream->Finish();
        if (!status.ok()) {
            ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
            unpackStatus(status, response);
            goto out;
        }

        get_server_trailing_metadata(context, response);

        if (response->server_errono != ISULAD_SUCCESS) {
            response->cc = ISULAD_ERR_EXEC;
            goto out;
        }
out:
        if (request->attach_stdin) {
            pthread_cancel(writer.native_handle());
            if (writer.joinable()) {
                writer.join();
            }
        }
        return (response->cc == ISULAD_SUCCESS) ? 0 : -1;
    }
};
class ContainerTop : public ClientBase<ContainerService, ContainerService::Stub, isula_top_request, TopRequest,
    isula_top_response, TopResponse> {
public:
    explicit ContainerTop(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerTop() = default;

    auto request_to_grpc(const isula_top_request *request, TopRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        if (request->ps_argc > 0) {
            for (int i = 0; i < request->ps_argc; i++) {
                grequest->add_args(request->ps_args[i]);
            }
        }

        return 0;
    }

    auto response_from_grpc(TopResponse *gresponse, struct isula_top_response *response) -> int override
    {
        int i = 0;
        int num = gresponse->processes_size();

        if (num <= 0) {
            response->titles = nullptr;
            response->processes_len = 0;
            response->server_errono = gresponse->cc();
            if (!gresponse->errmsg().empty()) {
                response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
            }
            return 0;
        }

        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }
        if (!gresponse->titles().empty()) {
            response->titles = util_strdup_s(gresponse->titles().c_str());
        }
        if (static_cast<size_t>(num) > SIZE_MAX / sizeof(char *)) {
            ERROR("Too many summary info!");
            return -1;
        }
        response->processes = static_cast<char **>(util_common_calloc_s(num * sizeof(char *)));
        if (response->processes == nullptr) {
            ERROR("out of memory");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }
        for (i = 0; i < num; i++) {
            response->processes[i] = util_strdup_s(gresponse->processes(i).c_str());
        }
        response->processes_len = static_cast<size_t>(gresponse->processes_size());

        return 0;
    }

    auto check_parameter(const TopRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }
    auto grpc_call(ClientContext *context, const TopRequest &req, TopResponse *reply) -> Status override
    {
        return stub_->Top(context, req, reply);
    }
};

class ContainerStop : public ClientBase<ContainerService, ContainerService::Stub, isula_stop_request, StopRequest,
    isula_stop_response, StopResponse> {
public:
    explicit ContainerStop(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerStop() = default;

    auto request_to_grpc(const isula_stop_request *request, StopRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        grequest->set_force(request->force);
        grequest->set_timeout(request->timeout);

        return 0;
    }

    auto response_from_grpc(StopResponse *gresponse, isula_stop_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const StopRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const StopRequest &req, StopResponse *reply) -> Status override
    {
        return stub_->Stop(context, req, reply);
    }
};

class ContainerRename : public ClientBase<ContainerService, ContainerService::Stub, isula_rename_request, RenameRequest,
    isula_rename_response, RenameResponse> {
public:
    explicit ContainerRename(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerRename() = default;

    auto request_to_grpc(const isula_rename_request *request, RenameRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->old_name != nullptr) {
            grequest->set_oldname(request->old_name);
        }

        if (request->new_name != nullptr) {
            grequest->set_newname(request->new_name);
        }

        return 0;
    }

    auto response_from_grpc(RenameResponse *gresponse, isula_rename_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const RenameRequest &req) -> int override
    {
        if (req.oldname().empty()) {
            ERROR("Missing container old name in the request");
            return -1;
        }

        if (req.newname().empty()) {
            ERROR("Missing container new name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const RenameRequest &req, RenameResponse *reply) -> Status override
    {
        return stub_->Rename(context, req, reply);
    }
};

class ContainerResize : public ClientBase<ContainerService, ContainerService::Stub, isula_resize_request, ResizeRequest,
    isula_resize_response, ResizeResponse> {
public:
    explicit ContainerResize(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerResize() = default;

    auto request_to_grpc(const isula_resize_request *request, ResizeRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->id != nullptr) {
            grequest->set_id(request->id);
        }
        if (request->suffix != nullptr) {
            grequest->set_suffix(request->suffix);
        }
        grequest->set_height(request->height);

        grequest->set_width(request->width);

        return 0;
    }

    auto response_from_grpc(ResizeResponse *gresponse, isula_resize_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const ResizeRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container id in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const ResizeRequest &req, ResizeResponse *reply) -> Status override
    {
        return stub_->Resize(context, req, reply);
    }
};


class ContainerRestart : public ClientBase<ContainerService, ContainerService::Stub, isula_restart_request,
    RestartRequest, isula_restart_response, RestartResponse> {
public:
    explicit ContainerRestart(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerRestart() = default;

    auto request_to_grpc(const isula_restart_request *request, RestartRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        grequest->set_timeout(static_cast<int32_t>(request->timeout));

        return 0;
    }

    auto response_from_grpc(RestartResponse *gresponse, isula_restart_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const RestartRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const RestartRequest &req, RestartResponse *reply) -> Status override
    {
        return stub_->Restart(context, req, reply);
    }
};

class ContainerKill : public ClientBase<ContainerService, ContainerService::Stub, isula_kill_request, KillRequest,
    isula_kill_response, KillResponse> {
public:
    explicit ContainerKill(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerKill() = default;

    auto request_to_grpc(const isula_kill_request *request, KillRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        grequest->set_signal(request->signal);

        return 0;
    }

    auto response_from_grpc(KillResponse *gresponse, isula_kill_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const KillRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const KillRequest &req, KillResponse *reply) -> Status override
    {
        return stub_->Kill(context, req, reply);
    }
};

class ContainerExec : public ClientBase<ContainerService, ContainerService::Stub, isula_exec_request, ExecRequest,
    isula_exec_response, ExecResponse> {
public:
    explicit ContainerExec(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerExec() = default;

    auto request_to_grpc(const isula_exec_request *request, ExecRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_container_id(request->name);
        }
        if (request->suffix != nullptr) {
            grequest->set_suffix(request->suffix);
        }
        grequest->set_tty(request->tty);
        grequest->set_open_stdin(request->open_stdin);
        grequest->set_attach_stdin(request->attach_stdin);
        grequest->set_attach_stdout(request->attach_stdout);
        grequest->set_attach_stderr(request->attach_stderr);
        if (request->stdin != nullptr) {
            grequest->set_stdin(request->stdin);
        }
        if (request->stdout != nullptr) {
            grequest->set_stdout(request->stdout);
        }
        if (request->stderr != nullptr) {
            grequest->set_stderr(request->stderr);
        }
        for (int i = 0; i < request->argc; i++) {
            grequest->add_argv(request->argv[i]);
        }
        for (size_t i = 0; i < request->env_len; i++) {
            grequest->add_env(request->env[i]);
        }
        if (request->user != nullptr) {
            grequest->set_user(request->user);
        }

        return 0;
    }

    auto response_from_grpc(ExecResponse *gresponse, isula_exec_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        response->exit_code = gresponse->exit_code();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const ExecRequest &req) -> int override
    {
        if (req.container_id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const ExecRequest &req, ExecResponse *reply) -> Status override
    {
        return stub_->Exec(context, req, reply);
    }
};

class RemoteExecWriteToServerTask : public StoppableThread {
public:
    explicit RemoteExecWriteToServerTask(
        std::shared_ptr<ClientReaderWriter<RemoteExecRequest, RemoteExecResponse>> stream)
        : m_stream(std::move(std::move(stream)))
    {
    }
    ~RemoteExecWriteToServerTask() = default;

    void run() override
    {
        while (!stopRequested()) {
            int cmd = 0;
            cmd = getchar();
            RemoteExecRequest request;
            if (cmd == EOF) {
                request.set_finish(true);
            } else {
                char in = static_cast<char>(cmd);
                request.add_cmd(&in, 1);
            }
            if (!m_stream->Write(request)) {
                ERROR("Failed to write request to grpc server");
                break;
            }
            if (cmd == EOF) {
                break;
            }
        }
    }

private:
    std::shared_ptr<ClientReaderWriter<RemoteExecRequest, RemoteExecResponse>> m_stream;
};

class ContainerRemoteExec : public ClientBase<ContainerService, ContainerService::Stub, isula_exec_request,
    RemoteExecRequest, isula_exec_response, RemoteExecResponse> {
public:
    explicit ContainerRemoteExec(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerRemoteExec() = default;

    auto set_custom_header_metadata(ClientContext &context, const struct isula_exec_request *request,
                                    struct isula_exec_response *response) -> int
    {
        int ret = 0;
        char *json = nullptr;
        parser_error err = nullptr;
        container_exec_request exec = { 0 };
        struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
        // Set common name from cert.perm
        char common_name_value[ClientBaseConstants::COMMON_NAME_LEN] = { 0 };

        if (request == nullptr || request->name == nullptr) {
            ERROR("Missing container id in the request");
            return -1;
        }

        exec.container_id = request->name;
        exec.tty = request->tty;
        exec.attach_stdin = request->attach_stdin;
        exec.attach_stdout = request->attach_stdout;
        exec.attach_stderr = request->attach_stderr;
        exec.timeout = request->timeout;
        exec.argv = request->argv;
        exec.argv_len = static_cast<size_t>(request->argc);
        exec.env = request->env;
        exec.env_len = request->env_len;
        exec.suffix = request->suffix;
        json = container_exec_request_generate_json(&exec, &ctx, &err);
        if (json == nullptr) {
            format_errorf(&response->errmsg, "Can not generate json: %s", err);
            ret = -1;
            goto out;
        }
        ret = get_common_name_from_tls_cert(m_certFile.c_str(), common_name_value,
                                            ClientBaseConstants::COMMON_NAME_LEN);
        if (ret != 0) {
            ERROR("Failed to get common name in: %s", m_certFile.c_str());
            ret = -1;
            goto out;
        }
        context.AddMetadata("username", std::string(common_name_value, strlen(common_name_value)));
        context.AddMetadata("tls_mode", m_tlsMode);
        context.AddMetadata("isulad-remote-exec", json);
out:
        free(err);
        free(json);
        return ret;
    }
    static void get_server_trailing_metadata(ClientContext &context, isula_exec_response *response)
    {
        auto metadata = context.GetServerTrailingMetadata();
        auto cc = metadata.find("cc");
        if (cc != metadata.end()) {
            auto tmpstr = std::string(cc->second.data(), cc->second.length());
            response->server_errono = static_cast<uint32_t>(std::stoul(tmpstr, nullptr, 0));
        }
        auto exit_code = metadata.find("exit_code");
        if (exit_code != metadata.end()) {
            auto tmpstr = std::string(exit_code->second.data(), exit_code->second.length());
            response->exit_code = static_cast<uint32_t>(std::stoul(tmpstr, nullptr, 0));
        }
        auto errmsg = metadata.find("errmsg");
        if (errmsg != metadata.end()) {
            auto tmpstr = std::string(errmsg->second.data(), errmsg->second.length());
            response->errmsg = util_strdup_s(tmpstr.c_str());
        }
    }
    auto run(const struct isula_exec_request *request, struct isula_exec_response *response) -> int override
    {
        ClientContext context;

        if (set_custom_header_metadata(context, request, response) != 0) {
            ERROR("Failed to translate request to grpc");
            response->cc = ISULAD_ERR_INPUT;
            return -1;
        }

        std::shared_ptr<ClientReaderWriter<RemoteExecRequest, RemoteExecResponse>> stream(stub_->RemoteExec(&context));

        RemoteExecWriteToServerTask write_task(stream);
        std::thread writer([&]() {
            write_task.run();
        });

        RemoteExecResponse stream_response;
        while (stream->Read(&stream_response)) {
            if (stream_response.finish()) {
                break;
            }
            if (!stream_response.stdout().empty()) {
                std::cout << stream_response.stdout() << std::flush;
            }
            if (!stream_response.stderr().empty()) {
                std::cerr << stream_response.stderr() << std::flush;
            }
        }
        write_task.stop();
        stream->WritesDone();
        Status status = stream->Finish();
        if (!status.ok()) {
            ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
            unpackStatus(status, response);
            goto out;
        }

        get_server_trailing_metadata(context, response);

        if (response->server_errono != ISULAD_SUCCESS) {
            response->cc = ISULAD_ERR_EXEC;
            goto out;
        }
out:
        pthread_cancel(writer.native_handle());
        if (writer.joinable()) {
            writer.join();
        }
        return (response->cc == ISULAD_SUCCESS) ? 0 : -1;
    }
};

class ContainerInspect : public ClientBase<ContainerService, ContainerService::Stub, isula_inspect_request,
    InspectContainerRequest, isula_inspect_response, InspectContainerResponse> {
public:
    explicit ContainerInspect(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerInspect() = default;

    auto request_to_grpc(const isula_inspect_request *request, InspectContainerRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        grequest->set_bformat(request->bformat);
        grequest->set_timeout(request->timeout);

        return 0;
    }

    auto response_from_grpc(InspectContainerResponse *gresponse, isula_inspect_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->containerjson().empty()) {
            response->json = util_strdup_s(gresponse->containerjson().c_str());
        }
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const InspectContainerRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const InspectContainerRequest &req,
                   InspectContainerResponse *reply) -> Status override
    {
        return stub_->Inspect(context, req, reply);
    }
};

class ContainerDelete : public ClientBase<ContainerService, ContainerService::Stub, isula_delete_request, DeleteRequest,
    isula_delete_response, DeleteResponse> {
public:
    explicit ContainerDelete(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerDelete() = default;

    auto request_to_grpc(const isula_delete_request *request, DeleteRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        grequest->set_force(request->force);

        return 0;
    }

    auto response_from_grpc(DeleteResponse *gresponse, isula_delete_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->id().empty()) {
            response->name = util_strdup_s(gresponse->id().c_str());
        }
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const DeleteRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const DeleteRequest &req, DeleteResponse *reply) -> Status override
    {
        return stub_->Delete(context, req, reply);
    }
};

class ContainerList : public ClientBase<ContainerService, ContainerService::Stub, isula_list_request, ListRequest,
    isula_list_response, ListResponse> {
public:
    explicit ContainerList(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerList() = default;

    auto request_to_grpc(const isula_list_request *request, ListRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->filters != nullptr) {
            google::protobuf::Map<std::string, std::string> *map = nullptr;
            map = grequest->mutable_filters();
            for (size_t i = 0; i < request->filters->len; i++) {
                (*map)[request->filters->keys[i]] = request->filters->values[i];
            }
        }
        grequest->set_all(request->all);

        return 0;
    }

    auto response_from_grpc(ListResponse *gresponse, isula_list_response *response) -> int override
    {
        int i = 0;
        int num = gresponse->containers_size();

        if (num <= 0) {
            response->container_summary = nullptr;
            response->container_num = 0;
            response->server_errono = gresponse->cc();
            if (!gresponse->errmsg().empty()) {
                response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
            }
            return 0;
        }
        if (static_cast<size_t>(num) > SIZE_MAX / sizeof(isula_container_summary_info *)) {
            ERROR("Too many summary info!");
            return -1;
        }
        response->container_summary = static_cast<struct isula_container_summary_info **>(util_common_calloc_s(
                                                                                              sizeof(struct isula_container_summary_info *) * static_cast<size_t>(num)));
        if (response->container_summary == nullptr) {
            ERROR("out of memory");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }

        for (i = 0; i < num; i++) {
            if (get_container_summary_from_grpc(response, gresponse, i) != 0) {
                return -1;
            }
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const ListRequest &req, ListResponse *reply) -> Status override
    {
        return stub_->List(context, req, reply);
    }

private:
    static auto get_container_summary_from_grpc(isula_list_response *response, ListResponse *gresponse, int index) -> int
    {
        response->container_summary[index] =
            static_cast<struct isula_container_summary_info *>(util_common_calloc_s(sizeof(struct isula_container_summary_info)));
        if (response->container_summary[index] == nullptr) {
            ERROR("out of memory");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }
        const Container &in = gresponse->containers(index);

        const char *id = !in.id().empty() ? in.id().c_str() : "-";
        response->container_summary[index]->id = util_strdup_s(id);
        const char *name = !in.name().empty() ? in.name().c_str() : "-";
        response->container_summary[index]->name = util_strdup_s(name);
        response->container_summary[index]->runtime = !in.runtime().empty() ? util_strdup_s(in.runtime().c_str())
                                                      : nullptr;
        response->container_summary[index]->has_pid = static_cast<uint32_t>(static_cast<int>(in.pid()) != 0);
        response->container_summary[index]->pid = static_cast<uint32_t>(in.pid());
        response->container_summary[index]->status = static_cast<Container_Status>(in.status());
        response->container_summary[index]->image = !in.image().empty() ? util_strdup_s(in.image().c_str())
                                                    : util_strdup_s("none");
        response->container_summary[index]->command = !in.command().empty() ? util_strdup_s(in.command().c_str())
                                                      : util_strdup_s("-");
        const char *starttime = !in.startat().empty() ? in.startat().c_str() : "-";
        response->container_summary[index]->startat = util_strdup_s(starttime);

        const char *finishtime = !in.finishat().empty() ? in.finishat().c_str() : "-";
        response->container_summary[index]->finishat = util_strdup_s(finishtime);

        response->container_summary[index]->exit_code = in.exit_code();
        response->container_summary[index]->restart_count = static_cast<uint32_t>(in.restartcount());
        response->container_summary[index]->created = static_cast<int64_t>(in.created());
        std::string healthState;
        if (!in.health_state().empty()) {
            healthState = "(" + in.health_state() + ")";
        }
        response->container_summary[index]->health_state = !healthState.empty() ? util_strdup_s(healthState.c_str())
                                                           : nullptr;
        response->container_num++;

        return 0;
    }
};

class ContainerWait : public ClientBase<ContainerService, ContainerService::Stub, isula_wait_request, WaitRequest,
    isula_wait_response, WaitResponse> {
public:
    explicit ContainerWait(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerWait() = default;

    auto request_to_grpc(const isula_wait_request *request, WaitRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }
        if (request->id != nullptr) {
            grequest->set_id(request->id);
        }
        grequest->set_condition(request->condition);

        return 0;
    }

    auto response_from_grpc(WaitResponse *gresponse, isula_wait_response *response) -> int override
    {
        response->exit_code = static_cast<int>(gresponse->exit_code());
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const WaitRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const WaitRequest &req, WaitResponse *reply) -> Status override
    {
        return stub_->Wait(context, req, reply);
    }
};

class AttachWriteToServerTask : public StoppableThread {
public:
    explicit AttachWriteToServerTask(std::shared_ptr<ClientReaderWriter<AttachRequest, AttachResponse>> stream)
        : m_stream(std::move(std::move(stream)))
    {
    }
    ~AttachWriteToServerTask() = default;

    void run() override
    {
        while (!stopRequested()) {
            int cmd = 0;
            cmd = getchar();
            AttachRequest request;
            if (cmd == EOF) {
                request.set_finish(true);
            } else {
                char in = static_cast<char>(cmd);
                request.set_stdin(&in, 1);
            }
            if (!m_stream->Write(request)) {
                ERROR("Failed to write request to grpc server");
                break;
            }
            if (cmd == EOF) {
                break;
            }
        }
    }

private:
    std::shared_ptr<ClientReaderWriter<AttachRequest, AttachResponse>> m_stream;
};

class ContainerAttach : public ClientBase<ContainerService, ContainerService::Stub, isula_attach_request, AttachRequest,
    isula_attach_response, AttachResponse> {
public:
    explicit ContainerAttach(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerAttach() = default;

    auto set_custom_header_metadata(ClientContext &context, const struct isula_attach_request *request) -> int
    {
        if (request == nullptr || request->name == nullptr) {
            ERROR("Missing container id in the request");
            return -1;
        }
        // Set common name from cert.perm
        char common_name_value[ClientBaseConstants::COMMON_NAME_LEN] = { 0 };
        int ret = get_common_name_from_tls_cert(m_certFile.c_str(), common_name_value,
                                                ClientBaseConstants::COMMON_NAME_LEN);
        if (ret != 0) {
            ERROR("Failed to get common name in: %s", m_certFile.c_str());
            return -1;
        }
        context.AddMetadata("username", std::string(common_name_value, strlen(common_name_value)));
        context.AddMetadata("tls_mode", m_tlsMode);
        context.AddMetadata("container-id", std::string(request->name));
        context.AddMetadata("attach-stdin", request->attach_stdin ? "true" : "false");
        context.AddMetadata("attach-stdout", request->attach_stdout ? "true" : "false");
        context.AddMetadata("attach-stderr", request->attach_stderr ? "true" : "false");

        return 0;
    }
    static void get_server_trailing_metadata(ClientContext &context, isula_attach_response *response)
    {
        auto metadata = context.GetServerTrailingMetadata();
        auto cc = metadata.find("cc");
        if (cc != metadata.end()) {
            auto tmpstr = std::string(cc->second.data(), cc->second.length());
            response->server_errono = static_cast<uint32_t>(std::stoul(tmpstr, nullptr, 0));
        }
        auto errmsg = metadata.find("errmsg");
        if (errmsg != metadata.end()) {
            auto tmpstr = std::string(errmsg->second.data(), errmsg->second.length());
            response->errmsg = util_strdup_s(tmpstr.c_str());
        }
    }

    auto run(const struct isula_attach_request *request, struct isula_attach_response *response) -> int override
    {
        ClientContext context;

        if (set_custom_header_metadata(context, request) != 0) {
            ERROR("Failed to translate request to grpc");
            response->cc = ISULAD_ERR_INPUT;
            return -1;
        }

        std::shared_ptr<ClientReaderWriter<AttachRequest, AttachResponse>> stream(stub_->Attach(&context));

        AttachWriteToServerTask write_task(stream);
        std::thread writer([&]() {
            write_task.run();
        });

        if (request->attach_stdin) {
            AttachResponse stream_response;
            while (stream->Read(&stream_response)) {
                if (stream_response.finish()) {
                    break;
                }
                if (!stream_response.stdout().empty()) {
                    std::cout << stream_response.stdout() << std::flush;
                }
                if (!stream_response.stderr().empty()) {
                    std::cerr << stream_response.stderr() << std::flush;
                }
            }
        }
        write_task.stop();
        stream->WritesDone();
        Status status = stream->Finish();
        if (!status.ok()) {
            ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
            unpackStatus(status, response);
            goto out;
        }

        get_server_trailing_metadata(context, response);

        if (response->server_errono != ISULAD_SUCCESS) {
            response->cc = ISULAD_ERR_EXEC;
        }

out:
        if (request->attach_stdin) {
            pthread_cancel(writer.native_handle());
            if (writer.joinable()) {
                writer.join();
            }
        }
        return (response->cc == ISULAD_SUCCESS) ? 0 : -1;
    }
};

class ContainerPause : public ClientBase<ContainerService, ContainerService::Stub, isula_pause_request, PauseRequest,
    isula_pause_response, PauseResponse> {
public:
    explicit ContainerPause(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerPause() = default;

    auto request_to_grpc(const isula_pause_request *request, PauseRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }

        return 0;
    }

    auto response_from_grpc(PauseResponse *gresponse, isula_pause_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const PauseRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const PauseRequest &req, PauseResponse *reply) -> Status override
    {
        return stub_->Pause(context, req, reply);
    }
};

class ContainerResume : public ClientBase<ContainerService, ContainerService::Stub, isula_resume_request, ResumeRequest,
    isula_resume_response, ResumeResponse> {
public:
    explicit ContainerResume(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerResume() = default;

    auto request_to_grpc(const isula_resume_request *request, ResumeRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }

        return 0;
    }

    auto response_from_grpc(ResumeResponse *gresponse, isula_resume_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const ResumeRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const ResumeRequest &req, ResumeResponse *reply) -> Status override
    {
        return stub_->Resume(context, req, reply);
    }
};

class ContainerExport : public ClientBase<ContainerService, ContainerService::Stub, isula_export_request, ExportRequest,
    isula_export_response, ExportResponse> {
public:
    explicit ContainerExport(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerExport() = default;

    auto request_to_grpc(const isula_export_request *request, ExportRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }
        if (request->file != nullptr) {
            grequest->set_file(request->file);
        }

        return 0;
    }

    auto response_from_grpc(ExportResponse *gresponse, isula_export_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const ExportRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        if (req.file().empty()) {
            ERROR("Missing output file path in the request");
            return -1;
        }
        return 0;
    }

    auto grpc_call(ClientContext *context, const ExportRequest &req, ExportResponse *reply) -> Status override
    {
        return stub_->Export(context, req, reply);
    }
};

class ContainerUpdate : public ClientBase<ContainerService, ContainerService::Stub, isula_update_request, UpdateRequest,
    isula_update_response, UpdateResponse> {
public:
    explicit ContainerUpdate(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerUpdate() = default;

    auto request_to_grpc(const isula_update_request *request, UpdateRequest *grequest) -> int override
    {
        int ret = 0;
        char *json = nullptr;

        if (request == nullptr) {
            return -1;
        }

        isula_host_config_t hostconfig;
        (void)memset(&hostconfig, 0, sizeof(hostconfig));

        if (request->updateconfig != nullptr) {
            hostconfig.restart_policy = request->updateconfig->restart_policy;
            hostconfig.cr = request->updateconfig->cr;
        }
        ret = generate_hostconfig(&hostconfig, &json);
        if (ret != 0) {
            ERROR("Failed to generate hostconfig json");
            ret = -1;
            goto cleanup;
        }

        grequest->set_hostconfig(json);
        if (request->name != nullptr) {
            grequest->set_id(request->name);
        }

cleanup:
        free(json);
        return ret;
    }

    auto response_from_grpc(UpdateResponse *gresponse, isula_update_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const UpdateRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing container name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const UpdateRequest &req, UpdateResponse *reply) -> Status override
    {
        return stub_->Update(context, req, reply);
    }
};

class ContainerStats : public ClientBase<ContainerService, ContainerService::Stub, isula_stats_request, StatsRequest,
    isula_stats_response, StatsResponse> {
public:
    explicit ContainerStats(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerStats() = default;

    auto request_to_grpc(const isula_stats_request *request, StatsRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        for (size_t i = 0; request->containers != nullptr && i < request->containers_len; i++) {
            grequest->add_containers(request->containers[i]);
        }

        grequest->set_all(request->all);

        return 0;
    }

    auto response_from_grpc(StatsResponse *gresponse, isula_stats_response *response) -> int override
    {
        int size = gresponse->containers_size();
        if (size > 0) {
            response->container_stats =
                static_cast<isula_container_info *>(util_common_calloc_s(size * sizeof(struct isula_container_info)));
            if (response->container_stats == nullptr) {
                ERROR("Out of memory");
                return -1;
            }
            for (int i = 0; i < size; i++) {
                if (!gresponse->containers(i).id().empty()) {
                    response->container_stats[i].id = util_strdup_s(gresponse->containers(i).id().c_str());
                }
                response->container_stats[i].pids_current = gresponse->containers(i).pids_current();
                response->container_stats[i].cpu_use_nanos = gresponse->containers(i).cpu_use_nanos();
                response->container_stats[i].cpu_system_use = gresponse->containers(i).cpu_system_use();
                response->container_stats[i].online_cpus = gresponse->containers(i).online_cpus();
                response->container_stats[i].blkio_read = gresponse->containers(i).blkio_read();
                response->container_stats[i].blkio_write = gresponse->containers(i).blkio_write();
                response->container_stats[i].mem_used = gresponse->containers(i).mem_used();
                response->container_stats[i].mem_limit = gresponse->containers(i).mem_limit();
                response->container_stats[i].kmem_used = gresponse->containers(i).kmem_used();
                response->container_stats[i].kmem_limit = gresponse->containers(i).kmem_limit();
            }
            response->container_num = static_cast<size_t>(size);
        }
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const StatsRequest & /*req*/) -> int override
    {
        return 0;
    }

    auto grpc_call(ClientContext *context, const StatsRequest &req, StatsResponse *reply) -> Status override
    {
        return stub_->Stats(context, req, reply);
    }
};

class ContainerEvents : public ClientBase<ContainerService, ContainerService::Stub, isula_events_request, EventsRequest,
    isula_events_response, Event> {
public:
    explicit ContainerEvents(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerEvents() = default;

    auto run(const struct isula_events_request *request, struct isula_events_response *response) -> int override
    {
        int ret = 0;
        EventsRequest req;
        Event event;
        ClientContext context;
        Status status;
        container_events_format_t *isula_event = nullptr;

        if (SetMetadataInfo(context) != 0) {
            ERROR("Failed to set metadata info for authorization");
            response->cc = ISULAD_ERR_INPUT;
            return -1;
        }

        ret = events_request_to_grpc(request, &req);
        if (ret != 0) {
            ERROR("Failed to translate request to grpc");
            response->server_errono = ISULAD_ERR_INPUT;
            return -1;
        }

        std::unique_ptr<ClientReader<Event>> reader(stub_->Events(&context, req));
        while (reader->Read(&event)) {
            isula_event = static_cast<container_events_format_t *>(util_common_calloc_s(sizeof(container_events_format_t)));
            if (isula_event == nullptr) {
                ERROR("Out of memory");
                response->server_errono = ISULAD_ERR_EXEC;
                return -1;
            }
            event_from_grpc(isula_event, &event);
            if (request->cb != nullptr) {
                request->cb(isula_event);
            }
            container_events_format_free(isula_event);
            isula_event = nullptr;
        }
        status = reader->Finish();
        if (!status.ok()) {
            ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
            unpackStatus(status, response);
            return -1;
        }

        if (response->server_errono != ISULAD_SUCCESS) {
            response->cc = ISULAD_ERR_EXEC;
        }

        return (response->cc == ISULAD_SUCCESS) ? 0 : -1;
    }

private:
    static void protobuf_timestamp_to_grpc(const types_timestamp_t *timestamp, Timestamp *gtimestamp)
    {
        gtimestamp->set_seconds(timestamp->seconds);
        gtimestamp->set_nanos(timestamp->nanos);
    }

    static void protobuf_timestamp_from_grpc(types_timestamp_t *timestamp, const Timestamp &gtimestamp)
    {
        timestamp->has_seconds = gtimestamp.seconds() != 0;
        timestamp->seconds = gtimestamp.seconds();
        timestamp->has_nanos = gtimestamp.nanos() != 0;
        timestamp->nanos = gtimestamp.nanos();
    }

    void event_from_grpc(container_events_format_t *event, Event *gevent)
    {
        (void)memset(event, 0, sizeof(*event));

        if (gevent->has_timestamp()) {
            protobuf_timestamp_from_grpc(&event->timestamp, gevent->timestamp());
        }

        if (!gevent->opt().empty()) {
            event->opt = util_strdup_s(gevent->opt().c_str());
        }

        if (!gevent->id().empty()) {
            event->id = util_strdup_s(gevent->id().c_str());
        }

        const google::protobuf::Map<std::string, std::string> &map = gevent->annotations();
        for (const auto &iter : map) {
            std::string anno = iter.first + "=" + iter.second;
            (void)util_array_append(&event->annotations, anno.c_str());
            event->annotations_len++;
        }
    }

    auto events_request_to_grpc(const struct isula_events_request *request, EventsRequest *grequest) -> int
    {
        if (request == nullptr) {
            return -1;
        }

        grequest->set_storeonly(request->storeonly);

        if (request->id != nullptr) {
            grequest->set_id(request->id);
        }

        if (request->since.has_seconds || request->since.has_nanos) {
            protobuf_timestamp_to_grpc((&request->since), grequest->mutable_since());
        }
        if (request->until.has_seconds || request->until.has_nanos) {
            protobuf_timestamp_to_grpc((&request->until), grequest->mutable_until());
        }

        return 0;
    }
};

struct CopyFromContainerContext {
    CopyFromContainerRequest request;
    ClientContext context;
    ClientReader<CopyFromContainerResponse> *reader{};
};

// Note: len of buf can not smaller than ARCHIVE_BLOCK_SIZE
static auto CopyFromContainerRead(void *context, void *buf, size_t len) -> ssize_t
{
    CopyFromContainerResponse res;
    struct CopyFromContainerContext *gcopy = static_cast<struct CopyFromContainerContext *>(context);
    if (!gcopy->reader->Read(&res)) {
        return -1;
    }
    size_t data_len = res.data().length();
    if (data_len <= len) {
        (void)memcpy(buf, res.data().c_str(), data_len);
        return static_cast<ssize_t>(data_len);
    }

    return -1;
}

static auto CopyFromContainerFinish(void *context, char **err) -> int
{
    struct CopyFromContainerContext *gcopy = static_cast<struct CopyFromContainerContext *>(context);
    CopyFromContainerResponse res;

    if (gcopy->reader->Read(&res)) {
        // Connection still alive, cancel it
        gcopy->context.TryCancel();
        gcopy->reader->Finish();
    } else {
        Status status = gcopy->reader->Finish();
        if (!status.ok()) {
            ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
            if (!status.error_message().empty() &&
                (status.error_code() == StatusCode::UNKNOWN || status.error_code() == StatusCode::PERMISSION_DENIED ||
                 status.error_code() == grpc::StatusCode::INTERNAL)) {
                *err = util_strdup_s(status.error_message().c_str());
            } else {
                *err = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
            }
            return -1;
        }
    }
    delete gcopy->reader;
    delete gcopy;
    return 0;
}

class CopyFromContainer
    : public ClientBase<ContainerService, ContainerService::Stub, isula_copy_from_container_request,
      CopyFromContainerRequest, isula_copy_from_container_response, CopyFromContainerResponse> {
public:
    explicit CopyFromContainer(void *args)
        : ClientBase(args)
    {
    }
    ~CopyFromContainer() = default;

    auto run(const struct isula_copy_from_container_request *request,
             struct isula_copy_from_container_response *response) -> int override
    {
        int ret = 0;
        CopyFromContainerResponse res;
        struct CopyFromContainerContext *ctx = new (std::nothrow)(struct CopyFromContainerContext);
        if (ctx == nullptr) {
            return -1;
        }

        ret = copy_from_container_request_to_grpc(request, &ctx->request);
        if (ret != 0) {
            ERROR("Failed to translate request to grpc");
            response->server_errono = ISULAD_ERR_INPUT;
            delete ctx;
            return -1;
        }

        // Set common name from cert.perm
        char common_name_value[ClientBaseConstants::COMMON_NAME_LEN] = { 0 };
        ret = get_common_name_from_tls_cert(m_certFile.c_str(), common_name_value,
                                            ClientBaseConstants::COMMON_NAME_LEN);
        if (ret != 0) {
            ERROR("Failed to get common name in: %s", m_certFile.c_str());
            return -1;
        }
        ctx->context.AddMetadata("username", std::string(common_name_value, strlen(common_name_value)));
        ctx->context.AddMetadata("tls_mode", m_tlsMode);
        auto reader = stub_->CopyFromContainer(&ctx->context, ctx->request);
        reader->WaitForInitialMetadata();

        ctx->reader = reader.release();
        auto metadata = ctx->context.GetServerInitialMetadata();
        auto stat = metadata.find("isulad-container-path-stat");
        if (stat != metadata.end()) {
            char *err = nullptr;
            std::string json = std::string(stat->second.data(), stat->second.length());
            response->stat = container_path_stat_parse_data(json.c_str(), nullptr, &err);
            if (response->stat == nullptr) {
                ERROR("Invalid json: %s", err);
                free(err);
                CopyFromContainerFinish(ctx, &response->errmsg);
                return -1;
            }
            free(err);
        } else {
            CopyFromContainerFinish(ctx, &response->errmsg);
            return -1;
        }
        // Ignore the first reader which is used for transform metadata
        ctx->reader->Read(&res);
        response->reader.context = (void *)ctx;
        response->reader.read = CopyFromContainerRead;
        response->reader.close = CopyFromContainerFinish;

        return 0;
    }

private:
    static auto copy_from_container_request_to_grpc(const struct isula_copy_from_container_request *request,
                                                    CopyFromContainerRequest *grequest) -> int
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->runtime != nullptr) {
            grequest->set_runtime(request->runtime);
        }

        if (request->id != nullptr) {
            grequest->set_id(request->id);
        }

        if (request->srcpath != nullptr) {
            grequest->set_srcpath(request->srcpath);
        }

        return 0;
    }
};

class CopyToContainerWriteToServerTask : public StoppableThread {
public:
    explicit CopyToContainerWriteToServerTask(
        const struct io_read_wrapper *reader,
        std::shared_ptr<ClientReaderWriter<CopyToContainerRequest, CopyToContainerResponse>> stream)
        : m_reader(reader), m_stream(std::move(std::move(stream)))
    {
    }
    ~CopyToContainerWriteToServerTask() = default;

    void run() override
    {
        size_t len = ARCHIVE_BLOCK_SIZE;
        char *buf = static_cast<char *>(util_common_calloc_s(len));
        if (buf == nullptr) {
            ERROR("Out of memory");
            m_stream->WritesDone();
            return;
        }

        while (!stopRequested()) {
            ssize_t have_read_len = m_reader->read(m_reader->context, buf, len);
            CopyToContainerRequest request;
            request.set_data((const void*)buf, static_cast<size_t>(have_read_len));
            if (!m_stream->Write(request)) {
                DEBUG("Server may be exited, stop send data");
                break;
            }
        }
        free(buf);
        m_stream->WritesDone();
    }

private:
    const struct io_read_wrapper *m_reader;
    std::shared_ptr<ClientReaderWriter<CopyToContainerRequest, CopyToContainerResponse>> m_stream;
};

class CopyToContainer
    : public ClientBase<ContainerService, ContainerService::Stub, isula_copy_to_container_request,
      CopyToContainerRequest, isula_copy_to_container_response, CopyToContainerResponse> {
public:
    explicit CopyToContainer(void *args)
        : ClientBase(args)
    {
    }
    ~CopyToContainer() = default;

    auto set_custom_header_metadata(ClientContext &context, const struct isula_copy_to_container_request *request,
                                    struct isula_copy_to_container_response *response) -> int
    {
        int ret = 0;
        char *json = nullptr;
        char *err = nullptr;
        container_copy_to_request copy = { 0 };
        struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
        // Set common name from cert.perm
        char common_name_value[ClientBaseConstants::COMMON_NAME_LEN] = { 0 };

        if (request == nullptr || request->id == nullptr) {
            ERROR("Missing container id in the request");
            return -1;
        }

        copy.id = request->id;
        copy.runtime = request->runtime;
        copy.src_path = request->srcpath;
        copy.src_isdir = request->srcisdir;
        copy.src_rebase_name = request->srcrebase;
        copy.dst_path = request->dstpath;
        json = container_copy_to_request_generate_json(&copy, &ctx, &err);
        if (json == nullptr) {
            format_errorf(&response->errmsg, "Can not generate json: %s", err);
            ret = -1;
            goto out;
        }
        ret = get_common_name_from_tls_cert(m_certFile.c_str(), common_name_value,
                                            ClientBaseConstants::COMMON_NAME_LEN);
        if (ret != 0) {
            ERROR("Failed to get common name in: %s", m_certFile.c_str());
            ret = -1;
            goto out;
        }
        context.AddMetadata("username", std::string(common_name_value, strlen(common_name_value)));
        context.AddMetadata("tls_mode", m_tlsMode);
        context.AddMetadata("isulad-copy-to-container", json);
out:
        free(err);
        free(json);
        return ret;
    }

    auto run(const struct isula_copy_to_container_request *request,
             struct isula_copy_to_container_response *response) -> int
    override
    {
        ClientContext context;
        if (set_custom_header_metadata(context, request, response) != 0) {
            ERROR("Failed to translate request to grpc");
            response->cc = ISULAD_ERR_INPUT;
            return -1;
        }
        using StreamRSharedPtr = std::shared_ptr<ClientReaderWriter<CopyToContainerRequest, CopyToContainerResponse>>;
        StreamRSharedPtr stream(stub_->CopyToContainer(&context));

        CopyToContainerWriteToServerTask write_task(&request->reader, stream);
        std::thread writer([&]() {
            write_task.run();
        });

        CopyToContainerResponse stream_response;
        while (stream->Read(&stream_response)) {
            if (stream_response.finish()) {
                break;
            }
        }
        write_task.stop();
        writer.join();

        Status status = stream->Finish();
        if (!status.ok()) {
            ERROR("error_code: %d: %s", status.error_code(), status.error_message().c_str());
            unpackStatus(status, response);
            return -1;
        }

        return 0;
    }
};

class ContainerLogs : public ClientBase<ContainerService, ContainerService::Stub, isula_logs_request, LogsRequest,
    isula_logs_response, LogsResponse> {
public:
    explicit ContainerLogs(void *args)
        : ClientBase(args)
    {
    }
    ~ContainerLogs() = default;

    auto run(const struct isula_logs_request *request, struct isula_logs_response *response) -> int override
    {
        ClientContext context;
        LogsRequest grequest;
        int ret = -1;

        // Set common name from cert.perm
        char common_name_value[ClientBaseConstants::COMMON_NAME_LEN] = { 0 };
        ret = get_common_name_from_tls_cert(m_certFile.c_str(), common_name_value,
                                            ClientBaseConstants::COMMON_NAME_LEN);
        if (ret != 0) {
            ERROR("Failed to get common name in: %s", m_certFile.c_str());
            return -1;
        }
        context.AddMetadata("username", std::string(common_name_value, strlen(common_name_value)));
        context.AddMetadata("tls_mode", m_tlsMode);

        if (logs_request_to_grpc(request, &grequest) != 0) {
            ERROR("Failed to transform container request to grpc");
            response->server_errono = ISULAD_ERR_INPUT;
            return -1;
        }

        auto reader = stub_->Logs(&context, grequest);

        LogsResponse gresponse;
        while (reader->Read(&gresponse)) {
            show_container_log(request, gresponse);
        }
        Status status = reader->Finish();
        if (!status.ok()) {
            ERROR("error code: %d: %s", status.error_code(), status.error_message().c_str());
            unpackStatus(status, response);
            return -1;
        }
        return 0;
    }

private:
    static void show_container_log(const struct isula_logs_request *request, const LogsResponse &gresponse)
    {
        static std::ostream *os = nullptr;

        if (gresponse.stream() == "stdout") {
            os = &std::cout;
        } else if (gresponse.stream() == "stderr") {
            os = &std::cerr;
        } else {
            ERROR("Invalid container log: %s", gresponse.stream().c_str());
            return;
        }
        if (request->timestamps) {
            (*os) << gresponse.time() << " ";
        }
        (*os) << gresponse.data();
    }

    static auto logs_request_to_grpc(const struct isula_logs_request *request, LogsRequest *grequest) -> int
    {
        if (request == nullptr) {
            return -1;
        }
        if (request->id != nullptr) {
            grequest->set_id(request->id);
        }
        if (request->runtime != nullptr) {
            grequest->set_runtime(request->runtime);
        }
        if (request->since != nullptr) {
            grequest->set_since(request->since);
        }
        if (request->until != nullptr) {
            grequest->set_until(request->until);
        }
        grequest->set_timestamps(request->timestamps);
        grequest->set_follow(request->follow);
        grequest->set_tail(request->tail);
        grequest->set_details(request->details);
        return 0;
    }
};

auto grpc_containers_client_ops_init(isula_connect_ops *ops) -> int
{
    if (ops == nullptr) {
        return -1;
    }
    // implement following interface
    ops->container.version = container_func<isula_version_request, isula_version_response, ContainerVersion>;
    ops->container.info = container_func<isula_info_request, isula_info_response, ContainerInfo>;
    ops->container.create = container_func<isula_create_request, isula_create_response, ContainerCreate>;
    ops->container.start = container_func<isula_start_request, isula_start_response, ContainerStart>;
    ops->container.remote_start = container_func<isula_start_request, isula_start_response, ContainerRemoteStart>;
    ops->container.stop = container_func<isula_stop_request, isula_stop_response, ContainerStop>;
    ops->container.restart = container_func<isula_restart_request, isula_restart_response, ContainerRestart>;
    ops->container.remove = container_func<isula_delete_request, isula_delete_response, ContainerDelete>;
    ops->container.list = container_func<isula_list_request, isula_list_response, ContainerList>;
    ops->container.exec = container_func<isula_exec_request, isula_exec_response, ContainerExec>;
    ops->container.remote_exec = container_func<isula_exec_request, isula_exec_response, ContainerRemoteExec>;
    ops->container.attach = container_func<isula_attach_request, isula_attach_response, ContainerAttach>;
    ops->container.pause = container_func<isula_pause_request, isula_pause_response, ContainerPause>;
    ops->container.resume = container_func<isula_resume_request, isula_resume_response, ContainerResume>;
    ops->container.update = container_func<isula_update_request, isula_update_response, ContainerUpdate>;
    ops->container.kill = container_func<isula_kill_request, isula_kill_response, ContainerKill>;
    ops->container.stats = container_func<isula_stats_request, isula_stats_response, ContainerStats>;
    ops->container.wait = container_func<isula_wait_request, isula_wait_response, ContainerWait>;
    ops->container.events = container_func<isula_events_request, isula_events_response, ContainerEvents>;
    ops->container.inspect = container_func<isula_inspect_request, isula_inspect_response, ContainerInspect>;
    ops->container.export_rootfs = container_func<isula_export_request, isula_export_response, ContainerExport>;
    ops->container.copy_from_container =
        container_func<isula_copy_from_container_request, isula_copy_from_container_response, CopyFromContainer>;
    ops->container.copy_to_container =
        container_func<isula_copy_to_container_request, isula_copy_to_container_response, CopyToContainer>;
    ops->container.top = container_func<isula_top_request, isula_top_response, ContainerTop>;
    ops->container.rename = container_func<isula_rename_request, isula_rename_response, ContainerRename>;
    ops->container.resize = container_func<isula_resize_request, isula_resize_response, ContainerResize>;
    ops->container.logs = container_func<isula_logs_request, isula_logs_response, ContainerLogs>;

    return 0;
}

