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
 * Description: provide grpc server functions
 ******************************************************************************/
#include "grpc_service.h"
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <grpc++/grpc++.h>
#include <sstream>
#include <fstream>
#include "grpc_containers_service.h"
#include "grpc_images_service.h"
#include "grpc_volumes_service.h"
#include "runtime_runtime_service.h"
#include "runtime_image_service.h"
#ifdef ENABLE_NATIVE_NETWORK
#include "grpc_network_service.h"
#endif
#include "isula_libutils/log.h"
#include "network_plugin.h"
#include "errors.h"
#include "grpc_server_tls_auth.h"

using grpc::SslServerCredentialsOptions;

class GRPCServerImpl {
public:
    explicit GRPCServerImpl(Network::NetworkPluginConf &conf)
        : m_conf(conf)
    {
    }

    virtual ~GRPCServerImpl() = default;

    int Init(const struct service_arguments *args)
    {
        if (args == nullptr || args->hosts == nullptr) {
            ERROR("isulad config socket address is empty");
            return -1;
        }

        Errors err;
        m_runtimeRuntimeService.Init(m_conf, args->json_confs, err);
        if (err.NotEmpty()) {
            ERROR("Init runtime service failed: %s", err.GetCMessage());
            return -1;
        }
        auto hosts = std::vector<std::string>(args->hosts, args->hosts + args->hosts_len);
        for (auto host : hosts) {
            if (host.find("tcp://") == 0) {
                m_tcpPath.push_back(host.erase(0, std::string("tcp://").length()));
            } else {
                m_socketPath.push_back(host);
            }
        }

        if (ListeningPort(args, err)) {
            return -1;
        }

        // Register "service" as the instance through which we'll communicate with
        // clients. In this case it corresponds to an *synchronous* service.
        m_builder.RegisterService(&m_containerService);
        m_builder.RegisterService(&m_imagesService);
        m_builder.RegisterService(&m_volumeService);
        m_builder.RegisterService(&m_runtimeRuntimeService);
        m_builder.RegisterService(&m_runtimeImageService);
#ifdef ENABLE_NATIVE_NETWORK
        m_builder.RegisterService(&m_networkService);
#endif

        // Finally assemble the server.
        m_server = m_builder.BuildAndStart();
        if (m_server == nullptr) {
            ERROR("Failed to build and start grpc m_server");
            return -1;
        }
        return 0;
    }

    void Wait(void)
    {
        // Wait for the server to shutdown. Note that some other thread must be
        // responsible for shutting down the server for this call to ever return.
        m_server->Wait();
        m_runtimeRuntimeService.Wait();
    }

    void Shutdown(void)
    {
        m_server->Shutdown();
        m_runtimeRuntimeService.Shutdown();
        // Shutdown daemon, this operation should remove socket file.
        for (const auto &address : m_socketPath) {
            if (address.find(UNIX_SOCKET_PREFIX) == 0) {
                if (unlink(address.c_str() + strlen(UNIX_SOCKET_PREFIX)) < 0 && errno != ENOENT) {
                    WARN("Failed to remove '%s':%s", address.c_str(), strerror(errno));
                }
            }
        }
    }

private:
    int ListeningPort(const struct service_arguments *args, Errors &err)
    {
        if (args->json_confs->tls) {
            if (args->json_confs->authorization_plugin != nullptr) {
                AuthorizationPluginConfig::auth_plugin = args->json_confs->authorization_plugin;
            }

            std::string key = ReadTextFile(args->json_confs->tls_config->key_file, err);
            if (err.NotEmpty()) {
                return -1;
            }
            std::string cert = ReadTextFile(args->json_confs->tls_config->cert_file, err);
            if (err.NotEmpty()) {
                return -1;
            }
            std::string root { "" };
            if (args->json_confs->tls_verify) {
                root = ReadTextFile(args->json_confs->tls_config->ca_file, err);
                if (err.NotEmpty()) {
                    return -1;
                }
            }

            grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert { key, cert };
            grpc::SslServerCredentialsOptions sslOps {
                args->json_confs->tls_verify ? GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY :
                GRPC_SSL_DONT_REQUEST_CLIENT_CERTIFICATE
            };
            // Daemon modes : if tls_verify is set, Authenticate clients, otherwise do not
            // --tlsverify --tlscacert, --tlscert, --tlskey set: Authenticate clients
            // --tls, --tlscert, --tlskey: Do not authenticate clients
            sslOps.pem_root_certs = root;
            sslOps.pem_key_cert_pairs.push_back(key_cert);
            // Listen on the given tcp address with ssl/tls authentication mechanism.
            for (const auto &address : m_tcpPath) {
                m_builder.AddListeningPort(address, grpc::SslServerCredentials(sslOps));
                INFO("Server listening on %s", address.c_str());
            }
        } else {
            // Listen on the given tcp address without any authentication mechanism.
            for (const auto &address : m_tcpPath) {
                m_builder.AddListeningPort(address, grpc::InsecureServerCredentials());
                INFO("Server listening on %s", address.c_str());
            }
        }
        // Listen on the given socket address without any authentication mechanism.
        for (const auto &address : m_socketPath) {
            m_builder.AddListeningPort(address, grpc::InsecureServerCredentials());
            INFO("Server listening on %s", address.c_str());
        }

        return 0;
    }

    std::string ReadTextFile(const std::string &file, Errors &err)
    {
        if (file.empty()) {
            return "";
        }
        std::ifstream context(file.c_str(), std::ios::in);
        if (!context) {
            err.SetError("file does not exist: " + file);
            return "";
        }
        std::stringstream ss;
        if (context.is_open()) {
            ss << context.rdbuf();
            context.close();
        }
        return ss.str();
    }

private:
    Network::NetworkPluginConf m_conf;
    ContainerServiceImpl m_containerService;
    ImagesServiceImpl m_imagesService;
    VolumeServiceImpl m_volumeService;
    RuntimeRuntimeServiceImpl m_runtimeRuntimeService;
    RuntimeImageServiceImpl m_runtimeImageService;
#ifdef ENABLE_NATIVE_NETWORK
    network::NetworkServiceImpl m_networkService;
#endif
    ServerBuilder m_builder;
    std::vector<std::string> m_tcpPath;
    std::vector<std::string> m_socketPath;
    std::unique_ptr<Server> m_server;
};

GRPCServerImpl *g_grpcserver { nullptr };

int grpc_server_init(const struct service_arguments *args)
{
    if (args == nullptr) {
        return -1;
    }

    if (g_grpcserver != nullptr) {
        return 0;
    }

    /* note: get config from args, now use defaults */
    Network::NetworkPluginConf conf;
    if (args != nullptr && args->json_confs != nullptr) {
        if (args->json_confs->network_plugin != nullptr) {
            conf.SetPluginName(args->json_confs->network_plugin);
        }
        if (args->json_confs->cni_bin_dir != nullptr) {
            conf.SetPluginBinDir(args->json_confs->cni_bin_dir);
        }
        if (args->json_confs->cni_conf_dir != nullptr) {
            conf.SetPluginConfDir(args->json_confs->cni_conf_dir);
        }
    }
    g_grpcserver = new (std::nothrow) GRPCServerImpl(conf);
    if (g_grpcserver == nullptr) {
        return -1;
    }
    if (g_grpcserver->Init(args) != 0) {
        return -1;
    }

    return 0;
}

void grpc_server_wait(void)
{
    g_grpcserver->Wait();
}

void grpc_server_shutdown(void)
{
    g_grpcserver->Shutdown();
}
