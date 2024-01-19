/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2023-06-09
 * Description: provide cri unify services
 ******************************************************************************/
#ifndef DAEMON_ENTRY_CONNECT_GRPC_CRI_CRI_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_CRI_CRI_SERVICE_H
#include <grpcpp/server_builder.h>

#include <isula_libutils/isulad_daemon_configs.h>

#include "cri_runtime_runtime_service.h"
#include "cri_runtime_image_service.h"
#ifdef ENABLE_CRI_API_V1
#include "cri_v1_runtime_runtime_service.h"
#include "cri_v1_runtime_image_service.h"
#endif

namespace CRIUnify {

class CRIService {
public:
    CRIService() = default;
    CRIService(const CRIService &) = delete;
    CRIService &operator=(const CRIService &) = delete;
    virtual ~CRIService() = default;

    int Init(const isulad_daemon_configs *config);
    void Register(grpc::ServerBuilder &sb);
    void Wait(void);
    void Shutdown(void);

private:
    void doNetworkInit(Network::NetworkPluginConf &mConf, Errors &err);
private:
    // CRI v1alpha service
    // RuntimeRuntimeServiceImpl m_runtimeRuntimeService;
    // RuntimeImageServiceImpl m_runtimeImageService;

#ifdef ENABLE_CRI_API_V1
    // CRI v1 service
    RuntimeV1RuntimeServiceImpl m_runtimeV1RuntimeService;
    RuntimeV1ImageServiceImpl m_runtimeV1ImageService;


#endif

    // all required depends in CRI services
    std::string m_podSandboxImage;
    std::shared_ptr<Network::PluginManager> m_pluginManager;
    bool m_enableCRIV1;
};

}

#endif