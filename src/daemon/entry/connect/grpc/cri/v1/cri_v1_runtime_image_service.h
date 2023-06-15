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
 * Description: provide runtime image functions
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CONNECT_GRPC_CRI_V1_RUNTIME_IMAGE_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_CRI_V1_RUNTIME_IMAGE_SERVICE_H

#include "api_v1.grpc.pb.h"
#include <memory>
#include "callback.h"
#include "v1_cri_image_manager_service.h"

using namespace CRIV1;

// Implement of runtime RuntimeService
class RuntimeV1ImageServiceImpl : public
    runtime::v1::ImageService::Service {
public:
    RuntimeV1ImageServiceImpl();
    RuntimeV1ImageServiceImpl(const RuntimeV1ImageServiceImpl &) = delete;
    RuntimeV1ImageServiceImpl &operator=(const RuntimeV1ImageServiceImpl &) = delete;
    virtual ~RuntimeV1ImageServiceImpl() = default;

    grpc::Status PullImage(grpc::ServerContext *context,
                           const runtime::v1::PullImageRequest *request,
                           runtime::v1::PullImageResponse *reply) override;
    grpc::Status ListImages(grpc::ServerContext *context,
                            const runtime::v1::ListImagesRequest *request,
                            runtime::v1::ListImagesResponse *reply) override;
    grpc::Status ImageStatus(grpc::ServerContext *context,
                             const runtime::v1::ImageStatusRequest *request,
                             runtime::v1::ImageStatusResponse *reply) override;

    grpc::Status ImageFsInfo(grpc::ServerContext *context,
                             const runtime::v1::ImageFsInfoRequest *request,
                             runtime::v1::ImageFsInfoResponse *reply) override;
    grpc::Status RemoveImage(grpc::ServerContext *context,
                             const runtime::v1::RemoveImageRequest *request,
                             runtime::v1::RemoveImageResponse *reply) override;

private:
    std::unique_ptr<CRIV1::ImageManagerService> rService;
};
#endif // DAEMON_ENTRY_CONNECT_GRPC_CRI_V1_RUNTIME_IMAGE_SERVICE_H


