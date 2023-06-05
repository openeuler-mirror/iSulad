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

#ifndef DAEMON_ENTRY_CONNECT_GRPC_RUNTIME_IMAGE_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_RUNTIME_IMAGE_SERVICE_H

#include "api.grpc.pb.h"
#include <memory>
#include "callback.h"
#include "cri_image_manager_service.h"

using namespace CRI;

// Implement of runtime RuntimeService
class RuntimeImageServiceImpl : public
    runtime::v1alpha2::ImageService::Service {
public:
    RuntimeImageServiceImpl();
    RuntimeImageServiceImpl(const RuntimeImageServiceImpl &) = delete;
    RuntimeImageServiceImpl &operator=(const RuntimeImageServiceImpl &) = delete;
    virtual ~RuntimeImageServiceImpl() = default;

    grpc::Status PullImage(grpc::ServerContext *context,
                           const runtime::v1alpha2::PullImageRequest *request,
                           runtime::v1alpha2::PullImageResponse *reply) override;
    grpc::Status ListImages(grpc::ServerContext *context,
                            const runtime::v1alpha2::ListImagesRequest *request,
                            runtime::v1alpha2::ListImagesResponse *reply) override;
    grpc::Status ImageStatus(grpc::ServerContext *context,
                             const runtime::v1alpha2::ImageStatusRequest *request,
                             runtime::v1alpha2::ImageStatusResponse *reply) override;

    grpc::Status ImageFsInfo(grpc::ServerContext *context,
                             const runtime::v1alpha2::ImageFsInfoRequest *request,
                             runtime::v1alpha2::ImageFsInfoResponse *reply) override;
    grpc::Status RemoveImage(grpc::ServerContext *context,
                             const runtime::v1alpha2::RemoveImageRequest *request,
                             runtime::v1alpha2::RemoveImageResponse *reply) override;

private:
    std::unique_ptr<ImageManagerService> rService;
};
#endif // DAEMON_ENTRY_CONNECT_GRPC_RUNTIME_IMAGE_SERVICE_H


