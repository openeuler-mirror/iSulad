/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide runtime image functions
 ******************************************************************************/

#ifndef _RUNTIME_IMAGE_SERVICES_IMPL_H_
#define _RUNTIME_IMAGE_SERVICES_IMPL_H_

#include "api.grpc.pb.h"
#include "callback.h"
#include "cri_image_service.h"

// Implement of runtime RuntimeService
class RuntimeImageServiceImpl: public
    runtime::ImageService::Service {
public:
    grpc::Status PullImage(grpc::ServerContext *context,
                           const runtime::PullImageRequest *request,
                           runtime::PullImageResponse *reply) override;
    grpc::Status ListImages(grpc::ServerContext *context,
                            const runtime::ListImagesRequest *request,
                            runtime::ListImagesResponse *reply) override;
    grpc::Status ImageStatus(grpc::ServerContext *context,
                             const runtime::ImageStatusRequest *request,
                             runtime::ImageStatusResponse *reply) override;

    grpc::Status ImageFsInfo(grpc::ServerContext *context,
                             const runtime::ImageFsInfoRequest *request,
                             runtime::ImageFsInfoResponse *reply) override;
    grpc::Status RemoveImage(grpc::ServerContext *context,
                             const runtime::RemoveImageRequest *request,
                             runtime::RemoveImageResponse *reply) override;

private:
    CRIImageServiceImpl rService;
};
#endif /* _RUNTIME_IMAGE_SERVICES_IMPL_H_ */

