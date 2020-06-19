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

#include "runtime_image_service.h"
#include <memory>
#include <string>
#include <vector>
#include "cri_helpers.h"

#include "isula_libutils/log.h"

grpc::Status RuntimeImageServiceImpl::PullImage(grpc::ServerContext *context,
                                                const runtime::v1alpha2::PullImageRequest *request,
                                                runtime::v1alpha2::PullImageResponse *reply)
{
    Errors error;
    std::string imageRef = rService.PullImage(request->image(), request->auth(), error);
    if (!error.Empty() || imageRef.empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    reply->set_image_ref(imageRef);
    return grpc::Status::OK;
}

grpc::Status RuntimeImageServiceImpl::ListImages(grpc::ServerContext *context,
                                                 const runtime::v1alpha2::ListImagesRequest *request,
                                                 runtime::v1alpha2::ListImagesResponse *reply)
{
    std::vector<std::unique_ptr<runtime::v1alpha2::Image>> images;
    Errors error;

    rService.ListImages(request->filter(), &images, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = images.begin(); iter != images.end(); iter++) {
        runtime::v1alpha2::Image *image = reply->add_images();
        if (image == nullptr) {
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *image = *(iter->get());
    }
    return grpc::Status::OK;
}

grpc::Status RuntimeImageServiceImpl::ImageStatus(grpc::ServerContext *context,
                                                  const runtime::v1alpha2::ImageStatusRequest *request,
                                                  runtime::v1alpha2::ImageStatusResponse *reply)
{
    std::unique_ptr<runtime::v1alpha2::Image> image_info = nullptr;
    Errors error;

    image_info = rService.ImageStatus(request->image(), error);
    if (!error.Empty() && !CRIHelpers::IsImageNotFoundError(error.GetMessage())) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    if (image_info != nullptr) {
        runtime::v1alpha2::Image *image = reply->mutable_image();
        *image = *image_info;
    }

    return grpc::Status::OK;
}

grpc::Status RuntimeImageServiceImpl::ImageFsInfo(grpc::ServerContext *context,
                                                  const runtime::v1alpha2::ImageFsInfoRequest *request,
                                                  runtime::v1alpha2::ImageFsInfoResponse *reply)
{
    std::vector<std::unique_ptr<runtime::v1alpha2::FilesystemUsage>> usages;
    Errors error;

    rService.ImageFsInfo(&usages, error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }

    for (auto iter = usages.begin(); iter != usages.end(); ++iter) {
        runtime::v1alpha2::FilesystemUsage *fs_info = reply->add_image_filesystems();
        if (fs_info == nullptr) {
            return grpc::Status(grpc::StatusCode::UNKNOWN, "Out of memory");
        }
        *fs_info = *(iter->get());
    }
    return grpc::Status::OK;
}

grpc::Status RuntimeImageServiceImpl::RemoveImage(grpc::ServerContext *context,
                                                  const runtime::v1alpha2::RemoveImageRequest *request,
                                                  runtime::v1alpha2::RemoveImageResponse *reply)
{
    Errors error;

    rService.RemoveImage(request->image(), error);
    if (!error.Empty()) {
        return grpc::Status(grpc::StatusCode::UNKNOWN, error.GetMessage());
    }
    return grpc::Status::OK;
}


