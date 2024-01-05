/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
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
 * Description: provide grpc images functions
 ******************************************************************************/

#ifndef DAEMON_ENTRY_CONNECT_GRPC_GRPC_IMAGES_SERVICE_H
#define DAEMON_ENTRY_CONNECT_GRPC_GRPC_IMAGES_SERVICE_H

#include <grpc++/grpc++.h>

#include "images.grpc.pb.h"
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

// Implement of images service
class ImagesServiceImpl final : public images::ImagesService::Service {
public:
    ImagesServiceImpl() = default;
    ImagesServiceImpl(const ImagesServiceImpl &) = delete;
    ImagesServiceImpl &operator=(const ImagesServiceImpl &) = delete;
    virtual ~ImagesServiceImpl() = default;

    Status List(ServerContext *context, const images::ListImagesRequest *request, images::ListImagesResponse *reply) override;

    Status Delete(ServerContext *context, const images::DeleteImageRequest *request, images::DeleteImageResponse *reply) override;

    Status Tag(ServerContext *context, const images::TagImageRequest *request, images::TagImageResponse *reply) override;

    Status Import(ServerContext *context, const images::ImportRequest *request, images::ImportResponse *reply) override;

    Status Load(ServerContext *context, const images::LoadImageRequest *request, images::LoadImageResponse *reply) override;

    Status Inspect(ServerContext *context, const images::InspectImageRequest *request, images::InspectImageResponse *reply) override;

    Status Login(ServerContext *context, const images::LoginRequest *request, images::LoginResponse *reply) override;

    Status Logout(ServerContext *context, const images::LogoutRequest *request, images::LogoutResponse *reply) override;

    Status PullImage(ServerContext *context, const images::PullImageRequest *request,
                     ServerWriter<images::PullImageResponse> *writer) override;

#ifdef ENABLE_IMAGE_SEARCH
    Status Search(ServerContext *context, const images::SearchRequest *request, images::SearchResponse *reply) override;
#endif

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
    int image_list_request_from_grpc(const images::ListImagesRequest *grequest, image_list_images_request **request);

    void image_list_response_to_grpc(image_list_images_response *response, images::ListImagesResponse *gresponse);

    int image_remove_request_from_grpc(const images::DeleteImageRequest *grequest, image_delete_image_request **request);

    int image_tag_request_from_grpc(const images::TagImageRequest *grequest, image_tag_image_request **request);

    int image_import_request_from_grpc(const images::ImportRequest *grequest, image_import_request **request);

    void import_response_to_grpc(const image_import_response *response, images::ImportResponse *gresponse);

    int image_load_request_from_grpc(const images::LoadImageRequest *grequest, image_load_image_request **request);

    int inspect_request_from_grpc(const images::InspectImageRequest *grequest, image_inspect_request **request);

    void inspect_response_to_grpc(const image_inspect_response *response, images::InspectImageResponse *gresponse);

    int image_login_request_from_grpc(const images::LoginRequest *grequest, image_login_request **request);

    int image_logout_request_from_grpc(const images::LogoutRequest *grequest, image_logout_request **request);

    int image_pull_request_from_grpc(const images::PullImageRequest *grequest, image_pull_image_request **request);

    void image_pull_response_to_grpc(const image_pull_image_response *response, images::PullImageResponse *gresponse);

#ifdef ENABLE_IMAGE_SEARCH
    int search_request_from_grpc(const images::SearchRequest *grequest, image_search_images_request **request);

    void search_response_to_grpc(const image_search_images_response *response, images::SearchResponse *gresponse);
#endif
};

#endif // DAEMON_ENTRY_CONNECT_GRPC_GRPC_IMAGES_SERVICE_H
