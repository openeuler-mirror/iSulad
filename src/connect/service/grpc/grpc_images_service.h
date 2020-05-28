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
 * Description: provide grpc images functions
 ******************************************************************************/

#ifndef _GRPC_IMAGES_SERVICE_H_
#define _GRPC_IMAGES_SERVICE_H_

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

using namespace images;
using namespace containerd::types;

// Implement of images service
class ImagesServiceImpl final : public ImagesService::Service {
public:
    ImagesServiceImpl() = default;
    ImagesServiceImpl(const ImagesServiceImpl &) = delete;
    ImagesServiceImpl &operator=(const ImagesServiceImpl &) = delete;
    virtual ~ImagesServiceImpl() = default;

    Status List(ServerContext *context, const ListImagesRequest *request, ListImagesResponse *reply) override;

    Status Delete(ServerContext *context, const DeleteImageRequest *request, DeleteImageResponse *reply) override;

    Status Tag(ServerContext *context, const TagImageRequest *request, TagImageResponse *reply) override;

    Status Import(ServerContext *context, const ImportRequest *request, ImportResponse *reply) override;

    Status Load(ServerContext *context, const LoadImageRequest *request, LoadImageResponse *reply) override;

    Status Inspect(ServerContext *context, const InspectImageRequest *request, InspectImageResponse *reply) override;

    Status Login(ServerContext *context, const LoginRequest *request,
                 LoginResponse *reply) override;

    Status Logout(ServerContext *context, const LogoutRequest *request,
                  LogoutResponse *reply) override;

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
    int image_list_request_from_grpc(const ListImagesRequest *grequest, image_list_images_request **request);

    int image_list_response_to_grpc(image_list_images_response *response, ListImagesResponse *gresponse);

    int image_remove_request_from_grpc(const DeleteImageRequest *grequest, image_delete_image_request **request);

    int image_tag_request_from_grpc(const TagImageRequest *grequest, image_tag_image_request **request);

    int image_import_request_from_grpc(const ImportRequest *grequest, image_import_request **request);

    int import_response_to_grpc(const image_import_response *response, ImportResponse *gresponse);

    int image_load_request_from_grpc(const LoadImageRequest *grequest, image_load_image_request **request);

    int inspect_request_from_grpc(const InspectImageRequest *grequest, image_inspect_request **request);

    int inspect_response_to_grpc(const image_inspect_response *response, InspectImageResponse *gresponse);

    int image_login_request_from_grpc(const LoginRequest *grequest, image_login_request **request);

    int image_logout_request_from_grpc(const LogoutRequest *grequest, image_logout_request **request);
};

#endif /* _GRPC_IMAGES_SERVICE_H_ */

