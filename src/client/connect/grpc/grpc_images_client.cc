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
 * Description: provide grpc container service functions
 ******************************************************************************/
#include "grpc_images_client.h"
#include "api.grpc.pb.h"
#include "client_base.h"
#include "images.grpc.pb.h"
#include "utils.h"
#include <string>

using namespace images;

using grpc::ClientContext;
using grpc::Status;

class ImagesList : public ClientBase<ImagesService, ImagesService::Stub, isula_list_images_request, ListImagesRequest,
    isula_list_images_response, ListImagesResponse> {
public:
    explicit ImagesList(void *args)
        : ClientBase(args)
    {
    }
    ~ImagesList() = default;

    auto request_to_grpc(const isula_list_images_request *request, ListImagesRequest *grequest) -> int override
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
        return 0;
    }

    auto response_from_grpc(ListImagesResponse *gresponse, isula_list_images_response *response) -> int override
    {
        struct isula_image_info *images_list = nullptr;
        int i = 0;
        int num = gresponse->images_size();

        if (num <= 0) {
            response->images_list = nullptr;
            response->images_num = 0;
            response->server_errono = gresponse->cc();
            if (!gresponse->errmsg().empty()) {
                response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
            }
            return 0;
        }

        response->images_num = 0;

        if ((size_t)num > SIZE_MAX / sizeof(struct isula_image_info)) {
            ERROR("Too many images");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }
        images_list = (struct isula_image_info *)util_common_calloc_s(sizeof(struct isula_image_info) * (size_t)num);
        if (images_list == nullptr) {
            ERROR("out of memory");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }

        for (i = 0; i < num; i++) {
            const Image &image = gresponse->images(i);
            if (image.has_target()) {
                const char *media_type = !image.target().media_type().empty() ? image.target().media_type().c_str() :
                                         "-";
                images_list[i].type = util_strdup_s(media_type);
                const char *digest = !image.target().digest().empty() ? image.target().digest().c_str() : "-";
                images_list[i].digest = util_strdup_s(digest);
                images_list[i].size = image.target().size();
            }
            if (image.has_created_at()) {
                images_list[i].created = image.created_at().seconds();
                images_list[i].created_nanos = image.created_at().nanos();
            }
            const char *name = !image.name().empty() ? image.name().c_str() : "-";
            images_list[i].imageref = util_strdup_s(name);
        }

        response->images_list = images_list;
        response->images_num = (size_t)num;
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const ListImagesRequest &req, ListImagesResponse *reply) -> Status override
    {
        return stub_->List(context, req, reply);
    }
};

class ImagesDelete : public ClientBase<ImagesService, ImagesService::Stub, isula_rmi_request, DeleteImageRequest,
    isula_rmi_response, DeleteImageResponse> {
public:
    explicit ImagesDelete(void *args)
        : ClientBase(args)
    {
    }
    ~ImagesDelete() = default;

    auto request_to_grpc(const isula_rmi_request *request, DeleteImageRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->image_name != nullptr) {
            grequest->set_name(request->image_name);
        }
        grequest->set_force(request->force);

        return 0;
    }

    auto response_from_grpc(DeleteImageResponse *gresponse, isula_rmi_response *response) -> int override
    {
        response->server_errono = (uint32_t)gresponse->cc();

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const DeleteImageRequest &req) -> int override
    {
        if (req.name().empty()) {
            ERROR("Missing image name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const DeleteImageRequest &req, DeleteImageResponse *reply) -> Status override
    {
        return stub_->Delete(context, req, reply);
    }
};

class ImageTag : public ClientBase<ImagesService, ImagesService::Stub, isula_tag_request, TagImageRequest,
    isula_tag_response, TagImageResponse> {
public:
    explicit ImageTag(void *args)
        : ClientBase(args)
    {
    }
    ~ImageTag() = default;

    auto request_to_grpc(const isula_tag_request *request, TagImageRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->src_name != nullptr) {
            grequest->set_src_name(request->src_name);
        }
        if (request->dest_name != nullptr) {
            grequest->set_dest_name(request->dest_name);
        }

        return 0;
    }

    auto response_from_grpc(TagImageResponse *gresponse, isula_tag_response *response) -> int override
    {
        response->server_errono = (uint32_t)gresponse->cc();

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const TagImageRequest &req) -> int override
    {
        if (req.src_name().empty()) {
            ERROR("Missing source image name in the request");
            return -1;
        }
        if (req.dest_name().empty()) {
            ERROR("Missing destition image name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const TagImageRequest &req, TagImageResponse *reply) -> Status override
    {
        return stub_->Tag(context, req, reply);
    }
};

class ImagesLoad : public ClientBase<ImagesService, ImagesService::Stub, isula_load_request, LoadImageRequest,
    isula_load_response, LoadImageResponse> {
public:
    explicit ImagesLoad(void *args)
        : ClientBase(args)
    {
    }
    ~ImagesLoad() = default;

    auto request_to_grpc(const isula_load_request *request, LoadImageRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->file != nullptr) {
            grequest->set_file(request->file);
        }
        if (request->type != nullptr) {
            grequest->set_type(request->type);
        }
        if (request->tag != nullptr) {
            grequest->set_tag(request->tag);
        }

        return 0;
    }

    auto response_from_grpc(LoadImageResponse *gresponse, isula_load_response *response) -> int override
    {
        response->server_errono = (uint32_t)gresponse->cc();

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const LoadImageRequest &req) -> int override
    {
        if (req.file().empty()) {
            ERROR("Missing manifest file name in the request");
            return -1;
        }
        if (req.type().empty()) {
            ERROR("Missing image type in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const LoadImageRequest &req, LoadImageResponse *reply) -> Status override
    {
        return stub_->Load(context, req, reply);
    }
};

class Import : public ClientBase<ImagesService, ImagesService::Stub, isula_import_request, ImportRequest,
    isula_import_response, ImportResponse> {
public:
    explicit Import(void *args)
        : ClientBase(args)
    {
    }
    ~Import() = default;

    auto request_to_grpc(const isula_import_request *request, ImportRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->file != nullptr) {
            grequest->set_file(request->file);
        }
        if (request->tag != nullptr) {
            grequest->set_tag(request->tag);
        }

        return 0;
    }

    auto response_from_grpc(ImportResponse *gresponse, isula_import_response *response) -> int override
    {
        response->server_errono = (uint32_t)gresponse->cc();

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }
        if (!gresponse->id().empty()) {
            response->id = util_strdup_s(gresponse->id().c_str());
        }

        return 0;
    }

    auto check_parameter(const ImportRequest &req) -> int override
    {
        if (req.file().empty()) {
            ERROR("Missing tallball file name in the request");
            return -1;
        }
        if (req.tag().empty()) {
            ERROR("Missing image name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const ImportRequest &req, ImportResponse *reply) -> Status override
    {
        return stub_->Import(context, req, reply);
    }
};

class ImagesPull : public ClientBase<runtime::v1alpha2::ImageService, runtime::v1alpha2::ImageService::Stub,
    isula_pull_request, runtime::v1alpha2::PullImageRequest, isula_pull_response,
    runtime::v1alpha2::PullImageResponse> {
public:
    explicit ImagesPull(void *args)
        : ClientBase(args)
    {
    }
    ~ImagesPull() = default;

    auto request_to_grpc(const isula_pull_request *request, runtime::v1alpha2::PullImageRequest *grequest)
    -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->image_name != nullptr) {
            auto *image_spec = new (std::nothrow) runtime::v1alpha2::ImageSpec;
            if (image_spec == nullptr) {
                return -1;
            }
            image_spec->set_image(request->image_name);
            grequest->set_allocated_image(image_spec);
        }

        return 0;
    }

    auto response_from_grpc(runtime::v1alpha2::PullImageResponse *gresponse, isula_pull_response *response)
    -> int override
    {
        if (!gresponse->image_ref().empty()) {
            response->image_ref = util_strdup_s(gresponse->image_ref().c_str());
        }

        return 0;
    }

    auto check_parameter(const runtime::v1alpha2::PullImageRequest &req) -> int override
    {
        if (req.image().image().empty()) {
            ERROR("Missing image name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const runtime::v1alpha2::PullImageRequest &req,
                   runtime::v1alpha2::PullImageResponse *reply) -> Status override
    {
        return stub_->PullImage(context, req, reply);
    }
};

class ImageInspect : public ClientBase<ImagesService, ImagesService::Stub, isula_inspect_request, InspectImageRequest,
    isula_inspect_response, InspectImageResponse> {
public:
    explicit ImageInspect(void *args)
        : ClientBase(args)
    {
    }
    ~ImageInspect() = default;

    auto request_to_grpc(const isula_inspect_request *request, InspectImageRequest *grequest) -> int override
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

    auto response_from_grpc(InspectImageResponse *gresponse, isula_inspect_response *response) -> int override
    {
        response->server_errono = gresponse->cc();
        if (!gresponse->imagejson().empty()) {
            response->json = util_strdup_s(gresponse->imagejson().c_str());
        }
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const InspectImageRequest &req) -> int override
    {
        if (req.id().empty()) {
            ERROR("Missing image name in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const InspectImageRequest &req, InspectImageResponse *reply)
    -> Status override
    {
        return stub_->Inspect(context, req, reply);
    }
};

class Login : public ClientBase<ImagesService, ImagesService::Stub, isula_login_request, LoginRequest,
    isula_login_response, LoginResponse> {
public:
    explicit Login(void *args)
        : ClientBase(args)
    {
    }
    ~Login() = default;

    auto request_to_grpc(const isula_login_request *request, LoginRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->server != nullptr) {
            grequest->set_server(request->server);
        }
        if (request->username != nullptr) {
            grequest->set_username(request->username);
        }
        if (request->password != nullptr) {
            grequest->set_password(request->password);
        }
        if (request->type != nullptr) {
            grequest->set_type(request->type);
        }

        return 0;
    }

    auto response_from_grpc(LoginResponse *gresponse, isula_login_response *response) -> int override
    {
        response->server_errono = (uint32_t)gresponse->cc();

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const LoginRequest &req) -> int override
    {
        if (req.username().empty()) {
            ERROR("Missing username in the request");
            return -1;
        }
        if (req.password().empty()) {
            ERROR("Missing password in the request");
            return -1;
        }
        if (req.server().empty()) {
            ERROR("Missing server in the request");
            return -1;
        }
        if (req.type().empty()) {
            ERROR("Missing type in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const LoginRequest &req, LoginResponse *reply) -> Status override
    {
        return stub_->Login(context, req, reply);
    }
};

class Logout : public ClientBase<ImagesService, ImagesService::Stub, isula_logout_request, LogoutRequest,
    isula_logout_response, LogoutResponse> {
public:
    explicit Logout(void *args)
        : ClientBase(args)
    {
    }
    ~Logout() = default;

    auto request_to_grpc(const isula_logout_request *request, LogoutRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->server != nullptr) {
            grequest->set_server(request->server);
        }
        if (request->type != nullptr) {
            grequest->set_type(request->type);
        }

        return 0;
    }

    auto response_from_grpc(LogoutResponse *gresponse, isula_logout_response *response) -> int override
    {
        response->server_errono = (uint32_t)gresponse->cc();

        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const LogoutRequest &req) -> int override
    {
        if (req.server().empty()) {
            ERROR("Missing server in the request");
            return -1;
        }
        if (req.type().empty()) {
            ERROR("Missing type in the request");
            return -1;
        }

        return 0;
    }

    auto grpc_call(ClientContext *context, const LogoutRequest &req, LogoutResponse *reply) -> Status override
    {
        return stub_->Logout(context, req, reply);
    }
};

auto grpc_images_client_ops_init(isula_connect_ops *ops) -> int
{
    if (ops == nullptr) {
        return -1;
    }

    ops->image.list = container_func<isula_list_images_request, isula_list_images_response, ImagesList>;
    ops->image.remove = container_func<isula_rmi_request, isula_rmi_response, ImagesDelete>;
    ops->image.load = container_func<isula_load_request, isula_load_response, ImagesLoad>;
    ops->image.pull = container_func<isula_pull_request, isula_pull_response, ImagesPull>;
    ops->image.inspect = container_func<isula_inspect_request, isula_inspect_response, ImageInspect>;
    ops->image.login = container_func<isula_login_request, isula_login_response, Login>;
    ops->image.logout = container_func<isula_logout_request, isula_logout_response, Logout>;
    ops->image.tag = container_func<isula_tag_request, isula_tag_response, ImageTag>;
    ops->image.import = container_func<isula_import_request, isula_import_response, Import>;

    return 0;
}
