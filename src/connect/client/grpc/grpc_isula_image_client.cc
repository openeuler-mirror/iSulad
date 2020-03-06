/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-12
* Description: provide isula connect command definition
*******************************************************************************/
#include "grpc_isula_image_client.h"
#include <iostream>
#include <memory>
#include "isula_image.grpc.pb.h"
#include "isula_image.pb.h"
#include "utils.h"
#include "client_base.h"
#include "libisulad.h"

namespace {
int copy_image_tags_metadata(const isula::Image &gimage, struct image_metadata *metadata)
{
    int len;

    len = gimage.repo_tags_size();
    if (len > 0) {
        metadata->repo_tags = (char **)util_smart_calloc_s(sizeof(char *), static_cast<size_t>(len));
        if (metadata->repo_tags == nullptr) {
            ERROR("Out of memory");
            return -1;
        }
        for (int i = 0; i < len; i++) {
            metadata->repo_tags[i] = util_strdup_s(gimage.repo_tags(i).c_str());
            metadata->repo_tags_len++;
        }
    }

    return 0;
}

int copy_image_digests_metadata(const isula::Image &gimage, struct image_metadata *metadata)
{
    int len;

    len = gimage.repo_digests_size();
    if (len > 0) {
        metadata->repo_digests = (char **)util_smart_calloc_s(sizeof(char *), static_cast<size_t>(len));
        if (metadata->repo_digests == nullptr) {
            ERROR("Out of memory");
            return -1;
        }
        for (int i = 0; i < len; i++) {
            metadata->repo_digests[i] = util_strdup_s(gimage.repo_digests(i).c_str());
            metadata->repo_digests_len++;
        }
        metadata->size = static_cast<uint64_t>(gimage.size());
        metadata->uid = static_cast<int64_t>(gimage.uid().value());
    }

    return 0;
}

int copy_image_metadata(const isula::Image &gimage, struct image_metadata **metadata)
{
    struct image_metadata *tmp_data = (struct image_metadata *)util_common_calloc_s(sizeof(struct image_metadata));

    if (tmp_data == nullptr) {
        ERROR("Out of memory");
        return -1;
    }
    if (!gimage.id().empty()) {
        tmp_data->id = util_strdup_s(gimage.id().c_str());
    }

    if (copy_image_tags_metadata(gimage, tmp_data) != 0) {
        goto err_out;
    }

    if (copy_image_digests_metadata(gimage, tmp_data) != 0) {
        goto err_out;
    }

    tmp_data->size = gimage.size();

    if (gimage.has_uid()) {
        tmp_data->uid = gimage.uid().value();
    }

    if (!gimage.username().empty()) {
        tmp_data->username = util_strdup_s(gimage.username().c_str());
    }

    if (!gimage.created().empty()) {
        tmp_data->created = util_strdup_s(gimage.created().c_str());
    }

    if (!gimage.loaded().empty()) {
        tmp_data->loaded = util_strdup_s(gimage.loaded().c_str());
    }

    if (gimage.has_spec() && !gimage.spec().image().empty()) {
        tmp_data->oci_spec = util_strdup_s(gimage.spec().image().c_str());
    }
    *metadata = tmp_data;
    return 0;
err_out:
    free_image_metadata(tmp_data);
    return -1;
}
} // namespace

class ISulaContainerPrepare : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_prepare_request,
    isula::ContainerPrepareRequest, isula_prepare_response, isula::ContainerPrepareResponse> {
public:
    explicit ISulaContainerPrepare(void *args) : ClientBase(args)
    {
    }
    ~ISulaContainerPrepare() = default;

    int request_to_grpc(const isula_prepare_request *req, isula::ContainerPrepareRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->image != nullptr) {
            grequest->set_image(req->image);
        }
        if (req->id != nullptr) {
            grequest->set_id(req->id);
        }
        if (req->name != nullptr) {
            grequest->set_name(req->name);
        }
        if (req->storage_opts != nullptr) {
            for (size_t i = 0; i < req->storage_opts_len; i++) {
                grequest->add_storage_opts(req->storage_opts[i]);
            }
        }
        return 0;
    }

    int response_from_grpc(isula::ContainerPrepareResponse *gresp, isula_prepare_response *resp) override
    {
        if (!gresp->mount_point().empty()) {
            resp->mount_point = util_strdup_s(gresp->mount_point().c_str());
        }
        if (!gresp->image_conf().empty()) {
            resp->image_conf = util_strdup_s(gresp->image_conf().c_str());
        }
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::ContainerPrepareRequest &req) override
    {
        if (req.image().empty()) {
            ERROR("Need set image to prepare container");
            return -1;
        }
        if (req.id().empty()) {
            ERROR("Need set id for container");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ContainerPrepareRequest &req,
                     isula::ContainerPrepareResponse *reply) override
    {
        return stub_->ContainerPrepare(context, req, reply);
    }
};

class ISulaContainerRemove : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_remove_request,
    isula::ContainerRemoveRequest, isula_remove_response, isula::ContainerRemoveResponse> {
public:
    explicit ISulaContainerRemove(void *args) : ClientBase(args)
    {
    }

    ~ISulaContainerRemove() = default;

    int request_to_grpc(const isula_remove_request *req, isula::ContainerRemoveRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->name_id != nullptr) {
            grequest->set_name_id(req->name_id);
        }
        return 0;
    }

    int response_from_grpc(isula::ContainerRemoveResponse *gresp, isula_remove_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::ContainerRemoveRequest &req) override
    {
        if (req.name_id().empty()) {
            ERROR("Empty container id");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ContainerRemoveRequest &req,
                     isula::ContainerRemoveResponse *reply) override
    {
        return stub_->ContainerRemove(context, req, reply);
    }
};

class ISulaContainerMount : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_mount_request,
    isula::ContainerMountRequest, isula_mount_response, isula::ContainerMountResponse> {
public:
    explicit ISulaContainerMount(void *args) : ClientBase(args)
    {
    }

    ~ISulaContainerMount() = default;

    int request_to_grpc(const isula_mount_request *req, isula::ContainerMountRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->name_id != nullptr) {
            grequest->set_name_id(req->name_id);
        }
        return 0;
    }

    int response_from_grpc(isula::ContainerMountResponse *gresp, isula_mount_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::ContainerMountRequest &req) override
    {
        if (req.name_id().empty()) {
            ERROR("Empty container id");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ContainerMountRequest &req,
                     isula::ContainerMountResponse *reply) override
    {
        return stub_->ContainerMount(context, req, reply);
    }
};

class ISulaContainerUmount : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_umount_request,
    isula::ContainerUmountRequest, isula_umount_response, isula::ContainerUmountResponse> {
public:
    explicit ISulaContainerUmount(void *args) : ClientBase(args)
    {
    }

    ~ISulaContainerUmount() = default;

    int request_to_grpc(const isula_umount_request *req, isula::ContainerUmountRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->name_id != nullptr) {
            grequest->set_name_id(req->name_id);
        }
        return 0;
    }

    int response_from_grpc(isula::ContainerUmountResponse *gresp, isula_umount_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::ContainerUmountRequest &req) override
    {
        if (req.name_id().empty()) {
            ERROR("Empty container id");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ContainerUmountRequest &req,
                     isula::ContainerUmountResponse *reply) override
    {
        return stub_->ContainerUmount(context, req, reply);
    }
};

class ISulaContainersList : public ClientBase<isula::ImageService, isula::ImageService::Stub,
    isula_containers_list_request, isula::ListContainersRequest, isula_containers_list_response,
    isula::ListContainersResponse> {
public:
    explicit ISulaContainersList(void *args) : ClientBase(args)
    {
    }

    ~ISulaContainersList() = default;

    int request_to_grpc(const isula_containers_list_request *req, isula::ListContainersRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        return 0;
    }

    int response_from_grpc(isula::ListContainersResponse *gresp, isula_containers_list_response *resp) override
    {
        int containers_len = gresp->containers_size();
        if (containers_len > 0) {
            resp->containers = (json_map_string_bool *)util_common_calloc_s(sizeof(json_map_string_bool));
            if (resp->containers == nullptr) {
                ERROR("Out of memory");
                return -1;
            }
            for (const auto &iter : gresp->containers()) {
                if (append_json_map_string_bool(resp->containers, iter.first.c_str(), iter.second) != 0) {
                    ERROR("Out of memory");
                    return -1;
                }
            }
        }
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ListContainersRequest &req,
                     isula::ListContainersResponse *reply) override
    {
        return stub_->ListContainers(context, req, reply);
    }
};

class ISulaImagePull : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_pull_request,
    isula::PullImageRequest, isula_pull_response, isula::PullImageResponse> {
public:
    explicit ISulaImagePull(void *args) : ClientBase(args)
    {
    }

    ~ISulaImagePull() = default;

    int request_to_grpc(const isula_pull_request *req, isula::PullImageRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }

        if (req->image != nullptr && req->image->image != nullptr) {
            isula::ImageSpec *image_spec = new (std::nothrow) isula::ImageSpec;
            if (image_spec == nullptr) {
                return -1;
            }
            image_spec->set_image(req->image->image);
            grequest->set_allocated_image(image_spec);
        }

        if (req->auth != nullptr) {
            isula::AuthConfig *auth = new (std::nothrow) isula::AuthConfig;
            if (auth == nullptr) {
                return -1;
            }
            if (req->auth->username != nullptr) {
                auth->set_username(req->auth->username);
            }
            if (req->auth->password != nullptr) {
                auth->set_password(req->auth->password);
            }
            if (req->auth->auth != nullptr) {
                auth->set_auth(req->auth->auth);
            }
            if (req->auth->server_address != nullptr) {
                auth->set_server_address(req->auth->server_address);
            }
            if (req->auth->identity_token != nullptr) {
                auth->set_identity_token(req->auth->identity_token);
            }
            if (req->auth->registry_token != nullptr) {
                auth->set_registry_token(req->auth->registry_token);
            }

            grequest->set_allocated_auth(auth);
        }
        return 0;
    }

    int response_from_grpc(isula::PullImageResponse *gresp, isula_pull_response *resp) override
    {
        if (!gresp->image_ref().empty()) {
            resp->image_ref = util_strdup_s(gresp->image_ref().c_str());
        }
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::PullImageRequest &req) override
    {
        if (req.image().image().empty()) {
            ERROR("Missing image name in the request.");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::PullImageRequest &req,
                     isula::PullImageResponse *reply) override
    {
        return stub_->PullImage(context, req, reply);
    }
};

class ISulaImageStatus : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_status_request,
    isula::ImageStatusRequest, isula_status_response, isula::ImageStatusResponse> {
public:
    explicit ISulaImageStatus(void *args) : ClientBase(args)
    {
    }
    ~ISulaImageStatus() = default;

    int request_to_grpc(const isula_status_request *req, isula::ImageStatusRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->image != nullptr && req->image->image != nullptr) {
            isula::ImageSpec *image_spec = new (std::nothrow) isula::ImageSpec;
            if (image_spec == nullptr) {
                return -1;
            }
            image_spec->set_image(req->image->image);
            grequest->set_allocated_image(image_spec);
        }
        grequest->set_verbose(req->verbose);
        return 0;
    }

    int response_from_grpc(isula::ImageStatusResponse *gresp, isula_status_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();

        if (gresp->has_image()) {
            if (copy_image_metadata(gresp->image(), &(resp->image)) != 0) {
                return -1;
            }
        }
        if (gresp->info_size() > 0) {
            resp->info = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
            if (resp->info == nullptr) {
                ERROR("Out of memory");
                return -1;
            }
            auto iter = gresp->info().cbegin();
            while (iter != gresp->info().cend()) {
                if (append_json_map_string_string(resp->info, iter->first.c_str(), iter->second.c_str()) != 0) {
                    ERROR("Out of memory");
                    return -1;
                }
                ++iter;
            }
        }

        return 0;
    }

    int check_parameter(const isula::ImageStatusRequest &req) override
    {
        if (!req.has_image()) {
            ERROR("Empty image name");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ImageStatusRequest &req,
                     isula::ImageStatusResponse *reply) override
    {
        return stub_->ImageStatus(context, req, reply);
    }
};

class ISulaListImages : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_list_request,
    isula::ListImagesRequest, isula_list_response, isula::ListImagesResponse> {
public:
    explicit ISulaListImages(void *args) : ClientBase(args)
    {
    }
    ~ISulaListImages() = default;

    int request_to_grpc(const isula_list_request *req, isula::ListImagesRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->filter != nullptr) {
            std::unique_ptr<isula::ImageFilter> filter(new (std::nothrow) isula::ImageFilter);
            if (filter == nullptr) {
                ERROR("Out of memory");
                return -1;
            }
            std::unique_ptr<isula::ImageSpec> image(new (std::nothrow) isula::ImageSpec);
            if (image == nullptr) {
                ERROR("Out of memory");
                return -1;
            }
            image->set_image(req->filter);
            filter->set_allocated_image(image.release());
            grequest->set_allocated_filter(filter.release());
        }
        grequest->set_check(req->check);
        return 0;
    }

    int response_from_grpc(isula::ListImagesResponse *gresp, isula_list_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();

        int len = gresp->images_size();
        if (len <= 0) {
            return 0;
        }

        resp->images = (struct image_metadata **)util_smart_calloc_s(
                           sizeof(struct image_metadata *), static_cast<size_t>(len));
        if (resp->images == nullptr) {
            ERROR("Out of memory");
            return -1;
        }
        for (int i {}; i < len; i++) {
            if (copy_image_metadata(gresp->images(i), &(resp->images[i])) != 0) {
                return -1;
            }
            resp->images_len++;
        }

        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ListImagesRequest &req,
                     isula::ListImagesResponse *reply) override
    {
        return stub_->ListImages(context, req, reply);
    }
};

class ISulaRmi : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_rmi_request,
    isula::RemoveImageRequest, isula_rmi_response, isula::RemoveImageResponse> {
public:
    explicit ISulaRmi(void *args) : ClientBase(args)
    {
    }
    ~ISulaRmi() = default;

    int request_to_grpc(const isula_rmi_request *req, isula::RemoveImageRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->image == nullptr || req->image->image == nullptr) {
            return 0;
        }
        isula::ImageSpec *image = new (std::nothrow) isula::ImageSpec;
        if (image == nullptr) {
            ERROR("Out of memory");
            return -1;
        }
        image->set_image(req->image->image);
        grequest->set_allocated_image(image);
        grequest->set_force(req->force);
        return 0;
    }

    int response_from_grpc(isula::RemoveImageResponse *gresp, isula_rmi_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::RemoveImageRequest &req) override
    {
        if (req.has_image() && !req.image().image().empty()) {
            return 0;
        }
        ERROR("Image name is required.");
        return -1;
    }

    Status grpc_call(ClientContext *context, const isula::RemoveImageRequest &req,
                     isula::RemoveImageResponse *reply) override
    {
        return stub_->RemoveImage(context, req, reply);
    }
};

class ISulaLoad : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_load_request,
    isula::LoadImageRequest, isula_load_response, isula::LoadImageResponose> {
public:
    explicit ISulaLoad(void *args) : ClientBase(args)
    {
    }
    ~ISulaLoad() = default;

    int request_to_grpc(const isula_load_request *req, isula::LoadImageRequest *grequest) override
    {
        if (req == nullptr) {
            return -1;
        }
        if (req->file != nullptr) {
            grequest->set_file(req->file);
        }
        if (req->tag != nullptr) {
            grequest->set_tag(req->tag);
        }
        return 0;
    }

    int response_from_grpc(isula::LoadImageResponose *gresp, isula_load_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        if (!gresp->outmsg().empty()) {
            resp->outmsg = util_strdup_s(gresp->outmsg().c_str());
        }
        return 0;
    }

    int check_parameter(const isula::LoadImageRequest &req) override
    {
        if (req.file().empty()) {
            ERROR("Load image requires input file path");
            isulad_set_error_message("Load image requires input file path");
            return -1;
        }
        if (!req.tag().empty()) {
            if (util_valid_image_name(req.tag().c_str()) != true) {
                ERROR("Invalid tag %s", req.tag().c_str());
                isulad_try_set_error_message("Invalid tag:%s", req.tag().c_str());
                return -1;
            }
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::LoadImageRequest &req,
                     isula::LoadImageResponose *reply) override
    {
        return stub_->LoadImage(context, req, reply);
    }
};

class ISulaLogin : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_login_request,
    isula::LoginRequest, isula_login_response, isula::LoginResponse> {
public:
    explicit ISulaLogin(void *args) : ClientBase(args)
    {
    }
    ~ISulaLogin() = default;

    int request_to_grpc(const isula_login_request *req, isula::LoginRequest *grequest) override
    {
        if (req == nullptr) {
            isulad_set_error_message("invalid login request");
            return -1;
        }
        if (req->server != nullptr) {
            grequest->set_server(req->server);
        }
        if (req->username != nullptr) {
            grequest->set_username(req->username);
        }
        if (req->password != nullptr) {
            grequest->set_password(req->password);
        }
        return 0;
    }

    int response_from_grpc(isula::LoginResponse *gresp, isula_login_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::LoginRequest &req) override
    {
        if (req.server().empty()) {
            isulad_set_error_message("Login requires server address");
            return -1;
        }
        if (req.username().empty() || req.password().empty()) {
            isulad_set_error_message("Missing username or password");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::LoginRequest &req,
                     isula::LoginResponse *reply) override
    {
        return stub_->Login(context, req, reply);
    }
};

class ISulaLogout : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_logout_request,
    isula::LogoutRequest, isula_logout_response, isula::LogoutResponse> {
public:
    explicit ISulaLogout(void *args) : ClientBase(args)
    {
    }
    ~ISulaLogout() = default;

    int request_to_grpc(const isula_logout_request *req, isula::LogoutRequest *grequest) override
    {
        if (req == nullptr) {
            isulad_set_error_message("invalid logout request");
            return -1;
        }
        if (req->server != nullptr) {
            grequest->set_server(req->server);
        }
        return 0;
    }

    int response_from_grpc(isula::LogoutResponse *gresp, isula_logout_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::LogoutRequest &req) override
    {
        if (req.server().empty()) {
            isulad_set_error_message("Logout requires server address");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::LogoutRequest &req,
                     isula::LogoutResponse *reply) override
    {
        return stub_->Logout(context, req, reply);
    }
};

class ISulaExport : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_export_request,
    isula::ContainerExportRequest, isula_export_response, isula::ContainerExportResponse> {
public:
    explicit ISulaExport(void *args) : ClientBase(args)
    {
    }
    ~ISulaExport() = default;

    int request_to_grpc(const isula_export_request *req, isula::ContainerExportRequest *grequest) override
    {
        if (req == nullptr) {
            isulad_set_error_message("unvalid export request");
            return -1;
        }
        if (req->name_id != nullptr) {
            grequest->set_name_id(req->name_id);
        }
        if (req->output != nullptr) {
            grequest->set_output(req->output);
        }
        grequest->set_uid(req->uid);
        grequest->set_gid(req->gid);
        grequest->set_offset(req->offset);
        return 0;
    }

    int response_from_grpc(isula::ContainerExportResponse *gresp, isula_export_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    int check_parameter(const isula::ContainerExportRequest &req) override
    {
        if (req.name_id().empty()) {
            isulad_set_error_message("Export rootfs requires container name");
            return -1;
        }
        if (req.output().empty()) {
            isulad_set_error_message("Export rootfs requires output file path");
            return -1;
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ContainerExportRequest &req,
                     isula::ContainerExportResponse *reply) override
    {
        return stub_->ContainerExport(context, req, reply);
    }
};

class ISulaStorageStatus : public
    ClientBase<isula::ImageService, isula::ImageService::Stub, isula_storage_status_request,
    isula::GraphdriverStatusRequest, isula_storage_status_response, isula::GraphdriverStatusResponse> {
public:
    explicit ISulaStorageStatus(void *args) : ClientBase(args)
    {
    }
    ~ISulaStorageStatus() = default;

    int response_from_grpc(isula::GraphdriverStatusResponse *gresp, isula_storage_status_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();

        if (!gresp->status().empty()) {
            resp->status = util_strdup_s(gresp->status().c_str());
        }
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::GraphdriverStatusRequest &req,
                     isula::GraphdriverStatusResponse *reply) override
    {
        return stub_->GraphdriverStatus(context, req, reply);
    }
};

class ISulaContainerFsUsage : public
    ClientBase<isula::ImageService, isula::ImageService::Stub, isula_container_fs_usage_request,
    isula::ContainerFsUsageRequest, isula_container_fs_usage_response, isula::ContainerFsUsageResponse> {
public:
    explicit ISulaContainerFsUsage(void *args) : ClientBase(args)
    {
    }
    ~ISulaContainerFsUsage() = default;

    int request_to_grpc(const isula_container_fs_usage_request *req, isula::ContainerFsUsageRequest *grequest) override
    {
        if (req == nullptr) {
            isulad_set_error_message("invalid containerfsusage request");
            return -1;
        }
        if (req->name_id != nullptr) {
            grequest->set_name_id(req->name_id);
        }
        return 0;
    }

    int response_from_grpc(isula::ContainerFsUsageResponse *gresp, isula_container_fs_usage_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();

        if (!gresp->usage().empty()) {
            resp->usage = util_strdup_s(gresp->usage().c_str());
        }
        return 0;
    }

    int check_parameter(const isula::ContainerFsUsageRequest &req) override
    {
        if (req.name_id().empty()) {
            isulad_set_error_message("Required container id");
            return -1;
        }

        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ContainerFsUsageRequest &req,
                     isula::ContainerFsUsageResponse *reply) override
    {
        return stub_->ContainerFsUsage(context, req, reply);
    }
};

class ISulaImageFsInfo : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_image_fs_info_request,
    isula::ImageFsInfoRequest, isula_image_fs_info_response, isula::ImageFsInfoResponse> {
public:
    explicit ISulaImageFsInfo(void *args) : ClientBase(args)
    {
    }
    ~ISulaImageFsInfo() = default;

    int response_from_grpc(isula::ImageFsInfoResponse *gresp, isula_image_fs_info_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        resp->image_filesystems_len = 0;

        if (gresp->image_filesystems_size() <= 0) {
            return 0;
        }

        size_t len = static_cast<size_t>(gresp->image_filesystems_size());
        resp->image_filesystems = (struct filesystem_usage **)util_smart_calloc_s(
                                      sizeof(struct filesystem_usage *), len);
        if (resp->image_filesystems == nullptr) {
            ERROR("Out of memory");
            return -1;
        }
        for (int i = 0; i < gresp->image_filesystems_size(); i++) {
            struct filesystem_usage *tmp = nullptr;
            if (parse_filesystem_usage(gresp->image_filesystems(i), &tmp) != 0) {
                return -1;
            }
            resp->image_filesystems[i] = tmp;
            (resp->image_filesystems_len)++;
        }

        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::ImageFsInfoRequest &req,
                     isula::ImageFsInfoResponse *reply) override
    {
        return stub_->ImageFsInfo(context, req, reply);
    }

private:
    int parse_filesystem_usage(const isula::FilesystemUsage &gusage, struct filesystem_usage **cusage)
    {
        struct filesystem_usage *tmp_cusage = nullptr;

        tmp_cusage = (struct filesystem_usage *)util_common_calloc_s(sizeof(struct filesystem_usage));
        if (tmp_cusage == nullptr) {
            ERROR("Out of memory");
            return -1;
        }
        tmp_cusage->timestamp = gusage.timestamp();
        if (gusage.has_storage_id()) {
            tmp_cusage->uuid = util_strdup_s(gusage.storage_id().uuid().c_str());
        }
        if (gusage.has_used_bytes()) {
            tmp_cusage->used_bytes = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
            if (tmp_cusage->used_bytes == nullptr) {
                ERROR("Out of memory");
                free_filesystem_usage(tmp_cusage);
                return -1;
            }
            *(tmp_cusage->used_bytes) = gusage.used_bytes().value();
        }
        if (gusage.has_inodes_used()) {
            tmp_cusage->inodes_used = (uint64_t *)util_common_calloc_s(sizeof(uint64_t));
            if (tmp_cusage->inodes_used == nullptr) {
                ERROR("Out of memory");
                free_filesystem_usage(tmp_cusage);
                return -1;
            }
            *(tmp_cusage->inodes_used) = gusage.inodes_used().value();
        }
        *cusage = tmp_cusage;
        return 0;
    }
};

class ISulaHealthCheck : public ClientBase<isula::ImageService, isula::ImageService::Stub, isula_health_check_request,
    isula::HealthCheckRequest, isula_health_check_response, isula::HealthCheckResponse> {
public:
    explicit ISulaHealthCheck(void *args) : ClientBase(args)
    {
    }
    ~ISulaHealthCheck() = default;

    int response_from_grpc(isula::HealthCheckResponse *gresp, isula_health_check_response *resp) override
    {
        if (!gresp->errmsg().empty()) {
            resp->errmsg = util_strdup_s(gresp->errmsg().c_str());
        }
        resp->server_errono = gresp->cc();
        return 0;
    }

    Status grpc_call(ClientContext *context, const isula::HealthCheckRequest &req,
                     isula::HealthCheckResponse *reply) override
    {
        return stub_->HealthCheck(context, req, reply);
    }
};

int grpc_isula_image_client_ops_init(isula_image_ops *ops)
{
    if (ops == nullptr) {
        return -1;
    }

    ops->pull = container_func<isula_pull_request, isula_pull_response, ISulaImagePull>;
    ops->rmi = container_func<isula_rmi_request, isula_rmi_response, ISulaRmi>;
    ops->load = container_func<isula_load_request, isula_load_response, ISulaLoad>;
    ops->login = container_func<isula_login_request, isula_login_response, ISulaLogin>;
    ops->logout = container_func<isula_logout_request, isula_logout_response, ISulaLogout>;
    ops->image_fs_info = container_func<isula_image_fs_info_request, isula_image_fs_info_response, ISulaImageFsInfo>;

    ops->prepare = container_func<isula_prepare_request, isula_prepare_response, ISulaContainerPrepare>;
    ops->remove = container_func<isula_remove_request, isula_remove_response, ISulaContainerRemove>;
    ops->mount = container_func<isula_mount_request, isula_mount_response, ISulaContainerMount>;
    ops->umount = container_func<isula_umount_request, isula_umount_response, ISulaContainerUmount>;
    ops->containers_list =
        container_func<isula_containers_list_request, isula_containers_list_response, ISulaContainersList>;
    ops->container_export = container_func<isula_export_request, isula_export_response, ISulaExport>;
    ops->container_fs_usage =
        container_func<isula_container_fs_usage_request, isula_container_fs_usage_response, ISulaContainerFsUsage>;

    ops->list = container_func<isula_list_request, isula_list_response, ISulaListImages>;
    ops->status = container_func<isula_status_request, isula_status_response, ISulaImageStatus>;

    ops->storage_status = container_func<isula_storage_status_request, isula_storage_status_response,
         ISulaStorageStatus>;

    ops->health_check = container_func<isula_health_check_request, isula_health_check_response, ISulaHealthCheck>;

    return 0;
}
