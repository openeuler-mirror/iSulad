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
 * Description: provide grpc container service functions
 ******************************************************************************/
#include "grpc_images_client.h"
#include "client_base.h"
#include "images.grpc.pb.h"

#include <isula_libutils/auto_cleanup.h>
#include <isula_libutils/image_progress.h>
#include <string>
#include "show.h"
#include "utils.h"
#include "constants.h"

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
        images_list = (struct isula_image_info *)util_smart_calloc_s(sizeof(struct isula_image_info), (size_t)num);
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

class ImagesPull : public ClientBase<ImagesService, ImagesService::Stub,
    isula_pull_request, PullImageRequest,
    isula_pull_response, PullImageResponse> {
public:
    explicit ImagesPull(void *args)
        : ClientBase(args)
    {
    }
    ~ImagesPull() = default;

    auto request_to_grpc(const isula_pull_request *request, PullImageRequest *grequest)
    -> int override
    {
        if (request == nullptr) {
            return -1;
        }
        if (request->image_name != nullptr) {
            auto *image_spec = new (std::nothrow) ImageSpec;
            if (image_spec == nullptr) {
                return -1;
            }
            image_spec->set_image(request->image_name);
            grequest->set_allocated_image(image_spec);
        }

        grequest->set_is_progress_visible(request->is_progress_visible);

        return 0;
    }

    auto response_from_grpc(PullImageResponse *gresponse, isula_pull_response *response)
    -> int override
    {
        if (!gresponse->image_ref().empty()) {
            response->image_ref = util_strdup_s(gresponse->image_ref().c_str());
        }

        return 0;
    }

    auto check_parameter(const PullImageRequest &req) -> int override
    {
        if (req.image().image().empty()) {
            ERROR("Missing image name in the request");
            return -1;
        }

        return 0;
    }

    auto run(const struct isula_pull_request *request, struct isula_pull_response *response) -> int override
    {
        ClientContext context;
        PullImageRequest grequest;

#ifdef ENABLE_GRPC_REMOTE_CONNECT
#ifdef OPENSSL_VERIFY
        // Set common name from cert.perm
        char common_name_value[ClientBaseConstants::COMMON_NAME_LEN] = { 0 };
        int ret = get_common_name_from_tls_cert(m_certFile.c_str(), common_name_value,
                                                ClientBaseConstants::COMMON_NAME_LEN);
        if (ret != 0) {
            ERROR("Failed to get common name in: %s", m_certFile.c_str());
            return -1;
        }
        context.AddMetadata("username", std::string(common_name_value, strlen(common_name_value)));
        context.AddMetadata("tls_mode", m_tlsMode);
#endif
#endif
        if (request_to_grpc(request, &grequest) != 0) {
            ERROR("Failed to transform pull request to grpc");
            response->server_errono = ISULAD_ERR_INPUT;
            return -1;
        }

        auto reader = stub_->PullImage(&context, grequest);

        PullImageResponse gresponse;
        if (grequest.is_progress_visible()) {
            while (reader->Read(&gresponse)) {
                output_progress(gresponse);
            }
        } else {
            reader->Read(&gresponse);
            WARN("The terminal may not support ANSI Escape code. Display is skipped");
        }
        Status status = reader->Finish();
        if (!status.ok()) {
            ERROR("Error code: %d: %s", status.error_code(), status.error_message().c_str());
            unpackStatus(status, response);
            return -1;
        }
        response->image_ref = util_strdup_s(gresponse.image_ref().c_str());
        return 0;
    }

private:
    void output_progress(PullImageResponse &gresponse)
    {
        __isula_auto_free char *err = nullptr;
        struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };

        image_progress *progresses = image_progress_parse_data(gresponse.progress_data().c_str(), &ctx, &err);
        if (progresses == nullptr) {
            ERROR("Parse image progress error %s", err);
            return;
        }
        show_processes(progresses);
    }

    void get_printed_value(int64_t value, char *printed)
    {
        float float_value = 0.0;
        const float GB = 1024 * 1024 * 1024;
        const float MB = 1024 * 1024;
        const float KB = 1024;

        if ((float)value / GB > 1) {
            float_value = (float)value / GB;
            sprintf(printed, "%.2fGB", float_value);
        } else if ((float)value / MB > 1) {
            float_value = (float)value / MB;
            sprintf(printed, "%.2fMB", float_value);
        } else if ((float)value / KB > 1) {
            float_value = (float)value / KB;
            sprintf(printed, "%.2fKB", float_value);
        } else {
            sprintf(printed, "%ldB", value);
        }
    }

    void display_progress_bar(image_progress_progresses_element *progress_item, int width, bool if_show_all)
    {
        float progress = 0.0;
        int filled_width = 0;
        const int FLOAT_STRING_SIZE = 64;
        char total[FLOAT_STRING_SIZE] = {0};
        char current[FLOAT_STRING_SIZE] = {0};
        int empty_width = 0;

        if (progress_item->total != 0) {
            progress = (float)progress_item->current / (float)progress_item->total;
        }
        filled_width = (int)(progress * width);
        empty_width = width - filled_width;
        get_printed_value(progress_item->total, total);
        get_printed_value(progress_item->current, current);

        if (if_show_all) {
            int i = 0;

            printf("%s: [", progress_item->id);

            // Print filled characters
            for (i = 0; i < filled_width; i++) {
                printf("=");
            }
            printf(">");
            // Print empty characters
            for (i = 0; i < empty_width; i++) {
                printf(" ");
            }

            printf("] %s/%s", current, total);
        } else {
            printf("%s:  %s/%s", progress_item->id, current, total);
        }
        printf("\n");
        fflush(stdout);
    }

    void show_processes(image_progress *progresses)
    {
        size_t i = 0;
        static size_t len = 0;
        const int TERMINAL_SHOW_WIDTH = 110;
        const int width = 50;  // Width of the progress bars

        if (len != 0) {
            move_cursor_up(len);
        }
        clear_lines_below();
        len = progresses->progresses_len;
        int terminal_width = get_terminal_width();
        bool if_show_all = true;
        if (terminal_width < TERMINAL_SHOW_WIDTH) {
            if_show_all = false;
        }
        for (i = 0; i < len; i++) {
            display_progress_bar(progresses->progresses[i], width, if_show_all);
        }
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
#ifdef ENABLE_IMAGE_SEARCH
class ImageSearch : public ClientBase<ImagesService, ImagesService::Stub, isula_search_request, SearchRequest,
    isula_search_response, SearchResponse> {
public:
    explicit ImageSearch(void *args)
        : ClientBase(args)
    {
    }
    ~ImageSearch() = default;

    auto request_to_grpc(const isula_search_request *request, SearchRequest *grequest) -> int override
    {
        if (request == nullptr) {
            return -1;
        }

        if (request->search_name != nullptr) {
            grequest->set_search_name(request->search_name);
        }

        grequest->set_limit(request->limit);

        if (request->filters != nullptr) {
            auto *map = grequest->mutable_filters();
            for (size_t i = 0; i < request->filters->len; i++) {
                (*map)[request->filters->keys[i]] = request->filters->values[i];
            }
        }

        return 0;
    }

    auto response_from_grpc(SearchResponse *gresponse, isula_search_response *response) -> int override
    {
        struct search_image_info *search_result = nullptr;
        int i = 0;
        int num = gresponse->result_num();

        if (num <= 0) {
            response->search_result = nullptr;
            response->result_num = 0;
            response->server_errono = gresponse->cc();
            if (!gresponse->errmsg().empty()) {
                response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
            }
            return 0;
        }

        search_result = (struct search_image_info *)util_smart_calloc_s(sizeof(struct search_image_info), (size_t)num);
        if (search_result == nullptr) {
            ERROR("out of memory");
            response->cc = ISULAD_ERR_MEMOUT;
            return -1;
        }

        for (i = 0; i < num; i++) {
            const SearchImage &image = gresponse->search_result(i);
            const char *name = !image.name().empty() ? image.name().c_str() : "-";
            const char *description = !image.description().empty() ? image.description().c_str() : "-";

            search_result[i].star_count = image.star_count();
            search_result[i].is_official = image.is_official();
            search_result[i].is_automated = image.is_automated();
            search_result[i].name = util_strdup_s(name);
            search_result[i].description = util_strdup_s(description);
        }

        response->search_result = search_result;
        response->result_num = (uint32_t)gresponse->result_num();
        response->server_errono = gresponse->cc();
        if (!gresponse->errmsg().empty()) {
            response->errmsg = util_strdup_s(gresponse->errmsg().c_str());
        }

        return 0;
    }

    auto check_parameter(const SearchRequest &req) -> int override
    {
        if (req.search_name().empty()) {
            ERROR("Missing search_name in the request");
            return -1;
        }

        if (req.limit() < MIN_LIMIT || req.limit() > MAX_LIMIT) {
            ERROR("Invalid limit in the request");
            return -1;
        }
        return 0;
    }

    auto grpc_call(ClientContext *context, const SearchRequest &req, SearchResponse *reply) -> Status override
    {
        return stub_->Search(context, req, reply);
    }
};
#endif

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
#ifdef ENABLE_IMAGE_SEARCH
    ops->image.search = container_func<isula_search_request, isula_search_response, ImageSearch>;
#endif

    return 0;
}
