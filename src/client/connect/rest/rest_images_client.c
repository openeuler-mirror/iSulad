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
 * Description: provide image restful client functions
 ******************************************************************************/
#include "rest_images_client.h"
#include <unistd.h>
#include "error.h"
#include <limits.h>

#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "image.rest.h"
#include "rest_common.h"

/* image load request to rest */
static int image_load_request_to_rest(const struct isula_load_request *request, char **body, size_t *body_len)
{
    image_load_image_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_load_image_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    crequest->file = util_strdup_s(request->file);
    crequest->type = util_strdup_s(request->type);
    crequest->tag = util_strdup_s(request->tag);
    *body = image_load_image_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image load request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_image_load_image_request(crequest);
    return ret;
}

/* image list request to rest */
static int image_list_request_to_rest(const struct isula_list_images_request *request, char **body, size_t *body_len)
{
    image_list_images_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_list_images_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    *body = image_list_images_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image list request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_image_list_images_request(crequest);
    return ret;
}

/* image delete request to rest */
static int image_delete_request_to_rest(const struct isula_rmi_request *request, char **body, size_t *body_len)
{
    image_delete_image_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_delete_image_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->image_name) {
        crequest->image_name = util_strdup_s(request->image_name);
    }
    crequest->force = request->force;

    *body = image_delete_image_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image delete request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_image_delete_image_request(crequest);
    return ret;
}

static int unpack_image_info_to_list_response(image_list_images_response *cresponse,
                                              struct isula_list_images_response *response)
{
    size_t num = 0;
    struct isula_image_info *image_info = NULL;

    if (cresponse == NULL || response == NULL) {
        return -1;
    }

    num = cresponse->images_len;
    if (num > 0) {
        size_t i;
        image_info = (struct isula_image_info *)util_smart_calloc_s(sizeof(struct isula_image_info), num);
        if (image_info == NULL) {
            ERROR("out of memory");
            return -1;
        }
        response->images_num = num;
        response->images_list = image_info;
        for (i = 0; i < num; i++) {
            if (cresponse->images[i]->target != NULL) {
                image_info[i].type = cresponse->images[i]->target->media_type ?
                                     util_strdup_s(cresponse->images[i]->target->media_type) :
                                     util_strdup_s("-");
                image_info[i].digest = cresponse->images[i]->target->digest ?
                                       util_strdup_s(cresponse->images[i]->target->digest) :
                                       util_strdup_s("-");
                image_info[i].size = cresponse->images[i]->target->size;
            }
            if (cresponse->images[i]->created_at != NULL) {
                image_info[i].created = cresponse->images[i]->created_at->seconds;
                image_info[i].created_nanos = cresponse->images[i]->created_at->nanos;
            }
            image_info[i].imageref = cresponse->images[i]->name ? util_strdup_s(cresponse->images[i]->name) :
                                     util_strdup_s("-");
        }
    }

    return 0;
}
/* unpack image list response */
static int unpack_image_list_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_list_images_response *response = (struct isula_list_images_response *)arg;
    image_list_images_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = image_list_images_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid images list response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

    if (unpack_image_info_to_list_response(cresponse, response)) {
        ret = -1;
        goto out;
    }

out:
    free(err);
    free_image_list_images_response(cresponse);
    return ret;
}

/* unpack image load response */
static int unpack_image_load_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_load_response *c_load_response = (struct isula_load_response *)arg;
    image_load_image_response *load_response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    load_response = image_load_image_response_parse_data(message->body, NULL, &err);
    if (load_response == NULL) {
        ERROR("Invalid load image response:%s", err);
        ret = -1;
        goto out;
    }
    c_load_response->server_errono = load_response->cc;
    if (load_response->errmsg != NULL) {
        c_load_response->errmsg = util_strdup_s(load_response->errmsg);
    }
    ret = (load_response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_load_image_response(load_response);
    return ret;
}

/* rest image load */
static int rest_image_load(const struct isula_load_request *request, struct isula_load_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = image_load_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServiceLoad, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_image_load_response, (void *)response);
    if (ret != 0) {
        goto out;
    }
out:
    if (output != NULL) {
        buffer_free(output);
    }
    put_body(body);
    return ret;
}

/* unpack image delete response */
static int unpack_image_delete_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_rmi_response *c_rmi_response = (struct isula_rmi_response *)arg;
    image_delete_image_response *delete_response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    delete_response = image_delete_image_response_parse_data(message->body, NULL, &err);
    if (delete_response == NULL) {
        ERROR("Invalid delete image response:%s", err);
        ret = -1;
        goto out;
    }
    c_rmi_response->server_errono = delete_response->cc;
    if (delete_response->errmsg != NULL) {
        c_rmi_response->errmsg = util_strdup_s(delete_response->errmsg);
    }
    ret = (delete_response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_delete_image_response(delete_response);
    return ret;
}

/* rest image list */
static int rest_image_list(const struct isula_list_images_request *request, struct isula_list_images_response *response,
                           void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = image_list_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServiceList, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_image_list_response, (void *)response);
    if (ret != 0) {
        goto out;
    }
out:
    if (output != NULL) {
        buffer_free(output);
    }
    put_body(body);
    return ret;
}

/* rest image remove */
static int rest_image_remove(const struct isula_rmi_request *request, struct isula_rmi_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = image_delete_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServiceDelete, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_image_delete_response, (void *)response);
    if (ret != 0) {
        goto out;
    }
out:
    if (output != NULL) {
        buffer_free(output);
    }
    put_body(body);
    return ret;
}

/* inspect request to rest */
static int inspect_request_to_rest(const struct isula_inspect_request *li_request, char **body, size_t *body_len)
{
    image_inspect_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_inspect_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (li_request->name != NULL) {
        crequest->id = util_strdup_s(li_request->name);
    }

    crequest->bformat = li_request->bformat;
    crequest->timeout = li_request->timeout;

    *body = image_inspect_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate inspect request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_image_inspect_request(crequest);
    return ret;
}

/* unpack inspect response */
static int unpack_inspect_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_inspect_response *response = (struct isula_inspect_response *)arg;
    image_inspect_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = image_inspect_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid inspect response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = cresponse->cc;
    if (cresponse->image_json != NULL) {
        response->json = util_strdup_s(cresponse->image_json);
    }
    if (cresponse->errmsg != NULL) {
        response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_inspect_response(cresponse);
    return ret;
}

/* rest image inspect */
static int rest_image_inspect(const struct isula_inspect_request *li_request,
                              struct isula_inspect_response *li_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = inspect_request_to_rest(li_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServiceInspect, body, len, &output);
    if (ret != 0) {
        li_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        li_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_inspect_response, (void *)li_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (output != NULL) {
        buffer_free(output);
    }
    put_body(body);
    return ret;
}

/* image pull request to rest */
static int image_pull_request_to_rest(const struct isula_pull_request *request, char **body, size_t *body_len)
{
    image_pull_image_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_pull_image_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    crequest->image_name = util_strdup_s(request->image_name);

    *body = image_pull_image_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image pull request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_image_pull_image_request(crequest);
    return ret;
}

/* unpack image pull response */
static int unpack_image_pull_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_pull_response *c_rmi_response = (struct isula_pull_response *)arg;
    image_pull_image_response *pull_response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ERROR("Pull image check status code failed.\n");
        goto out;
    }

    pull_response = image_pull_image_response_parse_data(message->body, NULL, &err);
    if (pull_response == NULL) {
        ERROR("Invalid pull image response:%s", err);
        ret = -1;
        goto out;
    }

    c_rmi_response->server_errono = pull_response->cc;
    c_rmi_response->image_ref = util_strdup_s(pull_response->image_ref);
    c_rmi_response->errmsg = util_strdup_s(pull_response->errmsg);

    ret = (pull_response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_pull_image_response(pull_response);
    return ret;
}

/* rest image pull */
static int rest_image_pull(const struct isula_pull_request *request, struct isula_pull_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = image_pull_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServicePull, body, len, &output);
    if (ret != 0) {
        ERROR("Send pull request failed.");
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_image_pull_response, (void *)response);
    if (ret != 0) {
        ERROR("Get pull response failed.");
        goto out;
    }

out:
    buffer_free(output);
    put_body(body);
    return ret;
}

/* unpack image login response */
static int unpack_image_login_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_login_response *c_login_response = (struct isula_login_response *)arg;
    image_login_response *login_response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    login_response = image_login_response_parse_data(message->body, NULL, &err);
    if (login_response == NULL) {
        ERROR("Invalid login response:%s", err);
        ret = -1;
        goto out;
    }
    c_login_response->server_errono = login_response->cc;
    if (login_response->errmsg != NULL) {
        c_login_response->errmsg = util_strdup_s(login_response->errmsg);
    }
    ret = (login_response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_login_response(login_response);
    return ret;
}

/* image login request to rest */
static int image_login_request_to_rest(const struct isula_login_request *request, char **body, size_t *body_len)
{
    image_login_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_login_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    crequest->username = util_strdup_s(request->username);
    crequest->password = util_strdup_s(request->password);
    crequest->server = util_strdup_s(request->server);
    crequest->type = util_strdup_s(request->type);

    *body = image_login_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image login request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_image_login_request(crequest);
    return ret;
}

/* rest image login*/
static int rest_image_login(const struct isula_login_request *request, struct isula_login_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = image_login_request_to_rest(request, &body, &len);
    if (ret != 0) {
        ERROR("Build login request failed.");
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServiceLogin, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        ERROR("Send login request failed.");
        goto out;
    }
    ret = get_response(output, unpack_image_login_response, (void *)response);
    if (ret != 0) {
        ERROR("Get login response failed.");
        goto out;
    }

out:
    if (output != NULL) {
        buffer_free(output);
    }
    put_body(body);
    return ret;
}

/* unpack image logout response */
static int unpack_image_logout_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_logout_response *c_logout_response = (struct isula_logout_response *)arg;
    image_logout_response *logout_response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    logout_response = image_logout_response_parse_data(message->body, NULL, &err);
    if (logout_response == NULL) {
        ERROR("Invalid logout image response:%s", err);
        ret = -1;
        goto out;
    }
    c_logout_response->server_errono = logout_response->cc;
    c_logout_response->errmsg = util_strdup_s(logout_response->errmsg);
    ret = (logout_response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_logout_response(logout_response);
    return ret;
}

/* image login request to rest */
static int image_logout_request_to_rest(const struct isula_logout_request *request, char **body, size_t *body_len)
{
    image_logout_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_logout_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (request->server != NULL) {
        crequest->server = util_strdup_s(request->server);
    }
    if (request->type != NULL) {
        crequest->type = util_strdup_s(request->type);
    }
    *body = image_logout_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image logout request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_image_logout_request(crequest);
    return ret;
}

/* rest image login*/
static int rest_image_logout(const struct isula_logout_request *request, struct isula_logout_response *response,
                             void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = image_logout_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServiceLogout, body, len, &output);
    if (ret != 0) {
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_image_logout_response, (void *)response);
    if (ret != 0) {
        goto out;
    }

out:
    if (output != NULL) {
        buffer_free(output);
    }
    put_body(body);
    return ret;
}

/* image tag request to rest */
static int image_tag_request_to_rest(const struct isula_tag_request *request, char **body, size_t *body_len)
{
    image_tag_image_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_tag_image_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    crequest->src_name = util_strdup_s(request->src_name);
    crequest->dest_name = util_strdup_s(request->dest_name);

    *body = image_tag_image_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image tag request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_image_tag_image_request(crequest);
    return ret;
}

/* unpack image tag response */
static int unpack_image_tag_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_tag_response *c_tag_response = (struct isula_tag_response *)arg;
    image_tag_image_response *tag_response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ERROR("Tag image check status code failed.\n");
        goto out;
    }

    tag_response = image_tag_image_response_parse_data(message->body, NULL, &err);
    if (tag_response == NULL) {
        ERROR("Invalid tag image response:%s", err);
        ret = -1;
        goto out;
    }

    c_tag_response->server_errono = tag_response->cc;
    c_tag_response->errmsg = util_strdup_s(tag_response->errmsg);

    ret = (tag_response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_tag_image_response(tag_response);
    return ret;
}

/* rest image tag */
static int rest_image_tag(const struct isula_tag_request *request, struct isula_tag_response *response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = image_tag_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_request(socketname, RestHttpHead ImagesServiceTag, body, len, &output);
    if (ret != 0) {
        ERROR("Send tag request failed.");
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_image_tag_response, (void *)response);
    if (ret != 0) {
        ERROR("Get tag response failed.");
        goto out;
    }

out:
    buffer_free(output);
    put_body(body);
    return ret;
}

/* image import request to rest */
static int image_import_request_to_rest(const struct isula_import_request *request, char **body, size_t *body_len)
{
    image_import_request *crequest = NULL;
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(image_import_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    crequest->file = util_strdup_s(request->file);
    crequest->tag = util_strdup_s(request->tag);

    *body = image_import_request_generate_json(crequest, NULL, &err);
    if (*body == NULL) {
        ERROR("Failed to generate image import request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_image_import_request(crequest);

    return ret;
}

/* unpack image import response */
static int unpack_image_import_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_import_response *c_import_response = (struct isula_import_response *)arg;
    image_import_response *import_response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        ERROR("Tag image check status code failed.\n");
        goto out;
    }

    import_response = image_import_response_parse_data(message->body, NULL, &err);
    if (import_response == NULL) {
        ERROR("Invalid import image response:%s", err);
        ret = -1;
        goto out;
    }

    c_import_response->server_errono = import_response->cc;
    c_import_response->errmsg = util_strdup_s(import_response->errmsg);
    c_import_response->id = util_strdup_s(import_response->id);

    ret = (import_response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_image_import_response(import_response);

    return ret;
}

/* rest image import */
static int rest_image_import(const struct isula_import_request *request, struct isula_import_response *response,
                             void *arg)
{
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    char *body = NULL;
    Buffer *output = NULL;
    int ret = 0;
    size_t len = 0;

    ret = image_import_request_to_rest(request, &body, &len);
    if (ret != 0) {
        goto out;
    }

    ret = rest_send_request(socketname, RestHttpHead ImagesServiceImport, body, len, &output);
    if (ret != 0) {
        ERROR("Send import request failed.");
        response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        response->cc = ISULAD_ERR_EXEC;
        goto out;
    }

    ret = get_response(output, unpack_image_import_response, (void *)response);
    if (ret != 0) {
        ERROR("Get import response failed.");
        goto out;
    }

out:
    buffer_free(output);
    put_body(body);

    return ret;
}

/* rest images client ops init */
int rest_images_client_ops_init(isula_connect_ops *ops)
{
    if (ops == NULL) {
        return -1;
    }

    ops->image.list = &rest_image_list;
    ops->image.remove = &rest_image_remove;
    ops->image.load = &rest_image_load;
    ops->image.inspect = &rest_image_inspect;
    ops->image.pull = &rest_image_pull;
    ops->image.login = &rest_image_login;
    ops->image.logout = &rest_image_logout;
    ops->image.tag = &rest_image_tag;
    ops->image.import = &rest_image_import;

    return 0;
}
