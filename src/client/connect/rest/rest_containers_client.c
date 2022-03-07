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
 * Description: provide container restful functions
 ******************************************************************************/
#include "rest_containers_client.h"
#include <unistd.h>
#include "error.h"

#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "container.rest.h"
#include "rest_common.h"

/* create request to rest */
static int create_request_to_rest(const struct isula_create_request *lc_request, char **body, size_t *body_len)
{
    container_create_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_create_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (lc_request->host_spec_json != NULL) {
        crequest->hostconfig = util_strdup_s(lc_request->host_spec_json);
    }

    if (lc_request->container_spec_json != NULL) {
        crequest->customconfig = util_strdup_s(lc_request->container_spec_json);
    }

    if (lc_request->name != NULL) {
        crequest->id = util_strdup_s(lc_request->name);
    }
    if (lc_request->image != NULL) {
        crequest->image = util_strdup_s(lc_request->image);
    }
    if (lc_request->rootfs != NULL) {
        crequest->rootfs = util_strdup_s(lc_request->rootfs);
    }
    if (lc_request->runtime != NULL) {
        crequest->runtime = util_strdup_s(lc_request->runtime);
    }

    *body = container_create_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate create request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_create_request(crequest);
    return ret;
}

/* start request to rest */
static int start_request_to_rest(const struct isula_start_request *ls_request, char **body, size_t *body_len)
{
    container_start_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_start_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (ls_request->name != NULL) {
        crequest->id = util_strdup_s(ls_request->name);
    }
    if (ls_request->stdout != NULL) {
        crequest->stdout = util_strdup_s(ls_request->stdout);
    }
    if (ls_request->stdin != NULL) {
        crequest->stdin = util_strdup_s(ls_request->stdin);
    }
    if (ls_request->stderr != NULL) {
        crequest->stderr = util_strdup_s(ls_request->stderr);
    }
    crequest->attach_stdin = ls_request->attach_stdin;
    crequest->attach_stdout = ls_request->attach_stdout;
    crequest->attach_stderr = ls_request->attach_stderr;

    *body = container_start_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate start request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_start_request(crequest);
    return ret;
}

/* list request to rest */
static int list_request_to_rest(const struct isula_list_request *ll_request, char **body, size_t *body_len)
{
    container_list_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;
    size_t i, len;

    crequest = util_common_calloc_s(sizeof(container_list_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    crequest->all = ll_request->all;

    if (ll_request->filters == NULL || ll_request->filters->len == 0) {
        goto pack_json;
    }

    crequest->filters = util_common_calloc_s(sizeof(defs_filters));
    if (crequest->filters == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    len = ll_request->filters->len;
    if (len > SIZE_MAX / sizeof(char *)) {
        ERROR("Too many filters");
        ret = -1;
        goto out;
    }
    crequest->filters->keys = (char **)util_common_calloc_s(len * sizeof(char *));
    if (crequest->filters->keys == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    crequest->filters->values = (json_map_string_bool **)util_common_calloc_s(len * sizeof(json_map_string_bool *));
    if (crequest->filters->values == NULL) {
        ERROR("Out of memory");
        free(crequest->filters->keys);
        crequest->filters->keys = NULL;
        ret = -1;
        goto out;
    }

    for (i = 0; i < ll_request->filters->len; i++) {
        crequest->filters->values[crequest->filters->len] = util_common_calloc_s(sizeof(json_map_string_bool));
        if (crequest->filters->values[crequest->filters->len] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        if (append_json_map_string_bool(crequest->filters->values[crequest->filters->len],
                                        ll_request->filters->values[i], true)) {
            free(crequest->filters->values[crequest->filters->len]);
            crequest->filters->values[crequest->filters->len] = NULL;
            ERROR("Append failed");
            ret = -1;
            goto out;
        }
        crequest->filters->keys[crequest->filters->len] = util_strdup_s(ll_request->filters->keys[i]);
        crequest->filters->len++;
    }

pack_json:
    *body = container_list_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate list request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_list_request(crequest);
    return ret;
}

/* attach request to rest */
static int attach_request_to_rest(const struct isula_attach_request *la_request, char **body, size_t *body_len)
{
    container_attach_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_attach_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (la_request->name != NULL) {
        crequest->container_id = util_strdup_s(la_request->name);
    }
    if (la_request->stdout != NULL) {
        crequest->stdout = util_strdup_s(la_request->stdout);
    }
    if (la_request->stdin != NULL) {
        crequest->stdin = util_strdup_s(la_request->stdin);
    }
    if (la_request->stderr != NULL) {
        crequest->stderr = util_strdup_s(la_request->stderr);
    }
    *body = container_attach_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate attach request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_attach_request(crequest);
    return ret;
}

/* resume request to rest */
static int resume_request_to_rest(const struct isula_resume_request *lr_request, char **body, size_t *body_len)
{
    container_resume_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_resume_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (lr_request->name != NULL) {
        crequest->id = util_strdup_s(lr_request->name);
    }
    *body = container_resume_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate resume request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_resume_request(crequest);
    return ret;
}

/* wait request to rest */
static int wait_request_to_rest(const struct isula_wait_request *lw_request, char **body, size_t *body_len)
{
    container_wait_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_wait_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (lw_request->id != NULL) {
        crequest->id = util_strdup_s(lw_request->id);
    }
    crequest->condition = lw_request->condition;

    *body = container_wait_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate wait request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_wait_request(crequest);
    return ret;
}

/* unpack create response */
static int unpack_create_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_create_response *response = arg;
    container_create_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_create_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid create response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    if (cresponse->id != NULL) {
        response->id = util_strdup_s(cresponse->id);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_create_response(cresponse);
    return ret;
}

/* unpack start response */
static int unpack_start_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_start_response *start_response = arg;
    container_start_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_start_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid start response:%s", err);
        ret = -1;
        goto out;
    }
    start_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        start_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_start_response(cresponse);
    return ret;
}

static int unpack_container_info_for_list_response(container_list_response *cresponse,
                                                   struct isula_list_response *response)
{
    size_t num = 0;
    size_t i = 0;
    struct isula_container_summary_info **summary_info = NULL;

    if (cresponse == NULL || response == NULL) {
        return -1;
    }

    num = cresponse->containers_len;
    if (num == 0) {
        return 0;
    }
    if (num > SIZE_MAX / sizeof(struct isula_container_summary_info *)) {
        ERROR("Too many container summaries");
        return -1;
    }
    summary_info = (struct isula_container_summary_info **)util_common_calloc_s(
                       sizeof(struct isula_container_summary_info *) * num);
    if (summary_info == NULL) {
        ERROR("out of memory");
        return -1;
    }
    response->container_num = num;
    response->container_summary = summary_info;
    for (i = 0; i < num; i++) {
        summary_info[i] = (struct isula_container_summary_info *)util_common_calloc_s(
                              sizeof(struct isula_container_summary_info));
        if (summary_info[i] == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        summary_info[i]->id = cresponse->containers[i]->id ? util_strdup_s(cresponse->containers[i]->id) :
                              util_strdup_s("-");
        summary_info[i]->name = cresponse->containers[i]->name ? util_strdup_s(cresponse->containers[i]->name) :
                                util_strdup_s("-");
        summary_info[i]->runtime = cresponse->containers[i]->runtime ?
                                   util_strdup_s(cresponse->containers[i]->runtime) :
                                   util_strdup_s("-");
        summary_info[i]->has_pid = cresponse->containers[i]->pid != 0;
        summary_info[i]->pid = cresponse->containers[i]->pid;
        summary_info[i]->status = cresponse->containers[i]->status;
        summary_info[i]->image = cresponse->containers[i]->image ? util_strdup_s(cresponse->containers[i]->image) :
                                 util_strdup_s("-");
        summary_info[i]->command = cresponse->containers[i]->command ?
                                   util_strdup_s(cresponse->containers[i]->command) :
                                   util_strdup_s("-");
        summary_info[i]->startat = cresponse->containers[i]->startat ?
                                   util_strdup_s(cresponse->containers[i]->startat) :
                                   util_strdup_s("-");
        summary_info[i]->finishat = cresponse->containers[i]->finishat ?
                                    util_strdup_s(cresponse->containers[i]->finishat) :
                                    util_strdup_s("-");
        summary_info[i]->exit_code = cresponse->containers[i]->exit_code;
        summary_info[i]->restart_count = (unsigned int)cresponse->containers[i]->restartcount;
        summary_info[i]->created = cresponse->containers[i]->created;
    }

    return 0;
}
/* unpack list response */
static int unpack_list_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_list_response *response = arg;
    container_list_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_list_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid list response:%s", err);
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
    if (unpack_container_info_for_list_response(cresponse, response)) {
        ret = -1;
        goto out;
    }

out:
    free(err);
    free_container_list_response(cresponse);
    return ret;
}

/* unpack attach response */
static int unpack_attach_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_attach_response *attach_response = arg;
    container_attach_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_attach_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid attach response:%s", err);
        ret = -1;
        goto out;
    }
    attach_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        attach_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_attach_response(cresponse);
    return ret;
}

/* unpack resume response */
static int unpack_resume_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_resume_response *resume_response = arg;
    container_resume_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_resume_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid resume response:%s", err);
        ret = -1;
        goto out;
    }
    resume_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        resume_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_resume_response(cresponse);
    return ret;
}

/* unpack wait response */
static int unpack_wait_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_wait_response *response = arg;
    container_wait_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_wait_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid create response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = cresponse->cc;
    response->exit_code = (int)cresponse->exit_code;
    if (cresponse->errmsg != NULL) {
        response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free_container_wait_response(cresponse);
    free(err);
    return ret;
}

/* rest container create */
static int rest_container_create(const struct isula_create_request *lc_request,
                                 struct isula_create_response *lc_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *c_output = NULL;

    ret = create_request_to_rest(lc_request, &body, &len);
    if (ret != 0) {
        lc_response->cc = ISULAD_ERR_INPUT;
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceCreate, body, len, &c_output);
    if (ret != 0) {
        lc_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lc_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(c_output, unpack_create_response, (void *)lc_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (c_output != NULL) {
        buffer_free(c_output);
    }
    put_body(body);
    return ret;
}

/* rest container start */
static int rest_container_start(const struct isula_start_request *ls_request, struct isula_start_response *ls_response,
                                void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *s_output = NULL;

    ret = start_request_to_rest(ls_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceStart, body, len, &s_output);
    if (ret != 0) {
        ls_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        ls_response->cc = ISULAD_ERR_EXEC;
        ls_response->server_errono = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(s_output, unpack_start_response, (void *)ls_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (s_output != NULL) {
        buffer_free(s_output);
    }
    put_body(body);
    return ret;
}

/* rest container attach */
static int rest_container_attach(const struct isula_attach_request *la_request,
                                 struct isula_attach_response *la_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *a_output = NULL;

    ret = attach_request_to_rest(la_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceAttach, body, len, &a_output);
    if (ret != 0) {
        la_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        la_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(a_output, unpack_attach_response, (void *)la_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (a_output != NULL) {
        buffer_free(a_output);
    }
    put_body(body);
    return ret;
}

/* rest container list */
static int rest_container_list(const struct isula_list_request *ll_request, struct isula_list_response *ll_response,
                               void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *l_output = NULL;

    ret = list_request_to_rest(ll_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceList, body, len, &l_output);
    if (ret != 0) {
        ll_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        ll_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(l_output, unpack_list_response, (void *)ll_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (l_output != NULL) {
        buffer_free(l_output);
    }
    put_body(body);
    return ret;
}

/* rest container resume */
static int rest_container_resume(const struct isula_resume_request *lr_request,
                                 struct isula_resume_response *lr_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *r_output = NULL;

    ret = resume_request_to_rest(lr_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceResume, body, len, &r_output);
    if (ret != 0) {
        lr_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lr_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(r_output, unpack_resume_response, (void *)lr_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (r_output != NULL) {
        buffer_free(r_output);
    }
    put_body(body);
    return ret;
}

/* rest container wait */
static int rest_container_wait(const struct isula_wait_request *lw_request, struct isula_wait_response *lw_response,
                               void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *w_output = NULL;

    ret = wait_request_to_rest(lw_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceWait, body, len, &w_output);
    if (ret != 0) {
        lw_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lw_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(w_output, unpack_wait_response, (void *)lw_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (w_output != NULL) {
        buffer_free(w_output);
    }
    put_body(body);
    return ret;
}

/* stop request to rest */
static int stop_request_to_rest(const struct isula_stop_request *ls_request, char **body, size_t *body_len)
{
    container_stop_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_stop_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (ls_request->name != NULL) {
        crequest->id = util_strdup_s(ls_request->name);
    }
    crequest->force = ls_request->force;
    crequest->timeout = ls_request->timeout;

    *body = container_stop_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate stop request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_stop_request(crequest);
    return ret;
}

/* unpack stop response */
static int unpack_stop_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_stop_response *stop_response = arg;
    container_stop_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_stop_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid stop response:%s", err);
        ret = -1;
        goto out;
    }
    stop_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        stop_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_stop_response(cresponse);
    return ret;
}

/* rest container stop */
static int rest_container_stop(const struct isula_stop_request *ls_request, struct isula_stop_response *ls_response,
                               void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = stop_request_to_rest(ls_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceStop, body, len, &output);
    if (ret != 0) {
        ls_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        ls_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_stop_response, (void *)ls_response);
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

/* restart request to rest */
static int restart_request_to_rest(const struct isula_restart_request *lr_request, char **body, size_t *body_len)
{
    container_restart_request *creq = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    creq = util_common_calloc_s(sizeof(container_restart_request));
    if (creq == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (lr_request->name != NULL) {
        creq->id = util_strdup_s(lr_request->name);
    }
    creq->timeout = (int32_t)lr_request->timeout;

    *body = container_restart_request_generate_json(creq, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate restart request json: %s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_restart_request(creq);
    return ret;
}

/* unpack restart response */
static int unpack_restart_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_restart_response *response = arg;
    container_restart_response *cres = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cres = container_restart_response_parse_data(message->body, NULL, &err);
    if (cres == NULL) {
        ERROR("Invalid restart response: %s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = cres->cc;
    if (cres->errmsg != NULL) {
        response->errmsg = util_strdup_s(cres->errmsg);
    }
    ret = (cres->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_restart_response(cres);
    return ret;
}

/* rest container restart */
static int rest_container_restart(const struct isula_restart_request *lr_request,
                                  struct isula_restart_response *lr_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = restart_request_to_rest(lr_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceRestart, body, len, &output);
    if (ret != 0) {
        lr_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lr_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_restart_response, (void *)lr_response);

out:
    if (output != NULL) {
        buffer_free(output);
    }
    put_body(body);
    return ret;
}

/* update request to rest */
static int update_request_to_rest(const struct isula_update_request *lu_request, char **body, size_t *body_len)
{
    container_update_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_update_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (lu_request->name != NULL) {
        crequest->name = util_strdup_s(lu_request->name);
    }

    if (lu_request->host_spec_json != NULL) {
        crequest->host_config = util_strdup_s(lu_request->host_spec_json);
    }

    *body = container_update_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate update request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_update_request(crequest);
    return ret;
}

/* unpack update response */
static int unpack_update_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_update_response *update_response = arg;
    container_update_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_update_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid update response:%s", err);
        ret = -1;
        goto out;
    }
    update_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        update_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_update_response(cresponse);
    return ret;
}

/* rest container update */
static int rest_container_update(const struct isula_update_request *lu_request,
                                 struct isula_update_response *lu_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = update_request_to_rest(lu_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceUpdate, body, len, &output);
    if (ret != 0) {
        lu_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lu_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_update_response, (void *)lu_response);
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

/* version request to rest */
static int version_request_to_rest(const struct isula_version_request *lv_request, char **body, size_t *body_len)
{
    container_version_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_version_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    *body = container_version_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate version request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_version_request(crequest);
    return ret;
}

/* unpack version response */
static int unpack_version_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_version_response *version_response = arg;
    container_version_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_version_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid version response:%s", err);
        ret = -1;
        goto out;
    }
    version_response->server_errono = cresponse->cc;
    if (cresponse->version != NULL) {
        version_response->version = util_strdup_s(cresponse->version);
    }
    if (cresponse->git_commit != NULL) {
        version_response->git_commit = util_strdup_s(cresponse->git_commit);
    }
    if (cresponse->build_time != NULL) {
        version_response->build_time = util_strdup_s(cresponse->build_time);
    }
    if (cresponse->root_path != NULL) {
        version_response->root_path = util_strdup_s(cresponse->root_path);
    }
    if (cresponse->errmsg != NULL) {
        version_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_version_response(cresponse);
    return ret;
}

/* rest container version */
static int rest_container_version(const struct isula_version_request *lv_request,
                                  struct isula_version_response *lv_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = version_request_to_rest(lv_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceVersion, body, len, &output);
    if (ret != 0) {
        lv_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lv_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_version_response, (void *)lv_response);
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

/* pause request to rest */
static int pause_request_to_rest(const struct isula_pause_request *lp_request, char **body, size_t *body_len)
{
    container_pause_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_pause_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (lp_request->name != NULL) {
        crequest->id = util_strdup_s(lp_request->name);
    }

    *body = container_pause_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate pause request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_pause_request(crequest);
    return ret;
}

/* unpack pause response */
static int unpack_pause_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_pause_response *pause_response = arg;
    container_pause_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_pause_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid pause response:%s", err);
        ret = -1;
        goto out;
    }
    pause_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        pause_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_pause_response(cresponse);
    return ret;
}

/* rest container pause */
static int rest_container_pause(const struct isula_pause_request *lp_request, struct isula_pause_response *lp_response,
                                void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = pause_request_to_rest(lp_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServicePause, body, len, &output);
    if (ret != 0) {
        lp_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lp_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_pause_response, (void *)lp_response);
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

/* kill request to rest */
static int kill_request_to_rest(const struct isula_kill_request *lk_request, char **body, size_t *body_len)
{
    container_kill_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_kill_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (lk_request->name != NULL) {
        crequest->id = util_strdup_s(lk_request->name);
    }
    crequest->signal = lk_request->signal;

    *body = container_kill_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate kill request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_kill_request(crequest);
    return ret;
}

/* unpack kill response */
static int unpack_kill_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_kill_response *kill_response = arg;
    container_kill_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_kill_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid kill response:%s", err);
        ret = -1;
        goto out;
    }
    kill_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        kill_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_kill_response(cresponse);
    return ret;
}

/* rest container kill */
static int rest_container_kill(const struct isula_kill_request *lk_request, struct isula_kill_response *lk_response,
                               void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = kill_request_to_rest(lk_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceKill, body, len, &output);
    if (ret != 0) {
        lk_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        lk_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_kill_response, (void *)lk_response);
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

/* remove request to rest */
static int remove_request_to_rest(const struct isula_delete_request *ld_request, char **body, size_t *body_len)
{
    container_delete_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_delete_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (ld_request->name != NULL) {
        crequest->id = util_strdup_s(ld_request->name);
    }
    crequest->force = ld_request->force;

    *body = container_delete_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate remove request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_delete_request(crequest);
    return ret;
}

/* unpack remove response */
static int unpack_remove_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_delete_response *delete_response = arg;
    container_delete_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_delete_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid remove response:%s", err);
        ret = -1;
        goto out;
    }
    delete_response->server_errono = cresponse->cc;
    if (cresponse->errmsg != NULL) {
        delete_response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_delete_response(cresponse);
    return ret;
}

/* rest container remove */
static int rest_container_remove(const struct isula_delete_request *ld_request,
                                 struct isula_delete_response *ld_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *r_output = NULL;

    ret = remove_request_to_rest(ld_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceRemove, body, len, &r_output);
    if (ret != 0) {
        ld_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        ld_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(r_output, unpack_remove_response, (void *)ld_response);
    if (ret != 0) {
        goto out;
    }
out:
    if (r_output != NULL) {
        buffer_free(r_output);
    }
    put_body(body);
    return ret;
}

/* inspect request to rest */
static int inspect_request_to_rest(const struct isula_inspect_request *li_request, char **body, size_t *body_len)
{
    container_inspect_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_inspect_request));
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

    *body = container_inspect_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate inspect request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_inspect_request(crequest);
    return ret;
}

/* unpack inspect response */
static int unpack_inspect_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_inspect_response *response = arg;
    container_inspect_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_inspect_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid inspect response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = cresponse->cc;
    if (cresponse->container_json != NULL) {
        response->json = util_strdup_s(cresponse->container_json);
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
    free_container_inspect_response(cresponse);
    return ret;
}

/* rest container inspect */
static int rest_container_inspect(const struct isula_inspect_request *li_request,
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
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceInspect, body, len, &output);
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

/* exec request to rest */
static int exec_request_to_rest(const struct isula_exec_request *le_request, char **body, size_t *body_len)
{
    container_exec_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(container_exec_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    crequest->tty = le_request->tty;
    crequest->attach_stdin = le_request->attach_stdin;
    crequest->attach_stdout = le_request->attach_stdout;
    crequest->attach_stderr = le_request->attach_stderr;

    if (le_request->workdir != NULL) {
        crequest->workdir = util_strdup_s(le_request->workdir);
    }
    if (le_request->name != NULL) {
        crequest->container_id = util_strdup_s(le_request->name);
    }
    if (le_request->stdout != NULL) {
        crequest->stdout = util_strdup_s(le_request->stdout);
    }
    if (le_request->stdin != NULL) {
        crequest->stdin = util_strdup_s(le_request->stdin);
    }
    if (le_request->stderr != NULL) {
        crequest->stderr = util_strdup_s(le_request->stderr);
    }

    int i = 0;
    if (le_request->argc > 0) {
        if ((size_t)le_request->argc > SIZE_MAX / sizeof(char *)) {
            ERROR("Too many arguments!");
            ret = -1;
            goto out;
        }
        crequest->argv = (char **)util_common_calloc_s(sizeof(char *) * (size_t)le_request->argc);
        if (crequest->argv == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < le_request->argc; i++) {
            crequest->argv[i] = util_strdup_s(le_request->argv[i]);
        }
        crequest->argv_len = (size_t)le_request->argc;
    }
    if (le_request->env_len > 0) {
        if ((size_t)le_request->env_len > SIZE_MAX / sizeof(char *)) {
            ERROR("Too many environmental variables!");
            ret = -1;
            goto out;
        }
        crequest->env = (char **)util_common_calloc_s(sizeof(char *) * (size_t)le_request->env_len);
        if (crequest->env == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        for (i = 0; i < le_request->env_len; i++) {
            crequest->env[i] = util_strdup_s(le_request->env[i]);
        }
        crequest->env_len = (size_t)le_request->env_len;
    }

    *body = container_exec_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate exec request json:%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;
out:
    free(err);
    free_container_exec_request(crequest);
    return ret;
}

/* unpack exec response */
static int unpack_exec_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_exec_response *response = arg;
    container_exec_response *cresponse = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    cresponse = container_exec_response_parse_data(message->body, NULL, &err);
    if (cresponse == NULL) {
        ERROR("Invalid exec response:%s", err);
        ret = -1;
        goto out;
    }
    response->server_errono = cresponse->cc;
    response->exit_code = cresponse->exit_code;
    if (cresponse->errmsg != NULL) {
        response->errmsg = util_strdup_s(cresponse->errmsg);
    }
    ret = (cresponse->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_container_exec_response(cresponse);
    return ret;
}

/* rest container exec */
static int rest_container_exec(const struct isula_exec_request *le_request, struct isula_exec_response *le_response,
                               void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = exec_request_to_rest(le_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceExec, body, len, &output);
    if (ret != 0) {
        le_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        le_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_exec_response, (void *)le_response);
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

/* info request to rest */
static int info_request_to_rest(const struct isula_info_request *li_request, char **body, size_t *body_len)
{
    host_info_request *crequest = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;
    int ret = 0;

    crequest = util_common_calloc_s(sizeof(host_info_request));
    if (crequest == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    *body = host_info_request_generate_json(crequest, &ctx, &err);
    if (*body == NULL) {
        ERROR("Failed to generate info request json%s", err);
        ret = -1;
        goto out;
    }
    *body_len = strlen(*body) + 1;

out:
    free(err);
    free_host_info_request(crequest);
    return ret;
}

/* unpack info response */
static int unpack_info_response(const struct parsed_http_message *message, void *arg)
{
    struct isula_info_response *info_response = (struct isula_info_response *)arg;
    host_info_response *response = NULL;
    parser_error err = NULL;
    int ret = 0;

    ret = check_status_code(message->status_code);
    if (ret != 0) {
        goto out;
    }

    response = host_info_response_parse_data(message->body, NULL, &err);
    if (response == NULL) {
        ERROR("Invalid info response:%s", err);
        ret = -1;
        goto out;
    }

    info_response->server_errono = response->cc;
    if (response->version != NULL) {
        info_response->version = util_strdup_s(response->version);
    }
    if (response->kversion != NULL) {
        info_response->kversion = util_strdup_s(response->kversion);
    }
    if (response->os_type != NULL) {
        info_response->os_type = util_strdup_s(response->os_type);
    }
    if (response->architecture != NULL) {
        info_response->architecture = util_strdup_s(response->architecture);
    }
    if (response->nodename != NULL) {
        info_response->nodename = util_strdup_s(response->nodename);
    }
    if (response->operating_system != NULL) {
        info_response->operating_system = util_strdup_s(response->operating_system);
    }
    if (response->cgroup_driver != NULL) {
        info_response->cgroup_driver = util_strdup_s(response->cgroup_driver);
    }
    if (response->logging_driver != NULL) {
        info_response->logging_driver = util_strdup_s(response->logging_driver);
    }
    if (response->huge_page_size != NULL) {
        info_response->huge_page_size = util_strdup_s(response->huge_page_size);
    }
    if (response->isulad_root_dir != NULL) {
        info_response->isulad_root_dir = util_strdup_s(response->isulad_root_dir);
    }
    if (response->http_proxy != NULL) {
        info_response->http_proxy = util_strdup_s(response->http_proxy);
    }
    if (response->https_proxy != NULL) {
        info_response->https_proxy = util_strdup_s(response->https_proxy);
    }
    if (response->no_proxy != NULL) {
        info_response->no_proxy = util_strdup_s(response->no_proxy);
    }
    if (response->driver_name != NULL) {
        info_response->driver_name = util_strdup_s(response->driver_name);
    }
    if (response->driver_status != NULL) {
        info_response->driver_status = util_strdup_s(response->driver_status);
    }
    if (response->errmsg != NULL) {
        info_response->errmsg = util_strdup_s(response->errmsg);
    }
    info_response->total_mem = response->total_mem;
    info_response->containers_num = (uint32_t)response->containers_num;
    info_response->c_running = (uint32_t)response->c_running;
    info_response->c_paused = (uint32_t)response->c_paused;
    info_response->c_stopped = (uint32_t)response->c_stopped;
    info_response->images_num = (uint32_t)response->images_num;
    info_response->cpus = (uint32_t)response->cpus;

    ret = (response->cc == ISULAD_SUCCESS) ? 0 : -1;
    if (message->status_code == RESTFUL_RES_SERVERR) {
        ret = -1;
    }

out:
    free(err);
    free_host_info_response(response);
    return ret;
}

/* rest container info */
static int rest_container_info(const struct isula_info_request *li_request,
                               struct isula_info_response *li_response, void *arg)
{
    char *body = NULL;
    int ret = 0;
    size_t len = 0;
    client_connect_config_t *connect_config = (client_connect_config_t *)arg;
    const char *socketname = (const char *)(connect_config->socket);
    Buffer *output = NULL;

    ret = info_request_to_rest(li_request, &body, &len);
    if (ret != 0) {
        goto out;
    }
    ret = rest_send_requst(socketname, RestHttpHead ContainerServiceInfo, body, len, &output);
    if (ret != 0) {
        li_response->errmsg = util_strdup_s(errno_to_error_message(ISULAD_ERR_CONNECT));
        li_response->cc = ISULAD_ERR_EXEC;
        goto out;
    }
    ret = get_response(output, unpack_info_response, (void *)li_response);
    if (ret != 0) {
        goto out;
    }

out:
    buffer_free(output);
    put_body(body);
    return ret;
}

/* rest containers client ops init */
int rest_containers_client_ops_init(isula_connect_ops *ops)
{
    if (ops == NULL) {
        return -1;
    }

    ops->container.create = &rest_container_create;
    ops->container.start = &rest_container_start;
    ops->container.stop = &rest_container_stop;
    ops->container.restart = &rest_container_restart;
    ops->container.remove = &rest_container_remove;
    ops->container.inspect = &rest_container_inspect;
    ops->container.list = &rest_container_list;
    ops->container.exec = &rest_container_exec;
    ops->container.pause = &rest_container_pause;
    ops->container.attach = &rest_container_attach;
    ops->container.resume = &rest_container_resume;
    ops->container.update = &rest_container_update;
    ops->container.kill = &rest_container_kill;
    ops->container.version = &rest_container_version;
    ops->container.wait = &rest_container_wait;
    ops->container.info = &rest_container_info;

    return 0;
}
