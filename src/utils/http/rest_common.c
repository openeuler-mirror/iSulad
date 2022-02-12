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
 * Description: provide rest common functions
 ******************************************************************************/
#include "rest_common.h"

#include <dlfcn.h>
#include <string.h>
#include <http_parser.h>
#include <stdlib.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "buffer.h"
#include "http.h"
#include "parser.h"
#include "utils_string.h"

typedef size_t (*buffer_strlen_t)(Buffer *buf);
typedef int (*parse_http_t)(const char *buf, size_t len, struct parsed_http_message *m, enum http_parser_type type);
typedef Buffer *(*buffer_alloc_t)(size_t initial_size);
typedef void (*buffer_free_t)(Buffer *buf);
typedef int (*http_request_t)(const char *url, struct http_get_options *options, long *response_code,
                              int recursive_len);
typedef void (*free_http_get_options_t)(struct http_get_options *options);

struct httpclient_ops {
    void *handle;

    parse_http_t parse_http_op;
    http_request_t http_request_op;
    free_http_get_options_t free_http_get_options_op;

    buffer_strlen_t buffer_strlen_op;
    buffer_alloc_t buffer_alloc_op;
    buffer_free_t buffer_free_op;
};

static struct httpclient_ops g_hc_ops;

/*
 * dlclose may leak the fd which is opened by dlopen in lower version of glibc,
 * to avoid reach the fd limit when call http request multiple times,
 * we limited the max times of open libhttpclient to 3, make sure we can release memory
 * in subcmd run (include rest request of create, start, need call dlclose 2 times).
 */
#define MAX_KEEP_OPS_CNT 3
static int g_ops_status = 0;

/* check status code */
int check_status_code(int status_code)
{
    if (status_code == RESTFUL_RES_OK || status_code == RESTFUL_RES_SERVERR) {
        return 0;
    } else if (status_code == RESTFUL_RES_NOTIMPL) {
        ERROR("Not implement interface");
        return -1;
    } else if (status_code == RESTFUL_RES_NOTFOUND) {
        ERROR("Can not connect to service");
        return -1;
    } else if (status_code == RESTFUL_RES_ERROR) {
        ERROR("Server internal error");
        return -1;
    }

    ERROR("Unknown http status found:'%d'", status_code);
    return -1;
}

/* free httpclient ops */
static void free_httpclient_ops(struct httpclient_ops *ops)
{
    if (ops == NULL || ops->handle == NULL) {
        return;
    }
    if (g_ops_status == MAX_KEEP_OPS_CNT) {
        return;
    }
    dlclose(ops->handle);
    (void)memset(ops, 0, sizeof(struct httpclient_ops));
}

/* ops init */
static int ops_init(struct httpclient_ops *ops)
{
    void *handle = NULL;
    int ret = -1;

    if (ops == NULL) {
        return ret;
    }
    (void)memset(ops, 0, sizeof(struct httpclient_ops));
    handle = dlopen("libhttpclient.so", RTLD_LAZY);
    if (handle == NULL) {
        COMMAND_ERROR("Dlopen libhttpclient: %s", dlerror());
        goto out;
    }
    ops->handle = handle;
    ops->buffer_strlen_op = (buffer_strlen_t)dlsym(handle, "buffer_strlen");
    if (ops->buffer_strlen_op == NULL) {
        COMMAND_ERROR("dlsym buffer_strlen: %s", dlerror());
        goto badcleanup;
    }
    ops->buffer_alloc_op = (buffer_alloc_t)dlsym(handle, "buffer_alloc");
    if (ops->buffer_alloc_op == NULL) {
        COMMAND_ERROR("dlsym buffer_alloc: %s", dlerror());
        goto badcleanup;
    }
    ops->buffer_free_op = (buffer_free_t)dlsym(handle, "buffer_free");
    if (ops->buffer_free_op == NULL) {
        COMMAND_ERROR("dlsym buffer_free: %s", dlerror());
        goto badcleanup;
    }
    ops->parse_http_op = (parse_http_t)dlsym(handle, "parse_http");
    if (ops->parse_http_op == NULL) {
        COMMAND_ERROR("dlsym parse_http: %s", dlerror());
        goto badcleanup;
    }
    ops->http_request_op = (http_request_t)dlsym(handle, "http_request");
    if (ops->http_request_op == NULL) {
        COMMAND_ERROR("dlsym http_request: %s", dlerror());
        goto badcleanup;
    }
    ops->free_http_get_options_op = (free_http_get_options_t)dlsym(handle, "free_http_get_options");
    if (ops->free_http_get_options_op == NULL) {
        COMMAND_ERROR("dlsym free_http_get_options: %s", dlerror());
        goto badcleanup;
    }

    g_ops_status++;
    if (g_ops_status > MAX_KEEP_OPS_CNT) {
        g_ops_status = MAX_KEEP_OPS_CNT;
    }

    return 0;
badcleanup:
    ERROR("bad cleanup");
    free_httpclient_ops(ops);
out:
    return ret;
}

/* get response */
int get_response(Buffer *output, unpack_response_func_t unpack_func, void *arg)
{
    char *tmp = NULL;
    int ret = 0;
    size_t reslen = 0;
    struct parsed_http_message *msg = NULL;

    if (output == NULL || unpack_func == NULL) {
        ERROR("Invalid parameter");
        return -1;
    }

    if (g_hc_ops.handle == NULL || g_hc_ops.parse_http_op == NULL || g_hc_ops.buffer_strlen_op == NULL) {
        ERROR("http client ops is null");
        return -1;
    }
    msg = util_common_calloc_s(sizeof(struct parsed_http_message));
    if (msg == NULL) {
        ERROR("Failed to malloc memory");
        ret = -1;
        goto out;
    }

    tmp = strstr(output->contents, "HTTP/1.1");
    if (tmp == NULL) {
        ERROR("Failed to parse response, the response did not have HTTP/1.1\n");
        ret = -1;
        goto out;
    }

    reslen = g_hc_ops.buffer_strlen_op(output) - (size_t)(tmp - output->contents);

    ret = g_hc_ops.parse_http_op(tmp, reslen, msg, HTTP_RESPONSE);
    if (ret != 0) {
        ERROR("Failed to parse response, the response did not have HTTP/1.1\n");
        ret = -1;
        goto out;
    }

    ret = unpack_func(msg, arg);

out:
    free_httpclient_ops(&g_hc_ops);
    if (msg != NULL) {
        if (msg->body != NULL) {
            free(msg->body);
        }
        free(msg);
    }

    return ret;
}

static int init_http_client_opt()
{
    if (g_hc_ops.handle == NULL && ops_init(&g_hc_ops) != 0) {
        return -1;
    }
    if (g_hc_ops.http_request_op == NULL || g_hc_ops.buffer_alloc_op == NULL ||
        g_hc_ops.free_http_get_options_op == NULL) {
        return -1;
    }

    return 0;
}

static int set_http_get_options(const char *socket, char *request_body, size_t body_len,
                                struct http_get_options *options, Buffer **output)
{
    Buffer *output_buffer = NULL;
    const char *unix_raw_socket = NULL;
    const char *raw_socket = NULL;

    options->with_head = 1;
    options->with_header_json = 1;
    options->input = request_body;

    options->input_len = body_len;
    raw_socket = socket;
    unix_raw_socket = util_str_skip_str(raw_socket, "unix://");
    if (unix_raw_socket == NULL) {
        ERROR("Failed to util_str_skip_str  raw_socket");
        return -1;
    }
    options->unix_socket_path = util_strdup_s(unix_raw_socket);
    output_buffer = g_hc_ops.buffer_alloc_op(HTTP_GET_BUFFER_SIZE);
    if (output_buffer == NULL) {
        ERROR("Failed to malloc output_buffer");
        return -1;
    }

    *output = output_buffer;
    options->outputtype = HTTP_REQUEST_STRBUF;
    options->output = output_buffer;

    return 0;
}

/* rest send requst */
int rest_send_requst(const char *socket, const char *url, char *request_body, size_t body_len, Buffer **output)
{
    long response_code = 0;
    int ret = 0;
    struct http_get_options *options = NULL;

    if (socket == NULL || url == NULL || request_body == NULL || output == NULL) {
        ERROR("Invalid parameter");
        return -1;
    }
    if (init_http_client_opt()) {
        ERROR("Failed to init g_hc_ops");
        free_httpclient_ops(&g_hc_ops);
        return -1;
    }

    options = util_common_calloc_s(sizeof(struct http_get_options));
    if (options == NULL) {
        ERROR("Failed to malloc http_get_options");
        return -1;
    }

    if (set_http_get_options(socket, request_body, body_len, options, output)) {
        ret = -1;
        goto out;
    }

    ret = g_hc_ops.http_request_op(url, options, &response_code, 0);
    if (ret != 0) {
        ERROR("Failed to get http request: %d", ret);
        ret = -1;
        goto out;
    }

out:
    g_hc_ops.free_http_get_options_op(options);
    if (ret != 0) {
        free_httpclient_ops(&g_hc_ops);
    }
    return ret;
}

/* put body */
void put_body(char *body)
{
    free(body);
}
