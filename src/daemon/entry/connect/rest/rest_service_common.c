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
 * Description: provide container restful service common functions
 ******************************************************************************/
#include "rest_service_common.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"

#define UNIX_PATH_MAX 128
#define MAX_BODY_SIZE 8192

/* get body */
int get_body(const evhtp_request_t *req, size_t *size_out, char **record_out)
{
    evbuf_t *buf = req->buffer_in;
    size_t read_count = 0;
    size_t total = 0;
    size_t content_len = 0;
    char *body_out = NULL;
    char *body_p = NULL;
    int ret = 0;

    content_len = (size_t)evbuffer_get_length(buf);

    if (content_len >= MAX_BODY_SIZE) {
        ERROR("too big request,size: %zu", content_len);
        ret = -1;
        goto empty;
    } else if (content_len == 0) {
        ret = 0;
        goto empty;
    } else {
        body_out = util_common_calloc_s(content_len + 1);
        if (body_out == NULL) {
            ret = -1;
            ERROR("no valid memory");
            goto empty;
        }
    }

    body_p = body_out;
    read_count = (size_t)evbuffer_get_length(buf);
    while (read_count != 0) {
        int n;
        total += read_count;
        if (total > content_len) {
            ret = -1;
            ERROR("Read count out of range");
            free(body_out);
            goto empty;
        }
        n = evbuffer_remove(buf, body_p, content_len);
        body_p += n;

        read_count = (size_t)evbuffer_get_length(buf);
    }
    *size_out = content_len;
    *record_out = body_out;
    return ret;

empty:
    *size_out = 0;
    *record_out = NULL;
    return ret;
}

/* evhtp send repsponse */
void evhtp_send_response(evhtp_request_t *req, const char *responsedata, int rescode)
{
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "application/json", 0, 0));
    evbuffer_add(req->buffer_out, responsedata, strlen(responsedata));
    evhtp_send_reply(req, rescode);
}

