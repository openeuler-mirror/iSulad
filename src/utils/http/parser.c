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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container parser functions
 ******************************************************************************/
/*
 * Since some of this code is derived from http-parser, their copyright
 * is retained here....
 *
 * Copyright Joyent, Inc. and other Node contributors.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "parser.h"
#include <http_parser.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "utils.h"
#include "isula_libutils/log.h"

size_t strlncat(char *dststr, size_t size, const char *srcstr, size_t nsize)
{
    size_t ssize, dsize;

    ssize = (size_t)strnlen(srcstr, nsize);
    dsize = (size_t)strnlen(dststr, size);

    if (dsize < size) {
        size_t rsize = size - dsize;
        size_t ncpy = ssize < rsize ? ssize : (rsize - 1);
        (void)memcpy(dststr + dsize, srcstr, ncpy);
        dststr[dsize + ncpy] = '\0';
    }

    return ssize + dsize;
}

/* parser cb request url */
static int parser_cb_request_url(http_parser *parser, const char *buf,
                                 size_t len)
{
    struct parsed_http_message *m = parser->data;

    strlncat(m->request_url, sizeof(m->request_url), buf, len);
    return 0;
}

/* parser cb header field */
static int parser_cb_header_field(http_parser *parser, const char *buf,
                                  size_t len)
{
    struct parsed_http_message *m = parser->data;

    if (m->last_header_element != FIELD) {
        if (m->num_headers + 1 >= MAX_HEADERS) {
            ERROR("too many headers exceeded maxium number %d", MAX_HEADERS);
            return -1;
        }
        m->num_headers++;
    }

    strlncat(m->headers[m->num_headers - 1][0], sizeof(m->headers[m->num_headers - 1][0]), buf, len);

    m->last_header_element = FIELD;

    return 0;
}

/* parser cb header value */
static int parser_cb_header_value(http_parser *parser, const char *buf,
                                  size_t len)
{
    struct parsed_http_message *m = parser->data;

    strlncat(m->headers[m->num_headers - 1][1], sizeof(m->headers[m->num_headers - 1][1]), buf, len);
    m->last_header_element = VALUE;
    return 0;
}

/* parser check body is final */
static void parser_check_body_is_final(const http_parser *parser)
{
    struct parsed_http_message *m = parser->data;

    if (m->body_is_final) {
        fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
                "on last on_body callback call "
                "but it doesn't! ***\n\n");
        abort();
    }
    m->body_is_final = http_body_is_final(parser);
}

/* parser body cb */
static int parser_body_cb(http_parser *parser, const char *buf, size_t len)
{
    struct parsed_http_message *m = parser->data;
    size_t newsize;
    char *body = NULL;
    if (m->body_size > (SIZE_MAX - len) - 1) {
        ERROR("http body size is too large!");
        return -1;
    }
    newsize = m->body_size + len + 1;
    body = util_common_calloc_s(newsize);
    if (body == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    if (m->body != NULL && m->body_size > 0) {
        (void)memcpy(body, m->body, m->body_size);
        free(m->body);
    }

    m->body = body;

    strlncat(m->body, newsize, buf, len);
    m->body_size += len;
    parser_check_body_is_final(parser);
    return 0;
}

/* parser message begin cb */
static int parser_message_begin_cb(http_parser *p)
{
    struct parsed_http_message *m = p->data;
    m->message_begin_cb_called = TRUE;
    return 0;
}

/* parser headers complete cb */
static int parser_headers_complete_cb(http_parser *p)
{
    struct parsed_http_message *m = p->data;
    m->method = p->method;
    m->status_code = (int)(p->status_code);
    m->http_major = p->http_major;
    m->http_minor = p->http_minor;
    m->headers_complete_cb_called = TRUE;
    m->should_keep_alive = http_should_keep_alive(p);
    return 0;
}

/* parser message complete cb */
static int parser_message_complete_cb(http_parser *p)
{
    struct parsed_http_message *m = p->data;

    if (m->should_keep_alive != http_should_keep_alive(p)) {
        fprintf(stderr, "\n\n *** Error http_should_keep_alive() should have same "
                "value in both on_message_complete and on_headers_complete "
                "but it doesn't! ***\n\n");
        abort();
    }

    if (m->body_size &&
        http_body_is_final(p) &&
        !m->body_is_final) {
        fprintf(stderr, "\n\n *** Error http_body_is_final() should return 1 "
                "on last on_body callback call "
                "but it doesn't! ***\n\n");
        abort();
    }

    m->message_complete_cb_called = TRUE;


    return 0;
}

/* parser response status cb */
static int parser_response_status_cb(http_parser *p, const char *buf,
                                     size_t len)
{
    struct parsed_http_message *m = p->data;

    m->status_cb_called = TRUE;

    strlncat(m->response_status, sizeof(m->response_status), buf,
             len);
    return 0;
}

/* parser chunk header cb */
static int parser_chunk_header_cb(http_parser *p)
{
    struct parsed_http_message *m = p->data;

    int chunk_idx = m->num_chunks;
    m->num_chunks++;
    if (chunk_idx < MAX_CHUNKS && chunk_idx >= 0) {
        m->chunk_lengths[chunk_idx] = (int)p->content_length;
    }

    return 0;
}

/* parser chunk complete cb */
static int parser_chunk_complete_cb(http_parser *p)
{
    struct parsed_http_message *m = p->data;

    /* Here we want to verify that each chunk_header_cb is matched by a
     * chunk_complete_cb, so not only should the total number of calls to
     * both callbacks be the same, but they also should be interleaved
     * properly */
    if (m->num_chunks != m->num_chunks_complete + 1) {
        ERROR("chunk_header_cb is not matched by chunk_complate_cb");
        return -1;
    }

    m->num_chunks_complete++;
    return 0;
}

static http_parser_settings g_settings = {
    .on_message_begin = parser_message_begin_cb,
    .on_header_field = parser_cb_header_field,
    .on_header_value = parser_cb_header_value,
    .on_url = parser_cb_request_url,
    .on_status = parser_response_status_cb,
    .on_body = parser_body_cb,
    .on_headers_complete = parser_headers_complete_cb,
    .on_message_complete = parser_message_complete_cb,
    .on_chunk_header = parser_chunk_header_cb,
    .on_chunk_complete = parser_chunk_complete_cb
};

/* parser init */
static http_parser *parser_init(enum http_parser_type type,
                                struct parsed_http_message *m)
{
    http_parser *parser = NULL;

    parser = util_common_calloc_s(sizeof(http_parser));
    if (parser == NULL) {
        return NULL;
    }

    parser->data = m;

    http_parser_init(parser, type);

    return parser;
}

/* parser free */
static void parser_free(http_parser *parser)
{
    free(parser);
}

/* parse */
static size_t parse(const char *buf, size_t len, http_parser *parser)
{
    size_t nparsed;
    nparsed = http_parser_execute(parser, &g_settings, buf, len);
    return nparsed;
}

/* parse http */
int parse_http(const char *buf, size_t len, struct parsed_http_message *m,
               enum http_parser_type type)
{
    int ret = 0;
    http_parser *parser = NULL;
    size_t nparsed = 0;

    parser = parser_init(type, m);
    if (parser == NULL) {
        ret = -1;
        goto out;
    }

    nparsed = parse(buf, len, parser);
    if (nparsed != len) {
        ERROR("Failed to parse it, parsed :%zu, intput:%zu \n", nparsed, len);
        ret = -1;
        goto free_out;
    }

free_out:
    parser_free(parser);
out:
    return ret;
}

char *get_header_value(const struct parsed_http_message *m, const char *header)
{
    int i = 0;
    char *ret = NULL;

    for (i = 0; i < m->num_headers; i++) {
        if (strcmp(m->headers[i][0], header) == 0) {
            ret = (char *)m->headers[i][1];
            break;
        }
    }

    return ret;
}
