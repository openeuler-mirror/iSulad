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
 * Description: provide container restful common function definition
 ******************************************************************************/
#ifndef __REST_COMMON_H
#define __REST_COMMON_H

#include "http/buffer.h"
#include "http/http.h"
#include "parser.h"

#ifdef __cplusplus
extern "C" {
#endif

// Response status from restful server
#define RESTFUL_RES_ERROR 0
#define RESTFUL_RES_OK 200
#define RESTFUL_RES_NOTFOUND 404
#define RESTFUL_RES_SERVERR 500
#define RESTFUL_RES_NOTIMPL 501

typedef int (*unpack_response_func_t)(const struct parsed_http_message *message, void *arg);

int get_response(Buffer *output, unpack_response_func_t unpack_func, void *arg);

int rest_send_requst(const char *socket, const char *url, char *request_body, size_t body_len, Buffer **output);

int check_status_code(int status_code);

void put_body(char *body);

#ifdef __cplusplus
}
#endif

#endif /* __REST_COMMON_H */

