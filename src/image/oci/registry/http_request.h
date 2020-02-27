/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2020-03-05
 * Description: provide http request definition
 ******************************************************************************/
#ifndef __IMAGE_HTTP_REQUEST_H
#define __IMAGE_HTTP_REQUEST_H

#include "registry_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HEAD_ONLY = 0,
    BODY_ONLY = 1,
    HEAD_BODY = 2,
} resp_data_type;

int http_request_buf(pull_descriptor *desc, const char *url, const char **custom_headers, char **output,
                     resp_data_type type);
int http_request_file(pull_descriptor *desc, const char *url, const char **custom_headers, char *file);

#ifdef __cplusplus
}
#endif

#endif

