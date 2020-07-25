/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2020-07-01
 * Description: provide http mock
 ******************************************************************************/

#include "http_mock.h"

namespace {
MockHttp *g_http_mock = NULL;
}

void MockHttp_SetMock(MockHttp *mock)
{
    g_http_mock = mock;
}

int http_request(const char *url, struct http_get_options *options, long *response_code, int recursive_len)
{
    if (g_http_mock != NULL) {
        return g_http_mock->HttpRequest(url, options, response_code, recursive_len);
    }

    return -1;
}
