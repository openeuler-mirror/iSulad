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

#ifndef HTTP_MOCK_H_
#define HTTP_MOCK_H_

#include <gmock/gmock.h>
#include "http.h"

class MockHttp {
public:
    virtual ~MockHttp() = default;
    MOCK_METHOD4(HttpRequest, int(const char *url, struct http_get_options *options, long *response_code,
                                  int recursive_len));
};

void MockHttp_SetMock(MockHttp* mock);

#endif // HTTP_MOCK_H_
