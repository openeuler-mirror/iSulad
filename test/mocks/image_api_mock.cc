/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jikai
 * Create: 2023-10-20
 * Description: provide image api mock
 ******************************************************************************/

#include "image_api_mock.h"

namespace {
std::shared_ptr<MockImageApi> g_image_api_mock = nullptr;
}

void MockImageApi_SetMock(std::shared_ptr<MockImageApi> mock)
{
    g_image_api_mock = mock;
}

int im_image_summary(im_summary_request *request, im_summary_response **response)
{
    if (g_image_api_mock != nullptr) {
        return g_image_api_mock->ImImageSummary(request, response);
    }
    return 0;
}

void free_im_summary_request(im_summary_request *request)
{
    if (g_image_api_mock != nullptr) {
        g_image_api_mock->FreeImSummaryRequest(request);
    }
}

void free_im_summary_response(im_summary_response *response)
{
    if (g_image_api_mock != nullptr) {
        g_image_api_mock->FreeImSummaryResponse(response);
    }
}
