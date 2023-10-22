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

#ifndef ISULAD_TEST_MOCKS_IMAGE_API_MOCK_H
#define ISULAD_TEST_MOCKS_IMAGE_API_MOCK_H

#include <gmock/gmock.h>
#include <memory>

#include "image_api.h"

class MockImageApi {
public:
    MOCK_METHOD2(ImImageSummary, int(im_summary_request *request, im_summary_response **response));
    MOCK_METHOD1(FreeImSummaryRequest, void(im_summary_request *request));
    MOCK_METHOD1(FreeImSummaryResponse, void(im_summary_response *response));
};

void MockImageApi_SetMock(std::shared_ptr<MockImageApi> mock);

#endif
