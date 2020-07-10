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
 * Create: 2020-02-19
 * Description: provide image mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_IMAGE_MOCK_H
#define _ISULAD_TEST_MOCKS_IMAGE_MOCK_H

#include <gmock/gmock.h>
#include "image_api.h"

class MockImage {
public:
    virtual ~MockImage() = default;
    MOCK_METHOD1(ImContainerExport, int(const im_export_request *request));
    MOCK_METHOD1(FreeImExportRequest, void(im_export_request *ptr));
};

void MockImage_SetMock(MockImage *mock);

#endif // _ISULAD_TEST_MOCKS_IMAGE_MOCK_H
