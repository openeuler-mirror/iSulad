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
 * Create: 2020-02-19
 * Description: provide image mock
 ******************************************************************************/

#include "image_mock.h"

namespace {
MockImage *g_image_mock = NULL;
}

void MockImage_SetMock(MockImage* mock)
{
    g_image_mock = mock;
}

int im_get_storage_status(const char *image_type, im_storage_status_response **response)
{
    if (g_image_mock != nullptr) {
        return g_image_mock->ImGetStorageStatus(image_type, response);
    }
    return -1;
}

void free_im_storage_status_response(im_storage_status_response *ptr)
{
    if (g_image_mock != nullptr) {
        g_image_mock->FreeImStorageStatusResponse(ptr);
        return;
    }
    return;
}

int im_container_export(const im_export_request *request)
{
    if (g_image_mock != nullptr) {
        return g_image_mock->ImContainerExport(request);
    }
    return 0;
}

void free_im_export_request(im_export_request *ptr)
{
    if (g_image_mock != nullptr) {
        return g_image_mock->FreeImExportRequest(ptr);
    }
}
