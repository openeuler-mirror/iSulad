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
 * Author: wangrunze
 * Create: 2023-03-09
 * Description: provide mock for image store, layer store and driver overlay
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_REMOTE_STORE_MOCK_H
#define _ISULAD_TEST_MOCKS_REMOTE_STORE_MOCK_H

#include <gmock/gmock.h>

#include "image_store.h"
#include "layer_store.h"
#include "driver_overlay2.h"

class MockRemoteStore {
public:
    virtual ~MockRemoteStore() = default;
    // MOCK_METHOD1(OverlayRemoteLayerValid, bool(const char *));

    // MOCK_METHOD1(LayerRemoteLayerValid, bool(const char *));
    MOCK_METHOD1(LayerLoadOneLayer, int(const char *));
    MOCK_METHOD1(LayerRemoveOneLayer, int(const char *));

    MOCK_METHOD1(ImageAppendOneImage, int(const char *));
    MOCK_METHOD1(ImageRemoveOneImage, int(const char *));
    MOCK_METHOD1(ImageGetTopLayer, char *(const char *));
    MOCK_METHOD2(ImageValidSchemaV1, int(const char *, bool *));
};

#endif // _ISULAD_TEST_MOCKS_IMAGE_MOCK_H
