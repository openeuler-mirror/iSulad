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
 * Author: WuJing
 * Create: 2020-04-26
 * Description: provide image storage mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_STORAGE_MOCK_H
#define _ISULAD_TEST_MOCKS_STORAGE_MOCK_H

#include <gmock/gmock.h>
#include "storage.h"

class MockStorage {
public:
    virtual ~MockStorage() = default;
    MOCK_METHOD1(StorageLayersGetByUncompressDigest, struct layer_list * (const char *digest));
    MOCK_METHOD1(FreeLayerList, void(struct layer_list *ptr));
    MOCK_METHOD4(StorageImgCreate, int(const char *id, const char *parent_id, const char *metadata,
                                       struct storage_img_create_options *opts));
    MOCK_METHOD1(StorageImgGet, imagetool_image * (const char *img_id));
    MOCK_METHOD3(StorageImgSetBigData, int(const char *img_id, const char *key, const char *val));
    MOCK_METHOD2(StorageImgAddName, int(const char *img_id, const char *img_name));
    MOCK_METHOD2(StorageImgDelete, int(const char *img_id, bool commit));
    MOCK_METHOD2(StorageImgSetLoadedTime, int(const char *img_id, types_timestamp_t *loaded_time));
    MOCK_METHOD1(StorageImgSetImageSize, int(const char *image_id));
    MOCK_METHOD1(StorageGetImgTopLayer, char * (const char *id));
    MOCK_METHOD2(StorageLayerCreate, int(const char *layer_id, storage_layer_create_opts_t *opts));
    MOCK_METHOD1(StorageLayerGet, struct layer * (const char *layer_id));
    MOCK_METHOD2(StorageLayerTryRepairLowers, int(const char *layer_id, const char *last_layer_id));
    MOCK_METHOD1(FreeLayer, void(struct layer *l));
};

void MockStorage_SetMock(MockStorage* mock);

#endif // _ISULAD_TEST_MOCKS_STORAGE_MOCK_H
