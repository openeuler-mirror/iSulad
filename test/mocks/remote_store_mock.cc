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

#include "remote_store_mock.h"

namespace {
MockRemoteStore *g_remote_store_mock = nullptr;
}

int remote_load_one_layer(const char *id)
{
    if (g_remote_store_mock != nullptr) {
        return g_remote_store_mock->LayerLoadOneLayer(id);
    }
    return -1;
}

int remote_layer_remove_memory_stores_with_lock(const char *id)
{
    if (g_remote_store_mock != nullptr) {
        return g_remote_store_mock->LayerRemoveOneLayer(id);
    }
    return -1;
}

int image_store_validate_manifest_schema_version_1(const char *path, bool *valid)
{
    if (g_remote_store_mock != nullptr) {
        return g_remote_store_mock->ImageValidSchemaV1(path, valid);
    }
    return -1;
}

int remote_append_image_by_directory_with_lock(const char *image_dir)
{
    if (g_remote_store_mock != nullptr) {
        return g_remote_store_mock->ImageAppendOneImage(image_dir);
    }
    return -1;
}

int remote_remove_image_from_memory_with_lock(const char *id)
{
    if (g_remote_store_mock != nullptr) {
        return g_remote_store_mock->ImageRemoveOneImage(id);
    }
    return -1;
}

char *remote_image_get_top_layer_from_json(const char *img_id)
{
    if (g_remote_store_mock != nullptr) {
        return g_remote_store_mock->ImageGetTopLayer(img_id);
    }
    return nullptr;
}
