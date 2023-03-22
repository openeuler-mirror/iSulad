/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2023-03-16
 * Description: provide remote layer support ut
 ******************************************************************************/
#include <gtest/gtest.h>

#include "remote_store_mock.h"
#include "ro_symlink_maintain.h"
#include "remote_support.h"
#include "map.h"

using ::testing::Invoke;

bool invokeOverlayRemoteLayerValid(const char *id)
{
    return true; /* currently always valid overlay layer */
}

bool invokeLayerRemoteLayerValid(const char *id)
{
    return true;
}

int invokeLayerLoadOneLayer(const char *id)
{
    return 0;
}

int invokeLayerRemoveOneLayer(const char *id)
{
    return 0;
}

int invokeImageAppendOneImage(const char *id)
{
    return 0;
}

int invokeImageRemoveOneImage(const char *id)
{
    return 0;
}

char *invokeImageGetTopLayer(const char *id)
{
    return NULL;
}

int invokeImageValidSchemaV1(const char *path, bool *valid)
{
    return 0;
}

void mockCommonAll(MockRemoteStore *mock)
{
    EXPECT_CALL(*mock, LayerLoadOneLayer(::testing::_)).WillRepeatedly(Invoke(invokeLayerLoadOneLayer));
    EXPECT_CALL(*mock, LayerRemoveOneLayer(::testing::_)).WillRepeatedly(Invoke(invokeLayerRemoveOneLayer));

    EXPECT_CALL(*mock, ImageAppendOneImage(::testing::_)).WillRepeatedly(Invoke(invokeImageAppendOneImage));
    EXPECT_CALL(*mock, ImageRemoveOneImage(::testing::_)).WillRepeatedly(Invoke(invokeImageRemoveOneImage));
    EXPECT_CALL(*mock, ImageGetTopLayer(::testing::_)).WillRepeatedly(Invoke(invokeImageGetTopLayer));
    EXPECT_CALL(*mock, ImageValidSchemaV1(::testing::_, ::testing::_)).WillRepeatedly(Invoke(invokeImageValidSchemaV1));
}

TEST(remote_Layer_ut, test_map_diff)
{
    // old: a b x 
    // new: x b c
    map_t *old_one = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    map_t *new_one = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    bool exist = true;

    map_insert(old_one, (void *)"a", (void *)&exist);
    map_insert(old_one, (void *)"b", (void *)&exist);
    map_insert(new_one, (void *)"b", (void *)&exist);
    map_insert(new_one, (void *)"c", (void *)&exist);

    char **added = remote_added_layers(old_one, new_one);
    char **deleted = remote_deleted_layers(old_one, new_one);

    ASSERT_EQ(added[0][0], 'c');
    ASSERT_EQ(deleted[0][0], 'a');
}
