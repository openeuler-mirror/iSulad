/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: id name manager unit test
 * Author: zhongtao
 * Create: 2023-07-14
 */
#include <gtest/gtest.h>

#include "id_name_manager.h"

TEST(id_name_manager, test_id_manager)
{
    // before id_store_init()
    char *id = get_new_id();
    ASSERT_EQ(id, nullptr);
    ASSERT_EQ(try_add_id("id"), false);

    // after id_store_init()
    ASSERT_EQ(id_store_init(), 0);
    id = get_new_id();
    ASSERT_NE(id, nullptr);
    ASSERT_EQ(try_add_id(""), false);
    ASSERT_EQ(try_add_id("id"), true);
    ASSERT_EQ(try_add_id(id), false);

    ASSERT_EQ(try_remove_id(""), false);
    ASSERT_EQ(try_remove_id(id), true);
    ASSERT_EQ(try_remove_id(id), false);
    id_store_free();
    free(id);
}

TEST(id_name_manager, test_name_manager)
{
    // before name_store_init()
    ASSERT_EQ(try_add_name("name"), false);

    // after name_store_init()
    std::string name = "name";
    ASSERT_EQ(name_store_init(), 0);
    ASSERT_EQ(try_add_name(""), false);
    ASSERT_EQ(try_add_name(name.c_str()), true);
    ASSERT_EQ(try_add_name(name.c_str()), false);

    ASSERT_EQ(try_remove_name(""), false);
    ASSERT_EQ(try_remove_name(name.c_str()), true);
    ASSERT_EQ(try_remove_name(name.c_str()), false);
    name_store_free();
}