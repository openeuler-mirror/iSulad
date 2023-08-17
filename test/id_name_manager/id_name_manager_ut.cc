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

TEST(id_name_manager, test_id_name_manager)
{
    char *id = NULL;
    // before id_name_manager_init()
    ASSERT_EQ(id_name_manager_add_entry_with_new_id("name", &id), false);
    ASSERT_EQ(id, nullptr);

    // after id_name_manager_init()
    ASSERT_EQ(id_name_manager_init(), 0);

    ASSERT_EQ(id_name_manager_add_entry_with_existing_id(NULL, "name_testNULL"), false);
    ASSERT_EQ(id_name_manager_add_entry_with_new_id_and_name(&id, NULL), false);
    ASSERT_EQ(id_name_manager_add_entry_with_new_id(NULL, NULL), false);

    ASSERT_EQ(id_name_manager_add_entry_with_new_id("", &id), false);
    ASSERT_EQ(id_name_manager_add_entry_with_new_id("name", &id), true);
    ASSERT_NE(id, nullptr);
    ASSERT_EQ(id_name_manager_add_entry_with_existing_id(id, "name2"), false);
    ASSERT_EQ(id_name_manager_add_entry_with_existing_id("12345678", "name"), false);

    char *name = NULL;
    char *id2 = NULL;
    ASSERT_EQ(id_name_manager_add_entry_with_new_id_and_name(&id2, &name), true);
    ASSERT_STREQ(id2, name);

    ASSERT_EQ(id_name_manager_remove_entry("", NULL), false);
    ASSERT_EQ(id_name_manager_remove_entry("12345678", "name2"), false);

    ASSERT_EQ(id_name_manager_remove_entry(NULL, NULL), true);
    ASSERT_EQ(id_name_manager_remove_entry(id, "name"), true);
    ASSERT_EQ(id_name_manager_remove_entry(id2, name), true);

    id_name_manager_release();
    free(id);
}