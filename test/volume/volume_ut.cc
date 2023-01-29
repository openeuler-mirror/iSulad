/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: volume unit test
 * Author: zhongtao
 * Create: 2022-09-01
 */

#include <gtest/gtest.h>
#include "volume_api.h"
#include "local.h"

TEST(volume_ut, test_volume_api)
{
    const char *root_dir = static_cast<const char*>("/var/lib/isulad");

    int init = volume_init(root_dir);
    EXPECT_EQ(init, 0);

    // test register_driver
    char *driver_name_local = (char *)VOLUME_DEFAULT_DRIVER_NAME;
    volume_driver *volume_driver_null = nullptr;

    EXPECT_EQ(register_driver(driver_name_local, volume_driver_null), -1);

    volume_driver volume_driver_create_null = {
        .create = nullptr,
        .get = local_volume_get,
        .mount = local_volume_mount,
        .umount = local_volume_umount,
        .list = local_volume_list,
        .remove = local_volume_remove,
    };

    EXPECT_EQ(register_driver(driver_name_local, &volume_driver_create_null), -1);

    volume_driver volume_driver_complete = {
        .create = local_volume_create,
        .get = local_volume_get,
        .mount = local_volume_mount,
        .umount = local_volume_umount,
        .list = local_volume_list,
        .remove = local_volume_remove,
    };

    EXPECT_EQ(register_driver(driver_name_local, &volume_driver_complete), -1);

    // test volume_create
    char *volume_name_test = (char *)"create_test";
    struct volume_options *opts_null = nullptr;

    struct volume *create_failed = volume_create(driver_name_local, volume_name_test, opts_null);
    EXPECT_EQ(create_failed, nullptr);

    struct volume_options opts_complete;
    char *ref_id1 = (char *)"6c5dd5bacb14";
    opts_complete.ref = ref_id1;

    struct volume *create_success = volume_create(driver_name_local, volume_name_test, &opts_complete);
    EXPECT_STREQ(create_success->driver, driver_name_local);
    EXPECT_STREQ(create_success->name, volume_name_test);

    char *volume_name_null = nullptr;

    struct volume *create_success_with_name_null = volume_create(driver_name_local, volume_name_null, &opts_complete);
    EXPECT_NE(create_success_with_name_null->name, nullptr);
    EXPECT_STREQ(create_success_with_name_null->driver, driver_name_local);

    char *volume_name_random = create_success_with_name_null->name;

    // test volume_mount
    EXPECT_EQ(volume_mount(volume_name_null), -1);

    EXPECT_EQ(volume_mount(volume_name_test), 0);

    // test volume_umount
    EXPECT_EQ(volume_umount(volume_name_null), -1);

    EXPECT_EQ(volume_umount(volume_name_test), 0);

    // test volume_add_ref
    char *ref_null = nullptr;
    EXPECT_EQ(volume_add_ref(volume_name_test, ref_null), -1);

    char *ref_id2 = (char *)"e10d1990f516";
    EXPECT_EQ(volume_add_ref(volume_name_test, ref_id2), 0);

    // test volume_del_ref
    EXPECT_EQ(volume_del_ref(volume_name_test, ref_null), -1);

    EXPECT_EQ(volume_del_ref(volume_name_test, ref_id2), 0);

    // test volume_remove
    EXPECT_EQ(volume_remove(volume_name_test), -1);

    EXPECT_EQ(volume_del_ref(volume_name_test, ref_id1), 0);

    EXPECT_EQ(volume_remove(volume_name_test), 0);

    // test volume_prune
    struct volume_names *pruned;
    struct volume_names **pruned_null = nullptr;

    EXPECT_EQ(volume_prune(pruned_null), -1);

    volume_prune(&pruned);
    EXPECT_EQ(pruned->names_len, 0);

    EXPECT_EQ(volume_del_ref(volume_name_random, ref_id1), 0);

    volume_prune(&pruned);
    EXPECT_EQ(pruned->names_len, 1);
}