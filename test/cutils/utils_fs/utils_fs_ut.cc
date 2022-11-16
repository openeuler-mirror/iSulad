/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2022-10-13
 * Description: utils namespace unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "utils_fs.h"

int good_cb(const char *mp, const char *pattern)
{
    return 0;
}

int good_check_cb(const char *mp, const char *pattern)
{
    return pattern != nullptr ? 0 : -1;
}

int bad_cb(const char *mp, const char *pattern)
{
    return -1;
}

TEST(utils_fs, test_util_deal_with_mount_info)
{
    std::string spattern = "[0-9]*";

    ASSERT_EQ(util_deal_with_mount_info(good_cb, spattern.c_str()), true);
    ASSERT_EQ(util_deal_with_mount_info(bad_cb, spattern.c_str()), false);
    ASSERT_EQ(util_deal_with_mount_info(good_check_cb, spattern.c_str()), true);
    ASSERT_EQ(util_deal_with_mount_info(good_check_cb, nullptr), false);
}
