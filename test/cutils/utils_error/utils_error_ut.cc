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
#include "error.h"

TEST(utils_error, test_errno_to_error_message)
{
    const char *ret = nullptr;
    std::string internal_err = "Server internal error";
    std::string unknow_err = "Unknown error";

    ret = errno_to_error_message(ISULAD_SUCCESS);
    ASSERT_EQ(strcmp(ret, DEF_SUCCESS_STR), 0);

    ret = errno_to_error_message(ISULAD_ERR_INTERNAL);
    ASSERT_EQ(strcmp(ret, internal_err.c_str()), 0);

    ret = errno_to_error_message(ISULAD_ERR_UNKNOWN);
    ASSERT_EQ(strcmp(ret, unknow_err.c_str()), 0);
}

TEST(utils_error, test_format_errorf)
{
    char *out = nullptr;
    std::string target = "hello world";

    format_errorf(&out, "hello %s", "world");
    ASSERT_EQ(strcmp(out, target.c_str()), 0);

    format_errorf(nullptr, "hello %s", "world");
    format_errorf(&out, nullptr);
}