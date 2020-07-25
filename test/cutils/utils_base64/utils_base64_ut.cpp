/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: utils_convert unit test
 * Author: wangfengtu
 * Create: 2020-07-20
 */

#include <stdlib.h>
#include <stdio.h>
#include <climits>
#include <gtest/gtest.h>
#include "utils_base64.h"

TEST(utils_base64, test_util_base64)
{
    char *plain_text = (char*)"^cvdgfdgghaswere3575676y&*`~cx,xfdgdvcvdfd][';./?.,<>|\\!@#$%^&*()_+=-090wvvs3sdfel33cxvdf***$";
    char *encoded = NULL;
    char *decoded = NULL;
    size_t decoded_len = 0;

    // check long base64 encode/decode
    ASSERT_EQ(util_base64_encode((unsigned char*)plain_text, strlen(plain_text), &encoded), 0);
    ASSERT_STREQ(encoded, "XmN2ZGdmZGdnaGFzd2VyZTM1NzU2NzZ5JipgfmN4LHhmZGdkdmN2ZGZkXVsnOy4vPy4sPD58XCFAIyQlXiYqKClfKz0tMDkwd3Z2czNzZGZlbDMzY3h2ZGYqKiok");
    ASSERT_EQ(util_base64_decode((const char*)encoded, strlen(encoded), (unsigned char**)&decoded, &decoded_len), 0);
    ASSERT_STREQ(decoded, plain_text);
    ASSERT_EQ(strlen(plain_text), decoded_len);

    free(encoded);
    encoded = NULL;
    free(decoded);
    decoded = NULL;

    // check base64 decode with suffix '\0'
    ASSERT_EQ(util_base64_decode((const char*)"MQ==", strlen("MQ=="), (unsigned char**)&decoded, &decoded_len), 0);
    ASSERT_STREQ(decoded, "1");
    ASSERT_EQ(decoded_len, 1);

    free(decoded);
}
