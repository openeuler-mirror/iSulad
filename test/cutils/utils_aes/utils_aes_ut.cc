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
#include "utils_aes.h"

TEST(utils_aes, test_util_aes_key)
{
    std::string key_file = "./aes_key";
    unsigned char key_val[AES_256_CFB_KEY_LEN] = { 0 };

    unlink(key_file.c_str());
    ASSERT_NE(util_aes_key(key_file.c_str(), false, key_val), 0);
    ASSERT_NE(util_aes_key(nullptr, true, key_val), 0);
    ASSERT_NE(util_aes_key(nullptr, false, key_val), 0);
    ASSERT_NE(util_aes_key(key_file.c_str(), true, nullptr), 0);
    ASSERT_NE(util_aes_key(key_file.c_str(), false, nullptr), 0);
    ASSERT_NE(util_aes_key(nullptr, true, nullptr), 0);
    ASSERT_NE(util_aes_key(nullptr, false, nullptr), 0);
}

TEST(utils_aes, test_util_aes_encode)
{
    std::string key_file = "./aes_key";
    unsigned char key_val[AES_256_CFB_KEY_LEN] = { 0 };
    std::string test_data = "hello world";
    unsigned char *out = nullptr;

    ASSERT_EQ(util_aes_key(key_file.c_str(), true, key_val), 0);
    ASSERT_EQ(util_aes_encode(key_val, (unsigned char *)test_data.c_str(), test_data.size(), &out), 0);

    ASSERT_NE(util_aes_encode(nullptr, (unsigned char *)test_data.c_str(), test_data.size(), &out), 0);
    ASSERT_NE(util_aes_encode(key_val, nullptr, 0, &out), 0);
    ASSERT_NE(util_aes_encode(key_val, (unsigned char *)test_data.c_str(), 0, &out), 0);
    ASSERT_NE(util_aes_encode(key_val, (unsigned char *)test_data.c_str(), test_data.size(), nullptr), 0);

    unlink(key_file.c_str());
}

TEST(utils_aes, test_util_aes_decode)
{
    std::string key_file = "./aes_key";
    unsigned char key_val[AES_256_CFB_KEY_LEN] = { 0 };
    std::string test_data = "hello world";
    unsigned char *encode_data = nullptr;
    unsigned char *decode_data = nullptr;
    size_t aes_len = AES_256_CFB_IV_LEN;

    ASSERT_EQ(util_aes_key(key_file.c_str(), true, key_val), 0);
    ASSERT_EQ(util_aes_encode(key_val, (unsigned char *)test_data.c_str(), test_data.size(), &encode_data), 0);
    aes_len += test_data.size();
    ASSERT_EQ(util_aes_decode(key_val, encode_data, aes_len, &decode_data), 0);
    printf("get decode value = %s\n", (const char *)decode_data);
    ASSERT_EQ(strcmp(test_data.c_str(), (const char *)decode_data), 0);

    ASSERT_NE(util_aes_decode(nullptr, encode_data, aes_len, &decode_data), 0);
    ASSERT_NE(util_aes_decode(key_val, nullptr, 0, &decode_data), 0);
    ASSERT_NE(util_aes_decode(key_val, encode_data, 0, &decode_data), 0);
    ASSERT_NE(util_aes_decode(key_val, encode_data, aes_len, nullptr), 0);

    unlink(key_file.c_str());
}