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
 * Author: zhongtao
 * Create: 2023-07-18
 * Description: utils transform unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "errors.h"
#include "transform.h"
#include "utils_array.h"
#include "utils.h"

TEST(utils_transform, test_ProtobufMapToJsonMapForString)
{
    google::protobuf::Map<std::string, std::string> protobufMap;
    Errors error;

    json_map_string_string* result = Transform::ProtobufMapToJsonMapForString(protobufMap, error);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->len, 0);
    free_json_map_string_string(result);

    protobufMap.insert({"key1", "value1"});
    protobufMap.insert({"key2", "value2"});

    result = Transform::ProtobufMapToJsonMapForString(protobufMap, error);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(result->len, 2);
    free_json_map_string_string(result);
}

TEST(utils_transform, test_JsonMapToProtobufMapForString)
{
    json_map_string_string *src = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    ASSERT_NE(src, nullptr);
    google::protobuf::Map<std::string, std::string> dest;

    Transform::JsonMapToProtobufMapForString(nullptr, dest);
    ASSERT_TRUE(dest.empty());

    Transform::JsonMapToProtobufMapForString(src, dest);
    ASSERT_TRUE(dest.empty());

    append_json_map_string_string(src, "key1", "value1");
    append_json_map_string_string(src, "key2", "value2");

    Transform::JsonMapToProtobufMapForString(src, dest);
    ASSERT_EQ(dest.size(), 2);
    ASSERT_EQ(dest["key1"], "value1");
    ASSERT_EQ(dest["key2"], "value2");
    free_json_map_string_string(src);
}

TEST(utils_transform, test_StringVectorToCharArray)
{
    std::vector<std::string> path;

    char** result = Transform::StringVectorToCharArray(path);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(util_array_len(const_cast<const char **>(result)), 0);

    path = { "path1", "path2", "path3" };

    result = Transform::StringVectorToCharArray(path);
    ASSERT_NE(result, nullptr);
    ASSERT_STREQ(result[0], "path1");
    ASSERT_STREQ(result[1], "path2");
    ASSERT_STREQ(result[2], "path3");

    util_free_array(result);
}

TEST(utils_transform, test_CharArrayToStringVector)
{
    const char* arr1[] = {};
    std::vector<std::string> dest;

    Transform::CharArrayToStringVector(nullptr, 0, dest);
    Transform::CharArrayToStringVector(arr1, 0, dest);
    ASSERT_TRUE(dest.empty());

    const char* arr2[] = { "str1", "str2", "str3" };

    Transform::CharArrayToStringVector(const_cast<const char **>(arr2), 3, dest);
    ASSERT_EQ(dest.size(), 3);
    ASSERT_EQ(dest[0], "str1");
    ASSERT_EQ(dest[1], "str2");
    ASSERT_EQ(dest[2], "str3");
}