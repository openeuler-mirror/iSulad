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
 * Create: 2023-06-30
 * Description: provide transform functions
 *********************************************************************************/
#include "transform.h"

#include <iostream>

#include <isula_libutils/log.h>

#include "cxxutils.h"
#include "utils.h"
#include "constants.h"
namespace Transform {
auto ProtobufMapToJsonMapForString(const google::protobuf::Map<std::string, std::string> &protobufMap, Errors &error)
-> json_map_string_string *
{
    json_map_string_string *labels = (json_map_string_string *)util_common_calloc_s(sizeof(json_map_string_string));
    if (labels == nullptr) {
        ERROR("Out of memory");
        return nullptr;
    }

    if (protobufMap.empty()) {
        return labels;
    }

    if (protobufMap.size() > LIST_SIZE_MAX) {
        error.Errorf("Labels list is too long, the limit is %d", LIST_SIZE_MAX);
        goto cleanup;
    }
    for (auto &iter : protobufMap) {
        if (append_json_map_string_string(labels, iter.first.c_str(), iter.second.c_str()) != 0) {
            ERROR("Failed to append string");
            error.Errorf("Failed to append string");
            goto cleanup;
        }
    }

    return labels;
cleanup:
    free_json_map_string_string(labels);
    return nullptr;
}

void JsonMapToProtobufMapForString(const json_map_string_string *src,
                                   google::protobuf::Map<std::string, std::string> &dest)
{
    if (src == nullptr || src->keys == nullptr || src->values == nullptr) {
        return;
    }
    for (size_t i = 0; i < src->len; i++) {
        dest[std::string(src->keys[i])] = std::string(src->values[i]);
    }
}

auto StringVectorToCharArray(std::vector<std::string> &strVec) -> char **
{
    size_t len = strVec.size();
    char **result = (char **)util_smart_calloc_s(sizeof(char *), (len + 1));
    if (result == nullptr) {
        return nullptr;
    }
    size_t i {};
    for (const auto &it : strVec) {
        result[i++] = util_strdup_s(it.c_str());
    }

    return result;
}

void CharArrayToStringVector(const char **src, size_t len, std::vector<std::string> &dest)
{
    if (src == nullptr) {
        return;
    }
    for (size_t i {}; i < len; i++) {
        dest.push_back(std::string(src[i]));
    }
}

} // namespace Transform
