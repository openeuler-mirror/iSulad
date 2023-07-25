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
#ifndef UTILS_CPPUTILS_TRANSFORM_H
#define UTILS_CPPUTILS_TRANSFORM_H
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <google/protobuf/map.h>
#include <isula_libutils/json_common.h>
#include "errors.h"

namespace Transform {

auto ProtobufMapToJsonMapForString(const google::protobuf::Map<std::string, std::string> &protobufMap, Errors &error)
-> json_map_string_string *;

void JsonMapToProtobufMapForString(const json_map_string_string *src,
                                   google::protobuf::Map<std::string, std::string> &dest);

auto StringVectorToCharArray(std::vector<std::string> &strVec) -> char **;

void CharArrayToStringVector(const char **src, size_t len, std::vector<std::string> &dest);

}; // namespace Transform

#endif // UTILS_CPPUTILS_TRANSFORM_H