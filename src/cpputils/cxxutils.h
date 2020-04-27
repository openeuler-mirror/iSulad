/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: c++ common tools.
 * Author: wujing
 * Create: 2019-05-17
 ******************************************************************************/
#ifndef __CXXUTILS_H_
#define __CXXUTILS_H_

#include <iostream>
#include <string>
#include <vector>
#include <sstream>

namespace CXXUtils {
std::vector<std::string> Split(const std::string &str, char delimiter);
std::string StringsJoin(const std::vector<std::string> &vec, const std::string &sep);
};
#endif /* __CXXUTILS_H_ */

