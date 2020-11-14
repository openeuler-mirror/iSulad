/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2020-11-03
 * Description: provide mount spec fuzz test
 ******************************************************************************/

#include <iostream>
#include <string>
#include "utils_mount_spec.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string testData(reinterpret_cast<const char *>(data), size);
    char *errmsg = NULL;
    if (testData == "empty") {
        util_valid_mount_spec(nullptr, &errmsg);
    } else {
        util_valid_mount_spec(testData.c_str(), &errmsg);
    }
    free(errmsg);
    return 0;
}
