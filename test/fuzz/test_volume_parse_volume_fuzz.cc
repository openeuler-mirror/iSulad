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
 * Description: provide parse volume fuzz test
 ******************************************************************************/

#include <iostream>
#include <string>
#include "parse_volume.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string testData(reinterpret_cast<const char *>(data), size);
    defs_mount *mnt = NULL;
    if (testData == "empty") {
        mnt = parse_volume(nullptr);
    } else {
        mnt = parse_volume(testData.c_str());
    }
    free_defs_mount(mnt);
    return 0;
}
