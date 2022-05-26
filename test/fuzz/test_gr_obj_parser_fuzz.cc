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
 * Author: hejunjie
 * Create: 2022-05-12
 * Description: provide fuzz test for parser of group object
 ******************************************************************************/

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include "utils_pwgr.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string testData(reinterpret_cast<const char *>(data), size);
    std::string fileName("grstreamfile.txt");
    struct group gr;
    struct group *pgr = nullptr;
    char buf[BUFSIZ];

    std::ofstream outFile(fileName);
    outFile << testData;
    outFile.close();

    FILE *f = fopen(fileName.c_str(), "r");

    if (testData == "empty") {
        util_getgrent_r(nullptr, &gr, buf, sizeof(buf), &pgr);
    } else {
        util_getgrent_r(f, &gr, buf, sizeof(buf), &pgr);
    }

    fclose(f);
    return 0;
}
