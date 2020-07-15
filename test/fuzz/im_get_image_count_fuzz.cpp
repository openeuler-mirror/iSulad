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
 * Author: jikui
 * Create: 2020-07-09
 * Description: provide image fuzz test
 ******************************************************************************/

#include <iostream>
#include <string>
#include "image_api.h"
#include "utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string testData(reinterpret_cast<const char *>(data), size);
    im_image_count_request *rq = nullptr;
    char *tmp_type = nullptr;

    if (testData == "empty") {
        im_get_image_count(nullptr);
    } else {
        rq = (im_image_count_request *)util_common_calloc_s(sizeof(im_image_count_request));
        tmp_type = util_strdup_s(testData.c_str());
        rq->type = tmp_type;
        im_get_image_count(rq);

        free(tmp_type);
        free(rq);
    }
    return 0;
}
