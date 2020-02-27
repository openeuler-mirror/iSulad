/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2020-03-26
 * Description: provide base64 functions
 *******************************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>

#include "log.h"
#include "utils.h"
#include "utils_base64.h"

size_t util_base64_encode_string(char *bytes, size_t len, char *out, size_t out_len)
{
    return lws_b64_encode_string(bytes, len, out, out_len);
}

size_t util_base64_encode_len(size_t len)
{
    if (len % 3 == 0) {
        return len / 3 * 4;
    } else {
        return (len / 3 + 1) * 4;
    }
}

