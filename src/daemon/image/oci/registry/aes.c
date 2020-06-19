/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2020-04-23
 * Description: provide aes process functions
 ******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "aes.h"

int aes_decode(unsigned char *input, size_t input_len, unsigned char *output, size_t output_buf_len)
{
    int ret = 0;
    unsigned char aeskey[AES_256_CFB_KEY_LEN];

    ret = util_aes_key(AUTH_AESKEY, false, aeskey);
    if (ret != 0) {
        ERROR("init aes for decode auth failed");
        return ret;
    }

    ret = util_aes_decode(aeskey, input, input_len, (unsigned char *)output, output_buf_len);
    if (ret < 0) {
        ERROR("decode aes failed");
        ret = -1;
        goto out;
    }

out:

    return ret;
}

int aes_encode(unsigned char *input, size_t input_len, unsigned char *output, size_t output_buf_len)
{
    int ret = 0;
    unsigned char aeskey[AES_256_CFB_KEY_LEN];

    ret = util_aes_key(AUTH_AESKEY, true, aeskey);
    if (ret != 0) {
        ERROR("init aes for decode auth failed");
        return ret;
    }

    ret = util_aes_encode(aeskey, (unsigned char *)input, input_len, output, output_buf_len);
    if (ret < 0) {
        ERROR("encode aes failed");
        ret = -1;
        goto out;
    }

out:

    return ret;
}
