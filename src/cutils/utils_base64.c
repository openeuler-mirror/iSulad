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
 * Create: 2020-03-26
 * Description: provide base64 functions
 *******************************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_base64.h"
#include "openssl/pem.h"
#include "openssl/bio.h"

size_t util_base64_encode(unsigned char *bytes, size_t len, char *out, size_t out_len)
{
    BIO *base64 = NULL;
    BIO *io = NULL;
    size_t result_len = 0;
    int ret = 0;
    int bio_ret = 0;
    BUF_MEM *pmem = NULL;
    size_t i = 0;
    size_t count = 0;

    if (bytes == NULL || len == 0 || out == NULL || out_len < util_base64_encode_len(len)) {
        ERROR("Invalid param for encoding base64, input length %zu, out length %zu", len, out_len);
        return -1;
    }

    base64 = BIO_new(BIO_f_base64());
    if (base64 == NULL) {
        ERROR("bio new of base64 failed for base64 encode");
        ret = -1;
        goto out;
    }
    io = BIO_new(BIO_s_mem());
    if (io == NULL) {
        ERROR("bio new of memory failed for base64 encode");
        ret = -1;
        goto out;
    }
    io = BIO_push(base64, io);

    bio_ret = BIO_write(io, bytes, len);
    if (bio_ret <= 0) {
        ERROR("bio write failed, result is %d", bio_ret);
        ret = -1;
        goto out;
    }

    bio_ret = BIO_flush(io);
    if (bio_ret <= 0) {
        ERROR("bio flush failed, result is %d", bio_ret);
        ret = -1;
        goto out;
    }

    (void)BIO_get_mem_ptr(io, &pmem);
    // BIO_write append '\n' if every 76 chars have be output, so we need to strip them.
    for (i = 0; i < pmem->length; i++) {
        if (pmem->data[i] == '\n') {
            continue;
        }
        if (count + 1 == out_len) {
            ERROR("result length larger than output length, result length %zu, input length %zu, output length %zu",
                  pmem->length, len, out_len);
            ret = -1;
            goto out;
        }
        out[count] = pmem->data[i];
        count++;
    }

    if (count == 0) {
        ERROR("Base64 encode failed, result count is zero");
        ret = -1;
        goto out;
    }

    out[count] = 0;
    result_len = count + 1;

out:

    if (io != NULL) {
        BIO_free_all(io);
        io = NULL;
    }

    if (ret != 0) {
        return -1;
    } else {
        return result_len;
    }
}

size_t util_base64_encode_len(size_t len)
{
    if (len % 3 == 0) {
        return len / 3 * 4 + 1;
    } else {
        return (len / 3 + 1) * 4 + 1;
    }
}

size_t util_base64_decode_len(char *input, size_t len)
{
    size_t padding_count = 0;

    if (input == NULL || len < 4 || len % 4 != 0) {
        ERROR("Invalid param for base64 decode length, length is %ld", len);
        return -1;
    }

    if (input[len - 1] == '=') {
        padding_count++;
        if (input[len - 2] == '=') {
            padding_count++;
        }
    }

    return (strlen(input) / 4 * 3) - padding_count;
}

size_t util_base64_decode(char *input, size_t len, unsigned char *out, size_t out_len)
{
    BIO *base64 = NULL;
    BIO *io = NULL;
    int ret = 0;
    size_t result_len = util_base64_decode_len(input, len);
    size_t size = 0;

    if (input == NULL || result_len < 0 || out == 0 || result_len > out_len) {
        ERROR("Invalid param for base64 decode, input length %zu, result length %zu, output length %zu", len,
              result_len, out_len);
        return -1;
    }

    base64 = BIO_new(BIO_f_base64());
    if (base64 == NULL) {
        ERROR("bio new of base64 failed for base64 encode");
        ret = -1;
        goto out;
    }

    BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);

    io = BIO_new_mem_buf(input, len);
    io = BIO_push(base64, io);

    size = BIO_read(io, out, out_len);
    if (size != result_len) {
        ERROR("base64 decode failed, actual length not match calculated length, expected %zu, got %zu", result_len,
              size);
    }

out:
    if (io != NULL) {
        BIO_free_all(io);
        io = NULL;
    }

    if (ret != 0) {
        return -1;
    } else {
        return result_len;
    }
}
