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
 * Create: 2020-04-21
 * Description: provide aes functions
 ********************************************************************************/

#ifndef __UTILS_AES_H
#define __UTILS_AES_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_256_CFB_KEY_LEN 32
#define AES_256_CFB_IV_LEN 16

int util_aes_key(char *key_path, bool create, unsigned char *aeskey);

// This is the output buffer length, not the result data length.
size_t util_aes_encode_buf_len(size_t len);
// note: input bytes is "IV+data", "bytes + AES_256_CFB_IV_LEN" is the real data to be encoded.
int util_aes_encode(unsigned char *aeskey, unsigned char *bytes, size_t len, unsigned char *out, size_t out_len);

// This is the output buffer length, not the result data length.
size_t util_aes_decode_buf_len(size_t len);
// note: output bytes is "IV+data", "bytes + AES_256_CFB_IV_LEN" is the read encoded data.
int util_aes_decode(unsigned char *aeskey, unsigned char *bytes, size_t len, unsigned char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_AES_H */

