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
 ********************************************************************************/

#ifndef __UTILS_BASE64_H
#define __UTILS_BASE64_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// note: the output length must include the '\0' and the return size is include the '\0'.
size_t util_base64_encode(unsigned char *bytes, size_t len, char *out, size_t out_len);
size_t util_base64_encode_len(size_t len);
size_t util_base64_decode(char *input, size_t len, unsigned char *out, size_t out_len);
size_t util_base64_decode_len(char *input, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_BASE64_H */

