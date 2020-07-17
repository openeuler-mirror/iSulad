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

#ifndef UTILS_CUTILS_UTILS_BASE64_H
#define UTILS_CUTILS_UTILS_BASE64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int util_base64_encode(unsigned char *bytes, size_t len, char **out);

// note: The result out put will be *out_len + 1, and it's filled with '\0', so if the decoded
//       data is a string, it's safe to use it as a string.
int util_base64_decode(const char *input, size_t len, unsigned char **out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_UTILS_BASE64_H
