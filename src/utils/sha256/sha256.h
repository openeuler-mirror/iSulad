/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container sha256 definition
 ******************************************************************************/
#ifndef UTILS_SHA256_SHA256_H
#define UTILS_SHA256_SHA256_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <zlib.h>

#ifdef __cplusplus
extern "C" {
#endif

char *sha256_digest_file(const char *filename, bool isgzip);

char *sha256_digest_str(const char *val);

char *sha256_full_gzip_digest(const char *filename);

char *sha256_full_file_digest(const char *filename);

bool sha256_valid_digest_file(const char *path, const char *digest);

char *sha256_full_digest_str(char *str);

char *without_sha256_prefix(char *digest);

#ifdef __cplusplus
}
#endif

#endif
