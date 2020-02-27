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
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide container sha256 functions
 ********************************************************************************/

#ifndef __UTILS_STRING_H
#define __UTILS_STRING_H
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

bool strings_contains_any(const char *str, const char *substr);

bool strings_contains_word(const char *str, const char *substr);

int strings_count(const char *str, unsigned char c);

bool strings_in_slice(const char **strarray, size_t alen, const char *str);

char *strings_to_lower(const char *str);

char *strings_to_upper(const char *str);

int util_parse_byte_size_string(const char *s, int64_t *converted);

int util_parse_percent_string(const char *s, long *converted);

// Breaks src_str into an array of string according to _sep,
// note that two or more contiguous delimiter bytes  is considered to be a single delimiter
char **util_string_split(const char *src_str, char _sep);

// Breaks src_str into an array of string according to _sep,
// note that every delimiter bytes  is considered to be a single delimiter
char **util_string_split_multi(const char *src_str, char delim);

char **util_string_split_n(const char *src_str, char delim, size_t n);

const char *str_skip_str(const char *str, const char *skip);

char *util_string_delchar(const char *ss, unsigned char c);

void util_trim_newline(char *s);

char *util_trim_space(char *str);

char *util_trim_quotation(char *str);

char **str_array_dup(const char **src, size_t len);

char *util_string_join(const char *sep, const char **parts, size_t len);

char *util_string_append(const char *post, const char *pre);

int dup_array_of_strings(const char **src, size_t src_len, char ***dst, size_t *dst_len);

char *util_sub_string(const char *source, size_t offset, size_t length);

bool util_is_space_string(const char *str);

bool util_has_prefix(const char *str, const char *prefix);

bool util_has_suffix(const char *str, const char *suffix);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_STRING_H */

