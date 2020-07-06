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

#ifndef __UTILS_ARRAY_H
#define __UTILS_ARRAY_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t util_array_len(const char **array);

void util_free_array_by_len(char **array, size_t len);

void util_free_array(char **array);

int util_grow_array(char ***orig_array, size_t *orig_capacity, size_t size,
                    size_t increment);

int util_array_append(char ***array, const char *element);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_H */

