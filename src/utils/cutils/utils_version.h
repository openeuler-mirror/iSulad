/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-4-7
 * Description: provide version functions
 ********************************************************************************/

#ifndef UTILS_CUTILS_UTILS_VERSION_H
#define UTILS_CUTILS_UTILS_VERSION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

int util_version_compare(const char *first, const char *second, int *diff_value);
int util_version_greater_than(const char *first, const char *second, bool *result);
int util_version_greater_than_or_equal_to(const char *first, const char *second, bool *result);

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_UTILS_VERSION_H