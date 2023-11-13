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
 * Author: xuxuepeng
 * Create: 2023-11-08
 * Description: provide capbilities utils functions
 *******************************************************************************/

#ifndef UTILS_CUTILS_UTILS_CAP_H
#define UTILS_CUTILS_UTILS_CAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <linux/capability.h>

bool util_valid_cap(const char *cap);

/**
 * Get all supported capabilities for linux,
 * note that the returned strings are unmutable
 */
const char **util_get_all_caps(size_t *cap_len);

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_UTILS_CAP_H
