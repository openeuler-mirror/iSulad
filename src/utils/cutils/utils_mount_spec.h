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
 * Author: wangfengtu
 * Create: 2020-10-19
 * Description: provide mount spec utils functions
 ********************************************************************************/

#ifndef UTILS_CUTILS_UTILS_MOUNT_SPEC_H
#define UTILS_CUTILS_UTILS_MOUNT_SPEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "isula_libutils/mount_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_MOUNT_TYPE "volume"

bool util_valid_mount_spec(const char *mount_str, char **errmsg);

int util_parse_mount_spec(char *mount_str, mount_spec **spec, char **errmsg_out);

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_UTILS_MOUNT_SPEC_H
