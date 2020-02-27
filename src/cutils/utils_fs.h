/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2020-02-27
 * Description: provide file system utils functions
 *******************************************************************************/

#ifndef __UTILS_FS_H
#define __UTILS_FS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

char *util_get_fs_name(const char *path);

bool util_support_overlay(void);

bool util_support_d_type(const char *path);

int util_mount(const char *src, const char *dst, const char *mtype, const char *mntopts);
int util_force_mount(const char *src, const char *dst, const char *mtype, const char *mntopts);
bool util_detect_mounted(const char *path);
int util_ensure_mounted_as(const char *dst, const char *mntopts);
#ifdef __cplusplus
}
#endif

#endif /* __UTILS_FS_H */

