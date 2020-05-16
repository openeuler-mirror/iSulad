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
 * Author: lifeng
 * Create: 2020-02-27
 * Description: provide overlay2 types definition
 ******************************************************************************/
#ifndef __GRAPHDRIVER_OVERLAY2_TYPES_H
#define __GRAPHDRIVER_OVERLAY2_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

struct overlay_options {
    bool override_kernelcheck;
    uint64_t default_quota;
    const char *mount_program;
    bool skip_mount_home;
    const char *mount_options;
};

#ifdef __cplusplus
}
#endif

#endif

