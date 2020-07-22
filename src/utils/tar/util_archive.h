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
 * Create: 2020-03-14
 * Description: provide tar function definition
 *********************************************************************************/
#ifndef UTILS_TAR_UTIL_ARCHIVE_H
#define UTILS_TAR_UTIL_ARCHIVE_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "io_wrapper.h"

struct io_read_wrapper;

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    NONE_WHITEOUT_FORMATE = 0,
    OVERLAY_WHITEOUT_FORMATE = 1,
} whiteout_format_type;

struct archive_options {
    whiteout_format_type whiteout_format;
};

int archive_unpack(const struct io_read_wrapper *content, const char *dstdir, const struct archive_options *options);

bool valid_archive_format(const char *file);

#ifdef __cplusplus
}
#endif

#endif
