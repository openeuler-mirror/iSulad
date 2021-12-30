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
 * Description: provide tar function definition
 *********************************************************************************/

#ifndef UTILS_TAR_ISULAD_TAR_H
#define UTILS_TAR_ISULAD_TAR_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>

#include "io_wrapper.h"

struct io_read_wrapper;

#ifdef __cplusplus
extern "C" {
#endif

#define ARCHIVE_BLOCK_SIZE (32 * 1024)

struct archive_copy_info {
    char *path;
    bool exists;
    bool isdir;
    char *rebase_name;
};

void free_archive_copy_info(struct archive_copy_info *info);

struct archive_tar_resource_rebase_opts {
    bool compression;
    char *include_file;
};

struct archive_copy_info *copy_info_source_path(const char *path, bool follow_link, char **err);

char *prepare_archive_copy(const struct archive_copy_info *srcinfo, const struct archive_copy_info *dstinfo,
                           char **src_base, char **dst_base, char **err);

int tar_resource(const struct archive_copy_info *info, struct io_read_wrapper *archive_reader, char **err);

int archive_copy_to(const struct io_read_wrapper *content, const struct archive_copy_info *srcinfo,
                    const char *dstpath, char **err);

#ifdef __cplusplus
}
#endif

#endif
