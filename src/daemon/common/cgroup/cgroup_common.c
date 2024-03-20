/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-03-22
 * Description: provide cgroup common func definition
 ******************************************************************************/
#include "cgroup_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <sys/stat.h>

#include <isula_libutils/auto_cleanup.h>

#include "err_msg.h"
#include "utils.h"
#include "utils_array.h"
#include "sysinfo.h"
#include "cgroup_v1.h"
#include "cgroup_v2.h"
#include "path.h"

static int get_value_ull(const char *content, void *result)
{
    uint64_t ull_result = 0;

    if (util_safe_uint64(content, &ull_result) != 0) {
        ERROR("Failed to convert %s to uint64", content);
        return -1;
    }

    *(uint64_t *)result = ull_result;
    return 0;
}

int get_match_value_ull(const char *content, const char *match, void *result)
{
    __isula_auto_free char *llu_string = NULL;
    __isula_auto_free char *match_with_space = NULL;
    __isula_auto_array_t char **lines = NULL;
    char **worker = NULL;

    if (match == NULL) {
        return get_value_ull(content, result);
    }

    // match full string
    match_with_space = util_string_append(" ", match);
    if (match_with_space == NULL) {
        ERROR("Failed to append string");
        return -1;
    }

    lines = util_string_split(content, '\n');
    if (lines == NULL) {
        ERROR("Failed to split content %s", content);
        return -1;
    }

    for (worker = lines; worker && *worker; worker++) {
        if (util_has_prefix(*worker, match_with_space)) {
            break;
        }
    }
    if (*worker == NULL) {
        ERROR("Cannot find match string %s", match);
        return -1;
    }

    llu_string = util_sub_string(*worker, strlen(match_with_space), strlen(*worker) - strlen(match_with_space));
    if (llu_string == NULL) {
        ERROR("Failed to sub string");
        return -1;
    }
    llu_string = util_trim_space(llu_string);

    return get_value_ull(llu_string, result);
}

int get_cgroup_value_helper(const char *path, struct cgfile_t *cgfile, void *result)
{
    int nret = 0;
    char file_path[PATH_MAX] = { 0 };
    char real_path[PATH_MAX] = { 0 };
    char *content = NULL;

    if (path == NULL || strlen(path) == 0 || result == NULL) {
        ERROR("%s: Invalid arguments", cgfile->name);
        return -1;
    }

    nret = snprintf(file_path, sizeof(file_path), "%s/%s", path, cgfile->file);
    if (nret < 0 || (size_t)nret >= sizeof(file_path)) {
        ERROR("%s: failed to snprintf", cgfile->name);
        return -1;
    }

    if (util_clean_path(file_path, real_path, sizeof(real_path)) == NULL) {
        ERROR("%s: failed to clean path %s", cgfile->name, file_path);
        return -1;
    }

    content = util_read_content_from_file(real_path);
    if (content == NULL) {
        ERROR("%s: failed to read file %s", cgfile->name, real_path);
        return -1;
    }

    util_trim_newline(content);
    content = util_trim_space(content);

    nret = cgfile->get_value(content, cgfile->match, result);
    if (nret != 0) {
        ERROR("%s: failed to get value", cgfile->name);
    }

    free(content);
    return nret;
}