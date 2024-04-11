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

#define _GNU_SOURCE
#include "utils_version.h"

#include <isula_libutils/log.h>

#include "utils.h"
#include "utils_string.h"

struct parse_version {
    int major;
    int minor;
    int micro;
};

static bool do_parse_version(const char **splits, size_t splits_len, struct parse_version *ret)
{
    if (util_safe_int(splits[0], &ret->major) != 0) {
        ERROR("Failed to convert major version part: %s", splits[0]);
        return false;
    }

    if (splits_len >= 2 && util_safe_int(splits[1], &ret->minor) != 0) {
        ERROR("Failed to convert minor version part: %s", splits[1]);
        return false;
    }

    if (splits_len >= 3 && util_safe_int(splits[2], &ret->micro) != 0) {
        ERROR("Failed to convert micro version part: %s", splits[2]);
        return false;
    }

    return true;
}

static bool parse_version_from_str(const char *src_version, struct parse_version *result)
{
    __isula_auto_array_t char **splits = NULL;
    const size_t max_len = 4;
    size_t tlen = 0;
    bool ret = false;

    splits = util_string_split(src_version, '.');
    if (splits == NULL) {
        ERROR("Split version: \"%s\" failed", src_version);
        return false;
    }
    tlen = util_array_len((const char **)splits);
    if (tlen < 1 || tlen >= max_len) {
        ERROR("Invalid version: \"%s\"", src_version);
        return false;
    }

    ret = do_parse_version((const char **)splits, tlen, result);

    return ret;
}

static int do_compare_version(const struct parse_version *p_first, const struct parse_version *p_second)
{
    if (p_first->major != p_second->major) {
        return p_first->major - p_second->major;
    }
    if (p_first->minor != p_second->minor) {
        return p_first->minor - p_second->minor;
    }
    if (p_first->micro != p_second->micro) {
        return p_first->micro - p_second->micro;
    }

    return 0;
}

int util_version_compare(const char *first, const char *second, int *diff_value)
{
    struct parse_version first_parsed = { 0 };
    struct parse_version second_parsed = { 0 };

    if (first == NULL || second == NULL || diff_value == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    if (!parse_version_from_str(first, &first_parsed)) {
        return -1;
    }

    if (!parse_version_from_str(second, &second_parsed)) {
        return -1;
    }

    *diff_value = do_compare_version(&first_parsed, &second_parsed);

    return 0;
}

int util_version_greater_than(const char *first, const char *second, bool *result)
{
    int ret;
    int diff_value = 0;

    if (result == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    ret = util_version_compare(first, second, &diff_value);
    if (ret != 0) {
        return ret;
    }

    *result = (diff_value > 0);
    return ret;
}

int util_version_greater_than_or_equal_to(const char *first, const char *second, bool *result)
{
    int ret;
    int diff_value = 0;

    if (result == NULL) {
        ERROR("Invalid argument");
        return -1;
    }

    ret = util_version_compare(first, second, &diff_value);
    if (ret != 0) {
        return ret;
    }

    *result = (diff_value >= 0);
    return ret;
}
