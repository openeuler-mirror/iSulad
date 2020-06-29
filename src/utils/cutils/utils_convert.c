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
 * Description: provide container utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_convert.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>

static inline bool is_invalid_error_str(const char *err_str, const char *numstr)
{
    return err_str == NULL || err_str == numstr || *err_str != '\0';
}

int util_safe_u16(const char *numstr, uint16_t *converted)
{
    char *err_str = NULL;
    unsigned long int ui;

    if (numstr == NULL || converted == NULL) {
        return -EINVAL;
    }

    errno = 0;
    ui = strtoul(numstr, &err_str, 0);
    if (errno > 0) {
        return -errno;
    }

    if (is_invalid_error_str(err_str, numstr)) {
        return -EINVAL;
    }

    if (ui > 0xFFFF) {
        return -ERANGE;
    }

    *converted = (uint16_t)ui;
    return 0;
}

int util_safe_int(const char *num_str, int *converted)
{
    char *err_str = NULL;
    signed long int li;

    if (num_str == NULL || converted == NULL) {
        return -EINVAL;
    }

    errno = 0;
    li = strtol(num_str, &err_str, 0);
    if (errno > 0) {
        return -errno;
    }

    if (is_invalid_error_str(err_str, num_str)) {
        return -EINVAL;
    }

    if (li > INT_MAX || li < INT_MIN) {
        return -ERANGE;
    }

    *converted = (int)li;
    return 0;
}

int util_safe_uint(const char *numstr, unsigned int *converted)
{
    char *err_str = NULL;
    unsigned long long ull;

    if (numstr == NULL || converted == NULL) {
        return -EINVAL;
    }

    errno = 0;
    ull = strtoull(numstr, &err_str, 0);
    if (errno > 0) {
        return -errno;
    }

    if (is_invalid_error_str(err_str, numstr)) {
        return -EINVAL;
    }

    if (ull > UINT_MAX) {
        return -ERANGE;
    }

    *converted = (unsigned int)ull;
    return 0;
}

int util_safe_llong(const char *numstr, long long *converted)
{
    char *err_str = NULL;
    long long ll;

    if (numstr == NULL || converted == NULL) {
        return -EINVAL;
    }

    errno = 0;
    ll = strtoll(numstr, &err_str, 0);
    if (errno > 0) {
        return -errno;
    }

    if (is_invalid_error_str(err_str, numstr)) {
        return -EINVAL;
    }

    *converted = (long long)ll;
    return 0;
}

int util_safe_strtod(const char *numstr, double *converted)
{
    char *err_str = NULL;
    double ld;

    if (numstr == NULL || converted == NULL) {
        return -EINVAL;
    }

    errno = 0;
    ld = strtod(numstr, &err_str);
    if (errno > 0) {
        return -errno;
    }

    if (is_invalid_error_str(err_str, numstr)) {
        return -EINVAL;
    }

    *converted = ld;
    return 0;
}

static inline bool is_valid_str_bool_true(const char *str)
{
    return strcmp(str, "1") == 0 || strcmp(str, "t") == 0 || strcmp(str, "T") == 0 || strcmp(str, "true") == 0 ||
           strcmp(str, "TRUE") == 0 || strcmp(str, "True") == 0;
}

static inline bool is_valid_str_bool_false(const char *str)
{
    return strcmp(str, "0") == 0 || strcmp(str, "f") == 0 || strcmp(str, "F") == 0 || strcmp(str, "false") == 0 ||
           strcmp(str, "FALSE") == 0 || strcmp(str, "False") == 0;
}

int util_str_to_bool(const char *boolstr, bool *converted)
{
    if (boolstr == NULL || converted == NULL) {
        return -EINVAL;
    }
    if (is_valid_str_bool_true(boolstr)) {
        *converted = true;
    } else if (is_valid_str_bool_false(boolstr)) {
        *converted = false;
    } else {
        return -EINVAL;
    }
    return 0;
}

