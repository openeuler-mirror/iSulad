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
 * Author: lifeng
 * Create: 2020-09-28
 * Description: provide ulimit options parse function
 ******************************************************************************/
#include "opt_ulimit.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <isula_libutils/host_config.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_string.h"

static int check_ulimit_input(const char *val)
{
    int ret = 0;
    if (val == NULL || strcmp(val, "") == 0) {
        COMMAND_ERROR("ulimit argument can't be empty");
        ret = -1;
        goto out;
    }

    if (val[0] == '=' || val[strlen(val) - 1] == '=') {
        COMMAND_ERROR("Invalid ulimit argument: \"%s\", delimiter '=' can't"
                      " be the first or the last character",
                      val);
        ret = -1;
    }

out:
    return ret;
}

static void get_ulimit_split_parts(const char *val, char ***parts, size_t *parts_len, char deli)
{
    *parts = util_string_split_multi(val, deli);
    if (*parts == NULL) {
        COMMAND_ERROR("Out of memory");
        return;
    }
    *parts_len = util_array_len((const char **)(*parts));
}

static int parse_soft_hard_ulimit(const char *val, char **limitvals, size_t limitvals_len, int64_t *soft, int64_t *hard)
{
    int ret = 0;
    // parse soft
    ret = util_safe_llong(limitvals[0], (long long *)soft);
    if (ret < 0) {
        COMMAND_ERROR("Invalid ulimit soft value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
        ret = -1;
        goto out;
    }

    // parse hard if exists
    if (limitvals_len > 1) {
        ret = util_safe_llong(limitvals[1], (long long *)hard);
        if (ret < 0) {
            COMMAND_ERROR("Invalid ulimit hard value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
            ret = -1;
            goto out;
        }

        if (*soft > *hard) {
            COMMAND_ERROR("Ulimit soft limit must be less than or equal to hard limit: %lld > %lld",
                          (long long int)(*soft), (long long int)(*hard));
            ret = -1;
            goto out;
        }
    } else {
        *hard = *soft; // default to soft in case no hard was set
    }
out:
    return ret;
}

int check_opt_ulimit_type(const char *type)
{
    int ret = 0;
    char **tmptype = NULL;
    char *ulimit_valid_type[] = {
        // "as", // Disabled since this doesn't seem usable with the way Docker inits a container.
        "core",   "cpu",   "data", "fsize",  "locks",  "memlock",    "msgqueue", "nice",
        "nofile", "nproc", "rss",  "rtprio", "rttime", "sigpending", "stack",    NULL
    };

    for (tmptype = ulimit_valid_type; *tmptype != NULL; tmptype++) {
        if (strcmp(type, *tmptype) == 0) {
            break;
        }
    }

    if (*tmptype == NULL) {
        COMMAND_ERROR("Invalid ulimit type: %s", type);
        ret = -1;
    }
    return ret;
}

host_config_ulimits_element *parse_opt_ulimit(const char *val)
{
    int ret = 0;
    int64_t soft = 0;
    int64_t hard = 0;
    size_t parts_len = 0;
    size_t limitvals_len = 0;
    char **parts = NULL;
    char **limitvals = NULL;
    host_config_ulimits_element *ulimit = NULL;

    ret = check_ulimit_input(val);
    if (ret != 0) {
        return NULL;
    }

    get_ulimit_split_parts(val, &parts, &parts_len, '=');
    if (parts == NULL) {
        ERROR("Out of memory");
        return NULL;
    } else if (parts_len != 2) {
        COMMAND_ERROR("Invalid ulimit argument: %s", val);
        ret = -1;
        goto out;
    }

    ret = check_opt_ulimit_type(parts[0]);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    if (parts[1][0] == ':' || parts[1][strlen(parts[1]) - 1] == ':') {
        COMMAND_ERROR("Invalid ulimit value: \"%s\", delimiter ':' can't be the first"
                      " or the last character",
                      val);
        ret = -1;
        goto out;
    }

    // parse value
    get_ulimit_split_parts(parts[1], &limitvals, &limitvals_len, ':');
    if (limitvals == NULL) {
        ret = -1;
        goto out;
    }

    if (limitvals_len > 2) {
        COMMAND_ERROR("Too many limit value arguments - %s, can only have up to two, `soft[:hard]`", parts[1]);
        ret = -1;
        goto out;
    }

    ret = parse_soft_hard_ulimit(val, limitvals, limitvals_len, &soft, &hard);
    if (ret < 0) {
        goto out;
    }

    ulimit = util_common_calloc_s(sizeof(host_config_ulimits_element));
    if (ulimit == NULL) {
        ret = -1;
        goto out;
    }
    ulimit->name = util_strdup_s(parts[0]);
    ulimit->hard = hard;
    ulimit->soft = soft;

out:
    util_free_array(parts);
    util_free_array(limitvals);
    if (ret != 0) {
        free_host_config_ulimits_element(ulimit);
        ulimit = NULL;
    }

    return ulimit;
}