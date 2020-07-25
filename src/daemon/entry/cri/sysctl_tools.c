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
 * Description: provide sysctl functions
 ********************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>

#include "sysctl_tools.h"
#include "utils.h"

int get_sysctl(const char *sysctl, char **err)
{
    int ret = 0;
    int val = -1;
    int fd = -1;
    ssize_t rsize;
    char fullpath[PATH_MAX] = { 0 };
    char buff[MAX_BUFFER_SIZE] = { 0 };

    ret = snprintf(fullpath, PATH_MAX, "%s/%s", SYSCTL_BASE, sysctl);
    if (ret < 0 || ret >= PATH_MAX) {
        *err = util_strdup_s("Out of memory");
        goto free_out;
    }
    ret = -1;
    fd = util_open(fullpath, O_RDONLY, 0);
    if (fd < 0) {
        if (asprintf(err, "Open %s failed: %s", sysctl, strerror(errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        goto free_out;
    }
    rsize = util_read_nointr(fd, buff, MAX_BUFFER_SIZE);
    if (rsize <= 0) {
        if (asprintf(err, "Read file failed: %s", strerror(errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        goto free_out;
    }
    ret = util_safe_int(buff, &val);
    if (ret != 0) {
        if (asprintf(err, "Parse value : %s failed", buff) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        goto free_out;
    }

free_out:
    if (fd >= 0) {
        close(fd);
    }
    if (ret != 0 && !*err) {
        *err = util_strdup_s("Out of memory");
    }
    return val;
}

int set_sysctl(const char *sysctl, int new_value, char **err)
{
    int ret = 0;
    int val = -1;
    int fd = -1;
    ssize_t rsize;
    char fullpath[PATH_MAX] = { 0 };
    char buff[ISULAD_NUMSTRLEN64] = { 0 };

    ret = snprintf(fullpath, PATH_MAX, "%s/%s", SYSCTL_BASE, sysctl);
    if (ret < 0 || ret >= PATH_MAX) {
        *err = util_strdup_s("Out of memory");
        goto free_out;
    }
    ret = snprintf(buff, ISULAD_NUMSTRLEN64, "%d", new_value);
    if (ret < 0 || ret >= ISULAD_NUMSTRLEN64) {
        *err = util_strdup_s("Out of memory");
        goto free_out;
    }
    ret = -1;
    fd = util_open(fullpath, O_WRONLY, 0);
    if (fd < 0) {
        if (asprintf(err, "Open %s failed: %s", sysctl, strerror(errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        goto free_out;
    }
    rsize = util_write_nointr(fd, buff, strlen(buff));
    if (rsize <= 0) {
        if (asprintf(err, "Write new value failed: %s", strerror(errno)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        goto free_out;
    }

    ret = 0;
free_out:
    if (fd >= 0) {
        close(fd);
    }
    if (ret != 0 && !*err) {
        *err = util_strdup_s("Out of memory");
    }
    return val;
}

