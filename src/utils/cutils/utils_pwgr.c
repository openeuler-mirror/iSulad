/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: hejunjie
 * Create: 2022-04-08
 * Description: Provide line parser for android
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_pwgr.h"

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio_ext.h>

#include "isula_libutils/log.h"
#include "utils_string.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils.h"

static int hold_int(const char delim, bool required, char **src, unsigned int *dst)
{
    long long res = 0;
    char *walker = *src;
    char *err_str = NULL;

    if (**src == '\0') {
        ERROR("Empty subject on given entrie is not allowed.");
        return -1;
    }

    while (*walker != delim) {
        if (*walker == '\0') {
            break;
        }
        ++walker;
    }

    if (*walker == **src) {
        if (required) { // deafult 0 while required full content but integer part is missing
            *dst = 0;
            *src = walker + 1;
            return 0;
        }
        ERROR("Integer part is missing.");
        ++(*src);
        return -1;
    }

    res = strtoll(*src, &err_str, 0);
    if (errno == ERANGE) {
        ERROR("Parse int from string failed.");
        return -1;
    }
    if (res < 0) {
        ERROR("Gid uid shall not be negative.");
        return -1;
    }

    if (sizeof(void *) > 4 && res > UINT_MAX) { // make sure 64-bit platform behave same as 32-bit
        res = UINT_MAX;
    }
    res = res & UINT_MAX;
    *dst = (uint32_t)res;
    *src = err_str + 1; // update src to next valid context in line.

    return 0;
}

static int hold_string(const char delim, char **src, char **dst)
{
    if (**src == delim) { // if src point to deliminator, content parsing is skiped.
        *dst = "";
        *src = *src + 1;
        return 0;
    }

    if (**src == '\0') {
        return 0;
    }

    for (*dst = *src; **src != delim; ++(*src)) {
        if (**src == '\0') {
            break;
        }
    }
    if (**src == delim) {
        **src = '\0';
        ++(*src);
    }

    return 0;
}

static int parse_line_pw(const char delim, char *line, struct passwd *result)
{
    int ret = 0;
    bool required = false;

    ret = hold_string(delim, &line, &result->pw_name);
    if (ret != 0) {
        ERROR("Parse name error.");
        return ret;
    }

    required = (result->pw_name[0] == '+' || result->pw_name[0] == '-') ? true : false;

    ret = hold_string(delim, &line, &result->pw_passwd);
    if (ret != 0) {
        ERROR("Parse passwd error.");
        return ret;
    }

    ret = hold_int(delim, required, &line, &result->pw_uid);
    if (ret != 0) {
        // a legitimate line must have uid
        ERROR("Parse uid error.");
        return ret;
    }
    ret = hold_int(delim, required, &line, &result->pw_gid);
    if (ret != 0) {
        // it's ok to not provide gid
        ERROR("Parse gid error.");
    }

    ret = hold_string(delim, &line, &result->pw_gecos);
    if (ret != 0) {
        ERROR("Parse gecos error.");
        return ret;
    }

    ret = hold_string(delim, &line, &result->pw_dir);
    if (ret != 0) {
        ERROR("Parse dir error.");
        return ret;
    }

    ret = hold_string(delim, &line, &result->pw_shell);
    if (ret != 0) {
        ERROR("Parse shell error.");
        return ret;
    }

    return ret;
}

static char **hold_string_list(char **line, char *buf_start, char *buf_end, const char terminator)
{
    char **result = NULL;
    char **walker = NULL;

    if (**line == '\0') {
        return 0;
    }
    // For ultimate space usage, the blank area from buffer which was allocated from stack is used
    buf_start += __alignof__(char *) - 1;
    // align the starting position of the buffer to use it as a 2d array
    buf_start -= (buf_start - (char *)0) % __alignof__(char *);
    // record the starting position for latter return
    result = (char **)buf_start;
    // set stop edge for the buffer
    walker = result;

    for (; walker < (char **)buf_end; ++walker) {
        (void)util_trim_space(*line);
        if (hold_string(',', line, walker) != 0) {
            ERROR("Parse string list error.");
            return NULL;
        }

        if ((char *)(walker + 2) > buf_end) {
            return NULL;
        }

        if (**line == '\0') {
            return result;
        }
    }

    return result;
}

static int parse_line_gr(const char delim, char *line, size_t buflen, struct group *result)
{
    int ret = 0;
    bool rf = false;
    char *freebuff = line + 1 + strlen(line);
    char *buffend = line + buflen;

    ret = hold_string(delim, &line, &result->gr_name);
    if (ret != 0) {
        ERROR("Parse name error.");
        return ret;
    }

    ret = hold_string(delim, &line, &result->gr_passwd);
    if (ret != 0) {
        ERROR("Parse gecos error.");
        return ret;
    }
    if (result->gr_name[0] == '+' || result->gr_name[0] == '-') {
        rf = true;
    }

    ret = hold_int(delim, rf, &line, &result->gr_gid);
    if (ret != 0) {
        ERROR("Parse gid error.");
        return ret;
    }

    result->gr_mem = hold_string_list(&line, freebuff, buffend, ',');

    return 0;
}

int util_getpwent_r(FILE *stream, struct passwd *resbuf, char *buffer, size_t buflen, struct passwd **result)
{
    const char delim = ':';

    if (stream == NULL || resbuf == NULL || buffer == NULL) {
        ERROR("Password obj, params is NULL.");
        return -1;
    }

    if (buflen <= 1) {
        ERROR("Inadiquate buffer length was given.");
        return -1;
    }

    if (*result != NULL) {
        ERROR("Result shall point to null to start.");
        return -1;
    }

    __fsetlocking(stream, FSETLOCKING_BYCALLER);
    buffer[buflen - 1] = '\0';

    if (feof(stream)) {
        *result = NULL;
        return ENOENT;
    }

    while (fgets(buffer, buflen, stream) != NULL) {
        (void)util_trim_space(buffer);
        if (buffer[0] == '\0' || buffer[0] == '#' || strlen(buffer) < 1) {
            continue;
        }

        if (parse_line_pw(delim, buffer, resbuf) == 0) {
            break;
        }

        if (buffer[buflen - 1] != '\0') {
            *result = NULL;
            return ERANGE;
        }
    }
    *result = resbuf;

    return 0;
}

int util_getgrent_r(FILE *stream, struct group *resbuf, char *buffer, size_t buflen, struct group **result)
{
    const char delim = ':';

    if (stream == NULL || resbuf == NULL || buffer == NULL) {
        ERROR("Group obj, params is NULL.");
        return -1;
    }

    if (buflen <= 1) {
        ERROR("Inadiquate buffer length was given.");
        return -1;
    }

    if (*result != NULL) {
        ERROR("Result shall point to null to start.");
        return -1;
    }

    __fsetlocking(stream, FSETLOCKING_BYCALLER);
    buffer[buflen - 1] = '\0';

    if (feof(stream)) {
        *result = NULL;
        return ENOENT;
    }

    while (fgets(buffer, buflen, stream) != NULL) {
        (void)util_trim_space(buffer);
        if (buffer[0] == '\0' || buffer[0] == '#' || strlen(buffer) < 1) {
            continue;
        }

        if (parse_line_gr(delim, buffer, buflen, resbuf) == 0) {
            break;
        }

        if (buffer[buflen - 1] != '\0') {
            *result = NULL;
            return ERANGE;
        }
    }
    *result = resbuf;

    return 0;
}