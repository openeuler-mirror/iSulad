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
    unsigned long long int res = 0;
    char *err_str = NULL;

    // ensure *src not a empty string
    if (**src == '\0') {
        ERROR("Empty subject on given entrie is not allowed.");
        return -1;
    }

    errno = 0;
    // covert string to long long
    res = strtoull(*src, &err_str, 0);
    if (errno != 0 && errno != ERANGE) {
        ERROR("Parse int from string failed.");
        return -1;
    }

    // **src is not a digit
    if (err_str == *src) {
        if (!required) {
            ERROR("Integer part is missing.");
            return -1;
        }
        // if required, just set 0
        *dst = 0;
    } else {
        if (sizeof(void *) > 4 && res > UINT_MAX) { // make sure 64-bit platform behave same as 32-bit
            res = UINT_MAX;
        }
        res = res & UINT_MAX;
        *dst = (uint32_t)res;
    }

    // normal case
    if (*err_str == delim) {
        err_str++;
    } else if (*err_str != '\0') {
        ERROR("Invalid digit string.");
        return -1;
    }

    *src = err_str; // update src to next valid context in line.
    return 0;
}

static void hold_string(const char delim, char **src, char **dst)
{
    for (*dst = *src; **src != delim; ++(*src)) {
        if (**src == '\0') {
            break;
        }
    }

    if (**src == delim) {
        **src = '\0';
        ++(*src);
    }
}

static int parse_line_pw(const char delim, char *line, char *buffend, void *vresult)
{
    int ret = 0;
    bool required = false;
    char *walker = NULL;
    struct passwd *result = (struct passwd *)vresult;

    walker = strpbrk(line, "\n");
    if (walker != NULL) {
        // clear newline char
        *walker = '\0';
    }

    hold_string(delim, &line, &result->pw_name);

    required = (result->pw_name[0] == '+' || result->pw_name[0] == '-') ? true : false;

    hold_string(delim, &line, &result->pw_passwd);

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
        return ret;
    }

    hold_string(delim, &line, &result->pw_gecos);

    hold_string(delim, &line, &result->pw_dir);

    result->pw_shell = line;
    return 0;
}

static char **hold_string_list(char **line, char *buf_start, char *buf_end, const char terminator)
{
    char **result = NULL;
    char **walker = NULL;

    // For ultimate space usage, the blank area from buffer which was allocated from stack is used
    buf_start += __alignof__(char *) - 1;
    // align the starting position of the buffer to use it as a 2d array
    buf_start -= (buf_start - (char *)0) % __alignof__(char *);
    // record the starting position for latter return
    result = (char **)buf_start;
    // set stop edge for the buffer
    walker = result;

    for (; walker < (char **)buf_end; ++walker) {
        if (**line == '\0') {
            goto out;
        }

        (void)util_trim_space(*line);
        hold_string(',', line, walker);

        if ((char *)(walker + 2) > buf_end) {
            return NULL;
        }
    }

out:
    *walker = NULL;
    return result;
}

static int parse_line_gr(const char delim, char *line, char *buffend, void *vresult)
{
    int ret = 0;
    bool rf = false;
    char *freebuff = line + 1 + strlen(line);
    char *walker = NULL;
    struct group *result = (struct group *)vresult;

    walker = strpbrk(line, "\n");
    if (walker != NULL) {
        // clear newline char
        *walker = '\0';
    }

    hold_string(delim, &line, &result->gr_name);

    hold_string(delim, &line, &result->gr_passwd);

    if (result->gr_name[0] == '+' || result->gr_name[0] == '-') {
        rf = true;
    }

    ret = hold_int(delim, rf, &line, &result->gr_gid);
    if (ret != 0) {
        ERROR("Parse gid error.");
        return ret;
    }

    result->gr_mem = hold_string_list(&line, freebuff, buffend, ',');
    if (result->gr_mem == NULL) {
        ERROR("overflow of buffer.");
        return -1;
    }

    return 0;
}

typedef int (*line_parser_cb)(const char delim, char *line, char *buffend, void *vresult);

static int do_util_line_parser(FILE *stream, void *resbuf, char *buffer, size_t buflen, void **result,
                               line_parser_cb cb)
{
    const char delim = ':';
    char *buff_end = NULL;
    char *walker = NULL;
    bool got = false;
    int ret = 0;

    if (stream == NULL || resbuf == NULL || buffer == NULL || result == NULL) {
        ERROR("Password obj, params is NULL.");
        return -1;
    }

    if (buflen <= 1) {
        ERROR("Inadequate buffer length was given.");
        return -1;
    }

    buff_end = buffer + buflen - 1;
    flockfile(stream);

    while (1) {
        *buff_end = '\xff';
        walker = fgets_unlocked(buffer, buflen, stream);
        // if get NULL string
        if (walker == NULL) {
            *result = NULL;
            // reach end of file, return error
            if (feof(stream)) {
                ret = ENOENT;
                goto out;
            }
            // overflow buffer
            ret = ERANGE;
            goto out;
        }
        // just overflow last char in buffer
        if (*buff_end != '\xff') {
            *result = NULL;
            ret = ERANGE;
            goto out;
        }

        (void)util_trim_space(buffer);
        // skip comment line and empty line
        if (walker[0] == '#' || walker[0] == '\0') {
            continue;
        }

        if (cb(delim, walker, buff_end, resbuf) == 0) {
            got = true;
            break;
        }
    }
    if (!got) {
        *result = NULL;
        ret = ERANGE;
        goto out;
    }

    *result = resbuf;
    ret = 0;
out:
    funlockfile(stream);
    return ret;
}

int util_getpwent_r(FILE *stream, struct passwd *resbuf, char *buffer, size_t buflen, struct passwd **result)
{
    return do_util_line_parser(stream, resbuf, buffer, buflen, (void **)result, parse_line_pw);
}

int util_getgrent_r(FILE *stream, struct group *resbuf, char *buffer, size_t buflen, struct group **result)
{
    return do_util_line_parser(stream, resbuf, buffer, buflen, (void **)result, parse_line_gr);
}
