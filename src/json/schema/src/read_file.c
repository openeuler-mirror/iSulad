/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide file read functions
 ********************************************************************************/
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include <config.h>
#include "read_file.h"

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#define JSON_MAX_SIZE (10LL * 1024LL * 1024LL)
#define FILE_MODE 0640

static int do_check_fread_args(const FILE *stream, const size_t *length)
{
    if (stream == NULL) {
        return -1;
    }
    if (length == NULL) {
        return -1;
    }

    return 0;
}

char *fread_file(FILE *stream, size_t *length)
{
    char *buf = NULL;
    char *tmpbuf = NULL;
    size_t off = 0;

    if (do_check_fread_args(stream, length) != 0) {
        return NULL;
    }

    while (1) {
        size_t ret, newsize, sizejudge;
        sizejudge = (JSON_MAX_SIZE - BUFSIZ) - 1;
        if (sizejudge < off) {
            goto out;
        }
        newsize = off + BUFSIZ + 1;

        tmpbuf = (char *)calloc(1, newsize);
        if (tmpbuf == NULL) {
            goto out;
        }

        if (buf != NULL) {
            (void)memcpy(tmpbuf, buf, off);

            (void)memset(buf, 0, off);

            free(buf);
        }

        buf = tmpbuf;
        tmpbuf = NULL;

        ret = fread(buf + off, 1, BUFSIZ, stream);
        if (ret == 0 && ferror(stream)) {
            goto out;
        }
        if (ret < BUFSIZ || feof(stream)) {
            *length = off + ret + 1;
            buf[*length - 1] = '\0';
            return buf;
        }

        off += BUFSIZ;
    }
out:
    free(buf);
    free(tmpbuf);
    return NULL;
}

static int do_check_args(const char *path, const size_t *length)
{
    if (path == NULL || length == NULL) {
        return -1;
    }
    if (strlen(path) > PATH_MAX) {
        return -1;
    }
    return 0;
}

char *read_file(const char *path, size_t *length)
{
    char *buf = NULL;
    char rpath[PATH_MAX + 1] = { 0 };
    int fd = -1;
    int tmperrno = -1;
    FILE *fp = NULL;

    if (do_check_args(path, length) != 0) {
        return NULL;
    }

    if (realpath(path, rpath) == NULL) {
        return NULL;
    }

    fd = open(rpath, O_RDONLY | O_CLOEXEC, FILE_MODE);
    if (fd < 0) {
        return NULL;
    }

    fp = fdopen(fd, "r");
    tmperrno = errno;
    if (fp == NULL) {
        (void)close(fd);
        errno = tmperrno;
        return NULL;
    }

    buf = fread_file(fp, length);
    (void)fclose(fp);
    return buf;
}
