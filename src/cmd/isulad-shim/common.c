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
 * Author: leizhongkai
 * Create: 2020-1-21
 * Description: common functions of isulad-shim
 ******************************************************************************/

#define _GNU_SOURCE
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdarg.h>

int set_fd_no_inherited(int fd)
{
    int ret = SHIM_ERR;
    int flag = -1;

    flag = fcntl(fd, F_GETFD, 0);
    if (flag < 0) {
        return SHIM_ERR;
    }

    ret = fcntl(fd, F_SETFD, flag | FD_CLOEXEC);
    if (ret != 0) {
        return SHIM_ERR;
    }

    return SHIM_OK;
}

ssize_t read_nointr(int fd, void *buf, size_t count)
{
    ssize_t nret;

    if (buf == NULL) {
        return -1;
    }

    for (;;) {
        nret = read(fd, buf, count);
        if (nret < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        } else {
            break;
        }
    }

    return nret;
}

ssize_t write_nointr(int fd, const void *buf, size_t count)
{
    ssize_t nret;

    if (buf == NULL) {
        return -1;
    }

    for (;;) {
        nret = write(fd, buf, count);
        if (nret < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        } else {
            break;
        }
    }
    return nret;
}

ssize_t write_nointr_in_total(int fd, const char *buf, size_t count)
{
    ssize_t nret = 0;
    ssize_t nwritten;

    if (buf == NULL) {
        return -1;
    }

    for (nwritten = 0; nwritten < count;) {
        nret = write(fd, buf + nwritten, count - nwritten);
        if (nret < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            } else {
                return nret;
            }
        } else {
            nwritten += nret;
        }
    }

    return nwritten;
}

bool file_exists(const char *f)
{
    struct stat buf;
    int nret;

    if (f == NULL) {
        return false;
    }

    nret = stat(f, &buf);
    if (nret < 0) {
        return false;
    }
    return true;
}

int cmd_combined_output(const char *binary, const char *params[], void *output, int *output_len)
{
    int ret = SHIM_ERR;
    int status = 0;
    int exec_fd[2] = { -1, -1 };
    int stdio[2] = { -1, -1 };
    pid_t pid = 0;
    char exec_buff[BUFSIZ] = { 0 };
    ssize_t nread;

    if (pipe2(exec_fd, O_CLOEXEC) != 0) {
        return SHIM_ERR;
    }

    if (pipe2(stdio, O_CLOEXEC) != 0) {
        return SHIM_ERR;
    }

    pid = fork();
    if (pid == (pid_t) -1) {
        return SHIM_ERR;
    }

    // child
    if (pid == (pid_t)0) {
        close(exec_fd[0]);
        close(stdio[0]);
        dup2(stdio[1], 1);
        dup2(stdio[1], 2);
        execvp(binary, (char * const *)params);
        (void)dprintf(exec_fd[1], "fork/exec error: %s", strerror(errno));
        _exit(EXIT_FAILURE);
    }

    // parent
    close(exec_fd[1]);
    close(stdio[1]);
    nread = read_nointr(exec_fd[0], exec_buff, BUFSIZ - 1);
    if (nread > 0) {
        ret = SHIM_ERR;
        goto out;
    }
    *output_len = read_nointr(stdio[0], output, BUFSIZ - 1);

    close(stdio[0]);
    close(exec_fd[0]);
    wait(&status);
    ret = SHIM_OK;

out:
    if (ret != SHIM_OK && pid != 0) {
        kill(pid, 9);
    }

    return ret;
}

int generate_random_str(char *id, size_t len)
{
    int fd = -1;
    int num = 0;
    size_t i;
    const int m = 256;

    len = len / 2;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        return SHIM_ERR;
    }
    for (i = 0; i < len; i++) {
        int nret;
        if (read(fd, &num, sizeof(int)) < 0) {
            close(fd);
            return SHIM_ERR;
        }
        unsigned char rs = (unsigned char)(num % m);
        nret = snprintf((id + i * 2), ((len - i) * 2 + 1), "%02x", (unsigned int)rs);
        if (nret < 0) {
            close(fd);
            return SHIM_ERR;
        }
    }
    close(fd);
    id[i * 2] = '\0';

    return SHIM_OK;
}

void write_message(int fd, const char *level, const char *fmt, ...)
{
#define MAX_MSG_JSON_TEMPLATE 32
#define MAX_MESSAGE_CONTENT_LEN 128
#define MAX_MESSAGE_LEN (MAX_MSG_JSON_TEMPLATE + MAX_MESSAGE_CONTENT_LEN)
    if (fd < 0) {
        return;
    }

    char buf[MAX_MESSAGE_CONTENT_LEN] = { 0 };
    char msg[MAX_MESSAGE_LEN] = { 0 };
    int nwrite = -1;

    va_list arg_list;
    va_start(arg_list, fmt);
    vsnprintf(buf, MAX_MESSAGE_CONTENT_LEN, fmt, arg_list);
    va_end(arg_list);

    snprintf(msg, MAX_MESSAGE_LEN - 1, "{\"level\": \"%s\", \"msg\": \"%s\"}\n", level, buf);
    nwrite = write(fd, msg, strlen(msg));
    if (nwrite != strlen(msg)) {
        return;
    }
}

/* note: This function can only read small text file. */
char *read_text_file(const char *path)
{
    char *buf = NULL;
    long len = 0;
    size_t readlen = 0;
    FILE *filp = NULL;
    const long max_size = 10 * 1024 * 1024; /* 10M */

    if (path == NULL) {
        return NULL;
    }

    filp = fopen(path, "r");
    if (filp == NULL) {
        goto err_out;
    }
    if (fseek(filp, 0, SEEK_END)) {
        goto err_out;
    }

    len = ftell(filp);
    if (len > max_size) {
        goto err_out;
    }
    if (fseek(filp, 0, SEEK_SET)) {
        goto err_out;
    }

    buf = (char *)calloc(1, (size_t)(len + 1));
    if (buf == NULL) {
        goto err_out;
    }

    readlen = fread(buf, 1, (size_t)len, filp);
    if (((readlen < (size_t)len) && (!feof(filp))) || (readlen > (size_t)len)) {
        free(buf);
        buf = NULL;
        goto err_out;
    }

    buf[(size_t)len] = 0;

err_out:

    if (filp != NULL) {
        fclose(filp);
    }

    return buf;
}

void close_fd(int *pfd)
{
    if (pfd != NULL && *pfd != -1) {
        close(*pfd);
        *pfd = -1;
    }
}

int open_no_inherit(const char *path, int flag, mode_t mode)
{
    int fd = -1;
    int ret = SHIM_ERR;

    fd = open(path, flag, mode);
    if (fd < 0) {
        return -1;
    }

    ret = set_fd_no_inherited(fd);
    if (ret != SHIM_OK) {
        close(fd);
        return -1;
    }

    return fd;
}
