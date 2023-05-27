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
#include <limits.h>
#include <time.h>

int g_log_fd = -1;

void signal_routine(int sig)
{
    switch (sig) {
        case SIGALRM:
            write_message(g_log_fd, ERR_MSG, "runtime timeout");
            exit(EXIT_FAILURE);
        default:
            break;
    }
}

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
    if (ret != SHIM_OK) {
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
        if (read_nointr(fd, &num, sizeof(int)) < 0) {
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
    nwrite = write_nointr_in_total(fd, msg, strlen(msg));
    if (nwrite < 0 || (size_t)nwrite != strlen(msg)) {
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

static bool is_invalid_error_str(const char *err_str, const char *numstr)
{
    return err_str == NULL || err_str == numstr || *err_str != '\0';
}

int shim_util_safe_uint64(const char *numstr, uint64_t *converted)
{
    char *err_str = NULL;
    uint64_t ull;

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

    *converted = (uint64_t)ull;
    return 0;
}

void util_usleep_nointerupt(unsigned long usec)
{
#define SECOND_TO_USECOND_MUTIPLE 1000000
    int ret = 0;
    struct timespec request = { 0 };
    struct timespec remain = { 0 };
    if (usec == 0) {
        return;
    }

    request.tv_sec = (time_t)(usec / SECOND_TO_USECOND_MUTIPLE);
    request.tv_nsec = (long)((usec % SECOND_TO_USECOND_MUTIPLE) * 1000);

    do {
        ret = nanosleep(&request, &remain);
        request = remain;
    } while (ret == -1 && errno == EINTR);
}

void *util_smart_calloc_s(size_t unit_size, size_t count)
{
    // If count or size is 0,
    // then calloc() returns either NULL,
    // or a unique pointer value that can later be successfully passed to free()
    if (unit_size == 0 || count == 0) {
        return NULL;
    }

    if (count > (MAX_MEMORY_SIZE / unit_size)) {
        return NULL;
    }

    return calloc(count, unit_size);
}

size_t util_array_len(const char **array)
{
    const char **pos;
    size_t len = 0;

    for (pos = array; pos != NULL && *pos != NULL; pos++) {
        len++;
    }

    return len;
}

void util_free_array(char **array)
{
    char **p;

    for (p = array; p != NULL && *p != NULL; p++) {
        UTIL_FREE_AND_SET_NULL(*p);
    }
    free(array);
}

int util_grow_array(char ***orig_array, size_t *orig_capacity, size_t size, size_t increment)
{
    size_t add_capacity;
    char **add_array = NULL;

    if (orig_array == NULL || orig_capacity == NULL || increment == 0) {
        return -1;
    }

    if (((*orig_array) == NULL) || ((*orig_capacity) == 0)) {
        UTIL_FREE_AND_SET_NULL(*orig_array);
        *orig_capacity = 0;
    }

    add_capacity = *orig_capacity;
    while (size + 1 > add_capacity) {
        add_capacity += increment;
    }
    if (add_capacity != *orig_capacity) {
        add_array = util_smart_calloc_s(sizeof(void *), add_capacity);
        if (add_array == NULL) {
            return -1;
        }
        if (*orig_array != NULL) {
            (void)memcpy(add_array, *orig_array, *orig_capacity * sizeof(void *));
            UTIL_FREE_AND_SET_NULL(*orig_array);
        }

        *orig_array = add_array;
        *orig_capacity = add_capacity;
    }

    return 0;
}

char *util_strdup_s(const char *src)
{
    char *dst = NULL;

    if (src == NULL) {
        return NULL;
    }

    dst = strdup(src);
    if (dst == NULL) {
        abort();
    }

    return dst;
}

static char **make_empty_array()
{
    char **res_array = NULL;

    res_array = calloc(2, sizeof(char *));
    if (res_array == NULL) {
        return NULL;
    }
    res_array[0] = util_strdup_s("");
    return res_array;
}

static char **util_shrink_array(char **orig_array, size_t new_size)
{
    char **new_array = NULL;
    size_t i = 0;

    if (new_size == 0) {
        return orig_array;
    }
    new_array = util_smart_calloc_s(sizeof(char *), new_size);
    if (new_array == NULL) {
        return orig_array;
    }

    for (i = 0; i < new_size; i++) {
        new_array[i] = orig_array[i];
    }
    free(orig_array);
    return new_array;
}

char **util_string_split_multi(const char *src_str, char delim)
{
    int ret, tmp_errno;
    char *token = NULL;
    char *cur = NULL;
    char **res_array = NULL;
    char deli[2] = { delim, '\0' };
    size_t count = 0;
    size_t capacity = 0;
    char *tmpstr = NULL;

    if (src_str == NULL) {
        return NULL;
    }

    if (src_str[0] == '\0') {
        return make_empty_array();
    }

    tmpstr = util_strdup_s(src_str);
    cur = tmpstr;
    token = strsep(&cur, deli);
    while (token != NULL) {
        ret = util_grow_array(&res_array, &capacity, count + 1, 16);
        if (ret < 0) {
            goto err_out;
        }
        res_array[count] = util_strdup_s(token);
        count++;
        token = strsep(&cur, deli);
    }
    free(tmpstr);
    return util_shrink_array(res_array, count + 1);

err_out:
    tmp_errno = errno;
    free(tmpstr);
    util_free_array(res_array);
    errno = tmp_errno;
    return NULL;
}

void *util_common_calloc_s(size_t size)
{
    if (size == 0 || size > MAX_MEMORY_SIZE) {
        return NULL;
    }

    return calloc((size_t)1, size);
}