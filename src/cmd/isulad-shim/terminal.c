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
 * Author: gaohuatao
 * Create: 2020-3-9
 * Description: container logs ops
 ******************************************************************************/
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <termios.h> // IWYU pragma: keep
#include <isula_libutils/json_common.h>
#include <isula_libutils/logger_json_file.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "terminal.h"
#include "common.h"

#define BUF_CACHE_SIZE (16 * 1024)

static ssize_t shim_write_nointr_lock(log_terminal *terminal, const void *buf, size_t count)
{
    ssize_t ret;

    (void)pthread_rwlock_wrlock(&terminal->log_terminal_rwlock);
    ret = write_nointr(terminal->fd, buf, count);
    (void)pthread_rwlock_unlock(&terminal->log_terminal_rwlock);

    return ret;
}

static int shim_rename_old_log_file(log_terminal *terminal)
{
    int ret;
    unsigned int i;
    char tmp[PATH_MAX] = { 0 };
    char *rename_fname = NULL;

    for (i = terminal->log_maxfile - 1; i > 1; i--) {
        ret = snprintf(tmp, PATH_MAX, "%s.%u", terminal->log_path, i);
        if (ret < 0 || ret >= PATH_MAX) {
            free(rename_fname);
            return SHIM_ERR;
        }
        free(rename_fname);
        rename_fname = safe_strdup(tmp);

        ret = snprintf(tmp, PATH_MAX, "%s.%u", terminal->log_path, (i - 1));
        if (ret < 0 || ret >= PATH_MAX) {
            free(rename_fname);
            return SHIM_ERR;
        }

        ret = rename(tmp, rename_fname);
        if (ret < 0 && errno != ENOENT) {
            free(rename_fname);
            return SHIM_ERR;
        }
    }

    free(rename_fname);
    return SHIM_OK;
}

static int shim_dump_log_file(log_terminal *terminal)
{
    int ret;
    size_t len_path;
    char *file_newname = NULL;

    if (strlen(terminal->log_path) > (PATH_MAX - sizeof(".1"))) {
        return SHIM_ERR;
    }
    len_path = strlen(terminal->log_path) + sizeof(".1");

    /* isulad: rotate old log file first */
    ret = shim_rename_old_log_file(terminal);
    if (ret != 0) {
        return SHIM_ERR;
    }

    file_newname = calloc(len_path, 1);
    if (file_newname == NULL) {
        return SHIM_ERR;
    }

    ret = snprintf(file_newname, len_path, "%s.1", terminal->log_path);
    if (ret < 0 || (size_t)ret >= len_path) {
        ret = -1;
        goto clean_out;
    }

    /*
     * Rename the file console.log to console.log.1 then create and open console.log again.
     * fd points to console.log file always.
     */
    close(terminal->fd);
    terminal->fd = -1;
    (void)rename(terminal->log_path, file_newname);
    ret = shim_create_container_log_file(terminal);
clean_out:
    free(file_newname);
    return ret;
}

static int64_t get_log_file_size(int fd)
{
    struct stat log_st;
    int ret;

    ret = fstat(fd, &log_st);
    if (ret < 0) {
        return SHIM_ERR;
    }

    if (S_IFREG != (log_st.st_mode & S_IFMT)) {
        return SHIM_ERR;
    }

    return log_st.st_size;
}

static int shim_json_data_write(log_terminal *terminal, const char *buf, int read_count)
{
    int ret;
    int64_t available_space = -1;
    int64_t file_size;

    file_size = get_log_file_size(terminal->fd);
    if (file_size < 0) {
        return SHIM_ERR;
    }

    available_space = terminal->log_maxsize - file_size;
    if (read_count <= available_space) {
        return shim_write_nointr_lock(terminal, buf, read_count);
    }

    ret = shim_dump_log_file(terminal);
    if (ret < 0) {
        return SHIM_ERR;
    }

    /*
     * Now file is new, then write the max bytes that will be wrote to log file.
     * We have set the log file min size 16k, so the scenario of log_maxsize < read_count
     * shouldn't happen, otherwise, discard some last bytes.
     */
    ret = shim_write_nointr_lock(terminal, buf,
                                 terminal->log_maxsize < read_count ? terminal->log_maxsize : read_count);
    if (ret < 0) {
        return SHIM_ERR;
    }

    return (read_count - ret);
}

static bool get_time_buffer(struct timespec *timestamp, char *timebuffer, size_t maxsize)
{
    struct tm tm_utc = { 0 };
    int32_t nanos = 0;
    time_t seconds;
    size_t len = 0;
    int ret = 0;

    if (!timebuffer || !maxsize) {
        return false;
    }

    seconds = (time_t)timestamp->tv_sec;
    gmtime_r(&seconds, &tm_utc);
    strftime(timebuffer, maxsize, "%Y-%m-%dT%H:%M:%S", &tm_utc);

    nanos = (int32_t)timestamp->tv_nsec;
    len = strlen(timebuffer);
    ret = snprintf(timebuffer + len, (maxsize - len), ".%09dZ", nanos);
    if (ret < 0 || ret >= (maxsize - len)) {
        return false;
    }

    return true;
}

static bool get_now_time_buffer(char *timebuffer, size_t maxsize)
{
    int err = 0;
    struct timespec ts;

    err = clock_gettime(CLOCK_REALTIME, &ts);
    if (err != 0) {
        return false;
    }

    return get_time_buffer(&ts, timebuffer, maxsize);
}

static ssize_t shim_logger_write(log_terminal *terminal, const char *type, const char *buf, int read_count)
{
    logger_json_file *msg = NULL;
    ssize_t ret = -1;
    size_t len;
    char *json = NULL;
    char timebuffer[64] = { 0 };
    parser_error err = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY | OPT_GEN_NO_VALIDATE_UTF8, stderr };

    if (read_count < 0 || read_count >= INT_MAX) {
        return SHIM_ERR;
    }

    msg = calloc(sizeof(logger_json_file), 1);
    if (msg == NULL) {
        return SHIM_ERR;
    }

    msg->log = calloc(read_count, 1);
    if (!msg->log) {
        goto cleanup;
    }
    memcpy(msg->log, buf, read_count);
    msg->log_len = read_count;
    msg->stream = type ? safe_strdup(type) : safe_strdup("stdout");

    get_now_time_buffer(timebuffer, sizeof(timebuffer));
    msg->time = safe_strdup(timebuffer);
    json = logger_json_file_generate_json(msg, &ctx, &err);
    if (!json) {
        goto cleanup;
    }
    len = strlen(json);
    json[len] = '\n';
    if (terminal->fd < 0) {
        goto cleanup;
    }

    ret = shim_json_data_write(terminal, json, len + 1);
cleanup:
    free(json);
    free_logger_json_file(msg);
    free(err);
    return ret;
}

void shim_write_container_log_file(log_terminal *terminal, const char *type, char *buf, int read_count)
{
    static char cache[BUF_CACHE_SIZE];
    static int size = 0;
    int upto, index;
    int begin = 0, buf_readed = 0, buf_left = 0;

    if (terminal == NULL) {
        return;
    }

    if (buf != NULL && read_count > 0) {
        upto = size + read_count;
        if (upto > BUF_CACHE_SIZE) {
            upto = BUF_CACHE_SIZE;
        }

        if (upto > size) {
            buf_readed = upto - size;
            memcpy(cache + size, buf, buf_readed);
            buf_left = read_count - buf_readed;
            size += buf_readed;
        }
    }

    if (size == 0) {
        return;
    }

    for (index = 0; index < size; index++) {
        if (cache[index] == '\n') {
            (void)shim_logger_write(terminal, type, cache + begin, index - begin + 1);
            begin = index + 1;
        }
    }

    if (buf == NULL || (begin == 0 && size == BUF_CACHE_SIZE)) {
        if (begin < size) {
            (void)shim_logger_write(terminal, type, cache + begin, size - begin);
            begin = 0;
            size = 0;
        }
        if (buf == NULL) {
            return;
        }
    }

    if (begin > 0) {
        memcpy(cache, cache + begin, size - begin);
        size -= begin;
    }

    if (buf_left > 0) {
        memcpy(cache + size, buf + buf_readed, buf_left);
        size += buf_left;
    }
}

int shim_create_container_log_file(log_terminal *terminal)
{
    if (!terminal->log_path) {
        return SHIM_ERR;
    }

    terminal->fd = open(terminal->log_path, O_CLOEXEC | O_RDWR | O_CREAT | O_APPEND, 0600);
    if (terminal->fd < 0) {
        return SHIM_ERR;
    }

    return SHIM_OK;
}
