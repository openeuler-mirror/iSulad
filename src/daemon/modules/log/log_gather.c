/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide log gather functions
 ******************************************************************************/
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <strings.h>
#include <sys/prctl.h>

#include "log_gather_api.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "isulad_tar.h"
#include "utils_file.h"

typedef int (*log_save_t)(const void *buf, size_t count);
static log_save_t g_save_log_op = NULL;

static int g_fifo_fd = -1;
static char *g_fifo_path = NULL;
static int g_log_fd = -1;
static char *g_log_file = NULL;
static int64_t g_max_size = 4096;
static int g_max_file = 3;
static mode_t g_log_mode = S_IRUSR | S_IWUSR;

static int log_file_open();

static int file_rotate_gz(const char *file_name, int i)
{
    int ret = 0;
    char from_path[PATH_MAX] = { 0 };
    char to_path[PATH_MAX] = { 0 };

    ret = snprintf(from_path, PATH_MAX, "%s.%d.gz", file_name, (i - 1));
    if (ret >= PATH_MAX || ret < 0) {
        ERROR("sprint zip file name failed");
        return -1;
    }

    ret = snprintf(to_path, PATH_MAX, "%s.%d.gz", file_name, i);
    if (ret >= PATH_MAX || ret < 0) {
        ERROR("sprint zip file name failed");
        return -1;
    }

    if (rename(from_path, to_path) < 0 && errno != ENOENT) {
        WARN("Rename file: %s error: %s", from_path, strerror(errno));
        return -1;
    }

    return 0;
}

static int file_rotate_me(const char *file_name)
{
    int ret = 0;
    char tmp_path[PATH_MAX] = { 0 };

    ret = snprintf(tmp_path, PATH_MAX, "%s.1", file_name);
    if (ret >= PATH_MAX || ret < 0) {
        ERROR("Out of memory");
        return -1;
    }

    if (rename(file_name, tmp_path) < 0 && errno != ENOENT) {
        WARN("Rename file: %s error: %s", file_name, strerror(errno));
        return -1;
    }

    if (gzip(tmp_path, sizeof(tmp_path))) {
        WARN("Gzip file failed");
        return -2;
    }

    return 0;
}

static int file_rotate(const char *file_name, int max_files)
{
    int i = 0;

    if (file_name == NULL || max_files < 2) {
        return 0;
    }

    for (i = max_files - 1; i > 1; i--) {
        if (file_rotate_gz(file_name, i)) {
            return -1;
        }
    }

    return file_rotate_me(file_name);
}

/* get driver */
static int get_driver(const char *driver)
{
    if (driver == NULL) {
        return LOG_GATHER_DRIVER_NOSET;
    }
    if (strcasecmp(driver, "stdout") == 0) {
        return LOG_GATHER_DRIVER_STDOUT;
    }
    if (strcasecmp(driver, "file") == 0) {
        return LOG_GATHER_DRIVER_FILE;
    }

    return -1;
}

/* create fifo */
static int create_fifo()
{
    int ret = -1;

    ret = mknod(g_fifo_path, S_IFIFO | S_IRUSR | S_IWUSR, (dev_t)0);
    if (ret != 0 && errno != EEXIST) {
        COMMAND_ERROR("mknod failed: %s", strerror(errno));
    } else {
        ret = 0;
    }

    return ret;
}

/* open log */
static int open_log(bool change_size)
{
    int fd = -1;

    fd = util_open(g_fifo_path, O_RDWR | O_CLOEXEC, 0);
    if (fd == -1) {
        COMMAND_ERROR("open fifo %s failed: %s", g_fifo_path, strerror(errno));
        return fd;
    }

    if (change_size && fcntl(fd, F_SETPIPE_SZ, LOG_FIFO_SIZE) == -1) {
        COMMAND_ERROR("set fifo buffer size failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (g_fifo_fd != -1 && g_fifo_fd != fd) {
        close(g_fifo_fd);
    }

    g_fifo_fd = fd;
    return fd;
}

/* write into file */
static int write_into_file(const void *buf, size_t g_log_size)
{
    int ret = 0;
    static int64_t write_size = 0;

    if (!util_file_exists(g_log_file)) {
        COMMAND_ERROR("Log file: %s delete by someone.", g_log_file);
        if (log_file_open()) {
            COMMAND_ERROR("Reopen log file failed.");
            return -1;
        }
    }
    ret = (int)write(g_log_fd, buf, g_log_size);
    if (ret <= 0) {
        return ret;
    }

    write_size += ret;
    if (write_size <= g_max_size) {
        return 0;
    }

    /* Begin rotate log files */
    ret = file_rotate(g_log_file, g_max_file);
    if (ret == -1) {
        COMMAND_ERROR("Rotate failed");
        return ret;
    }

    write_size = 0;
    if (log_file_open()) {
        COMMAND_ERROR("Rotate file: reopen log file failed");
        ret = -1;
    }

    return ret;
}

/* check log file */
static int check_log_file()
{
    struct stat sbuf;
    int ret = -1;

    if (stat(g_log_file, &sbuf)) {
        return 0;
    }

    if (sbuf.st_size > g_max_size) {
        ret = file_rotate(g_log_file, g_max_file);
        if (ret != 0) {
            COMMAND_ERROR("Rotate log file %s failed.", g_log_file);
        } else {
            INFO("Log file large than %lu, rotate it.", g_max_size);
        }
    } else {
        ret = 0;
    }

    return ret;
}

/* write into stdout */
static int write_into_stdout(const void *buf, size_t g_log_size)
{
    int ret;

    ret = fprintf(stderr, "%s", (const char *)buf);
    return ret;
}

/* main loop */
void main_loop()
{
    int ecount = 0;
    char rev_buf[REV_BUF_SIZE + 1] = { 0 };

    if (g_save_log_op == NULL) {
        ERROR("Not supported g_save_log_op");
        return;
    }

    for (;;) {
        int len = (int)util_read_nointr(g_fifo_fd, rev_buf, REV_BUF_SIZE);
        if (len < 0) {
            if (ecount < 2) {
                COMMAND_ERROR("%d: Read message failed: %s", ecount++, strerror(errno));
            }
            continue;
        }
        ecount = 0;

        rev_buf[len] = '\0';
        if (g_save_log_op(rev_buf, (size_t)len) < 0) {
            COMMAND_ERROR("write message failed: %s", strerror(errno));
        }
    }
}

/* log file open */
static int log_file_open()
{
    int ret = 0;
    int fd = -1;

    umask(0000);

    if (g_log_file == NULL) {
        ret = -1;
        goto out;
    }
    fd = util_open(g_log_file, O_CREAT | O_WRONLY | O_APPEND, g_log_mode);
    if (fd == -1) {
        COMMAND_ERROR("Open %s failed: %s", g_log_file, strerror(errno));
        ret = -1;
        goto out;
    }

    /* change log file mode to config, if log file exist and with different mode */
    if (fchmod(fd, g_log_mode) != 0) {
        COMMAND_ERROR("Change mode of log file: %s failed: %s", g_log_file, strerror(errno));
        close(fd);
        ret = -1;
        goto out;
    }

    if (g_log_fd != -1 && g_log_fd != fd) {
        close(g_log_fd);
    }

    g_log_fd = fd;

out:
    umask(0022);
    return ret;
}

/* init log */
static int init_log(const struct log_gather_conf *lgconf)
{
    int driver = -1;
    int ret = -1;

    driver = get_driver(lgconf->g_log_driver);
    switch (driver) {
        case LOG_GATHER_DRIVER_STDOUT:
            g_save_log_op = write_into_stdout;
            break;
        case LOG_GATHER_DRIVER_FILE:
            if (lgconf->log_path == NULL) {
                COMMAND_ERROR("Driver is file, but file path is NULL");
                return ret;
            }
            g_log_mode = lgconf->log_file_mode;
            g_max_size = lgconf->max_size;
            g_max_file = lgconf->max_file;
            g_log_file = util_strdup_s(lgconf->log_path);
            if (check_log_file()) {
                goto err_out;
            }
            if (util_build_dir(g_log_file)) {
                COMMAND_ERROR("Build log file path failed.");
                goto err_out;
            }
            if (log_file_open()) {
                goto err_out;
            }
            g_save_log_op = write_into_file;
            break;
        case LOG_GATHER_DRIVER_NOSET:
            g_save_log_op = write_into_stdout;
            driver = LOG_GATHER_DRIVER_STDOUT;
            COMMAND_ERROR("Unset log driver, use stderr to log.");
            break;
        default:
            COMMAND_ERROR("Unsupported driver: %s", lgconf->g_log_driver);
            return ret;
    }
    ret = 0;

err_out:
    if (ret != 0) {
        free(g_log_file);
        g_log_file = NULL;
    }

    return ret;
}

/* log gather */
void *log_gather(void *arg)
{
    int ret = pthread_detach(pthread_self());
    struct log_gather_conf *lgconf = (struct log_gather_conf *)arg;

    if (ret != 0) {
        CRIT("Set log monitor thread detach fail");
        goto err_out;
    }
    prctl(PR_SET_NAME, "Log_gather");
    INFO("Begin to gather logs...");

    if (lgconf == NULL || lgconf->fifo_path == NULL) {
        COMMAND_ERROR("Invalid arguments");
        goto err_out;
    }
    if (lgconf->g_log_driver == NULL) {
        COMMAND_ERROR("Log driver is NULL");
        goto err_out;
    }

    if (g_fifo_path != NULL) {
        free(g_fifo_path);
    }

    g_fifo_path = util_strdup_s(lgconf->fifo_path);

    ret = create_fifo();
    if (ret != 0) {
        goto err_out;
    }
    ret = open_log(true);
    if (ret < 0) {
        goto err_out;
    }

    if (init_log(arg)) {
        goto err_out;
    }

    *(lgconf->exitcode) = 0;

    main_loop();
    goto pexit;

err_out:
    if (lgconf != NULL) {
        *(lgconf->exitcode) = 1;
    }
pexit:
    return NULL;
}
