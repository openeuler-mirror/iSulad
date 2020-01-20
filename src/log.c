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
 * Create: 2018-11-08
 * Description: provide container log function
 ******************************************************************************/
#define _GNU_SOURCE
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include "log.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <inttypes.h>

#include "utils.h"

const char * const g_log_prio_name[] = {
    "FATAL", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "TRACE"
};

#define MAX_MSG_LENGTH 4096
#define MAX_LOG_PREFIX_LENGTH 15

static __thread char *g_log_prefix = NULL;

static bool g_log_quiet = false;
static char *g_log_module = NULL;
static int g_log_level = ISULA_LOG_DEBUG;
static int g_log_driver = LOG_DRIVER_STDOUT;
int g_isulad_log_fd = -1;

/* set log prefix */
void set_log_prefix(const char *prefix)
{
    if (prefix == NULL) {
        return;
    }
    if (g_log_prefix != NULL) {
        free(g_log_prefix);
    }
    g_log_prefix = util_strdup_s(prefix);
}

void set_default_command_log_config(const char *name, struct log_config *log)
{
    log->quiet = true;
    log->name = name;
    log->file = NULL;
    log->priority = "DEBUG";
    log->driver = "stdout";
}

/* free log prefix */
void free_log_prefix()
{
    if (g_log_prefix != NULL) {
        free(g_log_prefix);
    }
    g_log_prefix = NULL;
}

static ssize_t isulad_save_log(int fd, const void *buf, size_t count)
{
    ssize_t nret = 0;

    for (;;) {
        nret = write(fd, buf, count);
        if (nret < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    return nret;
}

void do_fifo_log(const struct log_object_metadata *meta, const char *timestamp, const char *msg);
void do_stderr_log(const struct log_object_metadata *meta, const char *timestamp, const char *msg);

/* change str logdriver to enum */
int change_str_logdriver_to_enum(const char *driver)
{
    if (driver == NULL) {
        return LOG_DRIVER_NOSET;
    }
    if (strcasecmp(driver, "stdout") == 0) {
        return LOG_DRIVER_STDOUT;
    }
    if (strcasecmp(driver, "fifo") == 0) {
        return LOG_DRIVER_FIFO;
    }

    return -1;
}

#define LOG_FIFO_SIZE (1024 * 1024)
/* open fifo */
static int open_fifo(const char *fifo_path)
{
    int nret = 0;
    int fifo_fd = -1;

    if (fifo_path == NULL) {
        COMMAND_ERROR("Empty fifo path");
        return -1;
    }
    nret = mknod(fifo_path, S_IFIFO | S_IRUSR | S_IWUSR, (dev_t)0);
    if (nret && errno != EEXIST) {
        COMMAND_ERROR("Mknod failed: %s\n", strerror(errno));
        return nret;
    }

    fifo_fd = util_open(fifo_path, O_RDWR | O_NONBLOCK, 0);
    if (fifo_fd == -1) {
        COMMAND_ERROR("Open fifo %s failed: %s\n", fifo_path, strerror(errno));
        return -1;
    }

    if (fcntl(fifo_fd, F_SETPIPE_SZ, LOG_FIFO_SIZE) == -1) {
        COMMAND_ERROR("Set fifo buffer size failed: %s", strerror(errno));
        close(fifo_fd);
        return -1;
    }

    return fifo_fd;
}

static int log_init_checker(const struct log_config *log)
{
    int i = 0;
    int driver = 0;

    if (log == NULL || log->name == NULL || log->priority == NULL) {
        return -1;
    }

    for (i = ISULA_LOG_FATAL; i < ISULA_LOG_MAX; i++) {
        if (strcasecmp(g_log_prio_name[i], log->priority) == 0) {
            g_log_level = i;
            break;
        }
    }

    if (i == ISULA_LOG_MAX) {
        fprintf(stderr, "Unable to parse logging level:%s\n", log->priority);
        return -1;
    }

    driver = change_str_logdriver_to_enum(log->driver);
    if (driver < 0) {
        fprintf(stderr, "Invalid log driver: %s\n", log->driver);
        return -1;
    }
    g_log_driver = driver;
    return 0;
}

/* log init */
int log_init(struct log_config *log)
{
    int nret = 0;
    char *full_path = NULL;

    if (g_isulad_log_fd != -1) {
        fprintf(stderr, "isulad log_init called with log already initialized\n");
        return 0;
    }

    if (log_init_checker(log) != 0) {
        return -1;
    }

    free(g_log_module);
    g_log_module = util_strdup_s(log->name);
    g_log_quiet = log->quiet;

    if (log->file == NULL) {
        if (g_log_driver == LOG_DRIVER_FIFO) {
            fprintf(stderr, "Must set log file if driver is %s\n", log->driver);
            nret = -1;
        }
        goto out;
    }
    full_path = util_strdup_s(log->file);

    if (util_build_dir(full_path)) {
        fprintf(stderr, "failed to create dir for log file\n");
        nret = -1;
        goto out;
    }
    g_isulad_log_fd = open_fifo(full_path);

    if (g_isulad_log_fd == -1) {
        nret = -1;
    }
out:
    if (nret != 0 && g_log_driver == LOG_DRIVER_FIFO) {
        g_log_driver = LOG_DRIVER_NOSET;
    }
    free(full_path);

    return nret;
}

static char *parse_timespec_to_human()
{
    struct timespec timestamp;
    struct tm ptm = {0};
    char date_time[ISULAD_LOG_TIME_MAX_LEN] = { 0 };
    int nret;
#define SEC_TO_NSEC 1000000
#define FIRST_YEAR_OF_GMT 1900

    if (clock_gettime(CLOCK_REALTIME, &timestamp) == -1) {
        COMMAND_ERROR("Failed to get real time");
        return 0;
    }

    if (localtime_r(&(timestamp.tv_sec), &ptm) == NULL) {
        SYSERROR("Transfer timespec failed");
        return NULL;
    }

    nret = snprintf(date_time, ISULAD_LOG_TIME_MAX_LEN, "%04d%02d%02d%02d%02d%02d.%03ld",
                    ptm.tm_year + FIRST_YEAR_OF_GMT, ptm.tm_mon + 1, ptm.tm_mday, ptm.tm_hour, ptm.tm_min, ptm.tm_sec,
                    timestamp.tv_nsec / SEC_TO_NSEC);

    if (nret < 0 || nret >= ISULAD_LOG_TIME_MAX_LEN) {
        COMMAND_ERROR("Sprintf failed");
        return NULL;
    }

    return util_strdup_s(date_time);
}

static int do_log_by_driver(const struct log_object_metadata *meta, const char *msg, const char *date_time)
{
    switch (g_log_driver) {
        case LOG_DRIVER_STDOUT:
            if (g_log_quiet) {
                break;
            }
            do_stderr_log(meta, date_time, msg);
            break;
        case LOG_DRIVER_FIFO:
            if (g_isulad_log_fd == -1) {
                fprintf(stderr, "Do not set log file\n");
                return -1;
            }
            do_fifo_log(meta, date_time, msg);
            break;
        case LOG_DRIVER_NOSET:
            break;
        default:
            COMMAND_ERROR("Invalid log driver");
            return -1;
    }
    return 0;
}

int new_log(const struct log_object_metadata *meta, const char *format, ...)
{
    int rc = 0;
    int ret = 0;
    va_list args;
    char msg[MAX_MSG_LENGTH] = { 0 };
    char *date_time = NULL;

    va_start(args, format);
    rc = vsnprintf(msg, MAX_MSG_LENGTH, format, args);
    va_end(args);
    if (rc < 0) {
        rc = snprintf(msg, MAX_MSG_LENGTH, "%s", "Failed to truncate print error log");
        if (rc < 0 || (size_t)rc >= MAX_MSG_LENGTH) {
            return 0;
        }
    }

    date_time = parse_timespec_to_human();
    if (date_time == NULL) {
        goto out;
    }

    ret = do_log_by_driver(meta, msg, date_time);

out:
    free(date_time);
    return ret;
}

void do_fifo_log(const struct log_object_metadata *meta, const char *timestamp, const char *msg)
{
    int log_fd = -1;
    int nret = 0;
    size_t size = 0;
    char *tmp_prefix = NULL;
    char log_buffer[ISULAD_LOG_BUFFER_SIZE] = { 0 };

    if (meta == NULL || meta->level > g_log_level) {
        return;
    }
    log_fd = g_isulad_log_fd;
    if (log_fd == -1) {
        return;
    }

    tmp_prefix = g_log_prefix != NULL ? g_log_prefix : g_log_module;
    if (tmp_prefix != NULL && strlen(tmp_prefix) > MAX_LOG_PREFIX_LENGTH) {
        tmp_prefix = tmp_prefix + (strlen(tmp_prefix) - MAX_LOG_PREFIX_LENGTH);
    }
    if (meta->file != NULL) {
        nret = snprintf(log_buffer, sizeof(log_buffer), "%15s %s %-8s %s:%s:%d - %s",
                        tmp_prefix ? tmp_prefix : "", timestamp, g_log_prio_name[meta->level],
                        meta->file, meta->func, meta->line, msg);
    } else {
        nret = snprintf(log_buffer, sizeof(log_buffer), "%s %s", timestamp, msg);
    }

    if (nret < 0) {
        return;
    }

    size = (size_t)nret;
    if (size > (sizeof(log_buffer) - 1)) {
        size = sizeof(log_buffer) - 1;
    }

    log_buffer[size] = '\n';

    if (isulad_save_log(log_fd, log_buffer, (size + 1)) == -1) {
        COMMAND_ERROR("Write log into logfile failed");
    }
}

/* log append stderr */
void do_stderr_log(const struct log_object_metadata *meta, const char *timestamp, const char *msg)
{
    char *tmp_prefix = NULL;

    if (meta == NULL || meta->level > g_log_level) {
        return;
    }

    tmp_prefix = g_log_prefix ? g_log_prefix : g_log_module;
    if (tmp_prefix != NULL && strlen(tmp_prefix) > MAX_LOG_PREFIX_LENGTH) {
        tmp_prefix = tmp_prefix + (strlen(tmp_prefix) - MAX_LOG_PREFIX_LENGTH);
    }

    if (meta->file != NULL) {
        fprintf(stderr, "%15s ", tmp_prefix ? tmp_prefix : "");
    }
    fprintf(stderr, "%s ", timestamp);
    if (meta->file != NULL) {
        fprintf(stderr, "%-8s ", g_log_prio_name[meta->level]);
        fprintf(stderr, "%s:%s:%d - ", meta->file, meta->func, meta->line);
    }
    fprintf(stderr, "%s", msg);
    fprintf(stderr, "\n");
}

