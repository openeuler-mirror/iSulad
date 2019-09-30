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
#include "securec.h"

#include "utils.h"

const char * const g_log_prio_name[] = {
    "FATAL", "ALERT", "CRIT", "ERROR", "WARN", "NOTICE", "INFO", "DEBUG", "TRACE"
};

#define MAX_MSG_LENGTH 4096

static __thread char *g_log_prefix = NULL;

static char *g_log_vmname = NULL;
static bool g_log_quiet = false;
static int g_log_level = ISULA_LOG_DEBUG;
static int g_log_driver = LOG_DRIVER_STDOUT;
int g_lcrd_log_fd = -1;

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
    log->name = name;
    log->quiet = true;
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

/* write nointr */
static ssize_t write_nointr(int fd, const void *buf, size_t count)
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

void log_append_logfile(const struct log_object_metadata *metadata, const char *timestamp, const char *msg);
void log_append_stderr(const struct log_object_metadata *metadata, const char *timestamp, const char *msg);

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

    if (g_lcrd_log_fd != -1) {
        fprintf(stderr, "lcrd log_init called with log already initialized\n");
        return 0;
    }

    if (log_init_checker(log) != 0) {
        return -1;
    }

    free(g_log_vmname);
    g_log_vmname = util_strdup_s(log->name);

    g_log_quiet = log->quiet;

    if (log->file == NULL || strcmp(log->file, "none") == 0) {
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
    g_lcrd_log_fd = open_fifo(full_path);

    if (g_lcrd_log_fd == -1) {
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
    struct tm ptm = { 0 };
    char date_time[ISULAD_LOG_BUFFER_SIZE] = { 0 };
    int nret;

    if (clock_gettime(CLOCK_REALTIME, &timestamp) == -1) {
        fprintf(stderr, "Failed to get real time\n");
        return 0;
    }

    if (localtime_r(&(timestamp.tv_sec), &ptm) == NULL) {
        SYSERROR("Transfer timespec failed");
        return NULL;
    }

    nret = sprintf_s(date_time, ISULAD_LOG_BUFFER_SIZE, "%04d%02d%02d%02d%02d%02d.%03ld",
                     ptm.tm_year + 1900, ptm.tm_mon + 1, ptm.tm_mday, ptm.tm_hour, ptm.tm_min, ptm.tm_sec,
                     timestamp.tv_nsec / 1000000);

    if (nret < 0) {
        COMMAND_ERROR("Sprintf failed");
        return NULL;
    }

    return util_strdup_s(date_time);
}

/* log append */
int log_append(const struct log_object_metadata *metadata, const char *format, ...)
{
    int rc = 0;
    va_list args;
    char msg[MAX_MSG_LENGTH] = { 0 };
    char *date_time = NULL;
    int ret = 0;

    va_start(args, format);
    rc = vsprintf_s(msg, MAX_MSG_LENGTH, format, args);
    va_end(args);
    if (rc < 0 || rc >= MAX_MSG_LENGTH) {
        rc = sprintf_s(msg, MAX_MSG_LENGTH, "%s", "!!LONG LONG A LOG!!");
        if (rc < 0) {
            return 0;
        }
    }

    date_time = parse_timespec_to_human();
    if (date_time == NULL) {
        goto out;
    }

    switch (g_log_driver) {
        case LOG_DRIVER_STDOUT:
            if (g_log_quiet) {
                break;
            }
            log_append_stderr(metadata, date_time, msg);
            break;
        case LOG_DRIVER_FIFO:
            if (g_lcrd_log_fd == -1) {
                COMMAND_ERROR("Do not set log file");
                ret = -1;
                goto out;
            }
            log_append_logfile(metadata, date_time, msg);
            break;
        case LOG_DRIVER_NOSET:
            break;
        default:
            COMMAND_ERROR("Invalid log driver");
            ret = -1;
            goto out;
    }

out:
    free(date_time);
    return ret;
}

/* log append logfile */
void log_append_logfile(const struct log_object_metadata *metadata, const char *timestamp, const char *msg)
{
    int log_fd = -1;
    int nret = 0;
    size_t size = 0;
    char *tmp_prefix = NULL;
    char log_buffer[ISULAD_LOG_BUFFER_SIZE] = { 0 };

    if (metadata == NULL || metadata->level > g_log_level) {
        return;
    }
    log_fd = g_lcrd_log_fd;
    if (log_fd == -1) {
        return;
    }

    tmp_prefix = g_log_prefix != NULL ? g_log_prefix : g_log_vmname;
    if (tmp_prefix != NULL && strlen(tmp_prefix) > 15) {
        tmp_prefix = tmp_prefix + (strlen(tmp_prefix) - 15);
    }
    if (metadata->func != NULL && metadata->file != NULL) {
        nret = sprintf_s(log_buffer, sizeof(log_buffer), "%15s %s %-8s %s - %s:%s:%d - %s",
                         tmp_prefix ? tmp_prefix : "", timestamp, g_log_prio_name[metadata->level],
                         g_log_vmname ? g_log_vmname : "lcrd", metadata->file, metadata->func,
                         metadata->line, msg);
    } else {
        nret = sprintf_s(log_buffer, sizeof(log_buffer), "%s %s", timestamp, msg);
    }

    if (nret < 0) {
        return;
    }

    size = (size_t)nret;
    if (size > (sizeof(log_buffer) - 1)) {
        size = sizeof(log_buffer) - 1;
    }

    log_buffer[size] = '\n';

    if (write_nointr(log_fd, log_buffer, (size + 1)) == -1) {
        fprintf(stderr, "write log into logfile failed");
    }
}

/* log append stderr */
void log_append_stderr(const struct log_object_metadata *metadata, const char *timestamp, const char *msg)
{
    char *tmp_prefix = NULL;

    if (metadata == NULL || metadata->level > g_log_level) {
        return;
    }

    tmp_prefix = g_log_prefix ? g_log_prefix : g_log_vmname;
    if (tmp_prefix != NULL && strlen(tmp_prefix) > 15) {
        tmp_prefix = tmp_prefix + (strlen(tmp_prefix) - 15);
    }

    if (metadata->func != NULL && metadata->file != NULL) {
        fprintf(stderr, "%15s ", tmp_prefix ? tmp_prefix : "");
    }
    fprintf(stderr, "%s ", timestamp);
    if (metadata->func != NULL && metadata->file != NULL) {
        fprintf(stderr, "%-8s ", g_log_prio_name[metadata->level]);
        fprintf(stderr, "%s - ", g_log_vmname ? g_log_vmname : "lcrd");
        fprintf(stderr, "%s:%s:%d - ", metadata->file, metadata->func, metadata->line);
    }
    fprintf(stderr, "%s", msg);
    fprintf(stderr, "\n");
}

/* lcrd unix trans to utc */
int lcrd_unix_trans_to_utc(char *buf, size_t bufsize, const struct timespec *time)
{
    int ret = 0;
    int64_t trans_to_days = 0;
    int64_t all_days = 0;
    int64_t age = 0;
    int64_t doa = 0;
    int64_t yoa = 0;
    int64_t real_year = 0;
    int64_t doy = 0;
    int64_t nom = 0;
    int64_t real_day = 0;
    int64_t real_month = 0;
    int64_t trans_to_sec = 0;
    int64_t real_hours = 0;
    int64_t hours_to_sec = 0;
    int64_t real_minutes = 0;
    int64_t real_seconds = 0;
    char ns[LCRD_NUMSTRLEN64] = { 0 };

    /* Transtate seconds to number of days. */
    trans_to_days = time->tv_sec / 86400;

    /* Calculate days from 0000-03-01 to 1970-01-01.Days base it*/
    all_days = trans_to_days + 719468;

    /* compute the age.One age means 400 years(146097 days) */
    age = (all_days >= 0 ? all_days : all_days - 146096) / 146097;

    /* The day-of-age (doa) can then be found by subtracting the  genumber */
    doa = (all_days - age * 146097);

    /* Calculate year-of-age (yoa, range [0, 399]) */
    yoa = ((doa - (doa / 1460)) + (doa / 36524) - (doa / 146096)) / 365;

    /* Compute the year this moment */
    real_year = yoa + age * 400;

    /* Calculate the day-of-year */
    doy = doa - (365 * yoa + yoa / 4 - yoa / 100);

    /* Compute the month number. */
    nom = (5 * doy + 2) / 153;

    /* Compute the real_day. */
    real_day = (doy - ((153 * nom + 2) / 5)) + 1;

    /* Compute the correct month. */
    real_month = nom + (nom < 10 ? 3 : -9);

    /* Add one year before March */
    if (real_month < 3) {
        real_year++;
    }

    /* Translate days in the age to seconds. */
    trans_to_sec = trans_to_days * 86400;

    /* Compute the real_hours */
    real_hours = (time->tv_sec - trans_to_sec) / 3600;

    /* Translate the real hours to seconds. */
    hours_to_sec = real_hours * 3600;

    /* Calculate the real minutes */
    real_minutes = ((time->tv_sec - trans_to_sec) - hours_to_sec) / 60;

    /* Calculate the real seconds */
    real_seconds = (((time->tv_sec - trans_to_sec) - hours_to_sec) - (real_minutes * 60));

    ret = sprintf_s(ns, LCRD_NUMSTRLEN64, "%ld", time->tv_nsec);
    if (ret < 0 || ret >= LCRD_NUMSTRLEN64) {
        return -1;
    }

    /* Create the final timestamp */
    ret = sprintf_s(buf, bufsize, "%" PRId64 "%02" PRId64 "%02" PRId64 "%02" PRId64 "%02" PRId64 "%02" PRId64 ".%.3s",
                    real_year, real_month, real_day, real_hours, real_minutes, real_seconds, ns);
    if (ret < 0 || (size_t)ret >= bufsize) {
        return -1;
    }

    return 0;
}
