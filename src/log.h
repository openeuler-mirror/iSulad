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
 * Description: provide container log function definition
 ******************************************************************************/
#ifndef __LCRD_LOG_H
#define __LCRD_LOG_H

#include <syslog.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif

#define LCRD_LOG_BUFFER_SIZE 4096

/* We're logging in seconds and nanoseconds. Assuming that the underlying
 * datatype is currently at maximum a 64bit integer, we have a date string that
 * is of maximum length (2^64 - 1) * 2 = (21 + 21) = 42.
 * */
#define LCRD_LOG_TIME_SIZE 42

enum g_log_driver { LOG_DRIVER_STDOUT, LOG_DRIVER_FIFO, LOG_DRIVER_SYSLOG, LOG_DRIVER_NOSET };

struct log_config {
    const char *name;
    const char *file;
    const char *priority;
    const char *prefix;
    const char *driver;
    bool quiet;
};

/* location information of the logging event */
struct log_locinfo {
    const char *file;
    const char *func;
    int line;
};

#define LOG_LOCINFO_INIT                                      \
    {                                                         \
        .file = __FILE__, .func = __func__, .line = __LINE__, \
    }

/* brief logging event object */
struct log_event {
    int priority;
    struct log_locinfo *locinfo;
};
int log_init(struct log_config *log);

void set_default_command_log_config(const char *name, struct log_config *log);

void set_log_prefix(const char *prefix);

void free_log_prefix();

int change_str_logdriver_to_enum(const char *driver);

int log_append(const struct log_event *event, const char *format, ...);

#define DEBUG(format, ...)                               \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_DEBUG;                      \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define INFO(format, ...)                                \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_INFO;                       \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define NOTICE(format, ...)                              \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_NOTICE;                     \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define WARN(format, ...)                                \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_WARNING;                    \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define ERROR(format, ...)                               \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_ERR;                        \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define EVENT(format, ...)                         \
    do {                                           \
        struct log_event append_log_event;                    \
        append_log_event.locinfo = NULL;                      \
        append_log_event.priority = LOG_ERR;                  \
        log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define CRIT(format, ...)                                \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_CRIT;                       \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define ALERT(format, ...)                               \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_ALERT;                      \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define FATAL(format, ...)                               \
    do {                                                 \
        struct log_locinfo locinfo = LOG_LOCINFO_INIT;   \
        struct log_event append_log_event;                          \
        append_log_event.locinfo = &locinfo;                        \
        append_log_event.priority = LOG_EMERG;                      \
        (void)log_append(&append_log_event, format, ##__VA_ARGS__); \
    } while (0)

#define SYSERROR(format, ...)                                  \
    do {                                                       \
        ERROR("%s - " format, strerror(errno), ##__VA_ARGS__); \
    } while (0)

#define COMMAND_ERROR(fmt, args...)         \
    do {                                    \
        fprintf(stderr, fmt "\n", ##args);  \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* __LCRD_LOG_H */

