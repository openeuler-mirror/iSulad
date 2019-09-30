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

#include <stdbool.h>
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

#define ISULAD_LOG_BUFFER_SIZE 4096

/* We're logging in seconds and nanoseconds. Assuming that the underlying
 * datatype is currently at maximum a 64bit integer, we have a date string that
 * is of maximum length (2^64 - 1) * 2 = (21 + 21) = 42.
 * */
#define LCRD_LOG_TIME_SIZE 42

enum g_log_driver { LOG_DRIVER_STDOUT, LOG_DRIVER_FIFO, LOG_DRIVER_NOSET };

enum isula_log_level {
    ISULA_LOG_FATAL = 0,
    ISULA_LOG_ALERT,
    ISULA_LOG_CRIT,
    ISULA_LOG_ERROR,
    ISULA_LOG_WARN,
    ISULA_LOG_NOTICE,
    ISULA_LOG_INFO,
    ISULA_LOG_DEBUG,
    ISULA_LOG_TRACE,
    ISULA_LOG_MAX
};

struct log_config {
    const char *name;
    const char *file;
    const char *priority;
    const char *prefix;
    const char *driver;
    bool quiet;
};

/* brief logging event object */
struct log_object_metadata {
    /* location information of the logging item */
    const char *file;
    const char *func;
    int line;

    int level;
};

#define LOG_METADATA_INIT                                     \
    {                                                         \
        .file = __FILE__, .func = __func__, .line = __LINE__, \
    }


int log_init(struct log_config *log);

void set_default_command_log_config(const char *name, struct log_config *log);

void set_log_prefix(const char *prefix);

void free_log_prefix();

int change_str_logdriver_to_enum(const char *driver);

int log_append(const struct log_object_metadata *metadata, const char *format, ...);

#define ISULA_COMMON_LOG(loglevel, format, ...)                             \
    do {                                                                    \
        struct log_object_metadata meta = LOG_METADATA_INIT;                \
        meta.level = loglevel;                                              \
        (void)log_append(&meta, format, ##__VA_ARGS__);                     \
    } while (0)

#define DEBUG(format, ...)                                                  \
    ISULA_COMMON_LOG(ISULA_LOG_DEBUG, format, ##__VA_ARGS__)

#define INFO(format, ...)                                \
    ISULA_COMMON_LOG(ISULA_LOG_INFO, format, ##__VA_ARGS__)

#define NOTICE(format, ...)                              \
    ISULA_COMMON_LOG(ISULA_LOG_NOTICE, format, ##__VA_ARGS__)

#define WARN(format, ...)                                \
    ISULA_COMMON_LOG(ISULA_LOG_WARN, format, ##__VA_ARGS__)

#define ERROR(format, ...)                               \
    ISULA_COMMON_LOG(ISULA_LOG_ERROR, format, ##__VA_ARGS__)

#define EVENT(format, ...)                                    \
    do {                                                      \
        struct log_object_metadata metadata;                  \
        metadata.level = ISULA_LOG_ERROR;                     \
        metadata.func = NULL;                                 \
        metadata.file = NULL;                                 \
        log_append(&metadata, format, ##__VA_ARGS__);         \
    } while (0)

#define CRIT(format, ...)                                \
    ISULA_COMMON_LOG(ISULA_LOG_CRIT, format, ##__VA_ARGS__)

#define ALERT(format, ...)                               \
    ISULA_COMMON_LOG(ISULA_LOG_ALERT, format, ##__VA_ARGS__)

#define FATAL(format, ...)                               \
    ISULA_COMMON_LOG(ISULA_LOG_FATAL, format, ##__VA_ARGS__)

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
