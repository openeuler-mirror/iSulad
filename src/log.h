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
#ifndef __ISULAD_LOG_H
#define __ISULAD_LOG_H

#include <stdbool.h>
#include <errno.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 02000000
#endif

#define ISULAD_LOG_BUFFER_SIZE 4096

#define ISULAD_LOG_TIME_MAX_LEN 21

enum g_log_driver {
    LOG_DRIVER_STDOUT,
    LOG_DRIVER_FIFO,
    LOG_DRIVER_NOSET,
};

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
    bool quiet;
    const char *name;
    const char *file;
    const char *priority;
    const char *prefix;
    const char *driver;
};

/* brief logging event object */
struct log_object_metadata {
    /* location information of the logging item */
    const char *file;
    const char *func;
    int line;

    int level;
};

int log_init(struct log_config *log);

void set_default_command_log_config(const char *name, struct log_config *log);

void set_log_prefix(const char *prefix);

void free_log_prefix();

int change_str_logdriver_to_enum(const char *driver);

int new_log(const struct log_object_metadata *meta, const char *format, ...);

#define COMMON_LOG(loglevel, format, ...)                                                   \
    do {                                                                                    \
        struct log_object_metadata meta = {                                          \
            .file = __FILENAME__, .func = __func__, .line = __LINE__, .level = loglevel,    \
        };                                                                                  \
        (void)new_log(&meta, format, ##__VA_ARGS__);                                     \
    } while (0)

#define DEBUG(format, ...)                               \
    COMMON_LOG(ISULA_LOG_DEBUG, format, ##__VA_ARGS__)

#define INFO(format, ...)                                \
    COMMON_LOG(ISULA_LOG_INFO, format, ##__VA_ARGS__)

#define NOTICE(format, ...)                              \
    COMMON_LOG(ISULA_LOG_NOTICE, format, ##__VA_ARGS__)

#define WARN(format, ...)                                \
    COMMON_LOG(ISULA_LOG_WARN, format, ##__VA_ARGS__)

#define ERROR(format, ...)                               \
    COMMON_LOG(ISULA_LOG_ERROR, format, ##__VA_ARGS__)

#define EVENT(format, ...)                                                      \
    do {                                                                        \
        struct log_object_metadata meta = {                              \
            .file = NULL, .func = NULL, .line = 0, .level = ISULA_LOG_ERROR,    \
        };                                                                      \
        (void)new_log(&meta, format, ##__VA_ARGS__);                         \
    } while (0)

#define CRIT(format, ...)                                \
    COMMON_LOG(ISULA_LOG_CRIT, format, ##__VA_ARGS__)

#define ALERT(format, ...)                               \
    COMMON_LOG(ISULA_LOG_ALERT, format, ##__VA_ARGS__)

#define FATAL(format, ...)                               \
    COMMON_LOG(ISULA_LOG_FATAL, format, ##__VA_ARGS__)

#define SYSERROR(format, ...)                                  \
    do {                                                       \
        ERROR("%s - " format, strerror(errno), ##__VA_ARGS__); \
    } while (0)

#define COMMAND_ERROR(fmt, args...)         \
    do {                                    \
        (void)fprintf(stderr, fmt "\n", ##args);  \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* __ISULAD_LOG_H */

