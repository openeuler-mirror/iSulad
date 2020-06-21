/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container isulad definition
 ******************************************************************************/
#ifndef __LIB_ISULAD_H
#define __LIB_ISULAD_H

#include <stdbool.h>
#include <stdint.h>
#include "utils_timestamp.h"
#include "constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/* record the isulad errmsg */
extern __thread char *g_isulad_errmsg;

/* clear the g_isulad_errmsg */
#define DAEMON_CLEAR_ERRMSG()          \
    do {                               \
        if (g_isulad_errmsg != NULL) { \
            free(g_isulad_errmsg);     \
            g_isulad_errmsg = NULL;    \
        }                              \
    } while (0)

typedef enum {
    EVENTS_TYPE_EXIT = 0,
    EVENTS_TYPE_STOPPED1 = 1,
    EVENTS_TYPE_STARTING = 2,
    EVENTS_TYPE_RUNNING1 = 3,
    EVENTS_TYPE_STOPPING = 4,
    EVENTS_TYPE_ABORTING = 5,
    EVENTS_TYPE_FREEZING = 6,
    EVENTS_TYPE_FROZEN = 7,
    EVENTS_TYPE_THAWED = 8,
    EVENTS_TYPE_OOM = 9,
    EVENTS_TYPE_CREATE = 10,
    EVENTS_TYPE_START,
    EVENTS_TYPE_RESTART,
    EVENTS_TYPE_STOP,
    EVENTS_TYPE_EXEC_CREATE,
    EVENTS_TYPE_EXEC_START,
    EVENTS_TYPE_EXEC_DIE,
    EVENTS_TYPE_ATTACH,
    EVENTS_TYPE_KILL,
    EVENTS_TYPE_TOP,
    EVENTS_TYPE_RENAME,
    EVENTS_TYPE_ARCHIVE_PATH,
    EVENTS_TYPE_EXTRACT_TO_DIR,
    EVENTS_TYPE_UPDATE,
    EVENTS_TYPE_PAUSE,
    EVENTS_TYPE_UNPAUSE,
    EVENTS_TYPE_EXPORT,
    EVENTS_TYPE_RESIZE,
    EVENTS_TYPE_PAUSED1,
    EVENTS_TYPE_MAX_STATE
} container_events_type_t;

typedef enum {
    EVENTS_TYPE_IMAGE_LOAD = 0,
    EVENTS_TYPE_IMAGE_REMOVE,
    EVENTS_TYPE_IMAGE_PULL,
    EVENTS_TYPE_IMAGE_LOGIN,
    EVENTS_TYPE_IMAGE_LOGOUT,
    EVENTS_TYPE_IMAGE_MAX_STATE
} image_events_type_t;

struct isulad_events_format {
    types_timestamp_t timestamp;
    uint32_t has_type;
    container_events_type_t type;
    char *opt;
    char *id;
    char **annotations;
    size_t annotations_len;
    uint32_t has_pid;
    uint32_t pid;
    uint32_t has_exit_status;
    uint32_t exit_status;
};

typedef void(handle_events_callback_t)(struct isulad_events_format *event);

typedef bool (*stream_check_call_cancelled)(void *context);
typedef bool (*stream_write_fun_t)(void *writer, void *data);
typedef bool (*stream_read_fun_t)(void *reader, void *data);
typedef bool (*stream_add_initial_metadata_fun_t)(void *context, const char *header, const char *val);

typedef struct {
    void *context;
    stream_check_call_cancelled is_cancelled;
    stream_add_initial_metadata_fun_t add_initial_metadata;
    void *writer;
    stream_write_fun_t write_func;
    void *reader;
    stream_read_fun_t read_func;
} stream_func_wrapper;

struct isulad_events_request {
    handle_events_callback_t *cb;
    bool storeonly;
    char *id;
    types_timestamp_t since;
    types_timestamp_t until;
};

struct isulad_events_response {
    uint32_t server_errono;
    uint32_t cc;
    char *errmsg;
};

struct isulad_copy_from_container_request {
    char *id;
    char *runtime;
    char *srcpath;
};

struct isulad_copy_from_container_response {
    char *data;
    size_t data_len;
};

struct isulad_copy_to_container_data {
    char *data;
    size_t data_len;
};

struct isulad_logs_request {
    char *id;
    char *runtime;

    char *since;
    char *until;
    bool timestamps;
    bool follow;
    int64_t tail;
    bool details;
};

struct isulad_logs_response {
    uint32_t cc;
    char *errmsg;
};

struct isulad_health_check_request {
    char *service;
};

struct isulad_health_check_response {
    Health_Serving_Status health_status;
    uint32_t cc;
    char *errmsg;
};

struct isulad_container_rename_request {
    char *old_name;
    char *new_name;
};

struct isulad_container_rename_response {
    char *id;
    uint32_t cc;
    char *errmsg;
};

struct isulad_container_resize_request {
    char *id;
    char *suffix;
    uint32_t height;
    uint32_t width;
};

struct isulad_container_resize_response {
    char *id;
    uint32_t cc;
    char *errmsg;
};

struct isulad_image_info {
    char *imageref;
    char *type;
    char *digest;
    int64_t created; /* seconds */
    int32_t created_nanos;
    int64_t size; /* Bytes */
};

struct isulad_create_image_request {
    struct isulad_image_info image_info;
};

struct isulad_create_image_response {
    uint32_t cc;
    uint32_t server_errono;
    struct isulad_image_info image_info;
    char *errmsg;
};

struct container_log_config {
    char *driver;
    char *path;
    int rotate;
    int64_t size;
};

void container_log_config_free(struct container_log_config *conf);

void isulad_events_request_free(struct isulad_events_request *request);

void isulad_copy_from_container_request_free(struct isulad_copy_from_container_request *request);

void isulad_copy_from_container_response_free(struct isulad_copy_from_container_response *response);

void isulad_set_error_message(const char *format, ...);

void isulad_try_set_error_message(const char *format, ...);

void isulad_append_error_message(const char *format, ...);

void isulad_container_rename_request_free(struct isulad_container_rename_request *request);

void isulad_container_rename_response_free(struct isulad_container_rename_response *response);

void isulad_container_resize_request_free(struct isulad_container_resize_request *request);

void isulad_container_resize_response_free(struct isulad_container_resize_response *response);

void isulad_logs_request_free(struct isulad_logs_request *request);
void isulad_logs_response_free(struct isulad_logs_response *response);

void isulad_events_format_free(struct isulad_events_format *value);

#ifdef __cplusplus
}
#endif

#endif
