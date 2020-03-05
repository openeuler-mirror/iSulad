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
 * Description: provide container isulad definition
 ******************************************************************************/
#ifndef __LIB_ISULAD_H
#define __LIB_ISULAD_H

#include <stdbool.h>
#include <stdint.h>

#include "container_def.h"

#ifdef __cplusplus
extern "C" {
#endif

/* record the isulad errmsg */
extern __thread char *g_isulad_errmsg;

#define CONTAINER_LOG_CONFIG_KEY_FILE "log.console.file"
#define CONTAINER_LOG_CONFIG_KEY_ROTATE "log.console.filerotate"
#define CONTAINER_LOG_CONFIG_KEY_SIZE "log.console.filesize"

#define BLOBS_PATH "blobs/sha256"
#define DIFF_LAYERS_PATH "snapshots/diff"
#define DEFAULT_TCP_HOST "tcp://localhost:2375"
#define DEFAULT_TLS_HOST "tcp://localhost:2376"

#define AUTH_PLUGIN "authz-broker"

#define ISULAD_ISULA_ADAPTER                      "isula-adapter"
#define ISULAD_ISULA_ACCEL_ARGS                   "isulad.accel.args"
#define ISULAD_ISULA_ACCEL_ARGS_SEPERATOR         ";"
#define ISULAD_ENABLE_PLUGINS                     "ISULAD_ENABLE_PLUGINS"
#define ISULAD_ENABLE_PLUGINS_SEPERATOR           ","
#define ISULAD_ENABLE_PLUGINS_SEPERATOR_CHAR      ','

#define MAX_HOSTS 10

/* clear the g_isulad_errmsg */
#define DAEMON_CLEAR_ERRMSG() do { \
        if (g_isulad_errmsg != NULL) { \
            free(g_isulad_errmsg); \
            g_isulad_errmsg = NULL; \
        } \
    } while (0)

typedef enum {
    NO_CLIENT_CERT = 0,
    REQUEST_CLIENT_CERT,
    REQUIRE_ANY_CLIENT_CERT,
    VERIFY_CLIENT_CERT_IF_GIVEN,
    REQUIRE_AND_VERIFY_CLIENT_CERT
} client_auth_type_t;

struct isulad_client_cgroup_resources {
    uint16_t blkio_weight;
    int64_t cpu_shares;
    int64_t cpu_period;
    int64_t cpu_quota;
    int64_t cpu_rt_period;
    int64_t cpu_rt_runtime;
    char *cpuset_cpus;
    char *cpuset_mems;
    int64_t memory_limit;
    int64_t memory_swap;
    int64_t memory_reservation;
    int64_t kernel_memory_limit;
    char **ulimits;
    size_t ulimits_len;
};

struct create_custom_config {
    /* environment variables */
    int env_len;
    char **env;

    /* cgroup resources */
    struct isulad_client_cgroup_resources cr;

    /* hugepage limits */
    int hugepage_limits_len;
    char **hugepage_limits;

    /* hook-spec file */
    char *hook_spec;

    /* pids limit */
    char *pids_limit;

    /* files limit */
    char *files_limit;

    /* user and group */
    char *user;

    /* hostname */
    char *hostname;

    /* privileged */
    bool privileged;

    /* readonly rootfs */
    bool readonly;

    /* alldevices */
    bool all_devices;

    /* system container */
    bool  system_container;

    /* cap add */
    int cap_adds_len;
    char **cap_adds;

    /* cap drop */
    int cap_drops_len;
    char **cap_drops;

    /* volumes to mount */
    int volumes_len;
    char **volumes;

    /* mounts to mount filesystem */
    int mounts_len;
    char **mounts;

    /* devices to populate in container */
    int devices_len;
    char **devices;

    /* blkio weight devices */
    int weight_dev_len;
    char **weight_devices;

    /* entrypoint */
    char *entrypoint;

    /* init command args */
    int command_len;
    char * const *commands;

    /* console log options */
    char *log_file;
    char *log_file_size;
    unsigned int log_file_rotate;

    char *share_ns[NAMESPACE_MAX];
};

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

typedef void (handle_events_callback_t)(struct isulad_events_format *event);

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

