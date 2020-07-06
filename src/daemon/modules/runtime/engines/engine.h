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
 * Description: provide container engine definition
 ******************************************************************************/
#ifndef __ISULAD_ENGINE_H
#define __ISULAD_ENGINE_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

#include "runtime_api.h"

struct runtime_container_resources_stats_info;
struct runtime_container_status_info;

#ifdef __cplusplus
extern "C" {
#endif

struct engine_cgroup_resources {
    uint64_t blkio_weight;
    uint64_t cpu_shares;
    uint64_t cpu_period;
    uint64_t cpu_quota;
    char *cpuset_cpus;
    char *cpuset_mems;
    uint64_t memory_limit;
    uint64_t memory_swap;
    uint64_t memory_reservation;
    uint64_t kernel_memory_limit;
};

typedef struct _engine_start_request_t {
    const char *name;
    const char *lcrpath;

    const char *logpath;
    const char *loglevel;

    bool daemonize;
    bool tty;
    bool open_stdin;
    const char **console_fifos;
    uint32_t start_timeout;
    const char *container_pidfile;
    const char *exit_fifo;
} engine_start_request_t;

typedef struct _engine_exec_request_t {
    const char *name;
    const char *lcrpath;

    const char *logpath;
    const char *loglevel;

    const char **console_fifos;

    const char *user;

    const char **env;
    size_t env_len;
    const char **args;
    size_t args_len;

    int64_t timeout;

    const char *suffix;

    bool tty;
    bool open_stdin;
} engine_exec_request_t;

typedef bool (*engine_create_t)(const char *, const char *, void *);

typedef bool (*engine_start_t)(const engine_start_request_t *request);

typedef bool (*engine_clean_t)(const char *name, const char *lcrpath, const char *logpath, const char *loglevel,
                               pid_t pid);

typedef bool (*engine_delete_t)(const char *name, const char *enginepath);

typedef bool (*engine_pause_t)(const char *name, const char *enginepath);

typedef bool (*engine_resume_t)(const char *name, const char *enginepath);

typedef bool (*engine_reset_t)(const char *name, const char *enginepath);

typedef bool (*engine_resize_t)(const char *name, const char *lcrpath, unsigned int height, unsigned int width);
typedef bool (*engine_exec_resize_t)(const char *name, const char *lcrpath, const char *suffix, unsigned int height,
                                     unsigned int width);

typedef bool (*engine_update_t)(const char *name, const char *enginepath, const struct engine_cgroup_resources *cr);

typedef bool (*engine_exec_t)(const engine_exec_request_t *request, int *exit_code);

typedef int (*engine_get_container_status_t)(const char *name, const char *enginepath,
                                             struct runtime_container_status_info *status);

typedef int (*engine_get_container_resources_stats_t)(const char *name, const char *enginepath,
                                                      struct runtime_container_resources_stats_info *rs_stats);

typedef bool (*engine_get_container_pids_t)(const char *name, const char *rootpath, pid_t **pids, size_t *pids_len);

typedef bool (*engine_console_t)(const char *name, const char *enginepath, char *in_fifo, char *out_fifo,
                                 char *err_fifo);

typedef int (*engine_log_init_t)(const char *name, const char *file, const char *priority, const char *prefix,
                                 int quiet, const char *enginepath);

typedef uint32_t (*engine_get_errno_t)();

typedef const char *(*engine_get_errmsg_t)();

typedef void (*engine_clear_errmsg_t)();

struct engine_operation {
    char *engine_type;
    engine_create_t engine_create_op;
    engine_start_t engine_start_op;
    engine_delete_t engine_delete_op;
    engine_pause_t engine_pause_op;
    engine_resume_t engine_resume_op;
    engine_reset_t engine_reset_op;
    engine_resize_t engine_resize_op;
    engine_exec_resize_t engine_exec_resize_op;
    engine_exec_t engine_exec_op;
    engine_console_t engine_console_op;
    engine_get_container_status_t engine_get_container_status_op;
    engine_get_container_resources_stats_t engine_get_container_resources_stats_op;
    engine_get_container_pids_t engine_get_container_pids_op;
    engine_log_init_t engine_log_init_op;
    engine_update_t engine_update_op;
    engine_get_errmsg_t engine_get_errmsg_op;
    engine_clear_errmsg_t engine_clear_errmsg_op;
    engine_clean_t engine_clean_op;
};

extern int engines_global_init();

extern void engine_operation_free(struct engine_operation *eop);

extern int engines_discovery(const char *name);

extern struct engine_operation *engines_get_handler(const char *name);

#ifdef __cplusplus
}
#endif

#endif
