/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2019-11-22
 * Description: provide runtime function definition
 ******************************************************************************/
#ifndef __RUNTIME_H
#define __RUNTIME_H

#include <stdint.h>
#include <stdbool.h>

#include "container_unix.h"
#include "engine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RUNTIME_NOT_IMPLEMENT_RESET -2

typedef struct _rt_create_params_t {
    const char *rootfs;
    const char *bundle;
    const char *state;
    const char *real_rootfs;
    void *oci_config_data;
    bool terminal;
    const char *stdin;
    const char *stdout;
    const char *stderr;
} rt_create_params_t;


typedef struct _rt_start_params_t {
    const char *rootpath;
    bool tty;
    bool open_stdin;

    const char *logpath;
    const char *loglevel;

    const char **console_fifos;

    uint32_t start_timeout;

    const char *container_pidfile;
    const char *exit_fifo;
    const oci_runtime_spec_process_user *puser;
} rt_start_params_t;

typedef struct _rt_restart_params_t {
    const char *rootpath;
} rt_restart_params_t;

typedef struct _rt_clean_params_t {
    const char *rootpath;
    const char *statepath;
    const char *logpath;
    const char *loglevel;
    pid_t pid;
} rt_clean_params_t;

typedef struct _rt_rm_params_t {
    const char *rootpath;
} rt_rm_params_t;

typedef struct _rt_get_console_conf_params_t {
    const char *rootpath;
    struct engine_console_config *config;
} rt_get_console_conf_params_t;

typedef struct _rt_status_params_t {
    const char *rootpath;
} rt_status_params_t;

typedef struct _rt_exec_params_t {
    const char *rootpath;
    const char *logpath;
    const char *loglevel;
    const char **console_fifos;
    int64_t timeout;
    const char *user;
    const char * const *args;
    size_t args_len;
    const char * const *envs;
    size_t envs_len;
} rt_exec_params_t;

typedef struct _rt_pause_params_t {
    const char *rootpath;
} rt_pause_params_t;

typedef struct _rt_resume_params_t {
    const char *rootpath;
} rt_resume_params_t;

struct rt_ops {
    /* detect whether runtime is of this runtime type */
    bool (*detect)(const char *runtime);

    /* runtime ops */
    int (*rt_create)(const char *name, const char *runtime, const rt_create_params_t *params);

    int (*rt_start)(const char *name, const char *runtime, const rt_start_params_t *params, container_pid_t *pid_info);

    int (*rt_restart)(const char *name, const char *runtime, const rt_restart_params_t *params);

    int (*rt_clean_resource)(const char *name, const char *runtime, const rt_clean_params_t *params);

    int (*rt_rm)(const char *name, const char *runtime, const rt_rm_params_t *params);

    int (*rt_get_console_config)(const char *name, const char *runtime, const rt_get_console_conf_params_t *params);

    int (*rt_status)(const char *name, const char *runtime, const rt_status_params_t *params,
                     struct engine_container_info *status);

    int (*rt_exec)(const char *name, const char *runtime, const rt_exec_params_t *params,
                   int *exit_code);

    int (*rt_pause)(const char *name, const char *runtime, const rt_pause_params_t *params);
    int (*rt_resume)(const char *name, const char *runtime, const rt_resume_params_t *params);
};

int runtime_create(const char *name, const char *runtime, const rt_create_params_t *params);
int runtime_clean_resource(const char *name, const char *runtime, const rt_clean_params_t *params);
int runtime_start(const char *name, const char *runtime, const rt_start_params_t *params, container_pid_t *pid_info);
int runtime_restart(const char *name, const char *runtime, const rt_restart_params_t *params);
int runtime_rm(const char *name, const char *runtime, const rt_rm_params_t *params);
int runtime_get_console_config(const char *name, const char *runtime, const rt_get_console_conf_params_t *params);
int runtime_status(const char *name, const char *runtime, const rt_status_params_t *params,
                   struct engine_container_info *status);
int runtime_exec(const char *name, const char *runtime, const rt_exec_params_t *params,
                 int *exit_code);
int runtime_pause(const char *name, const char *runtime, const rt_pause_params_t *params);
int runtime_resume(const char *name, const char *runtime, const rt_resume_params_t *params);

#ifdef __cplusplus
}
#endif

#endif

