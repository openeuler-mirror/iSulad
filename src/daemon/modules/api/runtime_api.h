/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2019-11-22
 * Description: provide runtime function definition
 ******************************************************************************/
#ifndef __RUNTIME_H
#define __RUNTIME_H

#include <stdint.h>
#include <stdbool.h>
#include "libisulad.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/oci_runtime_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RUNTIME_NOT_IMPLEMENT_RESET -2

typedef enum {
    RUNTIME_CONTAINER_STATUS_UNKNOWN = 0,
    RUNTIME_CONTAINER_STATUS_CREATED = 1,
    RUNTIME_CONTAINER_STATUS_STARTING = 2,
    RUNTIME_CONTAINER_STATUS_RUNNING = 3,
    RUNTIME_CONTAINER_STATUS_STOPPED = 4,
    RUNTIME_CONTAINER_STATUS_PAUSED = 5,
    RUNTIME_CONTAINER_STATUS_RESTARTING = 6,
    RUNTIME_CONTAINER_STATUS_MAX_STATE = 7
} Runtime_Container_Status;

struct runtime_container_status_info {
    bool has_pid;
    uint32_t pid;
    Runtime_Container_Status status;
};

struct runtime_container_resources_stats_info {
    uint64_t pids_current;
    /* CPU usage */
    uint64_t cpu_use_nanos;
    uint64_t cpu_system_use;
    /* BlkIO usage */
    uint64_t blkio_read;
    uint64_t blkio_write;
    /* Memory usage */
    uint64_t mem_used;
    uint64_t mem_limit;
    /* Kernel Memory usage */
    uint64_t kmem_used;
    uint64_t kmem_limit;
};

typedef struct _rt_create_params_t {
    const char *rootfs;
    const char *bundle;
    const char *state;
    void *oci_config_data;
    bool terminal;
    const char *stdin;
    const char *stdout;
    const char *stderr;
    const char *exit_fifo;
    bool tty;
    bool open_stdin;
} rt_create_params_t;

typedef struct _rt_start_params_t {
    const char *rootpath;
    const char *state;
    bool tty;
    bool open_stdin;

    const char *logpath;
    const char *loglevel;

    const char **console_fifos;

    uint32_t start_timeout;

    const char *container_pidfile;
    const char *exit_fifo;
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

typedef struct _rt_status_params_t {
    const char *rootpath;
    const char *state;
} rt_status_params_t;

typedef struct _rt_stats_params_t {
    const char *rootpath;
    const char *state;
} rt_stats_params_t;

typedef struct _rt_exec_params_t {
    const char *rootpath;
    const char *state;
    const char *logpath;
    const char *loglevel;
    const char **console_fifos;
    int64_t timeout;
    const char *suffix;
    defs_process *spec;
    bool attach_stdin;
} rt_exec_params_t;

typedef struct _rt_pause_params_t {
    const char *rootpath;
    const char *state;
} rt_pause_params_t;

typedef struct _rt_resume_params_t {
    const char *rootpath;
    const char *state;
} rt_resume_params_t;

typedef struct _rt_attach_params_t {
    const char *rootpath;
    const char *stdin;
    const char *stdout;
    const char *stderr;
} rt_attach_params_t;

typedef struct _rt_update_params_t {
    const char *rootpath;
    const host_config *hostconfig;
} rt_update_params_t;

typedef struct _rt_listpids_params_t {
    const char *rootpath;
} rt_listpids_params_t;

typedef struct _rt_listpids_out_t {
    pid_t *pids;
    size_t pids_len;
} rt_listpids_out_t;

typedef struct _rt_resize_params_t {
    const char *rootpath;
    unsigned int height;
    unsigned int width;
} rt_resize_params_t;

typedef struct _rt_exec_resize_params_t {
    const char *rootpath;
    const char *suffix;
    unsigned int height;
    unsigned int width;
} rt_exec_resize_params_t;

struct rt_ops {
    /* detect whether runtime is of this runtime type */
    bool (*detect)(const char *runtime);

    /* runtime ops */
    int (*rt_create)(const char *name, const char *runtime, const rt_create_params_t *params);

    int (*rt_start)(const char *name, const char *runtime, const rt_start_params_t *params, container_pid_t *pid_info);

    int (*rt_restart)(const char *name, const char *runtime, const rt_restart_params_t *params);

    int (*rt_clean_resource)(const char *name, const char *runtime, const rt_clean_params_t *params);

    int (*rt_rm)(const char *name, const char *runtime, const rt_rm_params_t *params);

    int (*rt_status)(const char *name, const char *runtime, const rt_status_params_t *params,
                     struct runtime_container_status_info *status);

    int (*rt_resources_stats)(const char *name, const char *runtime, const rt_stats_params_t *params,
                              struct runtime_container_resources_stats_info *rs_stats);

    int (*rt_exec)(const char *name, const char *runtime, const rt_exec_params_t *params, int *exit_code);

    int (*rt_pause)(const char *name, const char *runtime, const rt_pause_params_t *params);
    int (*rt_resume)(const char *name, const char *runtime, const rt_resume_params_t *params);

    int (*rt_attach)(const char *name, const char *runtime, const rt_attach_params_t *params);

    int (*rt_update)(const char *name, const char *runtime, const rt_update_params_t *params);

    int (*rt_listpids)(const char *name, const char *runtime, const rt_listpids_params_t *params,
                       rt_listpids_out_t *out);
    int (*rt_resize)(const char *name, const char *runtime, const rt_resize_params_t *params);
    int (*rt_exec_resize)(const char *name, const char *runtime, const rt_exec_resize_params_t *params);
};

int runtime_create(const char *name, const char *runtime, const rt_create_params_t *params);
int runtime_clean_resource(const char *name, const char *runtime, const rt_clean_params_t *params);
int runtime_start(const char *name, const char *runtime, const rt_start_params_t *params, container_pid_t *pid_info);
int runtime_restart(const char *name, const char *runtime, const rt_restart_params_t *params);
int runtime_rm(const char *name, const char *runtime, const rt_rm_params_t *params);
int runtime_status(const char *name, const char *runtime, const rt_status_params_t *params,
                   struct runtime_container_status_info *status);
int runtime_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                            struct runtime_container_resources_stats_info *rs_stats);
int runtime_exec(const char *name, const char *runtime, const rt_exec_params_t *params, int *exit_code);
int runtime_pause(const char *name, const char *runtime, const rt_pause_params_t *params);
int runtime_resume(const char *name, const char *runtime, const rt_resume_params_t *params);
int runtime_attach(const char *name, const char *runtime, const rt_attach_params_t *params);

int runtime_update(const char *name, const char *runtime, const rt_update_params_t *params);

int runtime_listpids(const char *name, const char *runtime, const rt_listpids_params_t *params, rt_listpids_out_t *out);
void free_rt_listpids_out_t(rt_listpids_out_t *out);
int runtime_resize(const char *name, const char *runtime, const rt_resize_params_t *params);
int runtime_exec_resize(const char *name, const char *runtime, const rt_exec_resize_params_t *params);

int runtime_init();
#ifdef __cplusplus
}
#endif

#endif
