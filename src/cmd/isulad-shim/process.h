/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: leizhongkai
 * Create: 2020-1-20
 * Description: process definition
 ******************************************************************************/

#ifndef CMD_ISULAD_SHIM_PROCESS_H
#define CMD_ISULAD_SHIM_PROCESS_H

#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include "isula_libutils/shim_client_process_state.h"
#include "terminal.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    stdid_in = 0,
    stdid_out,
    stdid_err
};

typedef struct {
    int in;
    int out;
    int err;
} stdio_t;

typedef struct fd_node {
    int fd;
    bool is_log;
    struct fd_node *next;
} fd_node_t;

typedef struct {
    int fd_from;
    fd_node_t *fd_to;
    int id;// 0,1,2
    pthread_mutex_t mutex;
} io_copy_t;

typedef struct {
    int epfd;
    pthread_t tid;
    pthread_attr_t attr;
    sem_t sem_thd;
    io_copy_t *ioc;
    bool shutdown;
    bool is_stdin;
    log_terminal *terminal;
} io_thread_t;

typedef struct process {
    char *id;
    char *bundle;
    char *runtime;
    char *console_sock_path;
    int io_loop_fd;
    int exit_fd;
    int ctr_pid;
    log_terminal *terminal;
    stdio_t *stdio;
    stdio_t *shim_io;
    io_thread_t *io_threads[3];// stdin,stdout,stderr
    shim_client_process_state *state;
    sem_t sem_mainloop;
} process_t;

typedef struct {
    int listen_fd;
    process_t *p;
} console_accept_t;

typedef struct {
    int pid;
    int status;
} process_exit_t;



process_t* new_process(char *id, char *bundle, char *runtime);

int open_io(process_t *p);
int process_io_init(process_t *p);
int create_process(process_t *p);
int process_signal_handle_routine(process_t *p);

#ifdef __cplusplus
}
#endif

#endif

