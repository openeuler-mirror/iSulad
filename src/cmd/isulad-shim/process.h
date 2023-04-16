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
    STDID_IN = 0,
    STDID_OUT,
    STDID_ERR,
    EXEC_RESIZE
};

typedef struct {
    int in;
    int out;
    int err;
    int resize;
} stdio_t;

typedef struct process {
    char *id;
    char *bundle;
    char *runtime;
    char *console_sock_path; // pty socket path
    int io_loop_fd;
    int exit_fd;
    int ctr_pid;
    int sync_fd;
    int listen_fd;
    int recv_fd;
    bool block_read;
    log_terminal *terminal;
    stdio_t *stdio; // shim to on runtime side, in:r out/err: w
    stdio_t *shim_io; // shim io on isulad side, in: w  out/err: r
    stdio_t *isulad_io; // isulad io, in:r out/err: w
    shim_client_process_state *state;
    sem_t sem_mainloop;
    char *buf;
} process_t;

typedef struct {
    int pid;
    int status;
} process_exit_t;

process_t* new_process(char *id, char *bundle, char *runtime);

int process_io_start(process_t *p, pthread_t *tid_epoll);
int create_process(process_t *p);
int process_signal_handle_routine(process_t *p, const pthread_t tid_epoll, const unsigned int timeout);

#ifdef __cplusplus
}
#endif

#endif

