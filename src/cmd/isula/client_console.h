/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-10-20
 * Description: provide client console functions
 ******************************************************************************/
#ifndef CMD_ISULA_CLIENT_CONSOLE_H
#define CMD_ISULA_CLIENT_CONSOLE_H

#include <semaphore.h>
#include <stdbool.h>
#include "client_arguments.h"

#ifdef __cplusplus
extern "C" {
#endif

struct command_fifo_config {
    char *stdin_path;
    char *stdout_path;
    char *stderr_path;
    char *stdin_name;
    char *stdout_name;
    char *stderr_name;
    sem_t *wait_open;
    sem_t *wait_exit;
};

int create_console_fifos(bool attach_stdin, bool attach_stdout, bool attach_stderr, const char *name, const char *type,
                         struct command_fifo_config **pconsole_fifos);

int start_client_console_thread(struct command_fifo_config *console_fifos, bool tty);

void free_command_fifo_config(struct command_fifo_config *fifos);

void delete_command_fifo(struct command_fifo_config *fifos);

int start_client_console_resize_thread(struct client_arguments *args);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_ISULA_COMMANDS_H
