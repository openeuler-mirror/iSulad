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
 * Create: 2017-11-22
 * Description: provide container commands definition
 ******************************************************************************/
#ifndef __COMMAND_H
#define __COMMAND_H

#include "client_arguments.h"
#include <semaphore.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLIENT_RUNDIR "/var/run/isula"

// A command is described by:
// @name: The name which should be passed as a second parameter
// @executor: The function that will be executed if the command
// matches. Receives the argc of the program minus two, and
// the rest os argv
// @description: Brief description, will show in help messages
// @longdesc: Long descripton to show when you run `help <command>`
struct command {
    const char *const name;
    int (*executor)(int, const char **);
    const char *const description;
    const char *const longdesc;
    struct client_arguments *args;
};

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

// Gets a pointer to a command, to allow implementing custom behavior
// returns null if not found.
//
// NOTE: Command arrays must end in a command with all member is NULL
const struct command *command_by_name(const struct command *cmds, const char *const name);

// Default help command if implementation doesn't prvide one
int commmand_default_help(const char *const program_name, struct command *commands, int argc, const char **argv);

int run_command(struct command *commands, int argc, const char **argv);

#ifdef __cplusplus
}
#endif

#endif /* __COMMAND_H */
