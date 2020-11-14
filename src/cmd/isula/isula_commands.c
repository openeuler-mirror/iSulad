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
 * Description: provide container command functions
 ******************************************************************************/
#include "isula_commands.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <syslog.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "client_arguments.h"
#include "config.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "constants.h"
#include "utils_file.h"
#include "utils_string.h"

static void send_msg_to_syslog(int argc, const char **argv)
{
    int nret = 0;
    int fd = -1;
    int i = 0;
    bool found = false;
    ssize_t len = 0;
    pid_t ppid = -1;
    char cmdline_path[PATH_MAX] = { 0 };
    char cmdline[MAX_BUFFER_SIZE + 1] = { 0 };
    char *msg = NULL;
    const char *target_command[] = { "kill", "restart", "rm", "stop", NULL };

    if (argc < 2) {
        COMMAND_ERROR("Invalid arguments to send syslog");
        return;
    }
    for (; target_command[i] != NULL; i++) {
        if (strcmp(argv[1], target_command[i]) == 0) {
            found = true;
            break;
        }
    }
    if (!found) {
        return;
    }
    ppid = getppid();
    // get parent cmdline, "/proc/ppid/cmdline"
    nret = snprintf(cmdline_path, PATH_MAX, "/proc/%d/cmdline", ppid);
    if (nret < 0 || nret >= PATH_MAX) {
        COMMAND_ERROR("Get parent '%d' cmdline path failed", ppid);
        return;
    }
    fd = util_open(cmdline_path, O_RDONLY, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0) {
        COMMAND_ERROR("Open parent '%d' cmdline path failed", ppid);
        return;
    }

    len = util_read_nointr(fd, cmdline, MAX_BUFFER_SIZE);
    if (len < 0) {
        COMMAND_ERROR("Read cmdline failed");
        goto free_out;
    }
    msg = util_string_join(" ", argv, (size_t)argc);
    if (msg == NULL) {
        msg = util_strdup_s(argv[1]);
    }

    openlog("isulad-client", LOG_PID, LOG_USER);
    syslog(LOG_DEBUG, "received command [%s] from parent [%d] cmdline [%s]", msg, ppid, cmdline);
    closelog();
free_out:
    close(fd);
    free(msg);
}

static void print_version()
{
    printf("Version %s, commit %s\n", VERSION, ISULAD_GIT_COMMIT);
}

/* compare commands */
int compare_commands(const void *s1, const void *s2)
{
    return strcmp((*(const struct command *)s1).name, (*(const struct command *)s2).name);
}

const struct command *command_by_args(const struct command *cmds, int argc, const char **argv)
{
    size_t i = 0;

    if (cmds == NULL) {
        return NULL;
    }

    while (1) {
        if (cmds[i].name == NULL) {
            return NULL;
        }

        if (strcmp(cmds[i].name, argv[1]) == 0) {
            if (cmds[i].subname == NULL) {
                return cmds + i;
            } else {
                if (argc > 2 && strcmp(cmds[i].subname, argv[2]) == 0) {
                    return cmds + i;
                }
            }
        }

        ++i;
    }
}

bool valid_subname(const struct command *cmds, const char *name)
{
    size_t i = 0;

    if (cmds == NULL || name == NULL) {
        return false;
    }

    while (1) {
        if (cmds[i].name == NULL) {
            return false;
        }

        if (strcmp(cmds[i].name, name) == 0 && cmds[i].subname != NULL) {
            return true;
        }

        ++i;
    }
}

// Default help command if implementation doesn't provide one
int command_default_help(const char * const name, const char * const subname, struct command *commands,
                         int argc, const char **argv)
{
    char cmd_name[PATH_MAX] = { 0 };
    const char *lastname = NULL;

    if (commands == NULL) {
        return 1;
    }

    if (get_cmd_name(name, subname, cmd_name, sizeof(cmd_name)) != 0) {
        printf("Failed to sprintf command name: %s\n", strerror(errno));
        return 1;
    }

    if (argc == 0) {
        size_t i = 0;
        size_t max_size = 0;
        printf("USAGE:\n");
        printf("\t%s <command> [args...]\n", cmd_name);
        printf("\n");

        for (i = 0; commands[i].name != NULL; i++) {
            size_t cmd_size = strlen(commands[i].name);
            if (cmd_size > max_size) {
                max_size = cmd_size;
            }
        }
        qsort(commands, i, sizeof(commands[0]), compare_commands);

        if (subname == NULL) {
            printf("MANAGEMENT COMMANDS:\n");
            for (i = 0; commands[i].name != NULL; i++) {
                if (commands[i].subname != NULL &&
                    (lastname == NULL || strcmp(lastname, commands[i].name) != 0)) {
                    printf("\t%*s\t%s\n", -(int)max_size, commands[i].name, commands[i].description);
                    lastname = commands[i].name;
                }
            }
            printf("\n");
        }

        printf("COMMANDS:\n");
        for (i = 0; commands[i].name != NULL; i++) {
            if (subname != NULL) {
                if (commands[i].subname != NULL && commands[i].subdescription != NULL) {
                    printf("\t%*s\t%s\n", -(int)max_size, commands[i].subname, commands[i].subdescription);
                }
            } else {
                if (commands[i].subname == NULL) {
                    printf("\t%*s\t%s\n", -(int)max_size, commands[i].name, commands[i].description);
                }
            }
        }

        printf("\n");
        if (subname == NULL) {
            print_common_help();
        }
        return 0;
    } else if (argc > 1) {
        printf("%s: unrecognized argument: \"%s\"\n", cmd_name, argv[1]);
        return 1;
    }

    return 0;
}

/* run command */
int run_command(struct command *commands, int argc, const char **argv)
{
    const struct command *command = NULL;
    size_t name_num = 1;
    const char *subname = NULL;
    char cmd_name[PATH_MAX] = {0};

    if (argc == 1) {
        return command_default_help(argv[0], NULL, commands,
                                    argc - 1, (const char **)(argv + 1));
    }

    if (argc >= 2 && valid_subname(commands, argv[1])) {
        subname = argv[1];
        name_num++;
    }

    if (argc == name_num) {
        return command_default_help(argv[0], subname, commands,
                                    argc - name_num, (const char **)(argv + name_num));
    }

    if (argc > name_num && strcmp(argv[name_num], "--help") == 0) {
        return command_default_help(argv[0], subname, commands,
                                    argc - name_num - 1, (const char **)(argv + name_num + 1));
    }

    if (strcmp(argv[1], "--version") == 0) {
        print_version();
        return 0;
    }

    command = command_by_args(commands, argc, argv);
    if (command != NULL) {
        send_msg_to_syslog(argc, argv);
        return command->executor(argc, (const char **)argv);
    }

    if (get_cmd_name(argv[0], subname, cmd_name, sizeof(cmd_name)) != 0) {
        printf("Failed to sprintf command name: %s\n", strerror(errno));
        return 1;
    }

    printf("%s: command \"%s\" not found\n", cmd_name, argv[name_num]);
    printf("run `%s --help` for a list of sub-commands\n", cmd_name);
    return 1;
}
