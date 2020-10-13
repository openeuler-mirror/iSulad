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
 * Author: zhangxiaoyu
 * Create: 2020-09-02
 * Description: provide network functions
 ******************************************************************************/
#include "network.h"

#include "isula_commands.h"
#include "isula_libutils/log.h"
#include "utils.h"

struct command g_network_commands[] = {
    {
        // `network create` sub-command
        "create", cmd_network_create_main, g_cmd_network_create_desc, NULL, &g_cmd_network_create_args
    },
    {
        // `network inspect` sub-command
        "inspect", cmd_network_inspect_main, g_cmd_network_inspect_desc, NULL, &g_cmd_network_inspect_args
    },
    {
        // `network ls` sub-command
        "ls", cmd_network_list_main, g_cmd_network_list_desc, NULL, &g_cmd_network_list_args
    },
    {
        // `network rm` sub-command
        "rm", cmd_network_remove_main, g_cmd_network_remove_desc, NULL, &g_cmd_network_remove_args
    },
    { NULL, NULL, NULL, NULL, NULL } // End of the list
};

const char g_cmd_network_desc[] = "Manage networks";
const char g_cmd_network_usage[] = "isula network COMMAND";

// isula network help
static int command_network_help(const char * const program_name, struct command *commands, int argc, const char **argv)
{
    const struct command *command = NULL;

    if (commands == NULL) {
        return 1;
    }

    if (argc == 0) {
        size_t i = 0;
        size_t max_size = 0;
        printf("USAGE:\n");
        printf("\t%s <command>\n", program_name);
        printf("\n");
        printf("COMMANDS:\n");
        for (i = 0; commands[i].name != NULL; i++) {
            size_t cmd_size = strlen(commands[i].name);
            if (cmd_size > max_size) {
                max_size = cmd_size;
            }
        }
        qsort(commands, i, sizeof(commands[0]), compare_commands);
        for (i = 0; commands[i].name != NULL; i++) {
            printf("\t%*s\t%s\n", -(int)max_size, commands[i].name, commands[i].description);
        }

        printf("\n");
        printf("Run %s COMMAND --help for more information on the COMMAND", program_name);
        printf("\n");
        return 0;
    } else if (argc > 1) {
        printf("%s: unrecognized command: \"%s\"\n", program_name, argv[1]);
        return 1;
    }

    command = command_by_name(commands, argv[0]);

    if (command == NULL) {
        printf("%s: sub-command \"%s\" not found\n", program_name, argv[0]);
        printf("Run `%s --help` for a list of sub-commands\n", program_name);
        return 1;
    }

    if (command->longdesc != NULL) {
        printf("%s\n", command->longdesc);
    }
    return 0;
}

int cmd_network_main(int argc, const char **argv)
{
    const struct command *command = NULL;
    char *program = NULL;

    program = util_string_join(" ", argv, 2);

    if (argc == 2) {
        return command_network_help(program, g_network_commands, argc - 2, (const char **)(argv + 2));
    }

    if (strcmp(argv[2], "--help") == 0) {
        // isula network help command format: isula network --help args
        return command_network_help(program, g_network_commands, argc - 3, (const char **)(argv + 3));
    }

    command = command_by_name(g_network_commands, argv[2]);
    if (command != NULL) {
        return command->executor(argc, (const char **)argv);
    }

    printf("%s: command \"%s\" not found\n", program, argv[2]);
    printf("Run `%s --help` for a list of sub-commands\n", program);
    return 1;
}