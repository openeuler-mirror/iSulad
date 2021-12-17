/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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
        "create", false, cmd_network_create_main, g_cmd_network_create_desc, NULL, &g_cmd_network_create_args
    },
    {
        // `network inspect` sub-command
        "inspect", false, cmd_network_inspect_main, g_cmd_network_inspect_desc, NULL, &g_cmd_network_inspect_args
    },
    {
        // `network ls` sub-command
        "ls", false, cmd_network_list_main, g_cmd_network_list_desc, NULL, &g_cmd_network_list_args
    },
    {
        // `network rm` sub-command
        "rm", false, cmd_network_remove_main, g_cmd_network_remove_desc, NULL, &g_cmd_network_remove_args
    },
    { NULL, NULL, NULL, NULL, NULL } // End of the list
};

const char g_cmd_network_desc[] = "Manage networks";
const char g_cmd_network_usage[] = "isula network COMMAND";

int cmd_network_main(int argc, const char **argv)
{
    const struct command *command = NULL;
    char *program = NULL;

    program = util_string_join(" ", argv, 2);

    if (argc == 2) {
        return command_subcmd_help(program, g_network_commands, argc - 2, (const char **)(argv + 2));
    }

    if (strcmp(argv[2], "--help") == 0) {
        // isula network help command format: isula network --help args
        return command_subcmd_help(program, g_network_commands, argc - 3, (const char **)(argv + 3));
    }

    command = command_by_name(g_network_commands, argv[2]);
    if (command != NULL) {
        return command->executor(argc, (const char **)argv);
    }

    printf("%s: command \"%s\" not found\n", program, argv[2]);
    printf("Run `%s --help` for a list of sub-commands\n", program);
    return 1;
}