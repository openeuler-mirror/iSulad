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
 * Author: wangfengtu
 * Create: 2020-10-14
 * Description: provide volume functions
 ******************************************************************************/
#include "volume.h"

#include "isula_commands.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "prune.h"
#include "list.h"
#include "remove.h"

const char g_cmd_volume_desc[] = "Manage volumes";

struct command g_volume_commands[] = {
    {
        // `volume ls` sub-command
        "ls", false, cmd_volume_ls_main, g_cmd_volume_ls_desc, NULL, &g_cmd_volume_ls_args
    },
    {
        // `volume prune` sub-command
        "prune", false, cmd_volume_prune_main, g_cmd_volume_prune_desc, NULL, &g_cmd_volume_prune_args
    },
    {
        // `volume rm` sub-command
        "rm", false, cmd_volume_rm_main, g_cmd_volume_rm_desc, NULL, &g_cmd_volume_rm_args
    },
    { NULL, false, NULL, NULL, NULL, NULL } // End of the list
};

int cmd_volume_main(int argc, const char **argv)
{
    const struct command *command = NULL;
    char *program = NULL;

    program = util_string_join(" ", argv, 2);

    if (argc == 2) {
        return command_subcmd_help(program, g_volume_commands, argc - 2, (const char **)(argv + 2));
    }

    if (strcmp(argv[2], "--help") == 0) {
        // isula volume help command format: isula volume --help
        return command_subcmd_help(program, g_volume_commands, argc - 3, (const char **)(argv + 3));
    }

    command = command_by_name(g_volume_commands, argv[2]);
    if (command != NULL) {
        return command->executor(argc, (const char **)argv);
    }

    printf("%s: command \"%s\" not found\n", program, argv[2]);
    printf("Run `%s --help` for a list of sub-commands\n", program);
    return 1;
}

