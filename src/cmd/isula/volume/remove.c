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
 * Create: 2020-09-04
 * Description: provide volume remove functions
 ******************************************************************************/
#include "remove.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"
#include "connect.h"
#include "protocol_type.h"

const char g_cmd_volume_rm_desc[] =
    "Remove one or more volumes. You cannot remove a volume that is in use by a container.";
const char g_cmd_volume_rm_usage[] = "rm [OPTIONS] VOLUME [VOLUME...]";

struct client_arguments g_cmd_volume_rm_args;

/*
 * remove a single volume
 */
static int client_volume_rm(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_remove_volume_request request = { 0 };
    struct isula_remove_volume_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_remove_volume_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    request.name = args->name;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->volume.remove) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->volume.remove(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        if (response->server_errono) {
            ret = ESERVERERROR;
        }
        goto out;
    }
out:
    isula_remove_volume_response_free(response);
    return ret;
}

int cmd_volume_rm_main(int argc, const char **argv)
{
    int i = 0;
    int err = 0;
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = 1;
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf) COMMON_OPTIONS(g_cmd_volume_rm_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_volume_rm_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_volume_rm_args.progname = argv[0];
    subcommand_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_volume_rm_desc,
                    g_cmd_volume_rm_usage);
    if (command_parse_args(&cmd, &g_cmd_volume_rm_args.argc, &g_cmd_volume_rm_args.argv)) {
        exit(exit_code);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("volume rm: log init failed");
        exit(exit_code);
    }

    if (g_cmd_volume_rm_args.argc == 0) {
        COMMAND_ERROR("\"volume rm\" requires at least 1 volume name");
        exit(exit_code);
    }

    if (g_cmd_volume_rm_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many volumes to remove.");
        exit(exit_code);
    }

    for (i = 0; i < g_cmd_volume_rm_args.argc; i++) {
        g_cmd_volume_rm_args.name = g_cmd_volume_rm_args.argv[i];
        int ret = client_volume_rm(&g_cmd_volume_rm_args);
        if (ret != 0) {
            ERROR("Volume \"%s\" remove failed", g_cmd_volume_rm_args.name);
            err = ret;
            continue;
        }
        printf("%s\n", g_cmd_volume_rm_args.name);
    }

    if (err) {
        exit(exit_code);
    }
    exit(EXIT_SUCCESS);
}
