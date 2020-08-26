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
 * Create: 2020-09-05
 * Description: provide volume prune functions
 ******************************************************************************/
#include "prune.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"
#include "connect.h"
#include "protocol_type.h"

#define PRUNE_OPTIONS(cmdargs) \
    { CMD_OPT_TYPE_BOOL, false, "force", 'f', &(cmdargs).force, "Do not prompt for confirmation", NULL },

const char g_cmd_volume_prune_desc[] = "Remove all unused local volumes";
const char g_cmd_volume_prune_usage[] = "prune [OPTIONS]";

struct client_arguments g_cmd_volume_prune_args;

/*
 * Remove all unused local volumes
 */
static int client_volume_prune(const struct client_arguments *args, char ***volumes, size_t *volumes_len)
{
    isula_connect_ops *ops = NULL;
    struct isula_prune_volume_request request = { 0 };
    struct isula_prune_volume_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_prune_volume_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->volume.prune) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->volume.prune(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        if (response->server_errono) {
            ret = ESERVERERROR;
        }
        goto out;
    }
    *volumes = response->volumes;
    response->volumes = NULL;
    *volumes_len = response->volumes_len;
    response->volumes_len = 0;

out:
    isula_prune_volume_response_free(response);
    return ret;
}

int cmd_volume_prune_main(int argc, const char **argv)
{
    int i = 0;
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = 1;
    command_t cmd;
    char **volumes = NULL;
    size_t volumes_len = 0;
    char ch = 'n';
    struct command_option options[] = { LOG_OPTIONS(lconf) COMMON_OPTIONS(g_cmd_volume_prune_args)
        PRUNE_OPTIONS(g_cmd_volume_prune_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_volume_prune_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_volume_prune_args.progname = argv[0];
    subcommand_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_volume_prune_desc,
                    g_cmd_volume_prune_usage);
    if (command_parse_args(&cmd, &g_cmd_volume_prune_args.argc, &g_cmd_volume_prune_args.argv)) {
        exit(exit_code);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("volume prune: log init failed");
        exit(exit_code);
    }

    if (g_cmd_volume_prune_args.argc != 0) {
        COMMAND_ERROR("%s: \"volume prune\" requires exactly 0 arguments.", g_cmd_volume_prune_args.progname);
        exit(exit_code);
    }

    if (!g_cmd_volume_prune_args.force) {
        printf("WARNING! This will remove all local volumes not used by at least one container.\n");
        printf("Are you sure you want to continue? [y/N]");
        ch = getchar();
        if (ch != 'y' && ch != 'Y') {
            exit(EXIT_SUCCESS);
        }
    }

    int ret = client_volume_prune(&g_cmd_volume_prune_args, &volumes, &volumes_len);
    if (ret != 0) {
        ERROR("Prune volumes failed");
        exit(exit_code);
    }

    for (i = 0; i < volumes_len; i++) {
        printf("%s\n", volumes[i]);
    }

    exit(EXIT_SUCCESS);
}
