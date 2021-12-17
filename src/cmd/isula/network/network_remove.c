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
 * Description: provide network remove functions
 ******************************************************************************/
#include "network_remove.h"

#include "isula_libutils/log.h"
#include "utils.h"

const char g_cmd_network_remove_desc[] = "Remove networks";
const char g_cmd_networ_remove_usage[] = "rm [OPTIONS] NETWORK [NETWORK...]";

struct client_arguments g_cmd_network_remove_args = {};

int network_remove(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_network_remove_request request = { 0 };
    struct isula_network_remove_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_network_remove_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    request.name = args->network_name;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->network.remove == NULL) {
        ERROR("Unimplemented network remove op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->network.remove(&request, response, &config);
    if (ret != 0 || response->name == NULL) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = -1;
        goto out;
    }

    if (response->errmsg != NULL) {
        COMMAND_ERROR("%s", response->errmsg);
    }
    printf("%s\n", g_cmd_network_remove_args.network_name);

out:
    isula_network_remove_response_free(response);
    return ret;
}

int cmd_network_remove_main(int argc, const char **argv)
{
    size_t i;
    bool success = true;
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf) COMMON_OPTIONS(g_cmd_network_remove_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);

    if (client_arguments_init(&g_cmd_network_remove_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_network_remove_args.progname = util_string_join(" ", argv, 2);
    subcommand_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv,
                    g_cmd_network_remove_desc, g_cmd_networ_remove_usage);
    if (command_parse_args(&cmd, &g_cmd_network_remove_args.argc, &g_cmd_network_remove_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_network_remove_args.argc == 0) {
        COMMAND_ERROR("\"%s rm\" requires at least 1 network name", g_cmd_network_remove_args.progname);
        exit(EINVALIDARGS);
    }

    if (g_cmd_network_remove_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many arguments.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_network_remove_args.argc; i++) {
        g_cmd_network_remove_args.network_name = g_cmd_network_remove_args.argv[i];
        if (network_remove(&g_cmd_network_remove_args) != 0) {
            ERROR("Remove network %s failed", g_cmd_network_remove_args.network_name);
            success = false;
            break;
        }
    }

    if (!success) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
