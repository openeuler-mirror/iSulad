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
 * Description: provide network create functions
 ******************************************************************************/
#include "network_create.h"

#include "isula_libutils/log.h"
#include "utils.h"

const char g_cmd_network_create_desc[] = "Create a network";
const char g_cmd_network_create_usage[] = "create [OPTIONS] [NETWORK]";

struct client_arguments g_cmd_network_create_args = {
    .custom_conf.driver = "bridge",
};

int network_create(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_network_create_request request = { 0 };
    struct isula_network_create_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_network_create_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (args->argc != 0) {
        if (strnlen(args->argv[0], MAX_NETWORK_NAME_LEN + 1) > MAX_NETWORK_NAME_LEN) {
            COMMAND_ERROR("Network name '%s' too long, max length:%d", args->argv[0], MAX_NETWORK_NAME_LEN);
            ret = -1;
            goto out;
        }
        request.name = args->argv[0];
    }

    if (args->custom_conf.driver != NULL) {
        request.driver = args->custom_conf.driver;
    }

    request.gateway = args->custom_conf.gateway;
    request.internal = args->custom_conf.internal;
    request.subnet = args->custom_conf.subnet;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->network.create == NULL) {
        ERROR("Unimplemented network create op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->network.create(&request, response, &config);
    if (ret != 0 || response->path == NULL) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }
    if (response->errmsg != NULL) {
        COMMAND_ERROR("%s", response->errmsg);
    }
    printf("%s\n", response->path);

out:
    isula_network_create_response_free(response);
    return ret;
}

int cmd_network_create_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf) NETWORK_CREATE_OPTIONS(g_cmd_network_create_args)
        COMMON_OPTIONS(g_cmd_network_create_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);

    if (client_arguments_init(&g_cmd_network_create_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_network_create_args.progname = util_string_join(" ", argv, 2);
    subcommand_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv,
                    g_cmd_network_create_desc, g_cmd_network_create_usage);
    if (command_parse_args(&cmd, &g_cmd_network_create_args.argc, &g_cmd_network_create_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_network_create_args.argc > 1) {
        COMMAND_ERROR("\"%s create\" requires at most 1 network name", g_cmd_network_create_args.progname);
        exit(EINVALIDARGS);
    }

    if (network_create(&g_cmd_network_create_args)) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
