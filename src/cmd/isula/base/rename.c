/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container stop functions
 ******************************************************************************/
#include "rename.h"

#include <stdlib.h>

#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "isula_connect.h"
#include "command_parser.h"
#include "connect.h"
#include "libisula.h"

const char g_cmd_rename_desc[] = "Rename a container";
const char g_cmd_rename_usage[] = "rename [OPTIONS] OLD_NAME NEW_NAME";

struct client_arguments g_cmd_rename_args = { 0 };

static int client_rename(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_rename_request request = { 0 };
    struct isula_rename_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(*response));
    if (response == NULL) {
        ERROR("Stop: Out of memory");
        return -1;
    }

    request.old_name = args->argv[0];
    request.new_name = args->argv[1];

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.rename) {
        ERROR("Unimplemented stop op");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->container.rename(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }
out:
    isula_rename_response_free(response);
    return ret;
}

int cmd_rename_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_rename_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_rename_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        exit(ECOMMON);
    }
    g_cmd_rename_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_rename_desc,
                 g_cmd_rename_usage);
    if (command_parse_args(&cmd, &g_cmd_rename_args.argc, &g_cmd_rename_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed\n");
        exit(ECOMMON);
    }

    if (g_cmd_rename_args.argc != 2) {
        COMMAND_ERROR("\"rename\" requires 2 arguments.");
        exit(ECOMMON);
    }

    if (client_rename(&g_cmd_rename_args)) {
        ERROR("Container \"%s\" rename failed", g_cmd_rename_args.argv[0]);
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
