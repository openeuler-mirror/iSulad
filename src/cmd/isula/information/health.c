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
 * Description: provide container health functions
 ******************************************************************************/
#include "health.h"

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "connect.h"
#include "constants.h"
#include "libisula.h"

const char g_cmd_health_check_desc[] = "iSulad health check";
const char g_cmd_health_check_usage[] = "health [command options]";

struct client_arguments g_cmd_health_check_args = {
    .service = NULL,
};

/*
 * Create a health check request message and call RPC
 */
static int client_health_check(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_health_check_request request = { 0 };
    struct isula_health_check_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_health_check_response));
    if (response == NULL) {
        ERROR("Health: Out of memory");
        return -1;
    }

    request.service = args->service;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->health.check) {
        ERROR("Unimplemented health op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->health.check(&request, response, &config);
    if (ret || response->health_status != HEALTH_SERVING_STATUS_SERVING) {
        ret = -1;
    }
out:
    isula_health_check_response_free(response);
    return ret;
}

int cmd_health_check_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };

    lconf.name = argv[0];
    lconf.priority = "ERROR";
    lconf.file = NULL;
    lconf.quiet = true;
    lconf.driver = "stdout";
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Health: log init failed");
        exit(ECOMMON);
    }

    command_t cmd;
    if (client_arguments_init(&g_cmd_health_check_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_health_check_args.progname = argv[0];
    struct command_option options[] = { HEALTH_OPTIONS(g_cmd_health_check_args),
               COMMON_OPTIONS(g_cmd_health_check_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv,
                 g_cmd_health_check_desc, g_cmd_health_check_usage);
    if (command_parse_args(&cmd, &g_cmd_health_check_args.argc, &g_cmd_health_check_args.argv)) {
        exit(EINVALIDARGS);
    }

    if (client_health_check(&g_cmd_health_check_args)) {
        printf("iSulad with socket name '%s' is NOT SERVING\n", g_cmd_health_check_args.socket);
        exit(ECOMMON);
    }

    printf("iSulad with socket name '%s' is SERVING\n", g_cmd_health_check_args.socket);
    exit(EXIT_SUCCESS);
}
